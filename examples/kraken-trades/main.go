package main

import (
	"fmt"
	"log"
	"os"
	"os/signal"
	"strconv"
	"syscall"

	"code.cryptowat.ch/cw-sdk-go/client/rest"
	"code.cryptowat.ch/cw-sdk-go/client/websocket"
	"code.cryptowat.ch/cw-sdk-go/common"
	"code.cryptowat.ch/cw-sdk-go/config"

	flag "github.com/spf13/pflag"
)

const (
	exchangeSymbol = "kraken"
)

func main() {
	// We need this since getting user's home dir can fail.
	defaultConfig, err := config.DefaultFilepath()
	if err != nil {
		log.Print(err)
		os.Exit(1)
	}

	var (
		configFile string
		verbose    bool
	)

	flag.StringVarP(&configFile, "config", "c", defaultConfig, "Configuration file")
	flag.BoolVarP(&verbose, "verbose", "v", false, "Prints all debug messages to stdout")

	flag.Parse()

	cfg, err := config.New(configFile)
	if err != nil {
		log.Print(err)
		os.Exit(1)
	}

	if err := cfg.Validate(); err != nil {
		log.Print(err)
		os.Exit(1)
	}

	restclient := rest.NewCWRESTClient(nil)

	// Get exchange description, in particular we'll need the ID to use it
	// in stream subscriptions.
	exchange, err := restclient.GetExchangeDescr(exchangeSymbol)
	if err != nil {
		log.Printf("failed to get details of %s: %s", exchangeSymbol, err)
		os.Exit(1)
	}

	// Get market descriptions, to know symbols (like "btcusd") by integer ID.
	marketsSlice, err := restclient.GetExchangeMarketsDescr(exchangeSymbol)
	if err != nil {
		log.Printf("failed to get markets of %s: %s", exchangeSymbol, err)
		os.Exit(1)
	}

	markets := map[common.MarketID]rest.MarketDescr{}
	for _, market := range marketsSlice {
		markets[common.MarketID(strconv.Itoa(market.ID))] = market
	}

	// Create a new stream connection instance. Note that the actual connection
	// will happen later.
	c, err := websocket.NewStreamClient(&websocket.StreamClientParams{
		WSParams: &websocket.WSParams{
			URL:       cfg.StreamURL,
			APIKey:    cfg.APIKey,
			SecretKey: cfg.SecretKey,
		},

		Subscriptions: []*websocket.StreamSubscription{
			&websocket.StreamSubscription{
				Resource: fmt.Sprintf("exchanges:%d:trades", exchange.ID),
			},
		},
	})
	if err != nil {
		log.Print(err)
		os.Exit(1)
	}

	if verbose {
		lastErrChan := make(chan error, 1)

		c.OnError(func(err error, disconnecting bool) {
			if disconnecting {
				lastErrChan <- err
				return
			}

			log.Printf("Error: %s", err)
		})

		// Ask for the state transition updates, and present them to the user somehow.
		c.OnStateChange(
			websocket.ConnStateAny,
			func(oldState, state websocket.ConnState) {
				select {
				case err := <-lastErrChan:
					if err != nil {
						log.Printf("State updated: %s -> %s: %s", websocket.ConnStateNames[oldState], websocket.ConnStateNames[state], err)
					} else {
						log.Printf("State updated: %s -> %s", websocket.ConnStateNames[oldState], websocket.ConnStateNames[state])
					}
				default:
					log.Printf("State updated: %s -> %s", websocket.ConnStateNames[oldState], websocket.ConnStateNames[state])
				}
			},
		)
	}

	// Listen for received market messages and print them
	c.OnMarketUpdate(func(market common.Market, md common.MarketUpdate) {
		if md.TradesUpdate == nil {
			return
		}

		tradesUpdate := md.TradesUpdate
		for _, trade := range tradesUpdate.Trades {
			log.Printf(
				"%-25s %-25s %-25s",
				fmt.Sprintf("Trade: %s (%s)", market.CurrencyPairID, markets[market.ID].Pair),
				fmt.Sprintf("Price: %s", trade.Price),
				fmt.Sprintf("Amount: %s", trade.Amount),
			)
		}
	})

	if verbose {
		log.Printf("Connecting to %s ...", c.URL())
	}

	// Finally, connect.
	if err := c.Connect(); err != nil {
		log.Print(err)
		os.Exit(1)
	}

	signals := make(chan os.Signal, 1)
	signal.Notify(signals, syscall.SIGINT, syscall.SIGQUIT, syscall.SIGTERM)

	// Wait until the OS signal is received, at which point we'll close the connection and quit.
	<-signals

	log.Print("Closing connection...")

	if err := c.Close(); err != nil {
		log.Printf("Failed to close connection: %s", err)
	}

}

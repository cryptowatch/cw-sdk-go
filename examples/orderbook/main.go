package main

import (
	"fmt"
	"log"
	"os"
	"os/signal"
	"syscall"

	"code.cryptowat.ch/cw-sdk-go/client/rest"
	"code.cryptowat.ch/cw-sdk-go/client/websocket"
	"code.cryptowat.ch/cw-sdk-go/common"
	"code.cryptowat.ch/cw-sdk-go/config"
	"code.cryptowat.ch/cw-sdk-go/orderbooks"

	flag "github.com/spf13/pflag"
)

const (
	defaultExchange = "kraken"
	defaultPair     = "btceur"
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
		exchange   string
		pair       string
	)

	flag.StringVarP(&configFile, "config", "c", defaultConfig, "Configuration file")
	flag.BoolVarP(&verbose, "verbose", "v", false, "Prints all debug messages to stdout")

	flag.StringVarP(&exchange, "exchange", "e", defaultExchange, "")
	flag.StringVarP(&pair, "pair", "p", defaultPair, "")

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

	// Get market description, in particular we'll need the ID to use it
	// in the stream subscription.
	market, err := restclient.GetMarketDescr(exchange, pair)
	if err != nil {
		log.Printf("failed to get market %s/%s: %s", exchange, pair, err)
		os.Exit(1)
	}

	// Create a new stream connection instance. Note that this does not yet
	// initiate the actual connection.
	c, err := websocket.NewStreamClient(&websocket.StreamClientParams{
		WSParams: &websocket.WSParams{
			URL:       cfg.StreamURL,
			APIKey:    cfg.APIKey,
			SecretKey: cfg.SecretKey,
		},

		Subscriptions: []*websocket.StreamSubscription{
			&websocket.StreamSubscription{
				Resource: fmt.Sprintf("markets:%d:book:deltas", market.ID),
			},
			&websocket.StreamSubscription{
				Resource: fmt.Sprintf("markets:%d:book:snapshots", market.ID),
			},
		},
	})
	if err != nil {
		log.Print(err)
		os.Exit(1)
	}

	// Create orderbook updater: it handles all snapshots and deltas correctly,
	// keeping track of sequence numbers, fetching snapshots from the REST API
	// when appropriate and replaying cached deltas on them, etc. We'll only
	// need to feed it with snapshots and deltas we receive from the wire, and
	// subscribe on orderbook updates using OnOrderBookUpdate.
	orderbookUpdater := orderbooks.NewOrderBookUpdater(&orderbooks.OrderBookUpdaterParams{
		SnapshotGetter: orderbooks.NewOrderBookSnapshotGetterRESTBySymbol(
			exchange, pair, &rest.CWRESTClientParams{
				APIURL: cfg.APIURL,
			},
		),
	})

	// Ask for the state transition updates and print them.
	c.OnStateChange(
		websocket.ConnStateAny,
		func(oldState, state websocket.ConnState) {
			log.Printf(
				"State updated: %s -> %s",
				websocket.ConnStateNames[oldState],
				websocket.ConnStateNames[state],
			)
		},
	)

	// Listen for market changes.
	c.OnMarketUpdate(
		func(market common.Market, md common.MarketUpdate) {
			if snapshot := md.OrderBookSnapshot; snapshot != nil {
				orderbookUpdater.ReceiveSnapshot(*snapshot)
			} else if delta := md.OrderBookDelta; delta != nil {
				// First, pretty-print the delta object.
				log.Println(PrettyDeltaUpdate{*delta}.String())

				orderbookUpdater.ReceiveDelta(*delta)
			}
		},
	)

	orderbookUpdater.OnUpdate(func(update orderbooks.Update) {
		if ob := update.OrderBookUpdate; ob != nil {
			log.Println("Updated orderbook:")
			orderbook := NewOrderBookMirror(*ob)
			log.Println(orderbook.PrettyString())
		} else if state := update.StateUpdate; state != nil {
			log.Printf("Updated state: %+v\n", state)
		} else if err := update.GetSnapshotError; err != nil {
			log.Println("Error", err)
		}
	})

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

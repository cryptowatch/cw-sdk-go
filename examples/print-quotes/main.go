package main

import (
	"fmt"
	"log"
	"os"
	"os/signal"
	"sort"
	"strconv"
	"syscall"

	"code.cryptowat.ch/cw-sdk-go/client/rest"
	"code.cryptowat.ch/cw-sdk-go/client/websocket"
	"code.cryptowat.ch/cw-sdk-go/common"
	"code.cryptowat.ch/cw-sdk-go/config"

	flag "github.com/spf13/pflag"
)

const (
	defaultPair = "btcusd"
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
		pair       string
	)

	flag.StringVarP(&configFile, "config", "c", defaultConfig, "Configuration file")
	flag.BoolVarP(&verbose, "verbose", "v", false, "Prints all debug messages to stdout")

	flag.StringVarP(&pair, "pair", "p", defaultPair, "Pair to watch")

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

	marketsIndex, err := restclient.GetMarketsIndex()
	if err != nil {
		log.Print(err)
		os.Exit(1)
	}

	pairDescr, err := restclient.GetPairDescr(pair)
	if err != nil {
		log.Print(err)
		os.Exit(1)
	}

	quoteVals := make(map[common.MarketID]string)
	marketSymbols := make(map[common.MarketID]string)

	for _, market := range marketsIndex {
		marketSymbols[common.MarketID(strconv.Itoa(market.ID))] = market.Exchange + " " + market.Pair
	}

	c, err := websocket.NewStreamClient(&websocket.StreamClientParams{
		WSParams: &websocket.WSParams{
			URL:       cfg.StreamURL,
			APIKey:    cfg.APIKey,
			SecretKey: cfg.SecretKey,
		},

		Subscriptions: []*websocket.StreamSubscription{
			&websocket.StreamSubscription{
				Resource: fmt.Sprintf("pairs:%d:trades", pairDescr.ID),
			},
		},
	})
	if err != nil {
		log.Print(err)
		os.Exit(1)
	}

	c.OnMarketUpdate(func(market common.Market, md common.MarketUpdate) {
		if md.TradesUpdate == nil {
			return
		}

		tradesUpdate := md.TradesUpdate
		trades := tradesUpdate.Trades

		quoteVals[market.ID] = trades[len(trades)-1].Price

		// Possible race - an update might be received when quoteVals are being read.
		// The same applies to marketSymbols.
		printQuotes(marketSymbols, quoteVals)
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

// Simple struct type quote for sorting quotes
type quote struct {
	symbol, value string
}

type quotes []quote

func (qs quotes) Equal(i, j int) bool {
	return qs[i].value == qs[j].value
}

func (qs quotes) Less(i, j int) bool {
	ival, _ := strconv.ParseFloat(qs[i].value, 32)
	jval, _ := strconv.ParseFloat(qs[j].value, 32)

	if ival == jval {
		return qs[i].symbol < qs[j].symbol
	}

	return ival < jval
}

func (qs quotes) Len() int {
	return len(qs)
}

func (qs quotes) Swap(i, j int) {
	qs[i], qs[j] = qs[j], qs[i]
}

// printQuotes draws all of the quotes we have received to the screen
func printQuotes(marketSymbols, quoteVals map[common.MarketID]string) {
	var lines quotes

	for k, v := range quoteVals {
		lines = append(lines, quote{marketSymbols[k], v})
	}

	sort.Sort(sort.Reverse(lines))

	// Clear screen
	print("\033[H\033[2J")

	for _, line := range lines {
		fmt.Printf("%20s %s\n", line.symbol, line.value)
	}

}

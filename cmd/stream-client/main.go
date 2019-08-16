/*
This is a simple app that allows to subscribe to and receive updates
for a given list of subscriptions.
*/
package main

import (
	"log"
	"os"
	"os/signal"
	"syscall"

	"code.cryptowat.ch/cw-sdk-go/client/websocket"
	"code.cryptowat.ch/cw-sdk-go/common"
	"code.cryptowat.ch/cw-sdk-go/config"

	flag "github.com/spf13/pflag"
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
		subs       []string
	)

	flag.StringVarP(&configFile, "config", "c", defaultConfig, "Configuration file")
	flag.BoolVarP(&verbose, "verbose", "v", false, "Prints all debug messages to stdout")
	flag.StringSliceVarP(&subs, "sub", "s", []string{}, "Subscription key. This flag can be given multiple times")

	flag.Parse()

	if len(subs) == 0 {
		log.Printf("Error: at least one subscription must be spicified")
		os.Exit(1)
	}

	cfg, err := config.New(configFile)
	if err != nil {
		log.Print(err)
		os.Exit(1)
	}

	if err := cfg.Validate(); err != nil {
		log.Print(err)
		os.Exit(1)
	}

	streamSubs := make([]*websocket.StreamSubscription, 0, len(subs))
	for _, s := range subs {
		streamSubs = append(streamSubs, &websocket.StreamSubscription{Resource: s})
	}

	// Setup market connection (but don't connect just yet).
	c, err := websocket.NewStreamClient(&websocket.StreamClientParams{
		WSParams: &websocket.WSParams{
			URL:       cfg.StreamURL,
			APIKey:    cfg.APIKey,
			SecretKey: cfg.SecretKey,
		},

		Subscriptions: streamSubs,
	})
	if err != nil {
		log.Print(err)
		os.Exit(1)
	}

	signals := make(chan os.Signal, 1)

	// Will print state changes to the user.
	if verbose {
		lastErrChan := make(chan error, 1)

		c.OnError(func(err error, disconnecting bool) {
			// If the client is going to disconnect because of that error, just save
			// the error to show later on the disconnection message.
			if disconnecting {
				lastErrChan <- err
				return
			}

			// Otherwise, print the error message right away.
			log.Printf("Error: %s", err)
		})

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

		c.OnBandwidthUpdate(func(b websocket.Bandwidth) {
			log.Println(b)
			if !b.OK {
				signals <- syscall.SIGQUIT
			}
		})
	}

	// Will print received market update messages.
	c.OnMarketUpdate(func(market common.Market, update common.MarketUpdate) {
		log.Printf("Update on market %s: %+v", market.ID, update)
	})

	c.OnPairUpdate(func(pair common.Pair, update common.PairUpdate) {
		log.Printf("Pair update on pair %s: %+v", pair.ID, update)
	})

	c.OnSubscriptionResult(func(result websocket.SubscriptionResult) {
		log.Printf("Subscription result: %+v", result)
	})

	c.OnUnsubscriptionResult(func(result websocket.UnsubscriptionResult) {
		log.Printf("Unsubscription result: %+v\n", result)
	})

	if verbose {
		log.Printf("Connecting to %s ...", c.URL())
	}

	// Finally, connect.
	if err := c.Connect(); err != nil {
		log.Print(err)
		os.Exit(1)
	}

	signal.Notify(signals, syscall.SIGINT, syscall.SIGQUIT, syscall.SIGTERM)

	// Wait until the OS signal is received, at which point we'll close the connection and quit.
	<-signals

	log.Print("Closing connection...")

	// The connection could already be closed, which would throw an error,
	// but we can swallow it
	c.Close()
}

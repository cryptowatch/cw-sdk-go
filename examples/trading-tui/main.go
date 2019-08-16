package main

import (
	"fmt"
	"os"
	"sort"
	"strings"

	"github.com/juju/errors"
	"github.com/rivo/tview"

	"code.cryptowat.ch/cw-sdk-go/client/rest"
	"code.cryptowat.ch/cw-sdk-go/client/websocket"
	"code.cryptowat.ch/cw-sdk-go/common"
	"code.cryptowat.ch/cw-sdk-go/config"

	flag "github.com/spf13/pflag"
)

func main() {
	// We need this since getting user's home dir can fail.
	defaultConfig, err := config.DefaultFilepath()
	if err != nil {
		fmt.Fprintf(os.Stderr, "%s\n", err)
		os.Exit(1)
	}

	var (
		configFile    string
		verbose       bool
		marketStrings []string
	)

	flag.StringVarP(&configFile, "config", "c", defaultConfig, "Configuration file")
	flag.BoolVarP(&verbose, "verbose", "v", false, "Prints all debug messages to stdout")
	flag.StringSliceVarP(&marketStrings, "market", "m", []string{}, "Market to handle, like kraken/btc/usd. This flag can be given multiple times")

	flag.Parse()

	if len(marketStrings) == 0 {
		fmt.Fprintf(os.Stderr, "%s\n", "Specify at least one --market <exchange>/<base>/<quote>")
		os.Exit(1)
	}

	cfg, err := config.New(configFile)
	if err != nil {
		fmt.Fprintf(os.Stderr, "%s\n", err)
		os.Exit(1)
	}

	if err := cfg.Validate(); err != nil {
		fmt.Fprintf(os.Stderr, "%s\n", err)
		fmt.Fprintf(
			os.Stderr,
			"Make sure your config file %s contains credentials, like this:\n%s\n",
			configFile,
			(&config.CW{}).Example().String(),
		)
		os.Exit(1)
	}

	statesTracker := NewConnStateTracker()

	markets, marketDescrByID := getMarketDescrs(marketStrings)

	app := tview.NewApplication()

	mainView := NewMainView(&MainViewParams{
		App:     app,
		Markets: markets,
	})

	sc, err := setupStreamClient(cfg, markets, mainView, statesTracker)
	if err != nil {
		fmt.Fprintf(os.Stderr, "Error setting up stream client: %s", err)
		os.Exit(1)
	}

	tc, err := setupTradeClient(cfg, markets, marketDescrByID, mainView, statesTracker)
	if err != nil {
		fmt.Fprintf(os.Stderr, "Error setting up trade client: %s", err)
		os.Exit(1)
	}

	fmt.Println("Starting UI ...")
	if err := app.SetRoot(mainView.GetUIPrimitive(), true).Run(); err != nil {
		fmt.Fprintf(os.Stderr, "Error: %s\n", err)
		sc.Close()
		tc.Close()
		os.Exit(1)
	}

	// We end up here when the user quits the UI

	fmt.Println("")
	fmt.Println("Closing connections...")

	sc.Close()
	tc.Close()

	fmt.Println("Have a nice day.")
}

func getStateListener(
	statesTracker *ConnStateTracker,
	mainView *MainView,
	cc ConnComponent,
) websocket.StateCallback {
	return func(oldState, state websocket.ConnState) {
		summary := statesTracker.SetComponentState(cc, state)

		if summary.AllConnected {
			mainView.HideMessagebox("connectivity_issues")
		} else {
			mainView.ShowMessagebox(
				"connectivity_issues",
				"Connecting",
				getConnectivityStatusMessage(summary),
				&MessageboxParams{
					Buttons: []string{},
				},
			)
		}
	}
}

func getConnectivityStatusMessage(summary *ConnStateSummary) string {
	return fmt.Sprintf(
		"Stream: %s\n\nTrading: %s",
		getComponentConnectivityStatusMessage(summary.States[ConnComponentStream]),
		getComponentConnectivityStatusMessage(summary.States[ConnComponentTrading]),
	)
}

func getComponentConnectivityStatusMessage(s ConnComponentState) string {
	ret := websocket.ConnStateNames[s.State]
	if s.State != websocket.ConnStateEstablished && s.LastErr != nil {
		ret += fmt.Sprintf(" (%s)", s.LastErr.Error())
	}

	return ret
}

func getMarketDescrs(marketStrings []string) (markets []MarketDescr, marketDescrByID map[common.MarketID]MarketDescr) {
	rest := rest.NewCWRESTClient(nil)

	marketDescrByID = map[common.MarketID]MarketDescr{}

	mchan := make(chan MarketDescr)

	for _, ms := range marketStrings {
		parts := strings.Split(ms, "/")
		if len(parts) != 3 {
			fmt.Fprintf(os.Stderr, "Invalid market %q, should contain 3 parts, like \"kraken/btc/usd\"\n", ms)
			os.Exit(1)
		}

		go func(exchange, base, quote string) {
			fmt.Printf("Getting descriptor of %s/%s/%s ...\n", exchange, base, quote)
			md, err := rest.GetMarketDescr(parts[0], parts[1]+parts[2])
			if err != nil {
				fmt.Fprintf(os.Stderr, "failed to get market %s/%s/%s: %s\n", exchange, base, quote, err)
				os.Exit(1)
			}

			fmt.Printf("Got %s/%s/%s\n", exchange, base, quote)

			mchan <- MarketDescr{
				ID:       common.MarketID(fmt.Sprintf("%d", md.ID)),
				Exchange: md.Exchange,
				Base:     strings.ToUpper(base),
				Quote:    strings.ToUpper(quote),
			}
		}(parts[0], parts[1], parts[2])
	}

	for i := 0; i < len(marketStrings); i++ {
		market := <-mchan
		markets = append(markets, market)
		marketDescrByID[market.ID] = market
	}

	sort.Sort(MarketDescrsSorted(markets))

	return markets, marketDescrByID
}

func setupStreamClient(
	cfg *config.CW,
	markets []MarketDescr,
	mainView *MainView,
	statesTracker *ConnStateTracker,
) (*websocket.StreamClient, error) {
	streamSubs := make([]*websocket.StreamSubscription, 0, len(markets))
	for _, m := range markets {
		streamSubs = append(streamSubs, &websocket.StreamSubscription{
			Resource: fmt.Sprintf("markets:%s:book:spread", m.ID),
		})
	}

	sc, err := websocket.NewStreamClient(&websocket.StreamClientParams{
		WSParams: &websocket.WSParams{
			URL:       cfg.StreamURL,
			APIKey:    cfg.APIKey,
			SecretKey: cfg.SecretKey,
		},

		Subscriptions: streamSubs,
	})
	if err != nil {
		return nil, errors.Trace(err)
	}

	sc.OnMarketUpdate(
		func(market common.Market, data common.MarketUpdate) {
			switch {
			case data.OrderBookSpreadUpdate != nil:
				spread := data.OrderBookSpreadUpdate
				mainView.SetMarketSpread(
					market.ID,
					spread.Bid,
					spread.Ask,
				)
			}
		},
	)

	sc.OnError(func(err error, disconnecting bool) {
		// If the client is going to disconnect because of that error, just save
		// the error to show later on the disconnection message.
		if disconnecting {
			statesTracker.SetComponentError(ConnComponentStream, err)
			return
		}

		// Otherwise, show the error message right away.
		mainView.ShowMessagebox(
			"stream_client_error_"+err.Error(),
			fmt.Sprintf("Stream client error"),
			err.Error(),
			nil,
		)
	})

	sc.OnStateChange(
		websocket.ConnStateAny,
		getStateListener(statesTracker, mainView, ConnComponentStream),
	)

	sc.Connect()

	return sc, nil
}

func setupTradeClient(
	cfg *config.CW,
	markets []MarketDescr,
	marketDescrByID map[common.MarketID]MarketDescr,
	mainView *MainView,
	statesTracker *ConnStateTracker,
) (*websocket.TradeClient, error) {
	tradeSubs := make([]*websocket.TradeSubscription, 0, len(markets))
	for _, m := range markets {
		tradeSubs = append(tradeSubs, &websocket.TradeSubscription{
			MarketID: common.MarketID(fmt.Sprintf("%s", m.ID)),
		})
	}

	tc, err := websocket.NewTradeClient(&websocket.TradeClientParams{
		WSParams: &websocket.WSParams{
			URL:       cfg.TradeURL,
			APIKey:    cfg.APIKey,
			SecretKey: cfg.SecretKey,
		},

		Subscriptions: tradeSubs,
	})
	if err != nil {
		return nil, errors.Trace(err)
	}

	// firstTradesUpdate is set to true initially and once we've disconnected, so
	// that the next trades update will overwrite the whole trades list.
	// Subsequent updates will just append to the list.
	firstTradesUpdate := true

	tc.OnOrdersUpdate(func(marketID common.MarketID, orders []common.PrivateOrder) {
		mainView.SetMarketOrders(marketID, orders)
	})

	// Balances grep flag: Ki49fK
	tc.OnBalancesUpdate(func(marketID common.MarketID, balances common.Balances) {
		mainView.SetMarketBalances(marketID, balances)
	})

	tc.OnTradesUpdate(func(marketID common.MarketID, trades []common.PrivateTrade) {
		// If this is the first trades update after we've connected, reset the
		// whole trades list; otherwise append to it.
		add := true
		if firstTradesUpdate {
			firstTradesUpdate = false
			add = false
		}

		mainView.SetMarketTrades(marketID, trades, add)
	})

	tc.OnMarketReadyChange(func(marketID common.MarketID, ready bool) {
		mainView.SetMarketReady(marketID, ready)

		if !ready {
			firstTradesUpdate = true
		}
	})

	tc.OnError(func(marketID common.MarketID, err error, disconnecting bool) {
		// If the client is going to disconnect because of that error, just save
		// the error to show later on the disconnection message.
		if disconnecting {
			statesTracker.SetComponentError(ConnComponentTrading, err)
			return
		}

		// Otherwise, show the error message right away.
		mainView.ShowMessagebox(
			"trade_client_error_"+err.Error(),
			fmt.Sprintf("%s error", marketDescrByID[marketID]),
			err.Error(),
			nil,
		)

	})

	tc.OnStateChange(
		websocket.ConnStateAny,
		getStateListener(statesTracker, mainView, ConnComponentTrading),
	)

	// Link UI requests to place/cancel orders with the trade client {{{
	mainView.SetOnPlaceOrderRequestCallback(
		func(orderOpt common.PlaceOrderOpt) {
			// It's called from the UI eventloop, so we can mess with UI right here.
			msgv := NewMessageView(mainView, &MessageViewParams{
				MessageID: "placing_order",
				Message:   "Placing order...",
			})
			msgv.Show()

			go func() {
				_, orderErr := tc.PlaceOrder(orderOpt)

				// This isn't UI eventloop, so we need to get there.
				mainView.params.App.QueueUpdateDraw(func() {
					msgv.Hide()

					if orderErr != nil {
						mainView.ShowMessagebox(
							"order_error", "", "Order failed: "+orderErr.Error(), nil,
						)
					}
				})
			}()
		},
	)

	mainView.SetOnCancelOrderRequestCallback(
		func(orderOpts common.CancelOrderOpt) {
			// It's called from the UI eventloop, so we can mess with UI right here.
			msgv := NewMessageView(mainView, &MessageViewParams{
				MessageID: "canceling_order",
				Message:   "Canceling order...",
			})
			msgv.Show()

			go func() {
				orderErr := tc.CancelOrder(orderOpts)

				// This isn't UI eventloop, so we need to get there.
				mainView.params.App.QueueUpdateDraw(func() {
					msgv.Hide()

					if orderErr != nil {
						mainView.ShowMessagebox(
							"cancel_order_error", "", "Cancel order failed: "+orderErr.Error(), nil,
						)
					}
				})
			}()
		},
	)
	// }}}

	tc.Connect()

	return tc, nil
}

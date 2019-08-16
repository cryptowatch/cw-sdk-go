package websocket

import (
	"context"
	"testing"
	"time"

	"github.com/golang/protobuf/proto"
	"github.com/gorilla/websocket"
	"github.com/juju/errors"
	"github.com/stretchr/testify/assert"

	"code.cryptowat.ch/cw-sdk-go/client/websocket/internal"
	"code.cryptowat.ch/cw-sdk-go/common"
	pbm "code.cryptowat.ch/cw-sdk-go/proto/markets"
	pbs "code.cryptowat.ch/cw-sdk-go/proto/stream"
)

var testStreamSubscriptions = []*StreamSubscription{
	{Resource: "foo"},
	{Resource: "bar"},
}

func TestStreamClient(t *testing.T) {
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()

	assert := assert.New(t)

	err := withTestServer(ctx, t, streamServer, func(tp *testServerParams) error {
		client, err := NewStreamClient(&StreamClientParams{
			WSParams: &WSParams{
				URL:       tp.url,
				APIKey:    testApiKey1,
				SecretKey: testSecretKey1,
			},
			Subscriptions: testStreamSubscriptions,
		})
		if err != nil {
			return errors.Trace(err)
		}

		updatesReceived := map[string]bool{
			"OrderBookSnapshot":     false,
			"OrderBookDelta":        false,
			"OrderBookSpreadUpdate": false,
			"TradesUpdate":          false,
			"IntervalsUpdate":       false,
			"SummaryUpdate":         false,
			"SparklineUpdate":       false,
			"VWAPUpdate":            false,
			"PerformanceUpdate":     false,
			"TrendlineUpdate":       false,
		}

		updates := make(chan string, len(updatesReceived))

		// Test market data callbacks

		client.OnMarketUpdate(func(m common.Market, md common.MarketUpdate) {
			assert.Equal(m.ID, common.MarketID("1"))
			assert.Equal(m.ExchangeID, "1")
			assert.Equal(m.CurrencyPairID, "1")

			switch {
			case md.OrderBookSnapshot != nil:
				ob := md.OrderBookSnapshot
				assert.Equal(ob.SeqNum, common.SeqNum(testOrderBookUpdate.SeqNum))
				for i, o := range testOrderBookUpdate.Bids {
					assert.Equal(publicOrderFromProto(o), ob.Bids[i])
				}
				for i, o := range testOrderBookUpdate.Asks {
					assert.Equal(publicOrderFromProto(o), ob.Asks[i])
				}
				updates <- "OrderBookSnapshot"

			case md.OrderBookDelta != nil:
				ob := md.OrderBookDelta
				assert.Equal(ob.SeqNum, common.SeqNum(testOrderBookDeltaUpdate.SeqNum))
				for i, o := range testOrderBookDeltaUpdate.Bids.Set {
					assert.Equal(publicOrderFromProto(o).Price, ob.Bids.Set[i].Price)
					assert.Equal(publicOrderFromProto(o).Amount, ob.Bids.Set[i].Amount)
				}
				assert.Equal(testOrderBookDeltaUpdate.Bids.RemoveStr, ob.Bids.Remove)

				for i, o := range testOrderBookDeltaUpdate.Asks.Set {
					assert.Equal(publicOrderFromProto(o).Price, ob.Asks.Set[i].Price)
					assert.Equal(publicOrderFromProto(o).Amount, ob.Asks.Set[i].Amount)
				}
				assert.Equal(testOrderBookDeltaUpdate.Asks.RemoveStr, ob.Asks.Remove)
				updates <- "OrderBookDelta"

			case md.OrderBookSpreadUpdate != nil:
				ob := md.OrderBookSpreadUpdate
				assert.Equal(testOrderBookSpreadUpdate.Timestamp, ob.Timestamp.UnixNano()/int64(time.Millisecond))
				assert.Equal(testOrderBookSpreadUpdate.Bid.PriceStr, ob.Bid.Price)
				assert.Equal(testOrderBookSpreadUpdate.Bid.AmountStr, ob.Bid.Price)
				assert.Equal(testOrderBookSpreadUpdate.Ask.PriceStr, ob.Ask.Price)
				assert.Equal(testOrderBookSpreadUpdate.Ask.AmountStr, ob.Ask.Amount)
				updates <- "OrderBookSpreadUpdate"

			case md.TradesUpdate != nil:
				tu := md.TradesUpdate
				for i, t := range testTradesUpdate.Trades {
					if t.Timestamp > 0 {
						assert.Equal(t.Timestamp, tu.Trades[i].Timestamp.Unix())
					}
					if t.TimestampMillis > 0 {
						assert.Equal(t.TimestampMillis, tu.Trades[i].Timestamp.Unix()*1000)
					}
					if t.TimestampNano > 0 {
						assert.Equal(t.TimestampNano, tu.Trades[i].Timestamp.UnixNano())
					}

					assert.Equal(t.ExternalId, tu.Trades[i].ExternalID)
					assert.Equal(t.PriceStr, tu.Trades[i].Price)
					assert.Equal(t.AmountStr, tu.Trades[i].Amount)
				}

				updates <- "TradesUpdate"

			case md.IntervalsUpdate != nil:
				iu := md.IntervalsUpdate
				for i, in := range testIntervalsUpdate.Intervals {
					assert.Equal(in.Closetime, iu.Intervals[i].CloseTime.Unix())
					assert.Equal(in.Period, int32(iu.Intervals[i].Period))
					assert.Equal(in.Ohlc.OpenStr, iu.Intervals[i].OHLC.Open)
					assert.Equal(in.Ohlc.HighStr, iu.Intervals[i].OHLC.High)
					assert.Equal(in.Ohlc.LowStr, iu.Intervals[i].OHLC.Low)
					assert.Equal(in.Ohlc.CloseStr, iu.Intervals[i].OHLC.Close)
					assert.Equal(in.VolumeBaseStr, iu.Intervals[i].VolumeBase)
					assert.Equal(in.VolumeQuoteStr, iu.Intervals[i].VolumeQuote)
				}
				updates <- "IntervalsUpdate"

			case md.SummaryUpdate != nil:
				su := md.SummaryUpdate
				assert.Equal(testSummaryUpdate.LastStr, su.Last)
				assert.Equal(testSummaryUpdate.HighStr, su.High)
				assert.Equal(testSummaryUpdate.LowStr, su.Low)
				assert.Equal(testSummaryUpdate.VolumeBaseStr, su.VolumeBase)
				assert.Equal(testSummaryUpdate.VolumeQuoteStr, su.VolumeQuote)
				assert.Equal(testSummaryUpdate.ChangeAbsoluteStr, su.ChangeAbsolute)
				assert.Equal(testSummaryUpdate.ChangePercentStr, su.ChangePercent)
				assert.Equal(testSummaryUpdate.NumTrades, su.NumTrades)
				updates <- "SummaryUpdate"

			case md.SparklineUpdate != nil:
				su := md.SparklineUpdate
				assert.Equal(testSparklineUpdate.Time, su.Timestamp.Unix())
				assert.Equal(testSparklineUpdate.PriceStr, su.Price)
				updates <- "SparklineUpdate"
			}

		})

		client.OnPairUpdate(func(p common.Pair, pd common.PairUpdate) {
			assert.Equal(p.ID, common.PairID("1"))
			switch {
			case pd.VWAPUpdate != nil:
				vu := pd.VWAPUpdate
				assert.Equal(float64ToString(testVWAPUpdate.Vwap), vu.VWAP)
				assert.Equal(testVWAPUpdate.Timestamp, vu.Timestamp.Unix())
				updates <- "VWAPUpdate"

			case pd.PerformanceUpdate != nil:
				pu := pd.PerformanceUpdate
				assert.Equal(common.PerformanceWindow(testPerformanceUpdate.Window), pu.Window)
				assert.Equal(float64ToString(testPerformanceUpdate.Performance), pu.Performance)
				updates <- "PerformanceUpdate"

			case pd.TrendlineUpdate != nil:
				tu := pd.TrendlineUpdate
				assert.Equal(common.PerformanceWindow(testTrendlineUpdate.Window), tu.Window)
				assert.Equal(testTrendlineUpdate.Price, tu.Price)
				assert.Equal(testTrendlineUpdate.Volume, tu.Volume)
				updates <- "TrendlineUpdate"
			}
		})

		if err := client.Connect(); err != nil {
			return errors.Trace(err)
		}

		if err := waitConnOpen(t, tp); err != nil {
			return errors.Errorf("waiting for new conn to be opened: %s", err)
		}

		if err := waitAuthnReq(t, tp, testApiKey1, testSecretKey1); err != nil {
			return errors.Errorf("waiting for authn request: %s", err)
		}

		if err := sendStreamAuthnResp(t, tp, pbs.AuthenticationResult_AUTHENTICATED); err != nil {
			return errors.Errorf("sending authn resp: %s", err)
		}

		subscriptions := []*StreamSubscription{
			// Market subscriptions
			{"markets:1:trades"},
			{"markets:1:summary"},
			{"markets:1:ohlc"},
			{"markets:1:book:snapshots"},
			{"markets:1:book:deltas"},
			{"markets:1:book:spread"},

			// Pair subscriptions
			{"pairs:1:vwap"},
			{"pairs:1:performance"},
			{"pairs:1:trendline"},
		}

		if err := client.Subscribe(subscriptions); err != nil {
			return errors.Errorf("subscribing to baz: %s", err)
		}

		if err := waitSubscribeMsg(t, tp, streamSubsToSubs(subscriptions)); err != nil {
			return errors.Errorf("waiting for subscribe message: %s", err)
		}

		if err := sendStreamUpdates(t, tp); err != nil {
			return errors.Errorf("sending market updates %s", err)
		}

		for i := 0; i < len(updatesReceived); i++ {
			select {
			case update := <-updates:
				if _, alreadyReceived := updatesReceived[update]; !alreadyReceived {
					t.Logf("update processsed %v", update)
					updatesReceived[update] = true
				}

			case <-time.After(1 * time.Second):
				t.Log("Missing updates")
				for u, e := range updatesReceived {
					if !e {
						t.Log(u)
					}
				}
				t.Fail()
			}
		}

		return nil
	})
	if err != nil {
		cancel()
		t.Log(errors.ErrorStack(err))
		t.Fatal(err)
	}
}

var testMarket = &pbm.Market{
	ExchangeId:     1,
	CurrencyPairId: 1,
	MarketId:       1,
}

var testOrderBookUpdate = &pbm.OrderBookUpdate{
	SeqNum: 1,
	Bids: []*pbm.Order{
		&pbm.Order{
			PriceStr:  "1.0",
			AmountStr: "1.0",
		},
		&pbm.Order{
			PriceStr:  "2.0",
			AmountStr: "2.0",
		},
	},
	Asks: []*pbm.Order{
		&pbm.Order{
			PriceStr:  "1.5",
			AmountStr: "1.5",
		},
		&pbm.Order{
			PriceStr:  "2.1",
			AmountStr: "2.1",
		},
	},
}

var testOrderBookDeltaUpdate = &pbm.OrderBookDeltaUpdate{
	SeqNum: 1,
	Bids: &pbm.OrderBookDeltaUpdate_OrderDeltas{
		Set: []*pbm.Order{
			&pbm.Order{
				PriceStr:  "1.0",
				AmountStr: "1.0",
			},
		},
		RemoveStr: []string{"1.0"},
	},
	Asks: &pbm.OrderBookDeltaUpdate_OrderDeltas{
		Set: []*pbm.Order{
			&pbm.Order{
				PriceStr:  "1.0",
				AmountStr: "1.0",
			},
		},
		RemoveStr: []string{"1.0"},
	},
}

var testOrderBookSpreadUpdate = &pbm.OrderBookSpreadUpdate{
	Timestamp: 1542223639,
	Bid: &pbm.Order{
		PriceStr:  "1.0",
		AmountStr: "1.0",
	},
	Ask: &pbm.Order{
		PriceStr:  "1.0",
		AmountStr: "1.0",
	},
}

var testTradesUpdate = &pbm.TradesUpdate{
	Trades: []*pbm.Trade{
		&pbm.Trade{
			ExternalId: "1",
			Timestamp:  1542218059,
			PriceStr:   "1.0",
			AmountStr:  "1.0",
		},
		&pbm.Trade{
			ExternalId:      "1",
			TimestampMillis: 1542218059000,
			PriceStr:        "1.0",
			AmountStr:       "1.0",
		},
		&pbm.Trade{
			ExternalId:    "1",
			TimestampNano: 1542218059000000000,
			PriceStr:      "1.0",
			AmountStr:     "1.0",
		},
	},
}

var testIntervalsUpdate = &pbm.IntervalsUpdate{
	Intervals: []*pbm.Interval{
		&pbm.Interval{
			Closetime: 1542219084,
			Period:    1,
			Ohlc: &pbm.Interval_OHLC{
				OpenStr:  "1.0",
				HighStr:  "1.0",
				LowStr:   "1.0",
				CloseStr: "1.0",
			},
			VolumeBaseStr:  "1.0",
			VolumeQuoteStr: "1.0",
		},
	},
}

var testSummaryUpdate = &pbm.SummaryUpdate{
	LastStr:           "1.0",
	HighStr:           "1.0",
	LowStr:            "1.0",
	VolumeBaseStr:     "1.0",
	VolumeQuoteStr:    "1.0",
	ChangeAbsoluteStr: "1.0",
	ChangePercentStr:  "1.0",
	NumTrades:         1,
}

var testSparklineUpdate = &pbm.SparklineUpdate{
	Time:     1542205889,
	PriceStr: "1.0",
}

var testPair uint64 = 1

var testVWAPUpdate = &pbm.PairVwapUpdate{
	Vwap:      1.9,
	Timestamp: 1136239445,
}

var testPerformanceUpdate = &pbm.PairPerformanceUpdate{
	Window:      "24h",
	Performance: 1.3,
}

var testTrendlineUpdate = &pbm.PairTrendlineUpdate{
	Window: "24h",
	Time:   1542205889,
	Price:  "1.0",
	Volume: "2.0",
}

func sendStreamUpdates(t *testing.T, tp *testServerParams) error {
	orderBookUpdate := &pbm.MarketUpdateMessage{
		Market: testMarket,
		Update: &pbm.MarketUpdateMessage_OrderBookUpdate{
			OrderBookUpdate: testOrderBookUpdate,
		},
	}
	if err := sendMarketUpdate(t, tp, orderBookUpdate); err != nil {
		return errors.Trace(err)
	}

	OrderBookDelta := &pbm.MarketUpdateMessage{
		Market: testMarket,
		Update: &pbm.MarketUpdateMessage_OrderBookDeltaUpdate{
			OrderBookDeltaUpdate: testOrderBookDeltaUpdate,
		},
	}
	if err := sendMarketUpdate(t, tp, OrderBookDelta); err != nil {
		return errors.Trace(err)
	}

	orderBookSpreadUpdate := &pbm.MarketUpdateMessage{
		Market: testMarket,
		Update: &pbm.MarketUpdateMessage_OrderBookSpreadUpdate{
			OrderBookSpreadUpdate: testOrderBookSpreadUpdate,
		},
	}
	if err := sendMarketUpdate(t, tp, orderBookSpreadUpdate); err != nil {
		return errors.Trace(err)
	}

	tradesUpdate := &pbm.MarketUpdateMessage{
		Market: testMarket,
		Update: &pbm.MarketUpdateMessage_TradesUpdate{
			TradesUpdate: testTradesUpdate,
		},
	}
	if err := sendMarketUpdate(t, tp, tradesUpdate); err != nil {
		return errors.Trace(err)
	}

	intervalsUpdate := &pbm.MarketUpdateMessage{
		Market: testMarket,
		Update: &pbm.MarketUpdateMessage_IntervalsUpdate{
			IntervalsUpdate: testIntervalsUpdate,
		},
	}
	if err := sendMarketUpdate(t, tp, intervalsUpdate); err != nil {
		return errors.Trace(err)
	}

	summaryUpdate := &pbm.MarketUpdateMessage{
		Market: testMarket,
		Update: &pbm.MarketUpdateMessage_SummaryUpdate{
			SummaryUpdate: testSummaryUpdate,
		},
	}
	if err := sendMarketUpdate(t, tp, summaryUpdate); err != nil {
		return errors.Trace(err)
	}

	sparklineUpdate := &pbm.MarketUpdateMessage{
		Market: testMarket,
		Update: &pbm.MarketUpdateMessage_SparklineUpdate{
			SparklineUpdate: testSparklineUpdate,
		},
	}
	if err := sendMarketUpdate(t, tp, sparklineUpdate); err != nil {
		return errors.Trace(err)
	}

	vwapUpdate := &pbm.PairUpdateMessage{
		Pair: testPair,
		Update: &pbm.PairUpdateMessage_VwapUpdate{
			VwapUpdate: testVWAPUpdate,
		},
	}
	if err := sendPairUpdate(t, tp, vwapUpdate); err != nil {
		return errors.Trace(err)
	}

	performanceUpdate := &pbm.PairUpdateMessage{
		Pair: testPair,
		Update: &pbm.PairUpdateMessage_PerformanceUpdate{
			PerformanceUpdate: testPerformanceUpdate,
		},
	}
	if err := sendPairUpdate(t, tp, performanceUpdate); err != nil {
		return errors.Trace(err)
	}

	trendlineUpdate := &pbm.PairUpdateMessage{
		Pair: testPair,
		Update: &pbm.PairUpdateMessage_TrendlineUpdate{
			TrendlineUpdate: testTrendlineUpdate,
		},
	}
	if err := sendPairUpdate(t, tp, trendlineUpdate); err != nil {
		return errors.Trace(err)
	}

	return nil
}

func sendMarketUpdate(t *testing.T, tp *testServerParams, update *pbm.MarketUpdateMessage) error {
	streamMessage := &pbs.StreamMessage{
		Body: &pbs.StreamMessage_MarketUpdate{
			MarketUpdate: update,
		},
	}
	data, err := proto.Marshal(streamMessage)
	if err != nil {
		return errors.Trace(err)
	}

	tp.tx <- internal.WebsocketTx{
		MessageType: websocket.BinaryMessage,
		Data:        data,
	}

	return nil
}

func sendPairUpdate(t *testing.T, tp *testServerParams, update *pbm.PairUpdateMessage) error {
	streamMessage := &pbs.StreamMessage{
		Body: &pbs.StreamMessage_PairUpdate{
			PairUpdate: update,
		},
	}
	data, err := proto.Marshal(streamMessage)
	if err != nil {
		return errors.Trace(err)
	}

	tp.tx <- internal.WebsocketTx{
		MessageType: websocket.BinaryMessage,
		Data:        data,
	}

	return nil
}

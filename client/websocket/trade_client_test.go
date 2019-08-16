package websocket

import (
	"context"
	"fmt"
	"strings"
	"testing"
	"time"

	"github.com/golang/protobuf/proto"
	"github.com/google/uuid"
	"github.com/gorilla/websocket"
	"github.com/juju/errors"
	"github.com/stretchr/testify/assert"

	"code.cryptowat.ch/cw-sdk-go/client/websocket/internal"
	"code.cryptowat.ch/cw-sdk-go/common"
	pbb "code.cryptowat.ch/cw-sdk-go/proto/broker"
	pbs "code.cryptowat.ch/cw-sdk-go/proto/stream"
)

// The following orders/trades/balances already exist on broker
var mockOrders = []common.PrivateOrder{
	common.PrivateOrder{
		ID:           uuid.New().String(),
		Amount:       "0.02",
		AmountFilled: "0.0",
		PriceParams: common.PriceParams{&common.PriceParam{
			Value: "1.0",
			Type:  common.AbsoluteValuePrice,
		}},
		OrderSide:   common.BuyOrder,
		OrderType:   common.LimitOrder,
		FundingType: common.SpotFunding,
		ExpireTime:  time.Now().Add(20 * time.Minute).Truncate(1 * time.Second),
		Timestamp:   time.Now().Add(-30 * time.Minute).Truncate(1 * time.Second),
	},
	common.PrivateOrder{
		ID:           uuid.New().String(),
		Amount:       "0.03",
		AmountFilled: "0.5",
		OrderSide:    common.SellOrder,
		OrderType:    common.MarketOrder,
		FundingType:  common.SpotFunding,
		Timestamp:    time.Now().Add(-25 * time.Minute).Truncate(1 * time.Second),
	},
}

var mockTrades = []common.PrivateTrade{
	common.PrivateTrade{
		ExternalID: uuid.New().String(),
		OrderID:    uuid.New().String(),
		Timestamp:  time.Now().Add(-30 * time.Minute).Truncate(1 * time.Second),
		Price:      "2.0",
		Amount:     "1.5",
		OrderSide:  common.BuyOrder,
	},
	common.PrivateTrade{
		ExternalID: uuid.New().String(),
		OrderID:    uuid.New().String(),
		Timestamp:  time.Now().Add(-20 * time.Minute).Truncate(1 * time.Second),
		Price:      "2.0",
		Amount:     "1.5",
		OrderSide:  common.BuyOrder,
	},
}

// Balances grep flag: Ki49fK
var mockBalances = common.Balances{
	common.SpotFunding: []common.Balance{
		common.Balance{
			Currency: "usd",
			Amount:   "1.0",
		},
	},

	common.MarginFunding: []common.Balance{
		common.Balance{
			Currency: "eth",
			Amount:   "1.0",
		},
	},
}

// AllBalances grep flag: Ai33fA
// var mockAllBalances = common.ExchangeBalances{
// 	"bitfinex": common.ExchangeBalance{
// 		Name:  "bitfinex",
// 		Error: "",
// 		Balances: common.Balances{
// 			0: []common.Balance{
// 				common.Balance{
// 					Asset:     "Bitcoin",
// 					Symbol:    "btc",
// 					Total:     "0.02324881",
// 					Available: "0.00478881",
// 				},
// 				common.Balance{
// 					Asset:     "United States dollar",
// 					Symbol:    "usd",
// 					Total:     "83.02322",
// 					Available: "43.065998",
// 				},
// 			},
// 			1: []common.Balance{
// 				common.Balance{
// 					Asset:     "Bitcoin Gold",
// 					Symbol:    "btg",
// 					Total:     "0.06",
// 					Available: "0.06",
// 				},
// 			},
// 		},
// 	},
// }

var mockPositions = []common.PrivatePosition{
	common.PrivatePosition{
		ExternalID:   uuid.New().String(),
		Timestamp:    time.Now().Add(-20 * time.Minute).Truncate(1 * time.Second),
		OrderSide:    common.BuyOrder,
		AvgPrice:     "1.3243",
		AmountOpen:   "1.0",
		AmountClosed: "0.5",
		OrderIDs:     []string{mockOrders[0].ID, mockOrders[1].ID},
		TradeIDs:     []string{mockTrades[0].ExternalID, mockTrades[1].ExternalID},
	},
}

func TestTradeConn(t *testing.T) {
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()

	marketID := "1"
	marketIDint := int64(1)

	err := withTestServer(ctx, t, brokerServer, func(tp *testServerParams) error {
		tradeParams := &TradeClientParams{
			WSParams: &WSParams{
				URL:       tp.url,
				APIKey:    testApiKey1,
				SecretKey: testSecretKey1,
			},
			Subscriptions: []*TradeSubscription{
				&TradeSubscription{
					MarketID: common.MarketID(marketID),
				},
			},
		}

		client, err := NewTradeClient(tradeParams)
		if err != nil {
			return errors.Trace(err)
		}

		// Add state tracker to the connection, so we'll see all state transitions
		st := NewStateTracker()
		st.addStateListener(client.wsConn, ConnStateAny, StateListenerOpt{})

		client.OnStateChange(ConnStateAny, func(prev, cur ConnState) {
			fmt.Println(ConnStateNames[prev], ConnStateNames[cur])
		})

		onErrorCalled := make(chan error, 1)
		client.OnError(func(marketID common.MarketID, err error, disconnecting bool) {
			onErrorCalled <- err
		})

		if err := client.Connect(); err != nil {
			return errors.Trace(err)
		}

		if err := st.expectState(t, ConnStateConnecting); err != nil {
			return errors.Trace(err)
		}

		// Wait for the new conn to be opened
		if err := waitConnOpen(t, tp); err != nil {
			return errors.Errorf("waiting for new conn to be opened: %s", err)
		}

		if err := st.expectState(t, ConnStateAuthenticating); err != nil {
			return errors.Trace(err)
		}

		// Wait for the authentication request
		if err := waitAuthnReq(t, tp, testApiKey1, testSecretKey1); err != nil {
			return errors.Errorf("waiting for authn request: %s", err)
		}

		// Send AuthenticationResult to the client
		if err := sendTradeAuthnResp(t, tp, pbs.AuthenticationResult_AUTHENTICATED); err != nil {
			return errors.Errorf("sending authn resp: %s", err)
		}

		if err := st.expectState(t, ConnStateEstablished); err != nil {
			return errors.Trace(err)
		}

		// Check states so far
		if err := st.checkStates([]string{
			"disconnected->connecting",
			"connecting->authenticating",
			"authenticating->established",
		}); err != nil {
			return errors.Trace(err)
		}

		// Send heartbeat (should be ignored by the client)
		tp.tx <- internal.WebsocketTx{
			MessageType: websocket.BinaryMessage,
			Data:        []byte{1},
		}

		// Send garbage, which should result in a reconnection
		tp.tx <- internal.WebsocketTx{
			MessageType: websocket.BinaryMessage,
			Data:        []byte{1, 2, 3},
		}

		if err := waitOnErrorStrCalled(onErrorCalled, "unsupported data"); err != nil {
			return errors.Trace(err)
		}

		// Wait for the connection being closed
		if err := waitConnClose(t, tp); err != nil {
			return errors.Errorf("waiting for connection being closed: %s", err)
		}

		if err := st.expectState(t, ConnStateWaitBeforeReconnect); err != nil {
			return errors.Trace(err)
		}

		if err := st.expectState(t, ConnStateConnecting); err != nil {
			return errors.Trace(err)
		}

		// Wait for the new conn to be opened
		if err := waitConnOpen(t, tp); err != nil {
			return errors.Errorf("waiting for new conn to be opened: %s", err)
		}

		if err := st.expectState(t, ConnStateAuthenticating); err != nil {
			return errors.Trace(err)
		}

		// Wait for the authentication request
		if err := waitAuthnReq(t, tp, testApiKey1, testSecretKey1); err != nil {
			return errors.Errorf("waiting for authn request: %s", err)
		}

		// Send AuthenticationResult to the client
		if err := sendTradeAuthnResp(t, tp, pbs.AuthenticationResult_AUTHENTICATED); err != nil {
			return errors.Errorf("sending authn resp: %s", err)
		}

		if err := st.expectState(t, ConnStateEstablished); err != nil {
			return errors.Trace(err)
		}

		// Check states so far
		if err := st.checkStates([]string{
			"disconnected->connecting",
			"connecting->authenticating",
			"authenticating->established",
			"established->wait-before-reconnect(websocket: close 1003 (unsupported data))",
			"wait-before-reconnect->connecting",
			"connecting->authenticating",
			"authenticating->established",
		}); err != nil {
			return errors.Trace(err)
		}

		onReadyCalled := make(chan struct{}, 1)
		client.OnReady(func() {
			onReadyCalled <- struct{}{}
		})

		if err := initMockBrokerConn(t, tp, marketIDint); err != nil {
			return errors.Trace(err)
		}

		if err := waitOnReadyCalled(t, tp, client, onReadyCalled); err != nil {
			return errors.Trace(err)
		}

		if err := sendPermissionsError(tp, marketIDint); err != nil {
			return errors.Trace(err)
		}

		if err := waitOnErrorCalled(onErrorCalled, ErrNoExchangeAccess); err != nil {
			return errors.Trace(err)
		}

		return nil
	})
	if err != nil {
		cancel()
		t.Log(errors.ErrorStack(err))
		t.Fatal(err)
	}
}

func TestTrading(t *testing.T) {
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()

	assert := assert.New(t)

	err := withTestServer(ctx, t, brokerServer, func(tp *testServerParams) error {
		marketID := common.MarketID("1")
		marketIDint := int64(1)

		testOrderParams := common.PlaceOrderOpt{
			PriceParams: common.PriceParams{&common.PriceParam{
				Value: "0.01",
				Type:  common.AbsoluteValuePrice,
			}},
			MarketID:    marketID,
			Amount:      "0.01",
			OrderSide:   common.BuyOrder,
			OrderType:   common.LimitOrder,
			FundingType: common.SpotFunding,

			// Truncate to second precision because Broker sends unix timestamps (seconds)
			ExpireTime: time.Now().Add(10 * time.Minute).Truncate(1 * time.Second),
		}

		client, err := NewTradeClient(&TradeClientParams{
			WSParams: &WSParams{
				URL:       tp.url,
				APIKey:    testApiKey1,
				SecretKey: testSecretKey1,
			},
			Subscriptions: []*TradeSubscription{
				&TradeSubscription{
					MarketID: marketID,
				},
			},
		})
		if err != nil {
			return errors.Trace(err)
		}

		// Add state tracker to the connection, so we'll see all state transitions
		// st := NewStateTracker()
		// st.addStateListener(client.streamConn, StateAny, StateListenerOpt{})

		if err := client.Connect(); err != nil {
			return errors.Trace(err)
		}

		// if err := st.expectState(t, StateConnecting); err != nil {
		// 	return errors.Trace(err)
		// }

		// Wait for the new conn to be opened
		if err := waitConnOpen(t, tp); err != nil {
			return errors.Errorf("waiting for new conn to be opened: %s", err)
		}

		// if err := st.expectState(t, StateAuthenticating); err != nil {
		// 	return errors.Trace(err)
		// }

		// Wait for the authentication request
		if err := waitAuthnReq(t, tp, testApiKey1, testSecretKey1); err != nil {
			return errors.Errorf("waiting for authn request: %s", err)
		}

		// Send AuthenticationResult to the client
		if err := sendTradeAuthnResp(t, tp, pbs.AuthenticationResult_AUTHENTICATED); err != nil {
			return errors.Errorf("sending authn resp: %s", err)
		}

		// if err := st.expectState(t, StateEstablished); err != nil {
		// 	return errors.Trace(err)
		// }

		go mockBrokerServer(ctx, t, tp, []int64{marketIDint})

		onReadyCalled := make(chan struct{}, 1)
		client.OnReady(func() {
			onReadyCalled <- struct{}{}
		})

		// Test placing order before client is ready
		order, err := client.PlaceOrder(testOrderParams)
		assert.Equal(ErrNotInitialized, errors.Cause(err))

		_, err = client.GetOrders(marketID)
		assert.Equal(ErrNotInitialized, errors.Cause(err))

		_, err = client.GetTrades(marketID)
		assert.Equal(ErrNotInitialized, errors.Cause(err))

		_, err = client.GetPositions(marketID)
		assert.Equal(ErrNotInitialized, errors.Cause(err))

		// Balances grep flag: Ki49fK
		_, err = client.GetBalances(marketID)
		assert.Equal(ErrNotInitialized, errors.Cause(err))

		if err := initMockBrokerConn(t, tp, marketIDint); err != nil {
			return errors.Trace(err)
		}

		if err := waitOnReadyCalled(t, tp, client, onReadyCalled); err != nil {
			return errors.Trace(err)
		}

		//
		// Make sure the client has initialized its cache correctly
		//

		// Balances grep flag: Ki49fK
		balances, err := client.GetBalances(marketID)
		assert.Equal(mockBalances, balances)
		assert.Equal(nil, err)

		orders, err := client.GetOrders(marketID)
		for i, o := range mockOrders {
			checkOrder(t, o, orders[i])
		}
		assert.Equal(nil, err)

		trades, err := client.GetTrades(marketID)
		assert.Equal(mockTrades, trades)
		assert.Equal(nil, err)

		// Order should work now
		order, err = client.PlaceOrder(testOrderParams)
		if err != nil {
			return errors.Trace(err)
		}

		assert.True(time.Now().After(order.Timestamp))
		assert.True(order.ExpireTime.Equal(testOrderParams.ExpireTime))

		assert.Equal(order.PriceParams, testOrderParams.PriceParams)
		assert.Equal(order.Amount, testOrderParams.Amount)
		assert.Equal(order.OrderSide, testOrderParams.OrderSide)
		assert.Equal(order.OrderType, testOrderParams.OrderType)
		assert.Equal(order.FundingType, testOrderParams.FundingType)
		assert.Equal(order.AmountFilled, "0.0")
		assert.Equal(order.Error, int32(0))

		// Pretend this happened in the background, then we send an orders update
		order.AmountFilled = "1.1"
		mockOrders = append(mockOrders, order)

		ordersUpdate := make(chan struct{}, 1)
		client.OnOrdersUpdate(func(marketID common.MarketID, os []common.PrivateOrder) {
			ordersUpdate <- struct{}{}
		})

		if err := sendOrdersUpdate(t, tp, marketIDint, mockOrders); err != nil {
			return errors.Trace(err)
		}

		if err := waitOrdersUpdate(t, tp, ordersUpdate); err != nil {
			return errors.Trace(err)
		}

		// Make sure the last order matches what was updated on the fake server
		orders, err = client.GetOrders(marketID)
		assert.Equal("1.1", orders[2].AmountFilled)
		assert.Equal(nil, err)

		if err := client.CancelOrder(common.CancelOrderOpt{
			MarketID: marketID,
			OrderID:  order.ID,
		}); err != nil {
			return errors.Trace(err)
		}

		// AllBalances grep flag: Ai33fA
		// allBalances, err := client.GetBalances()
		// assert.Equal(mockAllBalances, allBalances)
		// assert.Equal(nil, err)

		return nil
	})

	if err != nil {
		cancel()
		t.Log(errors.ErrorStack(err))
		t.Fatal(err)
	}
}

// Handle broker requests
func mockBrokerServer(ctx context.Context, t *testing.T, tp *testServerParams, marketIDs []int64) {
	if len(marketIDs) == 0 {
		t.Fatal("marketIDs can't be empty")
	}

	assert := assert.New(t)

	var order common.PrivateOrder

	for {
		select {
		case <-ctx.Done():
			return
		case event := <-tp.rx:
			var req pbb.BrokerRequest
			err := proto.Unmarshal(event.data, &req)
			if err != nil {
				t.Fatal(err)
			}

			if req.Id == "" {
				t.Fatal("request ID not set")
			}

			marketID := req.MarketId
			if marketID == 0 {
				if len(marketIDs) > 1 {
					t.Fatal("marketIDs has more than one item, and req.MarketId is empty")
				}

				marketID = marketIDs[0]
			}

			switch r := req.Request.(type) {
			case *pbb.BrokerRequest_PlaceOrderRequest:
				order = privateOrderFromProto(r.PlaceOrderRequest.Order)

				// The following would normally come from the exchange
				order.ID = uuid.New().String()
				order.AmountFilled = "0.0"
				order.Timestamp = time.Now()

				data, err := proto.Marshal(&pbb.BrokerUpdateMessage{
					MarketId: marketID,
					Update: &pbb.BrokerUpdateMessage_RequestResolutionUpdate{
						RequestResolutionUpdate: &pbb.RequestResolutionUpdate{
							Id:      req.Id,
							Error:   0,
							Message: "Success",
							Result: &pbb.RequestResolutionUpdate_PlaceOrderResult{
								PlaceOrderResult: &pbb.PlaceOrderResult{
									Order: privateOrderToProto(order),
								},
							},
						},
					},
				})
				if err != nil {
					t.Fatal(err)
				}

				tp.tx <- internal.WebsocketTx{
					MessageType: websocket.BinaryMessage,
					Data:        data,
				}

			case *pbb.BrokerRequest_CancelOrderRequest:
				orderId := r.CancelOrderRequest.GetOrderId()
				assert.Equal(orderId, order.ID)
				res := &pbb.BrokerUpdateMessage{
					MarketId: marketID,
					Update: &pbb.BrokerUpdateMessage_RequestResolutionUpdate{
						RequestResolutionUpdate: &pbb.RequestResolutionUpdate{
							Id:      req.Id,
							Error:   0,
							Message: "Success",
							Result: &pbb.RequestResolutionUpdate_CancelOrderResult{
								CancelOrderResult: &pbb.CancelOrderResult{
									OrderId: orderId,
								},
							},
						},
					},
				}

				data, err := proto.Marshal(res)
				if err != nil {
					t.Fatal(err)
				}

				tp.tx <- internal.WebsocketTx{
					MessageType: websocket.BinaryMessage,
					Data:        data,
				}

			// AllBalances grep flag: Ai33fA
			// case *pbb.BrokerRequest_AllBalancesRequest:
			// 	res := createAllBalancesUpdate(req.Id, mockAllBalances)
			// 	data, err := proto.Marshal(res)
			// 	if err != nil {
			// 		panic(err)
			// 	}

			// 	tp.tx <- internal.WebsocketTx{
			// 		MessageType: websocket.BinaryMessage,
			// 		Data:        data,
			// 	}

			default:
				t.Fatal("invalid data received")
			}
		}
	}
}

func initMockBrokerConn(t *testing.T, tp *testServerParams, marketID int64) error {
	if err := sendSessionStatusUpdate(t, tp, marketID); err != nil {
		return errors.Trace(err)
	}

	if err := sendOrdersUpdate(t, tp, marketID, mockOrders); err != nil {
		return errors.Trace(err)
	}

	if err := sendTradesUpdate(t, tp, marketID, mockTrades); err != nil {
		return errors.Trace(err)
	}

	if err := sendPositionsUpdate(t, tp, marketID, mockPositions); err != nil {
		return errors.Trace(err)
	}

	// Balances grep flag: Ki49fK
	if err := sendBalanceUpdate(t, tp, marketID, mockBalances); err != nil {
		return errors.Trace(err)
	}

	return nil
}

// Send an orders update with the given orders
func sendOrdersUpdate(t *testing.T, tp *testServerParams, marketID int64, orders []common.PrivateOrder) error {
	po := []*pbb.PrivateOrder{}

	for _, o := range orders {
		po = append(po, privateOrderToProto(o))
	}

	ou := &pbb.BrokerUpdateMessage{

		MarketId: marketID,
		Update: &pbb.BrokerUpdateMessage_OrdersUpdate{
			OrdersUpdate: &pbb.OrdersUpdate{
				Orders: po,
			},
		},
	}

	return sendBrokerUpdate(tp, ou)
}

func sendTradesUpdate(
	t *testing.T, tp *testServerParams, marketID int64, trades []common.PrivateTrade,
) error {
	pt := []*pbb.PrivateTrade{}

	for _, t := range trades {
		pt = append(pt, tradeToProto(t))
	}

	tu := &pbb.BrokerUpdateMessage{
		MarketId: marketID,
		Update: &pbb.BrokerUpdateMessage_TradesUpdate{
			TradesUpdate: &pbb.TradesUpdate{
				Trades: pt,
			},
		},
	}

	return sendBrokerUpdate(tp, tu)
}

func sendPositionsUpdate(
	t *testing.T, tp *testServerParams, marketID int64, positions []common.PrivatePosition,
) error {
	ps := []*pbb.PrivatePosition{}

	for _, p := range positions {
		ps = append(ps, positionToProto(p))
	}

	pu := &pbb.BrokerUpdateMessage{
		MarketId: marketID,
		Update: &pbb.BrokerUpdateMessage_PositionsUpdate{
			PositionsUpdate: &pbb.PositionsUpdate{
				Positions: ps,
			},
		},
	}

	return sendBrokerUpdate(tp, pu)
}

// Balances grep flag: Ki49fK
func sendBalanceUpdate(
	t *testing.T, tp *testServerParams, marketID int64, balances common.Balances,
) error {
	bu := &pbb.BrokerUpdateMessage{
		MarketId: marketID,
		Update: &pbb.BrokerUpdateMessage_BalancesUpdate{
			BalancesUpdate: &pbb.BalancesUpdate{
				Balances: balancesToProto(balances),
			},
		},
	}

	return sendBrokerUpdate(tp, bu)
}

// AllBalances grep flag: Ai33fA
// func createAllBalancesUpdate(id string, balances common.ExchangeBalances) *pbb.BrokerUpdateMessage {
// 	var result []*pbb.Balances

// 	for name, xbals := range balances {
// 		for ft, ftBals := range xbals.Balances {
// 			var bals []*pbb.Balance

// 			for _, b := range ftBals {
// 				bals = append(bals, &pbb.Balance{
// 					Asset:           b.Asset,
// 					Symbol:          b.Symbol,
// 					AmountTotal:     b.Total,
// 					AmountAvailable: b.Available,
// 				})
// 			}

// 			result = append(result, &pbb.Balances{
// 				FundingType: exchanges.FundingTypeToProto[exchanges.FundingType(common.FundingTypeNames[ft])],
// 				Name:        name,
// 				Error:       xbals.Error,
// 				Balances:    bals,
// 			})
// 		}
// 	}

// 	return &pbb.BrokerUpdateMessage{
// 		Update: &pbb.BrokerUpdateMessage_AllBalancesUpdate{
// 			AllBalancesUpdate: &pbb.AllBalancesUpdate{
// 				Id:       id,
// 				Balances: result,
// 			},
// 		},
// 	}
// }

func sendSessionStatusUpdate(t *testing.T, tp *testServerParams, marketID int64) error {
	su := &pbb.BrokerUpdateMessage{
		MarketId: marketID,
		Update: &pbb.BrokerUpdateMessage_SessionStatusUpdate{
			SessionStatusUpdate: &pbb.SessionStatusUpdate{
				Initialized:  true,
				Syncing:      false,
				LastSyncTime: time.Now().Unix(),
				SyncError:    0,
			},
		},
	}

	return sendBrokerUpdate(tp, su)
}

func sendBrokerUpdate(tp *testServerParams, u *pbb.BrokerUpdateMessage) error {
	data, err := proto.Marshal(u)
	if err != nil {
		return errors.Trace(err)
	}

	tp.tx <- internal.WebsocketTx{
		MessageType: websocket.BinaryMessage,
		Data:        data,
	}

	return nil
}

func waitOnReadyCalled(t *testing.T, tp *testServerParams, tc *TradeClient, onReadyCalled chan struct{}) error {
	select {
	case <-onReadyCalled:
		return nil

	case <-time.After(1 * time.Second):
		return errors.New("client.OnReady() was never executed")
	}
}

func waitOnErrorCalled(onErrorCalled chan error, expected error) error {
	select {
	case received := <-onErrorCalled:
		if expected != received {
			return errors.Errorf("Expected OnError %v received %v", expected, received)
		}
		return nil

	case <-time.After(1 * time.Second):
		return errors.New("client.OnError() was never called")
	}
}

func waitOnErrorStrCalled(onErrorCalled chan error, expected string) error {
	select {
	case received := <-onErrorCalled:
		if !strings.Contains(received.Error(), expected) {
			return errors.Errorf("Expected OnError %v received %v", expected, received)
		}
		return nil

	case <-time.After(1 * time.Second):
		return errors.New("client.OnError() was never called")
	}
}

func waitOrdersUpdate(t *testing.T, tp *testServerParams, ordersUpdate chan struct{}) error {
	select {
	case <-ordersUpdate:
		return nil

	case <-time.After(1 * time.Second):
		return errors.New("client did not receive orders update")
	}
}

func sendTradeAuthnResp(t *testing.T, tp *testServerParams, status pbs.AuthenticationResult_Status) error {
	sm := &pbb.BrokerUpdateMessage{
		Update: &pbb.BrokerUpdateMessage_AuthenticationResult{
			AuthenticationResult: &pbs.AuthenticationResult{
				Status: status,
			},
		},
	}

	data, err := proto.Marshal(sm)
	if err != nil {
		return errors.Trace(err)
	}

	tp.tx <- internal.WebsocketTx{
		MessageType: websocket.BinaryMessage,
		Data:        data,
	}

	return nil
}

func sendPermissionsError(tp *testServerParams, marketID int64) error {
	serverErr := &pbb.BrokerUpdateMessage{
		MarketId: marketID,
		Update: &pbb.BrokerUpdateMessage_ApiAccessorStatusUpdate{
			ApiAccessorStatusUpdate: &pbb.APIAccessorStatusUpdate{
				HasAccess:    false,
				Status:       0,
				StatusString: "",
			},
		},
	}

	data, err := proto.Marshal(serverErr)
	if err != nil {
		return errors.Trace(err)
	}

	tp.tx <- internal.WebsocketTx{
		MessageType: websocket.BinaryMessage,
		Data:        data,
	}

	return nil
}

func checkOrder(t *testing.T, expected, actual common.PrivateOrder) {
	assert := assert.New(t)

	expectedExpireTime := expected.ExpireTime
	if expectedExpireTime.IsZero() {
		expectedExpireTime = time.Unix(0, 0)
	}

	assert.True(expectedExpireTime.Equal(actual.ExpireTime))
	assert.True(expected.Timestamp.Equal(actual.Timestamp))

	assert.Equal(expected.PriceParams, actual.PriceParams)
	assert.Equal(expected.Amount, actual.Amount)
	assert.Equal(expected.OrderSide, actual.OrderSide)
	assert.Equal(expected.OrderType, actual.OrderType)
	assert.Equal(expected.FundingType, actual.FundingType)
	assert.Equal(expected.ID, actual.ID)
	assert.Equal(expected.Leverage, actual.Leverage)
	assert.Equal(expected.CurrentStop, actual.CurrentStop)
	assert.Equal(expected.InitialStop, actual.InitialStop)
	assert.Equal(expected.AmountFilled, actual.AmountFilled)
	assert.Equal(expected.Error, actual.Error)
}

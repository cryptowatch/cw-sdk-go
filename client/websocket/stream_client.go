package websocket

import (
	"sync"

	"github.com/golang/protobuf/proto"
	"github.com/gorilla/websocket"
	"github.com/juju/errors"

	"code.cryptowat.ch/cw-sdk-go/common"
	"code.cryptowat.ch/cw-sdk-go/config"
	pbm "code.cryptowat.ch/cw-sdk-go/proto/markets"
	pbs "code.cryptowat.ch/cw-sdk-go/proto/stream"
)

const (
	DefaultStreamURL = "wss://stream.cryptowat.ch"
)

// MarketUpdateCB defines a callback function for OnMarketUpdate.
type MarketUpdateCB func(common.Market, common.MarketUpdate)

type callMarketUpdateListenersReq struct {
	market    common.Market
	update    common.MarketUpdate
	listeners []MarketUpdateCB
}

// PairUpdateCB defines a callback function for OnPairUpdate.
type PairUpdateCB func(common.Pair, common.PairUpdate)

type callPairUpdateListenersReq struct {
	listeners []PairUpdateCB
	pair      common.Pair
	update    common.PairUpdate
}

type callSubscriptionResultListenersReq struct {
	listeners []SubscriptionResultCB
	result    SubscriptionResult
}

type callUnsubscriptionResultListenersReq struct {
	listeners []UnsubscriptionResultCB
	result    UnsubscriptionResult
}

type callBandwidthUpdateListenersReq struct {
	listeners []BandwidthUpdateCB
	msg       Bandwidth
}

type callMissedMessagesListenersReq struct {
	listeners []MissedMessagesCB
	msg       MissedMessages
}

// StreamClient is used to connect to Cryptowatch's data streaming backend.
// Typically you will get an instance using NewStreamClient(), set any state
// listeners for the connection you might need, then set data listeners for
// whatever data subscriptions you have. Finally, you can call Connect() to
// initiate the data stream.
type StreamClient struct {
	marketUpdateListeners         []MarketUpdateCB
	pairUpdateListeners           []PairUpdateCB
	subscriptionResultListeners   []SubscriptionResultCB
	unsubscriptionResultListeners []UnsubscriptionResultCB
	bandwidthUpdateListeners      []BandwidthUpdateCB
	missedMessagesListeners       []MissedMessagesCB

	callMarketUpdateListeners         chan callMarketUpdateListenersReq
	callPairUpdateListeners           chan callPairUpdateListenersReq
	callSubscriptionResultListeners   chan callSubscriptionResultListenersReq
	callUnsubscriptionResultListeners chan callUnsubscriptionResultListenersReq
	callBandwidthUpdateListeners      chan callBandwidthUpdateListenersReq
	callMissedMessagesListeners       chan callMissedMessagesListenersReq

	bandwidth Bandwidth

	// We want to ensure that wsConn's methods aren't available on the
	// StreamClient to avoid confusion, so we give it explicit name.
	wsConn *wsConn

	mtx sync.Mutex
}

type StreamSubscription struct {
	Resource string
}

func (s *StreamSubscription) GetResource() string {
	return s.Resource
}

type StreamClientParams struct {
	WSParams      *WSParams
	Subscriptions []*StreamSubscription
}

// NewStreamClient creates a new StreamClient instance with the given params.
// Although it starts listening for data immediately, you will still have to
// register listeners to handle that data, and then call Connect() explicitly.
func NewStreamClient(params *StreamClientParams) (*StreamClient, error) {
	// Make a copy of params struct because we might alter it below
	paramsCopy := *params
	params = &paramsCopy

	if params.WSParams == nil {
		params.WSParams = &WSParams{}

		// Fall back on config in ~/.cw/credentials.yml
		var cfg *config.CW
		defaultConfig, cfgErr := config.DefaultFilepath()
		if cfgErr == nil {
			cfg, cfgErr = config.New(defaultConfig)
		}
		if cfgErr == nil && cfg != nil {
			params.WSParams.APIKey = cfg.APIKey
			params.WSParams.SecretKey = cfg.SecretKey
			params.WSParams.URL = cfg.StreamURL
		}
	}

	if params.WSParams.URL == "" {
		params.WSParams.URL = DefaultStreamURL
	}

	wsConn, err := newWsConn(
		params.WSParams,
		&wsConnParamsInternal{
			unmarshalAuthnResult: unmarshalAuthnResultStream,
			subscriptions:        streamSubsToSubs(params.Subscriptions),
		},
	)
	if err != nil {
		return nil, errors.Trace(err)
	}

	sc := &StreamClient{
		wsConn:                            wsConn,
		callMarketUpdateListeners:         make(chan callMarketUpdateListenersReq, 1),
		callPairUpdateListeners:           make(chan callPairUpdateListenersReq, 1),
		callSubscriptionResultListeners:   make(chan callSubscriptionResultListenersReq, 1),
		callUnsubscriptionResultListeners: make(chan callUnsubscriptionResultListenersReq, 1),
		callBandwidthUpdateListeners:      make(chan callBandwidthUpdateListenersReq, 1),
		callMissedMessagesListeners:       make(chan callMissedMessagesListenersReq, 1),
	}

	sc.wsConn.onRead(func(data []byte) {
		var msg pbs.StreamMessage

		if err := proto.Unmarshal(data, &msg); err != nil {
			// Failed to parse incoming message: close connection (and if
			// reconnection was requested, then reconnect)
			sc.wsConn.disconnectOpt(nil, websocket.CloseUnsupportedData, "")
			return
		}

		switch msg.Body.(type) {
		case *pbs.StreamMessage_MarketUpdate:
			sc.marketUpdateHandler(msg.GetMarketUpdate())

		case *pbs.StreamMessage_PairUpdate:
			sc.pairUpdateHandler(msg.GetPairUpdate())

		case *pbs.StreamMessage_SubscriptionResult:
			sc.subscriptionResultHandler(msg.GetSubscriptionResult())

		case *pbs.StreamMessage_UnsubscriptionResult:
			sc.unsubscriptionResultHandler(msg.GetUnsubscriptionResult())

		case *pbs.StreamMessage_BandwidthUpdate:
			sc.bandwidthUpdateHandler(msg.GetBandwidthUpdate())

		case *pbs.StreamMessage_MissedMessages:
			sc.missedMessagesHandler(msg.GetMissedMessages())

		default:
			// not a supported type
		}

	})

	go sc.listen()

	return sc, nil
}

// listen is used internally to dispatch data to registered listeners.
func (sc *StreamClient) listen() {
	for {
		select {
		case req := <-sc.callMarketUpdateListeners:
			for _, l := range req.listeners {
				l(req.market, req.update)
			}

		case req := <-sc.callPairUpdateListeners:
			for _, l := range req.listeners {
				l(req.pair, req.update)
			}

		case req := <-sc.callSubscriptionResultListeners:
			for _, l := range req.listeners {
				l(req.result)
			}

		case req := <-sc.callUnsubscriptionResultListeners:
			for _, l := range req.listeners {
				l(req.result)
			}

		case req := <-sc.callBandwidthUpdateListeners:
			for _, l := range req.listeners {
				l(req.msg)
			}

		case req := <-sc.callMissedMessagesListeners:
			for _, l := range req.listeners {
				l(req.msg)
			}
		}
	}
}

// Market listeners

// OnMarketUpdate sets a callback for all market updates. MarketUpdateCB
// contains MarketUpdate, which is a container for every type of update. For each
// MarketUpdate, it will contain exactly one non-nil struct, which is one of the
// following:
// OrderBookSnapshot
// OrderBookDelta
// OrderBookSpreadUpdate
// TradesUpdate
// IntervalsUpdate
// SummaryUpdate
// SparklineUpdate
func (sc *StreamClient) OnMarketUpdate(cb MarketUpdateCB) {
	sc.mtx.Lock()
	defer sc.mtx.Unlock()

	sc.marketUpdateListeners = append(sc.marketUpdateListeners, cb)
}

// Pair listeners

// OnPairUpdate sets a callback for all pair updates. PairUpdateCB
// contains PairUpdate, which is a container for every type of pair update. For
// each MarketUpdate, there will be exactly one non-nil property, which is one of the
// following:
// VWAPUpdate
// PerformanceUpdate
// TrendlineUpdate
func (sc *StreamClient) OnPairUpdate(cb PairUpdateCB) {
	sc.mtx.Lock()
	defer sc.mtx.Unlock()

	sc.pairUpdateListeners = append(sc.pairUpdateListeners, cb)
}

// OnSubscriptionResult is called whenever a subscription attempt was made; it
// happens after the connection and authentication is successful, as well as
// after the call to Subscribe().
func (sc *StreamClient) OnSubscriptionResult(cb SubscriptionResultCB) {
	sc.mtx.Lock()
	defer sc.mtx.Unlock()

	sc.subscriptionResultListeners = append(sc.subscriptionResultListeners, cb)
}

// OnUnsubscriptionResult is called whenever an unsubscription attempt was
// made; it happens after the call to Unsubscribe().
func (sc *StreamClient) OnUnsubscriptionResult(cb UnsubscriptionResultCB) {
	sc.mtx.Lock()
	defer sc.mtx.Unlock()

	sc.unsubscriptionResultListeners = append(sc.unsubscriptionResultListeners, cb)
}

func (sc *StreamClient) OnBandwidthUpdate(cb BandwidthUpdateCB) {
	sc.mtx.Lock()
	defer sc.mtx.Unlock()

	sc.bandwidthUpdateListeners = append(sc.bandwidthUpdateListeners, cb)
}

// OnMissedMessages is sent to clients when the server was unable to send all
// requested messages to the client, so some of them were dropped on the floor.
// Typically this means that the client subscribed to too many subscriptions,
// so it should reduce the number of subscriptions.
func (sc *StreamClient) OnMissedMessages(cb MissedMessagesCB) {
	sc.mtx.Lock()
	defer sc.mtx.Unlock()

	sc.missedMessagesListeners = append(sc.missedMessagesListeners, cb)
}

// OnError registers a callback which will be called on all errors. When it's
// an error about disconnection, the OnError callbacks are called before the
// state listeners.
func (sc *StreamClient) OnError(cb OnErrorCB) {
	sc.wsConn.onError(cb)
}

// Dispatches incoming market update to registered listeners
func (sc *StreamClient) marketUpdateHandler(update *pbm.MarketUpdateMessage) {
	market := marketFromProto(update.Market)

	sc.mtx.Lock()
	marketListeners := make([]MarketUpdateCB, len(sc.marketUpdateListeners))
	copy(marketListeners, sc.marketUpdateListeners)
	sc.mtx.Unlock()

	switch update.Update.(type) {
	case *pbm.MarketUpdateMessage_OrderBookUpdate:
		update := orderBookSnapshotUpdateFromProto(update.GetOrderBookUpdate())
		sc.callMarketUpdateListeners <- callMarketUpdateListenersReq{
			market: market,
			update: common.MarketUpdate{
				OrderBookSnapshot: &update,
			},
			listeners: marketListeners,
		}

	case *pbm.MarketUpdateMessage_OrderBookDeltaUpdate:
		update := orderBookDeltaUpdateFromProto(update.GetOrderBookDeltaUpdate())
		sc.callMarketUpdateListeners <- callMarketUpdateListenersReq{
			market: market,
			update: common.MarketUpdate{
				OrderBookDelta: &update,
			},
			listeners: marketListeners,
		}

	case *pbm.MarketUpdateMessage_OrderBookSpreadUpdate:
		update := orderBookSpreadUpdateFromProto(update.GetOrderBookSpreadUpdate())
		sc.callMarketUpdateListeners <- callMarketUpdateListenersReq{
			market: market,
			update: common.MarketUpdate{
				OrderBookSpreadUpdate: &update,
			},
			listeners: marketListeners,
		}

	case *pbm.MarketUpdateMessage_TradesUpdate:
		update := tradesUpdateFromProto(update.GetTradesUpdate())
		sc.callMarketUpdateListeners <- callMarketUpdateListenersReq{
			market: market,
			update: common.MarketUpdate{
				TradesUpdate: &update,
			},
			listeners: marketListeners,
		}

	case *pbm.MarketUpdateMessage_IntervalsUpdate:
		update := intervalsUpdateFromProto(update.GetIntervalsUpdate())
		sc.callMarketUpdateListeners <- callMarketUpdateListenersReq{
			market: market,
			update: common.MarketUpdate{
				IntervalsUpdate: &update,
			},
			listeners: marketListeners,
		}

	case *pbm.MarketUpdateMessage_SummaryUpdate:
		update := summaryUpdateFromProto(update.GetSummaryUpdate())
		sc.callMarketUpdateListeners <- callMarketUpdateListenersReq{
			market: market,
			update: common.MarketUpdate{
				SummaryUpdate: &update,
			},
			listeners: marketListeners,
		}

	case *pbm.MarketUpdateMessage_SparklineUpdate:
		update := sparklineUpdateFromProto(update.GetSparklineUpdate())
		sc.callMarketUpdateListeners <- callMarketUpdateListenersReq{
			market: market,
			update: common.MarketUpdate{
				SparklineUpdate: &update,
			},
			listeners: marketListeners,
		}
	}
}

// Dispatches incoming pair update to registered listeners
func (sc *StreamClient) pairUpdateHandler(update *pbm.PairUpdateMessage) {
	pair := common.Pair{
		ID: common.PairID(uint64ToString(update.Pair)),
	}

	sc.mtx.Lock()
	pairListeners := make([]PairUpdateCB, len(sc.pairUpdateListeners))
	copy(pairListeners, sc.pairUpdateListeners)
	sc.mtx.Unlock()

	switch update.Update.(type) {
	case *pbm.PairUpdateMessage_VwapUpdate:
		update := vwapUpdateFromProto(update.GetVwapUpdate())
		sc.callPairUpdateListeners <- callPairUpdateListenersReq{
			pair: pair,
			update: common.PairUpdate{
				VWAPUpdate: &update,
			},
			listeners: pairListeners,
		}

	case *pbm.PairUpdateMessage_PerformanceUpdate:
		update := performanceUpdateFromProto(update.GetPerformanceUpdate())
		sc.callPairUpdateListeners <- callPairUpdateListenersReq{
			pair: pair,
			update: common.PairUpdate{
				PerformanceUpdate: &update,
			},
			listeners: pairListeners,
		}

	case *pbm.PairUpdateMessage_TrendlineUpdate:
		update := trendlineUpdateFromProto(update.GetTrendlineUpdate())
		sc.callPairUpdateListeners <- callPairUpdateListenersReq{
			pair: pair,
			update: common.PairUpdate{
				TrendlineUpdate: &update,
			},
			listeners: pairListeners,
		}
	}
}

func (sc *StreamClient) subscriptionResultHandler(update *pbs.SubscriptionResult) {
	result := subscriptionResultFromProto(update)

	sc.mtx.Lock()
	subresListeners := make([]SubscriptionResultCB, len(sc.subscriptionResultListeners))
	copy(subresListeners, sc.subscriptionResultListeners)
	sc.mtx.Unlock()

	sc.callSubscriptionResultListeners <- callSubscriptionResultListenersReq{
		result:    result,
		listeners: subresListeners,
	}
}

func (sc *StreamClient) unsubscriptionResultHandler(update *pbs.UnsubscriptionResult) {
	result := unsubscriptionResultFromProto(update)

	sc.mtx.Lock()
	subresListeners := make([]UnsubscriptionResultCB, len(sc.unsubscriptionResultListeners))
	copy(subresListeners, sc.unsubscriptionResultListeners)
	sc.mtx.Unlock()

	sc.callUnsubscriptionResultListeners <- callUnsubscriptionResultListenersReq{
		result:    result,
		listeners: subresListeners,
	}
}

func (sc *StreamClient) bandwidthUpdateHandler(update *pbs.BandwidthUpdate) {
	bandwidth := bandwidthFromProto(update)

	sc.mtx.Lock()
	sc.bandwidth = bandwidth
	bandwidthListeners := make([]BandwidthUpdateCB, len(sc.bandwidthUpdateListeners))
	copy(bandwidthListeners, sc.bandwidthUpdateListeners)
	sc.mtx.Unlock()

	sc.callBandwidthUpdateListeners <- callBandwidthUpdateListenersReq{
		msg:       bandwidth,
		listeners: bandwidthListeners,
	}

	if !bandwidth.OK {
		sc.wsConn.disconnectOpt(
			errors.New("No bandwidth"),
			websocket.CloseNormalClosure,
			"Disconnecting due to no bandwidth",
		)
		sc.Close()
	}
}

func (sc *StreamClient) missedMessagesHandler(update *pbs.MissedMessages) {
	msg := missedMessagesFromProto(update)

	sc.mtx.Lock()
	listeners := make([]MissedMessagesCB, len(sc.missedMessagesListeners))
	copy(listeners, sc.missedMessagesListeners)
	sc.mtx.Unlock()

	sc.callMissedMessagesListeners <- callMissedMessagesListenersReq{
		msg:       msg,
		listeners: listeners,
	}
}

// OnStateChange registers a new listener for the given state. The listener is
// registered with the default options (call the listener every time the state
// becomes active, and don't call the listener immediately for the current
// state). All registered callbacks for all states (and all messages, see
// OnMarketUpdate) will be called by the same internal goroutine, i.e. they are
// never called concurrently with each other.
//
// The order of listeners invocation for the same state is unspecified, and
// clients shouldn't rely on it.
//
// The listeners shouldn't block; a blocked listener will also block the whole
// stream connection.
//
// To subscribe to all state changes, use ConnStateAny as a state.
func (sc *StreamClient) OnStateChange(state ConnState, cb StateCallback) {
	sc.wsConn.onStateChange(state, cb)
}

// OnStateChangeOpt is like OnStateChange, but also takes additional
// options; see StateListenerOpt for details.
func (sc *StreamClient) OnStateChangeOpt(state ConnState, cb StateCallback, opt StateListenerOpt) {
	sc.wsConn.onStateChangeOpt(state, cb, opt)
}

// GetSubscriptions returns a slice of the current subscriptions.
func (sc *StreamClient) GetSubscriptions() []*StreamSubscription {
	return subsToStreamSubs(sc.wsConn.getSubscriptions())
}

// OnConnClosed allows the client to set a callback for when the connection is lost.
// The new state of the client could be ConnStateDisconnected or ConnStateWaitBeforeReconnect.
func (sc *StreamClient) OnConnClosed(cb ConnClosedCallback) {
	sc.wsConn.onConnClosed(cb)
}

// Subscribe makes a request to subscribe to the given keys. Example:
//
//   client.Subscribe([]*StreamSubscription{
//           &StreamSubscription{
//                   Resource: "markets:1:book:deltas",
//           },
//           &StreamSubscription{
//                   Resource: "markets:1:book:spread",
//           },
//   })
//
// The client must be connected and authenticated for this to work. See
// StreamClientParams.Subscriptions for more details.
//
// The subscription result, together with the current subscription status, will
// be delivered to the callback registered with OnSubscriptionResult.
func (sc *StreamClient) Subscribe(subs []*StreamSubscription) error {
	return sc.wsConn.subscribe(streamSubsToSubs(subs))
}

// Unsubscribe unsubscribes from the given set of keys. Also see notes for
// subscribe.
//
// The unsubscription result, together with the current subscription status,
// will be delivered to the callback registered with OnUnsubscriptionResult.
func (sc *StreamClient) Unsubscribe(subs []*StreamSubscription) error {
	return sc.wsConn.unsubscribe(streamSubsToSubs(subs))
}

// URL returns the url the client is connected to, e.g. wss://stream.cryptowat.ch.
func (sc *StreamClient) URL() string {
	return sc.wsConn.url()
}

// Connect either starts a connection goroutine (if state is
// ConnStateDisconnected), or makes it connect immediately, ignoring timeout
// (if the state is ConnStateWaitBeforeReconnect). For other states, this returns an
// error.
//
// Connect doesn't wait for the connection to establish; it returns immediately.
func (sc *StreamClient) Connect() (err error) {
	return sc.wsConn.connect()
}

// Close stops the connection (or reconnection loop, if active), and if
// websocket connection is active at the moment, closes it as well.
func (sc *StreamClient) Close() (err error) {
	return sc.wsConn.close()
}

func streamSubsToSubs(streamSubs []*StreamSubscription) []Subscription {
	subs := make([]Subscription, 0, len(streamSubs))

	for _, v := range streamSubs {
		subs = append(subs, v)
	}

	return subs
}

func subsToStreamSubs(subs []Subscription) []*StreamSubscription {
	streamSubs := make([]*StreamSubscription, 0, len(subs))

	for _, sub := range subs {
		v, ok := sub.(*StreamSubscription)
		if !ok {
			panic(errInvalidSubType)
		}

		streamSubs = append(streamSubs, v)
	}

	return streamSubs
}

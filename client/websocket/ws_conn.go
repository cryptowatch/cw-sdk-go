package websocket // import "code.cryptowat.ch/cw-sdk-go/client/websocket"

import (
	"context"
	"crypto/hmac"
	"crypto/sha512"
	"encoding/base64"
	"encoding/json"
	"fmt"
	"strings"
	"time"

	"github.com/golang/protobuf/proto"
	"github.com/gorilla/websocket"
	"github.com/juju/errors"
	"honnef.co/go/tools/version"

	"code.cryptowat.ch/cw-sdk-go/client/websocket/internal"
	pbc "code.cryptowat.ch/cw-sdk-go/proto/client"
	pbs "code.cryptowat.ch/cw-sdk-go/proto/stream"
)

// The following errors are returned from wsConn, which applies to both
// StreamClient and TradeClient.
var (
	// ErrNotConnected means the connection is not established when the client
	// tried to e.g. send a message, or close the connection.
	ErrNotConnected = errors.New("not connected")

	// ErrInvalidAuthn means that after the client has sent the authentication
	// info and was expecting the result from the server, it received something
	// else.
	ErrInvalidAuthn = errors.New("invalid authentication result")

	// ErrConnLoopActive means the client tried to connect when the client is
	// already connecting.
	ErrConnLoopActive = errors.New("connection loop is already active")

	// ErrBadCredentials means the provided APIKey and/or SecretKey were invalid.
	ErrBadCredentials = errors.New("bad credentials")

	// ErrTokenExpired means the authentication procedure took too long and the
	// token expired. The client retries authentication 3 times before actually
	// returning this error.
	ErrTokenExpired = errors.New("token is expired")

	// ErrBadNonce means the nonce used in the authentication request is not
	// larger than the last used nonce.
	ErrBadNonce = errors.New("bad nonce")

	// ErrUnknownAuthnError means some unexpected authentication problem;
	// possibly caused by an internal error on stream server.
	ErrUnknownAuthnError = errors.New("unknown authentication error")

	// errInvalidSubType means that different types of subscriptions were mixed
	// in the same list.
	errInvalidSubType = errors.New("invalid subscription type")
)

// WSParams contains options for opening a websocket connection.
type WSParams struct {
	// APIKey and SecretKey are needed to authenticate with Cryptowatch back end.
	// Inquire about getting access here: https://docs.google.com/forms/d/e/1FAIpQLSdhv_ceVtKA0qQcW6zQzBniRBaZ_cC4al31lDCeZirntkmWQw/viewform?c=0&w=1
	APIKey    string
	SecretKey string

	// URL is the URL to connect to over websockets. You will not have to set this
	// unless testing against a non-production environment since a default is
	// always used.
	URL string

	// ReconnectOpts contains settings for how to reconnect if the client becomes disconnected.
	// Sensible defaults are used.
	ReconnectOpts *ReconnectOpts
}

type Subscription interface {
	GetResource() string
}

type wsConnParamsInternal struct {
	unmarshalAuthnResult func(data []byte) (*pbs.AuthenticationResult, error)

	// subscriptions is a list of subscriptions.
	// When using a StreamClient the values are of concrete type StreamSubscription; when using a
	// TradeClient the values are of type TradeSubscription.
	subscriptions []Subscription
}

// ReconnectOpts are settings used to reconnect after being disconnected. By default, the client will reconnect
// with backoff starting with 0 seconds and increasing linearly up to 30 seconds. These are the most "aggressive"
// reconnect options permitted in the client. For example, you cannot set ReconnectTimeout to 0 and Backoff to false.
type ReconnectOpts struct {
	// Reconnect switch: if true, the client will attempt to reconnect to the websocket back
	// end if it is disconnected. If false, the client will stay disconnected.
	Reconnect bool

	// Reconnection backoff: if true, then the reconnection time will be
	// initially ReconnectTimeout, then will grow by 500ms on each unsuccessful
	// connection attempt; but it won't be longer than MaxReconnectTimeout.
	Backoff bool

	// Initial reconnection timeout: defaults to 0 seconds. If backoff=false,
	// a minimum reconnectTimeout of 1 second will be used.
	ReconnectTimeout time.Duration

	// Max reconnect timeout. If zero, then 30 seconds will be used.
	MaxReconnectTimeout time.Duration
}

var defaultReconnectOpts = &ReconnectOpts{
	Reconnect:           true,
	Backoff:             true,
	ReconnectTimeout:    0,
	MaxReconnectTimeout: 30 * time.Second,
}

// ConnState represents the websocket connection state
type ConnState int

// SubscriptionResult is sent to clients after subscription to some key(s) is
// attempted. It happens after successful authentication (if authentication
// message contained initial subscriptions) as well as after following requests
// to subscribe.
type SubscriptionResult struct {
	// Successful subscriptions
	Subscriptions []Subscription
	// Failed subscriptions
	Failed []SubscribeError `json:"Failed,omitempty"`
	// Current status: list of the keys to which the client is now subscribed
	Status SubscriptionStatus
}

func (v SubscriptionResult) String() string {
	data, err := json.Marshal(v)
	if err != nil {
		return fmt.Sprintf("[failed to stringify SubscriptionResult: %s]", err)
	}

	return string(data)
}

// UnsubscriptionResult is sent to clients in response to the request to
// unsubscribe.
type UnsubscriptionResult struct {
	// Successful unsubscriptions
	Subscriptions []Subscription
	// Faied unsubscriptions
	Failed []UnsubscribeError `json:"Failed,omitempty"`
	// Current status: list of the keys to which the client is now subscribed
	Status SubscriptionStatus
}

// BandwidthUpdate contains information about your stream bandwidth usage
type Bandwidth struct {
	OK             bool
	BytesRemaining int64
	BytesUsed      int64
}

func (b Bandwidth) String() string {
	return fmt.Sprintf("Bandwidth Remaining: %v; Bytes Remaining: %v; Bytes Used: %v;",
		b.OK, b.BytesRemaining, b.BytesUsed)
}

// MissedMessages is sent to clients when the server was unable to send all
// requested messages to the client, so some of them were dropped on the floor.
// Typically it means that the client subscribed to too much, so it should
// reduce the number of subscriptions.
type MissedMessages struct {
	// NumMissedMessages represents how many messages were dropped on the floor.
	NumMissedMessages int64
}

func (v UnsubscriptionResult) String() string {
	data, err := json.Marshal(v)
	if err != nil {
		return fmt.Sprintf("[failed to stringify UnsubscriptionResult: %s]", err)
	}

	return string(data)
}

// SubscribeError represents an error of a single key: it contains the key and
// the error message explaining why subscription has failed. Sent as part of
// SubscriptionResult.
type SubscribeError struct {
	Key          string
	Error        string
	Subscription Subscription
}

// UnsubscribeError represents an error of a single key: it contains the key
// and the error message explaining why unsubscription has failed. Sent as part
// of UnsubscriptionResult.
type UnsubscribeError struct {
	Key          string
	Error        string
	Subscription Subscription
}

// SubscriptionStatus contains the key to which the client is subscribed right
// now. Sent as part of SubscriptionResult and UnsubscriptionResult.
type SubscriptionStatus struct {
	Subscriptions []Subscription
}

// SubscriptionResultCB defines a callback function for OnSubscriptionResult.
type SubscriptionResultCB func(sr SubscriptionResult)

// SubscriptionResultCB defines a callback function for OnUnsubscriptionResult.
type UnsubscriptionResultCB func(sr UnsubscriptionResult)

type BandwidthUpdateCB func(b Bandwidth)

// MissedMessagesCB defines a callback function for OnMissedMessages.
type MissedMessagesCB func(mm MissedMessages)

// The following constants represent every possible ConnState.
const (
	// ConnStateDisconnected means we're disconnected and not trying to connect.
	// connLoop is not running.
	ConnStateDisconnected ConnState = iota

	// ConnStateWaitBeforeReconnect means we already tried to connect, but then
	// either the connection failed, or succeeded but later disconnected for some
	// reason (see stateCause), and now we're waiting for a timeout before
	// connecting again. wsConn is nil, but connCtx and connCtxCancel are not,
	// and connLoop is running.
	ConnStateWaitBeforeReconnect

	// ConnStateConnecting means we're calling websocket.DefaultDialer.Dial() right
	// now.
	ConnStateConnecting

	// ConnStateAuthenticating means the transport (websocket) connection is
	// established, and right now we're exchanging the authentication and
	// identification messages
	ConnStateAuthenticating

	// ConnStateEstablished means the connection is ready
	ConnStateEstablished

	// ConnStateAny can be used with onStateChange() and onStateChangeOpt()
	// in order to listen for all states.
	ConnStateAny = -1
)

// ConnStateNames contains human-readable names for connection states.
var ConnStateNames = map[ConnState]string{
	ConnStateDisconnected:        "disconnected",
	ConnStateWaitBeforeReconnect: "wait-before-reconnect",
	ConnStateConnecting:          "connecting",
	ConnStateAuthenticating:      "authenticating",
	ConnStateEstablished:         "established",
}

// wsConn represents a stream connection, it contains unexported fields
type wsConn struct {
	params         WSParams
	paramsInternal wsConnParamsInternal

	subscriptions map[string]struct{}
	subs          map[string]Subscription

	transport *internal.StreamTransportConn

	authnCtx       context.Context
	authnCtxCancel context.CancelFunc

	// Current state
	state ConnState

	// expectDisconnection is set to true when the client calls OnError callbacks
	// and initiates the disconnection. In this case, when the actual
	// disconnection happens, OnError callbacks won't be called with a generic
	// disconnection error.
	expectDisconnection bool

	stateListeners map[ConnState][]stateListener

	// onReadCB, if not nil, is called for each received websocket message.
	onReadCB onReadCallback

	// onErrorCBs contains on-error handlers
	onErrorCBs []OnErrorCB

	// internalEvents is a channel of events handled by eventLoop. See
	// internalEvent struct.
	internalEvents chan internalEvent
}

// internalEvent represents an event handled in eventLoop. Each field
// represents one kind of the event, and only a single field should be non-nil.
type internalEvent struct {
	// rxData contains data received from the server via websocket.
	rxData []byte
	// transportStateUpdate represents an update of transport layer state.
	transportStateUpdate *transportStateUpdate

	// reqOnStateChange is the result of the clients call to onStateChange
	// or onStateChangeOpt.
	reqOnStateChange *reqOnStateChange
	reqAddOnErrorCB  *reqAddOnErrorCB
	reqConnState     *reqConnState
	reqSubscribe     *reqSubscribe
	reqUnsubscribe   *reqUnsubscribe
}

// reqOnStateChange is a request to add state listener
type reqOnStateChange struct {
	state ConnState
	cb    StateCallback
	opt   StateListenerOpt

	result chan<- struct{}
}

type reqAddOnErrorCB struct {
	cb     OnErrorCB
	result chan<- struct{}
}

// reqConnState is a client request of conn state via connState().
type reqConnState struct {
	result chan<- ConnState
}

// reqSubscribe is a client request of conn state via Subscribe().
type reqSubscribe struct {
	subs   []Subscription
	result chan<- error
}

// reqUnsubscribe is a client request of conn state via Unsubscribe().
type reqUnsubscribe struct {
	subs   []Subscription
	result chan<- error
}

// transportStateUpdate is an update of transport layer state.
type transportStateUpdate struct {
	oldState internal.TransportState
	state    internal.TransportState

	cause error
}

// newWsConn creates a new websocket connection with the given params.
//
// Note that clients should manually call Connect on a newly created
// connection; the rationale is that clients might register some state and/or
// message handlers before the connection, to avoid any possible races.
func newWsConn(params *WSParams, paramsInternal *wsConnParamsInternal) (*wsConn, error) {
	p := *params

	if p.URL == "" {
		// Should never happen since client code for that is in the same package.
		return nil, errors.New("internal error: URL is empty")
	}

	if p.ReconnectOpts == nil {
		p.ReconnectOpts = defaultReconnectOpts
	}

	transport, err := internal.NewStreamTransportConn(&internal.StreamTransportParams{
		URL: p.URL,

		Reconnect:           p.ReconnectOpts.Reconnect,
		Backoff:             p.ReconnectOpts.Backoff,
		ReconnectTimeout:    p.ReconnectOpts.ReconnectTimeout,
		MaxReconnectTimeout: p.ReconnectOpts.MaxReconnectTimeout,
	})
	if err != nil {
		return nil, errors.Trace(err)
	}

	c := &wsConn{
		params:         p,
		paramsInternal: *paramsInternal,
		subscriptions:  make(map[string]struct{}),
		subs:           make(map[string]Subscription),
		transport:      transport,
		stateListeners: make(map[ConnState][]stateListener),
		internalEvents: make(chan internalEvent, 8),
	}

	for _, sub := range paramsInternal.subscriptions {
		c.subs[sub.GetResource()] = sub
	}

	transport.OnStateChange(
		func(_ *internal.StreamTransportConn, oldTransportState, transportState internal.TransportState, cause error) {
			c.internalEvents <- internalEvent{
				transportStateUpdate: &transportStateUpdate{
					oldState: oldTransportState,
					state:    transportState,
					cause:    cause,
				},
			}
		},
	)

	transport.OnRead(
		func(tc *internal.StreamTransportConn, data []byte) {
			c.internalEvents <- internalEvent{
				rxData: data,
			}
		},
	)

	// Start goroutine which will call state listeners
	go c.eventLoop()

	return c, nil
}

// onRead sets on-read callback; it should be called once right after creation
// of the wsConn by a wrapper (like StreamClient), before the connection is
// established.
func (c *wsConn) onRead(cb onReadCallback) {
	c.onReadCB = cb
}

// connect either starts a connection goroutine (if state is
// ConnStateDisconnected), or makes it connect immediately, ignoring timeout
// (if the state is ConnStateWaitBeforeReconnect). For other states, this returns an
// error.
//
// connect doesn't wait for the connection to establish; it returns immediately.
func (c *wsConn) connect() (err error) {
	defer func() {
		// Translate internal transport errors to public ones
		if errors.Cause(err) == internal.ErrConnLoopActive {
			err = errors.Trace(ErrConnLoopActive)
		}
	}()

	if err := c.transport.Connect(); err != nil {
		return errors.Trace(err)
	}

	return nil
}

// disconnect sends a "normal closure" websocket message to the server,
// causing it to disconnect, and when we receive the actual disconnection soon,
// the cause error given to the clients will be the cause given to disconnect.
//
// If cause is nil, then the upcoming disconnection error will be passed to
// clients as is.
//
// NOTE: disconnect should only be called from the eventLoop.
func (c *wsConn) disconnect(cause error) {
	c.disconnectOpt(cause, websocket.CloseNormalClosure, "")
}

// disconnectOpt sends a websocket closure message (with given closeCode and
// text) to the server, causing it to disconnect, and when we receive the
// actual disconnection soon, the cause error given to the clients will be the
// cause given to disconnectOpt.
//
// If passed cause is nil, then the upcoming disconnection error will be passed
// to clients as is.
//
// NOTE: disconnectOpt should only be called from the eventLoop.
func (c *wsConn) disconnectOpt(cause error, closeCode int, text string) {
	closeErr := c.transport.CloseOpt(
		websocket.FormatCloseMessage(closeCode, text),
		false,
	)
	if closeErr != nil {
		return
	}

	if cause != nil {
		c.expectDisconnection = true
		c.callOnErrorCBs(cause, true)
	}
}

// close stops the connection (or reconnection loop, if active), and if
// websocket connection is active at the moment, closes it as well.
func (c *wsConn) close() (err error) {
	defer func() {
		// Translate internal transport errors to public ones
		if errors.Cause(err) == internal.ErrNotConnected {
			err = errors.Trace(ErrNotConnected)
		}
	}()

	if err = c.transport.Close(); err != nil {
		return errors.Trace(err)
	}

	return nil
}

func (c *wsConn) handleAuthnResult(result *pbs.AuthenticationResult) error {
	// Got authentication result message
	switch result.Status {
	case pbs.AuthenticationResult_AUTHENTICATED:
		return nil

	case pbs.AuthenticationResult_TOKEN_EXPIRED:
		// The token is expired
		return ErrTokenExpired

	case pbs.AuthenticationResult_BAD_TOKEN:
		// User provided bad creds
		return ErrBadCredentials

	case pbs.AuthenticationResult_BAD_NONCE:
		return ErrBadNonce

	case pbs.AuthenticationResult_UNKNOWN:
		// Shouldn't happen normally; it can happen e.g. if stream has failed
		// to connect to biller, or failed to call biller's methods.
		return ErrUnknownAuthnError

	default:
		// Client problem
		return ErrUnknownAuthnError
	}
}

// StateCallback is a signature of a state listener. Arguments conn, oldState
// and state are self-descriptive; cause is the error which caused the current
// state. Cause is relevant only for ConnStateDisconnected and
// ConnStateWaitBeforeReconnect (in which case it's either the reason of failure to
// connect, or reason of disconnection), for other states it's always nil.
//
// See onStateChange.
type StateCallback func(prevState, curState ConnState)

// onReadCallback is a signature of (internal) incoming messages listener.
type onReadCallback func(data []byte)

// OnErrorCB is a signature of an error listener. If the error is going to
// cause the disconnection, disconnecting is set to true. In this case, the
// error listeners are always called before the state listeners, so
// applications can just save the error, and display it later, when the
// disconnection actually happens.
type OnErrorCB func(err error, disconnecting bool)

type StateListenerOpt struct {
	// If OneOff is true, the listener will only be called once; otherwise it'll
	// be called every time the requested state becomes active.
	OneOff bool

	// If CallImmediately is true, and the state being subscribed to is active
	// at the moment, the callback will be called immediately (with the "old"
	// state being equal to the new one)
	CallImmediately bool
}

// onStateChange registers a new listener for the given state. The listener is
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
func (c *wsConn) onStateChange(state ConnState, cb StateCallback) {
	c.onStateChangeOpt(state, cb, StateListenerOpt{})
}

// onStateChangeOpt is like onStateChange, but also takes additional
// options; see StateListenerOpt for details.
func (c *wsConn) onStateChangeOpt(state ConnState, cb StateCallback, opt StateListenerOpt) {
	result := make(chan struct{})

	c.internalEvents <- internalEvent{
		reqOnStateChange: &reqOnStateChange{
			state: state,
			cb:    cb,
			opt:   opt,

			result: result,
		},
	}

	<-result
}

func (c *wsConn) onError(cb OnErrorCB) {
	result := make(chan struct{})

	c.internalEvents <- internalEvent{
		reqAddOnErrorCB: &reqAddOnErrorCB{
			cb:     cb,
			result: result,
		},
	}

	<-result
}

// ConnClosedCallback defines the callback function for onConnClosed.
type ConnClosedCallback func(state ConnState)

// onConnClosed allows the client to set a callback for when the connection is lost.
// The new state of the client could be ConnStateDisconnected or ConnStateWaitBeforeReconnect.
func (c *wsConn) onConnClosed(cb ConnClosedCallback) {
	c.onStateChange(ConnStateDisconnected, func(_, curState ConnState) {
		cb(curState)
	})
	c.onStateChange(ConnStateWaitBeforeReconnect, func(_, curState ConnState) {
		cb(curState)
	})
}

// getSubscriptions returns a slice of the current subscriptions.
func (c *wsConn) getSubscriptions() []Subscription {
	subs := []Subscription{}

	for _, sub := range c.subs {
		subs = append(subs, sub)
	}

	return subs
}

// subscribe subscribes to the given set of keys. Example:
//
//   conn.subscribe([]Subscription{
//           &StreamSubscription{
//                   Resource: "markets:1:book:deltas",
//           },
//           &StreamSubscription{
//                   Resource: "markets:1:book:spread",
//           },
//   })
//
// The client must be connected and authenticated for this to work. See
// StreamClientParams.Subscriptions or TradeClientParams.Subscriptionsfor more details.
func (c *wsConn) subscribe(subs []Subscription) error {
	result := make(chan error, 1)

	c.internalEvents <- internalEvent{
		reqSubscribe: &reqSubscribe{
			subs:   subs,
			result: result,
		},
	}

	return <-result
}

// unsubscribe unsubscribes from the given set of subs. Also see notes for
// subscribe.
func (c *wsConn) unsubscribe(subs []Subscription) error {
	result := make(chan error, 1)

	c.internalEvents <- internalEvent{
		reqUnsubscribe: &reqUnsubscribe{
			subs:   subs,
			result: result,
		},
	}

	return <-result
}

// connState returns current client connection state.
func (c *wsConn) connState() ConnState {
	result := make(chan ConnState, 1)

	c.internalEvents <- internalEvent{
		reqConnState: &reqConnState{
			result: result,
		},
	}

	return <-result
}

// url returns the url the client is connected to, e.g. wss://stream.cryptowat.ch.
func (c *wsConn) url() string {
	return c.params.URL
}

// stateListener wraps a state change callback and a flag of whether the
// callback is one-off (one-off listeners are only called once, on the next
// event)
type stateListener struct {
	cb  StateCallback
	opt StateListenerOpt
}

type callStateListenersReq struct {
	listeners       []stateListener
	oldState, state ConnState
}

// NOTE: updateState should only be called from the eventLoop.
func (c *wsConn) updateState(state ConnState) {
	if c.state == state {
		// No need to do anything
		return
	}

	// Properly leave the current state
	c.enterLeaveState(c.state, false)

	oldState := c.state
	c.state = state

	// Properly enter the new state
	c.enterLeaveState(c.state, true)

	// Collect all listeners to call now
	// We'll call them a bit later, when the mutex is not locked
	listeners := append(c.stateListeners[state], c.stateListeners[ConnStateAny]...)

	// Remove one-off listeners
	c.stateListeners[state] = removeOneOff(c.stateListeners[state])
	c.stateListeners[ConnStateAny] = removeOneOff(c.stateListeners[ConnStateAny])

	// Request listeners invocation (will be invoked by a dedicated goroutine)
	c.callStateListeners(&callStateListenersReq{
		listeners: listeners,
		oldState:  oldState,
		state:     state,
	})
}

// NOTE: callOnErrorCBs should only be called from the eventLoop.
func (c *wsConn) callOnErrorCBs(err error, disconnecting bool) {
	for _, cb := range c.onErrorCBs {
		cb(err, disconnecting)
	}
}

// enterLeaveState should be called on leaving and entering each state. So,
// when changing state from A to B, it's called twice, like this:
//
//      enterLeaveState(A, false)
//      enterLeaveState(B, true)
//
// NOTE: enterLeaveState should only be called from eventLoop.
func (c *wsConn) enterLeaveState(state ConnState, enter bool) {
	switch state {

	case ConnStateAuthenticating:
		// authnCtx and its cancel func should only be present in the
		// ConnStateAuthenticating state.
		if enter {
			c.authnCtx, c.authnCtxCancel = context.WithCancel(context.Background())
		} else {
			c.authnCtxCancel()

			c.authnCtx = nil
			c.authnCtxCancel = nil
		}
	}
}

// removeOneOff takes a slice of listeners and returns a new one, with one-off
// listeners removed.
func removeOneOff(listeners []stateListener) []stateListener {

	newListeners := []stateListener{}

	for _, sl := range listeners {
		if !sl.opt.OneOff {
			newListeners = append(newListeners, sl)
		}
	}

	return newListeners
}

// NOTE: subscribeInternal should only be called from eventLoop.
func (c *wsConn) subscribeInternal(subs []Subscription) error {
	cm := &pbc.ClientMessage{
		Body: &pbc.ClientMessage_Subscribe{
			Subscribe: &pbc.ClientSubscribeMessage{
				Subscriptions: subsToProto(subs),
			},
		},
	}

	if err := c.sendProto(context.Background(), cm); err != nil {
		return errors.Annotatef(err, "subscribe")
	}

	for _, sub := range subs {
		c.subs[sub.GetResource()] = sub
	}

	return nil
}

// NOTE: unsubscribeInternal should only be called from eventLoop.
func (c *wsConn) unsubscribeInternal(subs []Subscription) error {
	cm := &pbc.ClientMessage{
		Body: &pbc.ClientMessage_Unsubscribe{
			Unsubscribe: &pbc.ClientUnsubscribeMessage{
				Subscriptions: subsToProto(subs),
			},
		},
	}

	if err := c.sendProto(context.Background(), cm); err != nil {
		return errors.Annotatef(err, "unsubscribe")
	}

	for _, sub := range subs {
		delete(c.subs, sub.GetResource())
	}

	return nil
}

// sendProto marshals and sends a protobuf message to the websocket if it's
// connected, or queues the data otherwise.
func (c *wsConn) sendProto(ctx context.Context, pb proto.Message) (err error) {
	defer func() {
		if errors.Cause(err) == internal.ErrNotConnected {
			err = errors.Trace(ErrNotConnected)
		}
	}()

	data, err := proto.Marshal(pb)
	if err != nil {
		return errors.Annotatef(err, "marshalling protobuf msg")
	}

	if err := c.transport.Send(ctx, data); err != nil {
		return errors.Trace(err)
	}

	return nil
}

// eventLoop handles all internal events like transport state change, received
// data, or client calls to add state listener. See internalEvent struct.
func (c *wsConn) eventLoop() {
loop:
	for {
		event := <-c.internalEvents

		if tsu := event.transportStateUpdate; tsu != nil {
			// Transport layer state changed.

			switch tsu.state {
			case
				internal.TransportStateDisconnected,
				internal.TransportStateWaitBeforeReconnect,
				internal.TransportStateConnecting:

				// Disconnected, WaitBeforeReconnect and Connecting are easy: they
				// translate 1-to-1 to the wsConn-level state.

				var state ConnState
				switch tsu.state {
				case internal.TransportStateDisconnected:
					state = ConnStateDisconnected
				case internal.TransportStateWaitBeforeReconnect:
					state = ConnStateWaitBeforeReconnect
				case internal.TransportStateConnecting:
					state = ConnStateConnecting
				default:
					// Should never be here
					panic(fmt.Sprintf("unexpected transport state: %d", tsu.state))
				}

				// Only call on-error callbacks if we didn't expect disconnection;
				// otherwise we have already called on-error callbacks earlier,
				// with the concrete error.
				if !c.expectDisconnection && tsu.cause != nil {
					c.callOnErrorCBs(tsu.cause, true)
				}
				c.expectDisconnection = false

				c.updateState(state)

			case internal.TransportStateConnected:
				// When transport layer is Connected, we need to set wsConn state to
				// Authenticating, and send authentication data to the server.

				c.updateState(ConnStateAuthenticating)
				ctx := c.authnCtx

				nonce := getNonce()
				token, err := c.generateToken(nonce)
				if err != nil {
					c.disconnect(errors.Trace(err))
					continue loop
				}

				authMsg := &pbc.ClientMessage{
					Body: &pbc.ClientMessage_ApiAuthentication{
						ApiAuthentication: &pbc.APIAuthenticationMessage{
							Token:               token,
							Nonce:               nonce,
							ApiKey:              c.params.APIKey,
							Source:              pbc.APIAuthenticationMessage_GOLANG_SDK,
							Version:             version.Version,
							ClientSubscriptions: subsToProto(c.getSubscriptions()),
						},
					},
				}

				if err := c.sendProto(ctx, authMsg); err != nil {
					c.disconnect(errors.Trace(err))
					continue loop
				}

			default:
				panic(fmt.Sprintf("Invalid transport layer state %v", tsu.state))
			}
		} else if data := event.rxData; data != nil {
			// Received some data. The way we handle it depends on the state:
			//
			// - Authenticating: interpret the data as authentication result,
			//   and if it's successful, then finally set state to Established.
			//   If not, initiate disconnection (and the state will be changed
			//   when we actually disconnect).
			// - Established: pass the data to clients (StreamClient or TradeClient)
			//   via OnRead callback
			// - Any other state: ignore. TODO: also call some error handler to
			//   notify the client.

			switch c.state {
			case ConnStateAuthenticating:
				// Expect authentication result, so try to unmarshal it
				unmarshalAuthnResult := c.paramsInternal.unmarshalAuthnResult
				if unmarshalAuthnResult == nil {
					c.disconnect(errors.Errorf("unmarshalAuthnResult is not set"))
					continue loop
				}

				authnResult, err := unmarshalAuthnResult(data)
				if err != nil {
					c.disconnect(errors.Trace(err))
					continue loop
				}

				if err := c.handleAuthnResult(authnResult); err != nil {
					c.disconnect(errors.Trace(err))
					continue loop
				}

				// Authentication is successful
				// We can now reset any backoff that has been applied
				c.transport.ResetTimeout()

				c.updateState(ConnStateEstablished)

			case ConnStateEstablished:
				// Pass message up to the client
				if c.onReadCB != nil {
					c.onReadCB(data)
				}

			default:
				// We don't expect to receive any messages in this state
				// TODO: report error to the client, but don't disconnect
			}

		} else if al := event.reqOnStateChange; al != nil {
			// Request to add a new state listener.

			sl := stateListener{
				cb:  al.cb,
				opt: al.opt,
			}

			// Determine whether the callback should be called right now
			callNow := al.opt.CallImmediately && (al.state == c.state || al.state == ConnStateAny)

			// Update stored listeners if needed
			if !al.opt.OneOff || !callNow {
				c.stateListeners[al.state] = append(c.stateListeners[al.state], sl)
			}

			if callNow {
				c.callStateListeners(&callStateListenersReq{
					listeners: []stateListener{sl},
					oldState:  c.state,
					state:     c.state,
				})
			}

			al.result <- struct{}{}
		} else if req := event.reqAddOnErrorCB; req != nil {
			// Request to add a new on-error callback

			// Update stored listeners if needed
			c.onErrorCBs = append(c.onErrorCBs, req.cb)

			req.result <- struct{}{}
		} else if req := event.reqConnState; req != nil {
			// Request to add a new state listener.
			req.result <- c.state
		} else if req := event.reqSubscribe; req != nil {
			// Request to subscribe
			err := c.subscribeInternal(req.subs)
			req.result <- err
		} else if req := event.reqUnsubscribe; req != nil {
			// Request to unsubscribe
			err := c.unsubscribeInternal(req.subs)
			req.result <- err
		}
	}
}

// NOTE: callStateListeners should only be called from the eventLoop, to ensure
// that all callbacks are only invoked from a single goroutine.
func (c *wsConn) callStateListeners(req *callStateListenersReq) {
	for _, sl := range req.listeners {
		sl.cb(req.oldState, req.state)
	}
}

// generateToken creates an access token based on the user's secret access key
func (c *wsConn) generateToken(nonce string) (string, error) {
	secretKeyData, err := base64.StdEncoding.DecodeString(c.params.SecretKey)
	if err != nil {
		return "", errors.Annotatef(err, "base64-decoding the secret key")
	}

	h := hmac.New(sha512.New, secretKeyData)
	payload := fmt.Sprintf("stream_access;access_key_id=%v;nonce=%v;", c.params.APIKey, nonce)
	h.Write([]byte(payload))
	return base64.StdEncoding.EncodeToString(h.Sum(nil)), nil
}

func getNonce() string {
	return fmt.Sprintf("%d", time.Now().UnixNano())
}

// isClosedConnError is needed because we don't have a separate type for
// that kind of error. Too bad.
func isClosedConnError(err error) bool {
	if err == nil {
		return false
	}

	str := err.Error()
	if strings.Contains(str, "use of closed network connection") {
		return true
	}

	return false
}

func subsToKeys(subs []Subscription) []string {
	keys := make([]string, 0, len(subs))

	for _, v := range subs {
		keys = append(keys, v.GetResource())
	}

	return keys
}

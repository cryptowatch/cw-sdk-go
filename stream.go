package streamclient

import (
	"context"
	"fmt"
	"sync"
	"time"

	pbc "github.com/cryptowatch/proto/client"
	pbs "github.com/cryptowatch/proto/stream"
	"github.com/golang/protobuf/proto"
	"github.com/gorilla/websocket"
	"github.com/juju/errors"
)

type State int

const (
	// StateDisconnected means we're disconnected and not trying to connect.
	// connLoop is not running.
	StateDisconnected State = iota

	// StateWaitBeforeReconnect means we already tried to connect, but then
	// either the connection failed, or succeeded but later disconnected for some
	// reason (see stateCause), and now we're waiting for a timeout before
	// connecting again. wsConn is nil, but connCtx and connCtxCancel are not,
	// and connLoop is running.
	StateWaitBeforeReconnect

	// StateConnecting means we're calling websocket.DefaultDialer.Dial() right
	// now.
	StateConnecting

	// StateAuthenticating occurs after connceting, while the stream server is authenticating
	StateAuthenticating

	// StateConnected means the websocket connection is established.
	StateConnected

	// StatesCnt is a number of states
	StatesCnt

	// StateAny can be used with AddStateListener() and AddStateListenerOpt()
	// in order to listen for all states.
	StateAny = -1
)

const (
	defaultURL = "wss://sb.cryptowat.ch"
)

var (
	StateNames = make([]string, StatesCnt)

	ErrUnknown        StreamError = errors.New("could not authenticate")
	ErrBadCredentials StreamError = errors.New("bad credentials")
	ErrNotConnected   StreamError = errors.New("not connected")
	ErrConnLoopActive StreamError = errors.New("connection loop is already active")
)

func init() {
	StateNames[StateDisconnected] = "disconnected"
	StateNames[StateWaitBeforeReconnect] = "wait_before_reconnect"
	StateNames[StateConnecting] = "connecting"
	StateNames[StateAuthenticating] = "authenticating"
	StateNames[StateConnected] = "connected"
}

type StreamError error

// StreamParams contains params for opening a client stream connection
// (see StreamConn)
type StreamParams struct {
	// Used for identification/authentication with Biller
	accessKeyId     string
	secretAccessKey string

	// Input by user
	Locale string

	// Server URL, e.g. wss://sb.cryptowat.ch
	URL string
	// Initial set of subscription keys
	Subscriptions []string

	// Called whenever an error occurs, so the client can handle it
	onError func(e error)

	// Whether the library should reconnect automatically
	Reconnect bool
	// Reconnection backoff: if true, then the reconnection time will be
	// initially ReconnectTimeout, then will become twice as long each
	// unsuccessful connection attempt; but it won't be longer than
	// MaxReconnectTimeout.
	Backoff bool
	// Initial reconnection timeout: if zero, then 1 second will be used
	ReconnectTimeout time.Duration
	// Max reconnect timeout. If zero, then 30 seconds will be used.
	MaxReconnectTimeout time.Duration
}

// StreamConn is a client stream connection; it's typically wrapped into more
// specific type of connection: e.g. MarketConn, which knows how to unmarshal
// the data being received.
type StreamConn struct {
	params StreamParams

	connTx        chan websocketTx
	callListeners chan callListenersReq

	stateListeners map[State][]stateListener

	// Current state
	state State
	// Error caused the current state; only relevant for StateDisconnected and
	// StateWaitBeforeReconnect, for other states it's always nil.
	stateCause error

	// connCtx and connCtxCancel are context and its cancel func for the
	// currently running connLoop. If no connLoop is running at the moment (i.e.
	// the state is StateDisconnected), these are nil.
	connCtx       context.Context
	connCtxCancel context.CancelFunc

	// wsConn is the currently active websocket connection, or nil if no
	// connection is established.
	wsConn *websocket.Conn

	// reconnectNow is a channel which is only non-nil in the
	// StateWaitBeforeReconnect state, and closing it causes the reconnection to
	// happen immediately
	reconnectNow chan struct{}

	mtx sync.Mutex
}

// stateListener wraps a state change callback and a flag of whether the
// callback is one-off (one-off listeners are only called once, on the next
// event)
type stateListener struct {
	cb  StateCallback
	opt StateListenerOpt
}

// websocketTx represents message to send to the websocket
type websocketTx struct {
	messageType int
	data        []byte
	res         chan error
}

type callListenersReq struct {
	listeners       []stateListener
	oldState, state State
	cause           error
}

// NewStreamConn creates a new stream connection. Typically not used directly
// by the clients; see more concrete connection types, e.g. NewMarketConn.
//
// Note that clients should manually call Connect on a newly created
// connection; the rationale is that clients might register some state and/or
// message handlers before the connection, to avoid any possible races.
func NewStreamConn(params *StreamParams) (*StreamConn, error) {
	c := &StreamConn{
		// Copy params defensively
		params: *params,

		state:          StateDisconnected,
		stateListeners: make(map[State][]stateListener),
		connTx:         make(chan websocketTx, 1),
		callListeners:  make(chan callListenersReq, 1),
	}

	if c.params.URL == "" {
		c.params.URL = defaultURL
	}

	// By default, set reconnection time to 1 second, and max reconnection
	// time to 30 seconds
	if c.params.ReconnectTimeout == 0 {
		c.params.ReconnectTimeout = 1 * time.Second
	}
	if c.params.MaxReconnectTimeout == 0 {
		c.params.MaxReconnectTimeout = 30 * time.Second
	}

	// When connected, will send client identification and authentication messages
	c.AddStateListener(StateConnected, sendClientID)
	c.AddStateListener(StateConnected, authenticateOnConnect)

	// Start writeLoop right away, before even connecting, so that an attempt to
	// write something while not connected will result in a proper error.
	go c.writeLoop()

	// Start goroutine which will call state listeners. See comment for
	// notifyLoop for the rationale of this design.
	go c.notifyLoop()

	return c, nil
}

// StateCallback is a signature of a state listener. Arguments conn, oldState
// and state are self-descriptive; cause is the error which caused the current
// state. Cause is relevant only for StateDisconnected and
// StateWaitBeforeReconnect (in which case it's either the reason of failure to
// connect, or reason of disconnection), for other states it's always nil.
//
// See AddStateListener.
type StateCallback func(conn *StreamConn, oldState, state State, cause error)

// AddStateListener registers a new listener for the given state. Listener is
// registered with the default options (zero values of all fields in
// StateListenerOpt). All registered callbacks for all states will be called by
// the same internal goroutine, i.e. they are never called concurrently with
// each other.
//
// The order of listeners invocation for the same state is unspecified, and
// clients shouldn't rely on it.
//
// To subscribe to all state changes, use StateAny.
func (c *StreamConn) AddStateListener(state State, cb StateCallback) {
	c.AddStateListenerOpt(state, cb, StateListenerOpt{})
}

type StateListenerOpt struct {
	// If OneOff is true, the listener will only be called once; otherwise it'll
	// be called every time the requested state becomes active.
	OneOff bool
	// If CallImmediately is true, and the state being subscribed to is active
	// at the moment, the callback will be called immediately (with the "old"
	// state being equal to the new one)
	CallImmediately bool
}

// AddStateListenerOpt is like AddStateListener, but also takes additional
// options; see StateListenerOpt for details.
func (c *StreamConn) AddStateListenerOpt(state State, cb StateCallback, opt StateListenerOpt) {
	sl := stateListener{
		cb:  cb,
		opt: opt,
	}

	c.mtx.Lock()
	defer c.mtx.Unlock()

	// Determine whether the callback should be called right now
	callNow := opt.CallImmediately && (state == c.state || state == StateAny)

	// Update stored listeners if needed
	if !opt.OneOff || !callNow {
		c.stateListeners[state] = append(c.stateListeners[state], sl)
	}

	if callNow {
		c.callListeners <- callListenersReq{
			listeners: []stateListener{sl},
			oldState:  c.state,
			state:     c.state,
			cause:     c.stateCause,
		}
	}
}

// Connect either starts a connection goroutine (if state is
// StateDisconnected), or makes it to stop waiting a timeout and connect right
// now (if state is StateWaitBeforeReconnect). For other states, returns an
// error.
//
// It doesn't wait for the connection to establish, and returns immediately.
func (c *StreamConn) Connect() error {

	c.mtx.Lock()
	defer c.mtx.Unlock()

	switch c.state {
	case StateDisconnected:
		// NOTE that we need to enter the state StateConnecting here and not in
		// connLoop, in order to prevent the race which would result in multiple
		// running connLoops.
		c.updateState(StateConnecting, nil)

		go c.connLoop(c.connCtx, c.connCtxCancel)

	case StateWaitBeforeReconnect:
		// We're waiting for a timeout before reconnecting; force it to reconnect
		// right now
		close(c.reconnectNow)

	case StateConnecting, StateConnected:
		// Already connected or connecting
		return errors.Trace(ErrConnLoopActive)
	}

	return nil
}

// Close stops reconnection loop (if reconnection was requested), and if
// websocket connection is active at the moment, closes it as well (with the
// code 1000, i.e. normal closure). If graceful websocket closure fails, the
// forceful one is performed.
func (c *StreamConn) Close() error {
	if err := c.closeInternal(websocket.FormatCloseMessage(websocket.CloseNormalClosure, ""), true); err != nil {
		return errors.Trace(err)
	}

	return nil
}

func (c *StreamConn) closeInternal(data []byte, stopReconnecting bool) error {
	c.mtx.Lock()
	wsConn := c.wsConn

	if c.state == StateDisconnected {
		c.mtx.Unlock()
		return errors.Trace(ErrNotConnected)
	}

	// If asked to stop reconnection, cancel the conn context, which will
	// cause connLoop to quit once the current websocket connection (if any)
	// is closed
	if stopReconnecting {
		c.connCtxCancel()
	}
	c.mtx.Unlock()

	// If websocket connection is active, close it, which will cause connLoop
	// break out of readLoop (and then either reconnect or quit, depending on the
	// stopReconnecting arg)
	if wsConn != nil {
		if err := wsConn.WriteControl(websocket.CloseMessage, data, time.Time{}); err != nil {
			// Graceful close failed, try to close forcefully
			return errors.Trace(wsConn.Close())
		}
	}

	c.updateState(StateDisconnected)

	return nil
}

// Subscribe subscribes to the given set of keys
func (c *StreamConn) Subscribe(keys []string) error {
	cm := &pbc.ClientMessage{
		Body: &pbc.ClientMessage_Subscribe{
			Subscribe: &pbc.ClientSubscribeMessage{
				SubscriptionKeys: keys,
			},
		},
	}

	if err := c.sendProto(cm); err != nil {
		return errors.Annotatef(err, "subscribe")
	}

	return nil
}

// Unsubscribe unsubscribes from the given set of keys
func (c *StreamConn) Unsubscribe(keys []string) error {
	cm := &pbc.ClientMessage{
		Body: &pbc.ClientMessage_Unsubscribe{
			Unsubscribe: &pbc.ClientUnsubscribeMessage{
				SubscriptionKeys: keys,
			},
		},
	}

	if err := c.sendProto(cm); err != nil {
		return errors.Annotatef(err, "unsubscribe")
	}

	return nil
}

// URL returns an url used for connection
func (c *StreamConn) URL() string {
	return c.params.URL
}

// GetState returns connection state
func (c *StreamConn) GetState() State {
	c.mtx.Lock()
	defer c.mtx.Unlock()
	return c.state
}

// onRead is called for every message received by the connection.
func (c *StreamConn) onRead(data []byte) {
	var msg pbs.StreamMessage
	if err := proto.Unmarshal(data, &msg); err != nil {
		// Close connection (and if reconnection was requested, then reconnect)
		c.closeInternal(
			websocket.FormatCloseMessage(websocket.CloseUnsupportedData, ""),
			false,
		)
	}
	switch msg.GetBody().(type) {
	case *pbs.StreamMessage_AuthenticationResult:
		authRes := msg.GetAuthenticationResult()
		c.authResponseHandler(authRes)

	case *pbs.StreamMessage_MarketUpdate:
		println("hello world 2")
	}
}

// send sends data to the websocket if it's connected
func (c *StreamConn) send(data []byte) error {
	// Note that we don't check here whether the socket is connected,
	// as it's checked by the writeLoop() which will receive our message
	// from c.connTx.

	res := make(chan error)

	// Request the websocket write
	c.connTx <- websocketTx{
		messageType: websocket.TextMessage,
		data:        data,
		res:         res,
	}

	// Wait for the resulting error
	if err := <-res; err != nil {
		return errors.Annotatef(err, "sending msg")
	}

	return nil
}

// sendProto marshals and sends a protobuf message to the websocket if it's
// connected, or queues the data otherwise.
func (c *StreamConn) sendProto(pb proto.Message) error {
	data, err := proto.Marshal(pb)
	if err != nil {
		return errors.Annotatef(err, "marshalling protobuf msg")
	}

	if err := c.send(data); err != nil {
		return errors.Trace(err)
	}

	return nil
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

// enterLeaveState should be called on leaving and entering each state. So,
// when changing state from A to B, it's called twice, like this:
//
//      enterLeaveState(A, false)
//      enterLeaveState(B, true)
func (c *StreamConn) enterLeaveState(state State, enter bool) {
	switch state {

	case StateDisconnected:
		// connCtx and its cancel func should be present in all states but
		// StateDisconnected
		if enter {
			c.connCtx = nil
			c.connCtxCancel = nil
		} else {
			c.connCtx, c.connCtxCancel = context.WithCancel(context.Background())
		}

	case StateWaitBeforeReconnect:
		// reconnectNow is present only in StateWaitBeforeReconnect
		if enter {
			c.reconnectNow = make(chan struct{})
		} else {
			c.reconnectNow = nil
		}

	case StateConnecting:
		// Nothing special to do for the StateConnecting state

	case StateConnected:
		// wsConn is present only in StateConnected
		if enter {
			// wsConn is set by the calling code
		} else {
			c.wsConn = nil
		}
	}
}

func (c *StreamConn) updateState(state State, cause error) {
	// NOTE: c.mtx should be locked when updateState is called

	if c.state == state {
		// No need to do anything
		return
	}

	// Properly leave the current state
	c.enterLeaveState(c.state, false)

	oldState := c.state
	c.state = state
	c.stateCause = cause

	// Properly enter the new state
	c.enterLeaveState(c.state, true)

	// Collect all listeners to call now
	// We'll call them a bit later, when the mutex is not locked
	listeners := append(c.stateListeners[state], c.stateListeners[StateAny]...)

	// Remove one-off listeners
	c.stateListeners[state] = removeOneOff(c.stateListeners[state])
	c.stateListeners[StateAny] = removeOneOff(c.stateListeners[StateAny])

	// Request listeners invocation (will be invoked by a dedicated goroutine)
	c.callListeners <- callListenersReq{
		listeners: listeners,
		oldState:  oldState,
		state:     state,
		cause:     cause,
	}
}

// connLoop establishes a connection, then keeps receiving all websocket
// messages (and calls onRead for each of them) until the connection is
// closed, then either waits for a timeout and connects again, or just quits.
func (c *StreamConn) connLoop(connCtx context.Context, connCtxCancel context.CancelFunc) {
	var connErr error

	nextReconnectTimeout := c.params.ReconnectTimeout

	defer func() {
		c.mtx.Lock()
		defer c.mtx.Unlock()
		c.updateState(StateDisconnected, connErr)
	}()

cloop:
	for {
		// When the goroutine is just started by Connect(), the state is already
		// StateConnecting (see Connect() for the explanation on why), in which
		// case the updateState below is a no-op. When reconnecting though, the
		// state is different here, so it'll be changed to StateConnecting.
		c.mtx.Lock()
		c.updateState(StateConnecting, nil)
		c.mtx.Unlock()

		var wsConn *websocket.Conn
		wsConn, _, connErr = websocket.DefaultDialer.Dial(c.params.URL, nil)
		if connErr == nil {
			// Connected successfully
			nextReconnectTimeout = c.params.ReconnectTimeout

			c.mtx.Lock()
			c.wsConn = wsConn
			c.updateState(StateConnected, nil)
			c.mtx.Unlock()

			// Will loop here until the websocket connection is closed
		recvLoop:
			for {
				msgType, data, err := wsConn.ReadMessage()
				if err != nil {
					connErr = err
					break recvLoop
				}

				switch msgType {
				case websocket.TextMessage, websocket.BinaryMessage:
					if len(data) == 1 && data[0] == 0x01 {
						// Heartbeat, ignore
						continue recvLoop
					}

					// Call on-read callback, if any
					c.onRead(data)

				case websocket.CloseMessage:
					// TODO: set connErr to something? So that the state listeners will
					// see that the reason of disconnection is that we've got a close
					// message.
					break recvLoop
				}
			}
		}

		// If shouldn't reconnect, we're done
		if !c.params.Reconnect {
			connCtxCancel()
		}

		// Check if we need to enter state StateWaitBeforeReconnect
		select {
		case <-connCtx.Done():
		default:
			// Looks like we should reconnect (after a timeout), so set the
			// appropriate state
			c.mtx.Lock()
			c.updateState(StateWaitBeforeReconnect, connErr)
			c.mtx.Unlock()
		}

		// Either wait for the timeout before reconnection, or quit.
	waitReconnect:
		select {
		case <-connCtx.Done():
			// Enough reconnections, quit now.
			break cloop

		case <-time.After(nextReconnectTimeout):
			// Will try to reconnect one more time
			break waitReconnect

		case <-c.reconnectNow:
			// Will try to reconnect one more time
			break waitReconnect
		}

		if c.params.Backoff {
			nextReconnectTimeout *= 2
			if nextReconnectTimeout > c.params.MaxReconnectTimeout {
				nextReconnectTimeout = c.params.MaxReconnectTimeout
			}
		}
	}
}

// writeLoop receives messages from c.connTx, and tries to send them
// to the active websocket connection, if any.
func (c *StreamConn) writeLoop() {
cloop:
	for {
		msg := <-c.connTx

		// Get currently active websocket connection
		c.mtx.Lock()
		wsConn := c.wsConn
		c.mtx.Unlock()

		if wsConn == nil {
			msg.res <- errors.Trace(ErrNotConnected)
			continue cloop
		}

		// Try to write the message
		err := errors.Trace(wsConn.WriteMessage(msg.messageType, msg.data))

		// Send resulting error to the requester
		msg.res <- err
	}
}

// notifyLoop calls state listeners. The rationale to have a separate goroutine
// for that is that the listeners should be called with c.mtx unlocked, and we
// don't want to unlock it in the middle of c.updateState()
func (c *StreamConn) notifyLoop() {
	for {
		req := <-c.callListeners

		for _, sl := range req.listeners {
			sl.cb(c, req.oldState, req.state, req.cause)
		}
	}
}

// sendClientID sends ClientIdentificationMessage, it's called on
// entering StateConnected state.
func sendClientID(c *StreamConn, oldState, new State, cause error) {
	cm := &pbc.ClientMessage{
		Body: &pbc.ClientMessage_Identification{
			Identification: &pbc.ClientIdentificationMessage{
				Useragent: fmt.Sprintf("Cryptowatch Stream Client Golang/%s", version),

				// TODO: probably pass revision via params so that it depends on a
				// client application rather than a library, or just leave it always
				// empty as it is now.
				//
				// It's not trivial to have a revision of the library repo, because it
				// should be go-gettable and importable by other code, and for that,
				// we'd need to include the revision constant into the repo. Obviously,
				// even if we do autogenerate some file with the revision on every
				// commit, it would actually represent previous commit, not the current
				// one, and this would be just weird.
				Revision:    "",
				Integration: "", // Irrelevant

				Locale:        c.params.Locale,
				Subscriptions: c.params.Subscriptions,
			},
		},
	}

	if err := c.sendProto(cm); err != nil {
		// Not much we can do about the error here; and we shouldn't set state to
		// Disconnected because it should be already done by the reader goroutine
	}
}

package orderbooks

import (
	"fmt"
	"math/rand"
	"time"

	"github.com/juju/errors"

	"code.cryptowat.ch/clock"
	"code.cryptowat.ch/cw-sdk-go/common"
)

const maxDeltasCacheSize = 50

type getSnapshotResult struct {
	snapshot common.OrderBookSnapshot
	err      error
}

// OrderBookUpdater maintains the up-to-date orderbook by applying live updates
// (which are typically fed to it from the StreamClient updates)
type OrderBookUpdater struct {
	params OrderBookUpdaterParams

	deltasChan            chan common.OrderBookDelta
	snapshotsChan         chan common.OrderBookSnapshot
	getSnapshotResultChan chan getSnapshotResult
	stopChan              chan struct{}
	addUpdateCB           chan OnUpdateCB

	curOrderBook *OrderBook

	updateCBs []OnUpdateCB

	cachedDeltas map[common.SeqNum]common.OrderBookDelta

	minDeltaNum *common.SeqNum
	maxDeltaNum *common.SeqNum

	// fetchSnapshotTimer is a timer which fires when we need to request a new
	// snapshot from the REST API.
	fetchSnapshotTimer *clock.Timer
	// fetchSnapshotAttempt represents how many times in a row we tried to fetch
	// a new snapshot from the REST API.
	fetchSnapshotAttempt int

	// isInSync reflects whether the order book is synchronized with the server.
	// Needed only for sending StateUpdate.
	isInSync bool

	// If firstSyncing is true, it means we'll be syncing the first time after
	// the app start; this is needed to use a smaller randomized delay before
	// fetching a snapshot.
	firstSyncing bool
}

// OrderBookUpdaterParams contains params for creating a new orderbook updater.
type OrderBookUpdaterParams struct {
	// SnapshotGetter is optional; it returns an up-to-date snapshot, typically
	// from REST API. See NewOrderBookSnapshotGetterRESTBySymbol.
	//
	// If SnapshotGetter is not set, then OrderBookUpdater will just wait for
	// the snapshot from the websocket (snapshot is delivered there every minute)
	SnapshotGetter OrderBookSnapshotGetter

	// Below are mockables; should only be set for tests. By default, prod values
	// will be used.

	clock clock.Clock

	// getSnapshotDelay returns the delay before fetching a snapshot from REST
	// API.
	getSnapshotDelay func(firstSyncing bool, fetchSnapshotAttempt int) time.Duration

	// gettingSnapshot is called right before running a goroutine with
	// GetOrderBookSnapshot. It's a no-op for prod.
	gettingSnapshot func()

	// internalEvent is called right after processing an event in eventLoop.
	// It's a no-op for prod.
	internalEvent func(ie internalEvent)
}

// NewOrderBookUpdater creates a new orderbook updater with the provided
// params.
func NewOrderBookUpdater(params *OrderBookUpdaterParams) *OrderBookUpdater {
	obu := &OrderBookUpdater{
		params: *params,

		deltasChan:            make(chan common.OrderBookDelta, 1),
		snapshotsChan:         make(chan common.OrderBookSnapshot, 1),
		getSnapshotResultChan: make(chan getSnapshotResult, 1),
		stopChan:              make(chan struct{}),
		addUpdateCB:           make(chan OnUpdateCB, 1),

		cachedDeltas: map[common.SeqNum]common.OrderBookDelta{},
		firstSyncing: true,
	}

	// Set prod values for mockables by default.

	if obu.params.clock == nil {
		obu.params.clock = clock.New()
	}

	if obu.params.getSnapshotDelay == nil {
		obu.params.getSnapshotDelay = getSnapshotDelayDefault
	}

	if obu.params.gettingSnapshot == nil {
		obu.params.gettingSnapshot = func() {}
	}

	if obu.params.internalEvent == nil {
		obu.params.internalEvent = func(ie internalEvent) {}
	}

	obu.getSnapshotFromAPIAfterTimeout()

	go obu.eventLoop()

	return obu
}

// ReceiveDelta should be called when a new orderbook delta is received from
// the websocket. If the delta applies cleanly to the internal orderbook,
// the OnUpdate callbacks will be called shortly.
func (obu *OrderBookUpdater) ReceiveDelta(delta common.OrderBookDelta) {
	obu.deltasChan <- delta
}

// ReceiveSnapshot should be called when a new orderbook snapshot is received
// from the websocket. The OnUpdate callbacks will be called shortly.
func (obu *OrderBookUpdater) ReceiveSnapshot(snapshot common.OrderBookSnapshot) {
	obu.snapshotsChan <- snapshot
}

type OnUpdateCB func(snapshot Update)

type Update struct {
	OrderBookUpdate  *common.OrderBookSnapshot
	StateUpdate      *StateUpdate
	GetSnapshotError error
}

// OnUpdate registers a new callback which will be called when an
// update is available: either state update or orderbook update. The callback
// will be called from the same internal eventloop, so they are never called
// concurrently with each other, and the callback shouldn't block.
func (obu *OrderBookUpdater) OnUpdate(cb OnUpdateCB) {
	obu.addUpdateCB <- cb
}

// StateUpdate is delivered to handlers (registered with OnUpdate) when
// the client becomes in sync or goes out of sync; see IsInSync field.
type StateUpdate struct {
	// IsInSync is true when the cached deltas cover the current snapshot.
	IsInSync bool

	// SeqNum is the sequence number of the current snapshot.
	SeqNum *common.SeqNum
	// MinDeltaNum is the min sequence number of the cached deltas.
	MinDeltaNum *common.SeqNum
	// MaxDeltaNum is the max sequence number of the cached deltas.
	MaxDeltaNum *common.SeqNum
}

func (su *StateUpdate) String() string {
	if su.IsInSync {
		return "Synchronized"
	}

	seqNum := "-"
	deltas := "-"

	if su.SeqNum != nil {
		seqNum = fmt.Sprintf("%d", *su.SeqNum)
	}

	if su.MinDeltaNum != nil && su.MaxDeltaNum != nil {
		deltas = fmt.Sprintf("%d - %d", *su.MinDeltaNum, *su.MaxDeltaNum)
	}

	return fmt.Sprintf("Out of sync: seqNum: %s, deltas: %s", seqNum, deltas)
}

// Close stops event loop; after that instance of OrderBookUpdater can't be
// used anymore.
func (obu *OrderBookUpdater) Close() error {
	close(obu.stopChan)
	return nil
}

// receiveDeltaInternal should only be called from the eventLoop.
func (obu *OrderBookUpdater) receiveDeltaInternal(delta common.OrderBookDelta) {
	if obu.minDeltaNum != nil && obu.maxDeltaNum != nil && delta.SeqNum == *obu.maxDeltaNum+1 {
		// Received normal delta in order, so store it into cachedDeltas map and
		// maybe delete the oldest delta.

		obu.cachedDeltas[delta.SeqNum] = delta
		*obu.maxDeltaNum += 1

		for (*obu.maxDeltaNum)-(*obu.minDeltaNum)+1 > maxDeltasCacheSize {
			delete(obu.cachedDeltas, *obu.minDeltaNum)
			*obu.minDeltaNum += 1
		}
	} else {
		// Received out-of-order delta, screw all existing deltas

		obu.minDeltaNum = new(common.SeqNum)
		obu.maxDeltaNum = new(common.SeqNum)

		*obu.minDeltaNum = delta.SeqNum
		*obu.maxDeltaNum = delta.SeqNum

		obu.cachedDeltas = map[common.SeqNum]common.OrderBookDelta{
			delta.SeqNum: delta,
		}
	}

	// Try to apply existing deltas, and if the current snapshot is outdated,
	// request a new one.
	obu.applyCachedDeltas()
	if !obu.isInSync {
		obu.getSnapshotFromAPIAfterTimeout()
		return
	}

	// The delta was applied cleanly, so, call the on-update callbacks
	snapshot := obu.curOrderBook.GetSnapshot()
	obu.callUpdateCBs(
		Update{
			OrderBookUpdate: &snapshot,
		},
	)
}

// receiveSnapshotInternal should only be called from the eventLoop.
func (obu *OrderBookUpdater) receiveSnapshotInternal(snapshot common.OrderBookSnapshot) {
	if obu.curOrderBook == nil {
		obu.curOrderBook = NewOrderBook(snapshot)
	} else {
		obu.curOrderBook.ApplySnapshot(snapshot)
	}

	obu.applyCachedDeltas()
	// Note that we shouldn't request a new snapshot if isInSync is false; it could
	// easily happen on some non-popular market where we don't receive any deltas
	// for a long time, so minDeltaNum is nil.

	// Now that we have updated orderbook, call the on-update callbacks
	snapshot = obu.curOrderBook.GetSnapshot()
	obu.callUpdateCBs(
		Update{
			OrderBookUpdate: &snapshot,
		},
	)
}

// applyCachedDeltas should only be called from the eventLoop.
//
// It tries to apply currently cached deltas to the orderbook; sets obu.isInSync
// if in the end the orderbook is synchronized with the server (doesn't matter
// if we actually applied anything to make that happen, or it was already the
// case).
func (obu *OrderBookUpdater) applyCachedDeltas() {
	// To be able to apply deltas we need both orderbook and cached deltas.
	// Unless we have all of that, cut short.
	if obu.curOrderBook == nil || obu.minDeltaNum == nil || obu.maxDeltaNum == nil {
		obu.isInSync = false
		return
	}

	var dcr deltasCheckResult

	for {
		dcr = checkDeltas(obu.curOrderBook.GetSeqNum(), *obu.minDeltaNum, *obu.maxDeltaNum)

		if dcr.nextDeltaApply == nil {
			// We don't have any relevant deltas to apply
			break
		}

		if err := obu.curOrderBook.ApplyDelta(obu.cachedDeltas[*dcr.nextDeltaApply]); err != nil {
			// Should never be here, because we check seq nums here before
			// calling ApplyDelta.

			// TODO: handle the error
			panic("ApplyDelta error: " + err.Error())
		}
	}

	wasInSync := obu.isInSync
	obu.isInSync = dcr.isInSync

	if obu.isInSync != wasInSync {
		obu.callUpdateCBs(
			Update{
				StateUpdate: obu.getStateUpdate(),
			},
		)
	}

	if obu.isInSync {
		obu.firstSyncing = false

		if obu.fetchSnapshotTimer != nil {
			// Fetching a snapshot from API was scheduled after a timeout, but
			// we've got a snapshot before that (from the stream), so cancel
			// reaching the API.

			obu.fetchSnapshotTimer.Stop()
			obu.resetSnapshotTimer()
		}
	}
}

// getSnapshotFromAPIAfterTimeout should only be called from the eventLoop.
func (obu *OrderBookUpdater) getSnapshotFromAPIAfterTimeout() {
	if obu.params.SnapshotGetter == nil {
		// SnapshotGetter wasn't provided, so just don't do anything here (and
		// we'll get in sync when we receive the snapshot from the websocket, it
		// happens every minute)
		return
	}

	if obu.fetchSnapshotTimer != nil {
		// Snapshot fetching is already scheduled, so nothing to do here
		return
	}

	delay := obu.params.getSnapshotDelay(obu.firstSyncing, obu.fetchSnapshotAttempt)

	obu.fetchSnapshotTimer = obu.params.clock.AfterFunc(delay, func() {
		// For testability, we shouldn't block in that callback, because it's
		// called synchronously by the time-mocking package (clocl). So, here we
		// just announce that we're going to get a snapshot, and then start another
		// goroutine which actually calls GetOrderBookSnapshot() etc.

		obu.params.gettingSnapshot()

		go func() {
			snapshot, err := obu.params.SnapshotGetter.GetOrderBookSnapshot()
			obu.getSnapshotResultChan <- getSnapshotResult{
				snapshot: snapshot,
				err:      err,
			}
		}()
	})
}

// resetSnapshotTimer should only be called from the eventLoop.
func (obu *OrderBookUpdater) resetSnapshotTimer() {
	obu.fetchSnapshotTimer = nil
	obu.fetchSnapshotAttempt = 0
}

// callUpdateCBs should only be called from the eventLoop.
func (obu *OrderBookUpdater) callUpdateCBs(update Update) {
	for _, cb := range obu.updateCBs {
		cb(update)
	}
}

// getStateUpdate should only be called from the eventLoop.
func (obu *OrderBookUpdater) getStateUpdate() *StateUpdate {
	ret := &StateUpdate{
		IsInSync:    obu.isInSync,
		MinDeltaNum: obu.minDeltaNum,
		MaxDeltaNum: obu.maxDeltaNum,
	}

	if obu.curOrderBook != nil {
		sn := obu.curOrderBook.GetSeqNum()
		ret.SeqNum = &sn
	}

	return ret
}

type internalEvent int

const (
	internalEventDeltaHandled internalEvent = iota
	internalEventSnapshotHandled
	internalEventGetSnapshotResultHandled
)

func (obu *OrderBookUpdater) eventLoop() {
	for {
		select {
		case delta := <-obu.deltasChan:
			obu.receiveDeltaInternal(delta)
			obu.params.internalEvent(internalEventDeltaHandled)

		case shapshot := <-obu.snapshotsChan:
			obu.receiveSnapshotInternal(shapshot)
			obu.params.internalEvent(internalEventSnapshotHandled)

		case res := <-obu.getSnapshotResultChan:
			if res.err != nil {
				// Got an error while receiving a snapshot, so just reset the timer so
				// that it'll be scheduled again on the next diff.
				obu.fetchSnapshotTimer = nil
				obu.fetchSnapshotAttempt += 1

				// Let the client code know about that error
				obu.callUpdateCBs(
					Update{
						GetSnapshotError: errors.Trace(res.err),
					},
				)

				obu.getSnapshotFromAPIAfterTimeout()

				obu.params.internalEvent(internalEventGetSnapshotResultHandled)
				break
			}

			// Reset attempts counter and timer
			obu.resetSnapshotTimer()

			// Update the orderbook state
			obu.receiveSnapshotInternal(res.snapshot)

			obu.params.internalEvent(internalEventGetSnapshotResultHandled)

		case cb := <-obu.addUpdateCB:
			obu.updateCBs = append(obu.updateCBs, cb)

		case <-obu.stopChan:
			return
		}
	}
}

type deltasCheckResult struct {
	// nextDeltaApply indicates the next delta number which should be applied to
	// the current snapshot (which has the number curSeqNum).
	//
	// If nextDeltaApply is nil, it means there are no suitable deltas to apply.
	nextDeltaApply *common.SeqNum

	// isInSync indicates whether the snapshot number (curSeqNum) is in sync with
	// the deltas we have.
	isInSync bool
}

func checkDeltas(curSeqNum, minDeltaNum, maxDeltaNum common.SeqNum) deltasCheckResult {
	// Check if we have some deltas to apply. NOTE that this check should
	// account for the uint32 overflows, so we can't just do something like
	// "if curSeqNum < *obu.maxDeltaNum" etc.
	//
	// So numCachedDeltas is the total number of cached deltas we have, and
	// numCachedDeltasOld is the number of deltas which are not newer than the
	// curSeqNum. And then, there are 3 cases:
	//
	// - numCachedDeltasOld < numCachedDeltas : we're in sync (cached deltas
	//   cover curSeqNum), and we have some new deltas to apply
	// - numCachedDeltasOld == numCachedDeltas : we're in sync (cached deltas
	//   cover curSeqNum), and we don't have any new deltas
	// - numCachedDeltasOld > numCachedDeltas : we're out of sync (cached deltas
	//   don't cover curSeqNum)
	numCachedDeltas := int(maxDeltaNum - minDeltaNum + 1)
	numCachedDeltasOld := int(curSeqNum - (minDeltaNum - 1))

	ret := deltasCheckResult{
		isInSync: numCachedDeltasOld <= numCachedDeltas,
	}

	if numCachedDeltasOld < numCachedDeltas {
		// We have some new deltas to apply, so specify which one should be the
		// first.
		ret.nextDeltaApply = new(common.SeqNum)
		*ret.nextDeltaApply = curSeqNum + 1
	}

	return ret
}

// getSnapshotDelayDefault calculates a delay before fetching a snapshot:
// randomized in 10 seconds, plus 5 seconds more after each subsequent attempt,
// but not more than 40 seconds overall
func getSnapshotDelayDefault(firstSyncing bool, fetchSnapshotAttempt int) time.Duration {
	delay := time.Duration(fetchSnapshotAttempt) * 5 * time.Second
	if delay > 30*time.Second {
		delay = 30 * time.Second
	}

	// Add random delay: around a second when syncing first time after the page
	// loads, and up to 10 seconds afterwards.
	//
	// The initial small delay is needed because on popular markets fetching
	// the snapshot immediately is usually not helpful since it arrives too
	// late (after a few missed deltas). So we wait for at least one second
	// before fetching a snapshot, and thus we have some time to cache a few
	// deltas.
	if firstSyncing {
		delay += 800*time.Millisecond + time.Duration(rand.Int31n(500))*time.Millisecond
	} else {
		delay += time.Duration(rand.Int31n(10)) * time.Second
	}

	return delay
}

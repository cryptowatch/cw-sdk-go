package orderbooks

import (
	"testing"
	"time"

	"github.com/juju/errors"
	"github.com/stretchr/testify/assert"

	"code.cryptowat.ch/clock"
	"code.cryptowat.ch/cw-sdk-go/common"
)

func TestUpdater(t *testing.T) {
	if err := testUpdaterRegular(t); err != nil {
		t.Fatal(errors.ErrorStack(err))
	}

	if err := testUpdaterNoSnapshotGetter(t); err != nil {
		t.Fatal(errors.ErrorStack(err))
	}
}

// testUpdaterRegular tests regular workflow:
// - outdated initial snapshot from REST
// - a few deltas after that snapshot
// - new snapshot from REST, slightly behind the deltas, so the relevant
//   deltas get applied and we get in sync
// - a few in-band deltas
// - out-of-band delta, so we get out of sync
// - requesting snapshot from REST, getting error
// - requesting snapshot from REST again, getting one, replaying deltas again
//   and getting in sync
func testUpdaterRegular(t *testing.T) (err error) {
	mocks := newUpdaterMocks()

	defer func() {
		if err != nil {
			err = errors.Annotatef(err, mocks.clock.Now().String())
		}
	}()

	updater := NewOrderBookUpdater(&OrderBookUpdaterParams{
		SnapshotGetter:   mocks.sgetter,
		clock:            mocks.clock,
		getSnapshotDelay: getSnapshotDelayMock,
		gettingSnapshot:  mocks.gettingSnapshot,
		internalEvent:    mocks.internalEvent,
	})

	updater.OnUpdate(func(update Update) {
		if ob := update.OrderBookUpdate; ob != nil {
			mocks.eventsChan <- updaterMockEvent{
				typ:             updaterMockEventTypeOBUpdate,
				orderBookUpdate: ob,
			}
		} else if state := update.StateUpdate; state != nil {
			mocks.eventsChan <- updaterMockEvent{
				typ:         updaterMockEventTypeStateUpdate,
				stateUpdate: state,
			}
		} else if err := update.GetSnapshotError; err != nil {
			mocks.eventsChan <- updaterMockEvent{
				typ:              updaterMockEventTypeGetSnapshotError,
				getSnapshotError: err,
			}
		}
	})

	if err := mocks.expectNoEvents(); err != nil {
		return errors.Trace(err)
	}

	mocks.clock.Add(1000 * time.Millisecond)

	if err := mocks.expectEvent(updaterMockEventTypeGettingSnapshot, nil); err != nil {
		return errors.Trace(err)
	}

	// Receive delta: we don't have a snapshot yet, so expect no updates
	if err := mocks.receiveDelta(updater, common.OrderBookDelta{
		SeqNum: 100,
		Bids: common.OrderDeltas{
			Set: []common.PublicOrder{
				common.PublicOrder{Price: "50", Amount: "1"},
			},
		},
	}); err != nil {
		return errors.Trace(err)
	}

	if err := mocks.expectNoEvents(); err != nil {
		return errors.Trace(err)
	}

	// Receive OLD snapshot from REST; should get an update with it, but no sync.
	mocks.sgetter.snapshotChan <- snapshotWithErr{
		snapshot: common.OrderBookSnapshot{
			SeqNum: 90,
			Bids: []common.PublicOrder{
				common.PublicOrder{Price: "1000", Amount: "1"},
			},
		},
	}

	if err := mocks.expectOrderBookUpdate(common.OrderBookSnapshot{
		SeqNum: 90,
		Bids: []common.PublicOrder{
			common.PublicOrder{Price: "1000", Amount: "1"},
		},
	}); err != nil {
		return errors.Trace(err)
	}

	if err := mocks.expectInternalEvent(internalEventGetSnapshotResultHandled); err != nil {
		return errors.Trace(err)
	}

	// Receive a few deltas: we don't have an up-to-date snapshot yet, so expect no updates
	if err := mocks.receiveDelta(updater, common.OrderBookDelta{
		SeqNum: 101,
		Asks: common.OrderDeltas{
			Set: []common.PublicOrder{
				common.PublicOrder{Price: "100", Amount: "1"},
			},
		},
	}); err != nil {
		return errors.Trace(err)
	}

	if err := mocks.receiveDelta(updater, common.OrderBookDelta{
		SeqNum: 102,
		Asks: common.OrderDeltas{
			Set: []common.PublicOrder{
				common.PublicOrder{Price: "200", Amount: "1"},
			},
		},
	}); err != nil {
		return errors.Trace(err)
	}

	if err := mocks.receiveDelta(updater, common.OrderBookDelta{
		SeqNum: 103,
		Asks: common.OrderDeltas{
			Set: []common.PublicOrder{
				common.PublicOrder{Price: "300", Amount: "1"},
			},
		},
	}); err != nil {
		return errors.Trace(err)
	}

	mocks.clock.Add(1000 * time.Millisecond)

	if err := mocks.expectEvent(updaterMockEventTypeGettingSnapshot, nil); err != nil {
		return errors.Trace(err)
	}

	// Receive 101 snapshot from REST; should get in sync and update with the
	// latest delta applied (103)
	mocks.sgetter.snapshotChan <- snapshotWithErr{
		snapshot: common.OrderBookSnapshot{
			SeqNum: 101,
			Asks: []common.PublicOrder{
				common.PublicOrder{Price: "1000", Amount: "1"},
			},
		},
	}

	// Getting in sync
	if err := mocks.expectStateUpdate(true); err != nil {
		return errors.Trace(err)
	}

	if err := mocks.expectOrderBookUpdate(common.OrderBookSnapshot{
		// Latest delta seq num
		SeqNum: 103,
		// Those asks (and empty bids) mean that there should be a snapshot 101
		// with only deltas 102 and 103 applied.
		//
		// More thorough testing of the logic for applying deltas is in
		// orderbook_test.go
		Asks: []common.PublicOrder{
			common.PublicOrder{Price: "200", Amount: "1"},
			common.PublicOrder{Price: "300", Amount: "1"},
			common.PublicOrder{Price: "1000", Amount: "1"},
		},
	}); err != nil {
		return errors.Trace(err)
	}

	if err := mocks.expectInternalEvent(internalEventGetSnapshotResultHandled); err != nil {
		return errors.Trace(err)
	}

	if err := mocks.expectNoEvents(); err != nil {
		return errors.Trace(err)
	}

	// Delta 104 (still in sync) {{{
	updater.ReceiveDelta(common.OrderBookDelta{
		SeqNum: 104,
		Asks: common.OrderDeltas{
			Set: []common.PublicOrder{
				common.PublicOrder{Price: "300", Amount: "2"},
			},
		},
	})

	if err := mocks.expectOrderBookUpdate(common.OrderBookSnapshot{
		SeqNum: 104,
		Asks: []common.PublicOrder{
			common.PublicOrder{Price: "200", Amount: "1"},
			common.PublicOrder{Price: "300", Amount: "2"},
			common.PublicOrder{Price: "1000", Amount: "1"},
		},
	}); err != nil {
		return errors.Trace(err)
	}

	if err := mocks.expectInternalEvent(internalEventDeltaHandled); err != nil {
		return errors.Trace(err)
	}
	// }}}

	// Delta 105 (still in sync) {{{
	updater.ReceiveDelta(common.OrderBookDelta{
		SeqNum: 105,
		Asks: common.OrderDeltas{
			Remove: []string{"300"},
		},
	})

	if err := mocks.expectOrderBookUpdate(common.OrderBookSnapshot{
		SeqNum: 105,
		Asks: []common.PublicOrder{
			common.PublicOrder{Price: "200", Amount: "1"},
			common.PublicOrder{Price: "1000", Amount: "1"},
		},
	}); err != nil {
		return errors.Trace(err)
	}

	if err := mocks.expectInternalEvent(internalEventDeltaHandled); err != nil {
		return errors.Trace(err)
	}
	// }}}

	// Snapshot 105 (still in sync) {{{
	updater.ReceiveSnapshot(common.OrderBookSnapshot{
		SeqNum: 105,
		Asks: []common.PublicOrder{
			common.PublicOrder{Price: "200", Amount: "1"},
			common.PublicOrder{Price: "1000", Amount: "1"},
		},
	})

	if err := mocks.expectOrderBookUpdate(common.OrderBookSnapshot{
		SeqNum: 105,
		Asks: []common.PublicOrder{
			common.PublicOrder{Price: "200", Amount: "1"},
			common.PublicOrder{Price: "1000", Amount: "1"},
		},
	}); err != nil {
		return errors.Trace(err)
	}

	if err := mocks.expectInternalEvent(internalEventSnapshotHandled); err != nil {
		return errors.Trace(err)
	}
	// }}}

	// Delta 107 (going out of sync) {{{
	updater.ReceiveDelta(common.OrderBookDelta{
		SeqNum: 107,
		Asks: common.OrderDeltas{
			Set: []common.PublicOrder{
				common.PublicOrder{Price: "20", Amount: "1"},
			},
		},
	})

	if err := mocks.expectStateUpdate(false); err != nil {
		return errors.Trace(err)
	}

	if err := mocks.expectInternalEvent(internalEventDeltaHandled); err != nil {
		return errors.Trace(err)
	}
	// }}}

	// Delta 108 {{{
	updater.ReceiveDelta(common.OrderBookDelta{
		SeqNum: 108,
		Asks: common.OrderDeltas{
			Set: []common.PublicOrder{
				common.PublicOrder{Price: "30", Amount: "1"},
			},
		},
	})

	if err := mocks.expectInternalEvent(internalEventDeltaHandled); err != nil {
		return errors.Trace(err)
	}
	// }}}

	// Advance time by 1 second, thus getting a snapshot from REST
	mocks.clock.Add(1000 * time.Millisecond)

	if err := mocks.expectEvent(updaterMockEventTypeGettingSnapshot, nil); err != nil {
		return errors.Trace(err)
	}

	// Error receiving snapshot from REST
	mocks.sgetter.snapshotChan <- snapshotWithErr{
		err: errors.Errorf("test err"),
	}

	// Get error update
	if err := mocks.expectGetSnapshotError(); err != nil {
		return errors.Trace(err)
	}

	if err := mocks.expectInternalEvent(internalEventGetSnapshotResultHandled); err != nil {
		return errors.Trace(err)
	}

	// No events after 1 second
	mocks.clock.Add(1000 * time.Millisecond)

	if err := mocks.expectNoEvents(); err != nil {
		return errors.Trace(err)
	}

	// Advance time by 1 more second, now we should be getting snapshot from REST
	// again
	mocks.clock.Add(1000 * time.Millisecond)

	if err := mocks.expectEvent(updaterMockEventTypeGettingSnapshot, nil); err != nil {
		return errors.Trace(err)
	}

	// Receive snapshot from REST: 107
	mocks.sgetter.snapshotChan <- snapshotWithErr{
		snapshot: common.OrderBookSnapshot{
			SeqNum: 107,
			Asks: []common.PublicOrder{
				common.PublicOrder{Price: "2000", Amount: "1"},
			},
		},
	}

	// Getting in sync
	if err := mocks.expectStateUpdate(true); err != nil {
		return errors.Trace(err)
	}

	if err := mocks.expectOrderBookUpdate(common.OrderBookSnapshot{
		// Latest delta seq num
		SeqNum: 108,
		// Those asks (and empty bids) mean that there should be a snapshot 101
		// with only deltas 102 and 103 applied.
		//
		// More thorough testing of the logic for applying deltas is in
		// orderbook_test.go
		Asks: []common.PublicOrder{
			common.PublicOrder{Price: "30", Amount: "1"},
			common.PublicOrder{Price: "2000", Amount: "1"},
		},
	}); err != nil {
		return errors.Trace(err)
	}

	if err := mocks.expectInternalEvent(internalEventGetSnapshotResultHandled); err != nil {
		return errors.Trace(err)
	}

	mocks.clock.Add(60 * time.Second)

	if err := mocks.expectNoEvents(); err != nil {
		return errors.Trace(err)
	}

	return nil
}

func testUpdaterNoSnapshotGetter(t *testing.T) (err error) {
	mocks := newUpdaterMocks()

	defer func() {
		if err != nil {
			err = errors.Annotatef(err, mocks.clock.Now().String())
		}
	}()

	updater := NewOrderBookUpdater(&OrderBookUpdaterParams{
		// WE DO NOT SET SnapshotGetter

		clock:            mocks.clock,
		getSnapshotDelay: getSnapshotDelayMock,
		gettingSnapshot:  mocks.gettingSnapshot,
		internalEvent:    mocks.internalEvent,
	})

	updater.OnUpdate(func(update Update) {
		if ob := update.OrderBookUpdate; ob != nil {
			mocks.eventsChan <- updaterMockEvent{
				typ:             updaterMockEventTypeOBUpdate,
				orderBookUpdate: ob,
			}
		} else if state := update.StateUpdate; state != nil {
			mocks.eventsChan <- updaterMockEvent{
				typ:         updaterMockEventTypeStateUpdate,
				stateUpdate: state,
			}
		} else if err := update.GetSnapshotError; err != nil {
			mocks.eventsChan <- updaterMockEvent{
				typ:              updaterMockEventTypeGetSnapshotError,
				getSnapshotError: err,
			}
		}
	})

	if err := mocks.expectNoEvents(); err != nil {
		return errors.Trace(err)
	}

	mocks.clock.Add(1000 * time.Millisecond)

	// Don't expect updaterMockEventTypeGettingSnapshot because SnapshotGetter is nil

	if err := mocks.expectNoEvents(); err != nil {
		return errors.Trace(err)
	}

	// And even after a minute, no events
	mocks.clock.Add(60 * time.Second)
	if err := mocks.expectNoEvents(); err != nil {
		return errors.Trace(err)
	}

	// Receive delta: we don't have a snapshot yet, so expect no updates
	if err := mocks.receiveDelta(updater, common.OrderBookDelta{
		SeqNum: 100,
		Bids: common.OrderDeltas{
			Set: []common.PublicOrder{
				common.PublicOrder{Price: "50", Amount: "1"},
			},
		},
	}); err != nil {
		return errors.Trace(err)
	}

	if err := mocks.expectNoEvents(); err != nil {
		return errors.Trace(err)
	}

	// Snapshot 100 (getting in sync) {{{
	updater.ReceiveSnapshot(common.OrderBookSnapshot{
		SeqNum: 100,
		Asks: []common.PublicOrder{
			common.PublicOrder{Price: "200", Amount: "1"},
			common.PublicOrder{Price: "1000", Amount: "1"},
		},
	})

	if err := mocks.expectStateUpdate(true); err != nil {
		return errors.Trace(err)
	}

	if err := mocks.expectOrderBookUpdate(common.OrderBookSnapshot{
		SeqNum: 100,
		Asks: []common.PublicOrder{
			common.PublicOrder{Price: "200", Amount: "1"},
			common.PublicOrder{Price: "1000", Amount: "1"},
		},
	}); err != nil {
		return errors.Trace(err)
	}

	if err := mocks.expectInternalEvent(internalEventSnapshotHandled); err != nil {
		return errors.Trace(err)
	}
	// }}}

	if err := mocks.expectNoEvents(); err != nil {
		return errors.Trace(err)
	}

	return nil
}

func TestCheckDeltas(t *testing.T) {
	type checkDeltasTestCase struct {
		curSeqNum, minDeltaNum, maxDeltaNum common.SeqNum
		want                                deltasCheckResult
	}

	testCases := []checkDeltasTestCase{
		// Regular numbers without overflow {{{
		checkDeltasTestCase{
			curSeqNum: 27, minDeltaNum: 30, maxDeltaNum: 35,
			want: deltasCheckResult{nil, false},
		},
		checkDeltasTestCase{
			curSeqNum: 28, minDeltaNum: 30, maxDeltaNum: 35,
			want: deltasCheckResult{nil, false},
		},
		checkDeltasTestCase{
			curSeqNum: 29, minDeltaNum: 30, maxDeltaNum: 35,
			want: deltasCheckResult{snPtr(30), true},
		},
		checkDeltasTestCase{
			curSeqNum: 30, minDeltaNum: 30, maxDeltaNum: 35,
			want: deltasCheckResult{snPtr(31), true},
		},
		checkDeltasTestCase{
			curSeqNum: 31, minDeltaNum: 30, maxDeltaNum: 35,
			want: deltasCheckResult{snPtr(32), true},
		},
		checkDeltasTestCase{
			curSeqNum: 32, minDeltaNum: 30, maxDeltaNum: 35,
			want: deltasCheckResult{snPtr(33), true},
		},
		checkDeltasTestCase{
			curSeqNum: 33, minDeltaNum: 30, maxDeltaNum: 35,
			want: deltasCheckResult{snPtr(34), true},
		},
		checkDeltasTestCase{
			curSeqNum: 34, minDeltaNum: 30, maxDeltaNum: 35,
			want: deltasCheckResult{snPtr(35), true},
		},
		checkDeltasTestCase{
			curSeqNum: 35, minDeltaNum: 30, maxDeltaNum: 35,
			want: deltasCheckResult{nil, true},
		},
		checkDeltasTestCase{
			curSeqNum: 36, minDeltaNum: 30, maxDeltaNum: 35,
			want: deltasCheckResult{nil, false},
		},
		checkDeltasTestCase{
			curSeqNum: 37, minDeltaNum: 30, maxDeltaNum: 35,
			want: deltasCheckResult{nil, false},
		},
		// }}}
		// Deltas without overflow (up to 0xfffffffe), curSeqNum overflows {{{
		checkDeltasTestCase{
			curSeqNum: 0xfffffff6, minDeltaNum: 0xfffffff9, maxDeltaNum: 0xfffffffe,
			want: deltasCheckResult{nil, false},
		},
		checkDeltasTestCase{
			curSeqNum: 0xfffffff7, minDeltaNum: 0xfffffff9, maxDeltaNum: 0xfffffffe,
			want: deltasCheckResult{nil, false},
		},
		checkDeltasTestCase{
			curSeqNum: 0xfffffff8, minDeltaNum: 0xfffffff9, maxDeltaNum: 0xfffffffe,
			want: deltasCheckResult{snPtr(0xfffffff9), true},
		},
		checkDeltasTestCase{
			curSeqNum: 0xfffffff9, minDeltaNum: 0xfffffff9, maxDeltaNum: 0xfffffffe,
			want: deltasCheckResult{snPtr(0xfffffffa), true},
		},
		checkDeltasTestCase{
			curSeqNum: 0xfffffffa, minDeltaNum: 0xfffffff9, maxDeltaNum: 0xfffffffe,
			want: deltasCheckResult{snPtr(0xfffffffb), true},
		},
		checkDeltasTestCase{
			curSeqNum: 0xfffffffb, minDeltaNum: 0xfffffff9, maxDeltaNum: 0xfffffffe,
			want: deltasCheckResult{snPtr(0xfffffffc), true},
		},
		checkDeltasTestCase{
			curSeqNum: 0xfffffffc, minDeltaNum: 0xfffffff9, maxDeltaNum: 0xfffffffe,
			want: deltasCheckResult{snPtr(0xfffffffd), true},
		},
		checkDeltasTestCase{
			curSeqNum: 0xfffffffd, minDeltaNum: 0xfffffff9, maxDeltaNum: 0xfffffffe,
			want: deltasCheckResult{snPtr(0xfffffffe), true},
		},
		checkDeltasTestCase{
			curSeqNum: 0xfffffffe, minDeltaNum: 0xfffffff9, maxDeltaNum: 0xfffffffe,
			want: deltasCheckResult{nil, true},
		},
		checkDeltasTestCase{
			curSeqNum: 0xffffffff, minDeltaNum: 0xfffffff9, maxDeltaNum: 0xfffffffe,
			want: deltasCheckResult{nil, false},
		},
		checkDeltasTestCase{
			curSeqNum: 0x00000000, minDeltaNum: 0xfffffff9, maxDeltaNum: 0xfffffffe,
			want: deltasCheckResult{nil, false},
		},
		// }}}
		// Deltas without overflow (up to 0xffffffff), curSeqNum overflows {{{
		checkDeltasTestCase{
			curSeqNum: 0xfffffff7, minDeltaNum: 0xfffffffa, maxDeltaNum: 0xffffffff,
			want: deltasCheckResult{nil, false},
		},
		checkDeltasTestCase{
			curSeqNum: 0xfffffff8, minDeltaNum: 0xfffffffa, maxDeltaNum: 0xffffffff,
			want: deltasCheckResult{nil, false},
		},
		checkDeltasTestCase{
			curSeqNum: 0xfffffff9, minDeltaNum: 0xfffffffa, maxDeltaNum: 0xffffffff,
			want: deltasCheckResult{snPtr(0xfffffffa), true},
		},
		checkDeltasTestCase{
			curSeqNum: 0xfffffffa, minDeltaNum: 0xfffffffa, maxDeltaNum: 0xffffffff,
			want: deltasCheckResult{snPtr(0xfffffffb), true},
		},
		checkDeltasTestCase{
			curSeqNum: 0xfffffffb, minDeltaNum: 0xfffffffa, maxDeltaNum: 0xffffffff,
			want: deltasCheckResult{snPtr(0xfffffffc), true},
		},
		checkDeltasTestCase{
			curSeqNum: 0xfffffffc, minDeltaNum: 0xfffffffa, maxDeltaNum: 0xffffffff,
			want: deltasCheckResult{snPtr(0xfffffffd), true},
		},
		checkDeltasTestCase{
			curSeqNum: 0xfffffffd, minDeltaNum: 0xfffffffa, maxDeltaNum: 0xffffffff,
			want: deltasCheckResult{snPtr(0xfffffffe), true},
		},
		checkDeltasTestCase{
			curSeqNum: 0xfffffffe, minDeltaNum: 0xfffffffa, maxDeltaNum: 0xffffffff,
			want: deltasCheckResult{snPtr(0xffffffff), true},
		},
		checkDeltasTestCase{
			curSeqNum: 0xffffffff, minDeltaNum: 0xfffffffa, maxDeltaNum: 0xffffffff,
			want: deltasCheckResult{nil, true},
		},
		checkDeltasTestCase{
			curSeqNum: 0x00000000, minDeltaNum: 0xfffffffa, maxDeltaNum: 0xffffffff,
			want: deltasCheckResult{nil, false},
		},
		checkDeltasTestCase{
			curSeqNum: 0x00000001, minDeltaNum: 0xfffffffa, maxDeltaNum: 0xffffffff,
			want: deltasCheckResult{nil, false},
		},
		// }}}
		// Deltas with overflow (0xfffffffe ... 0x00000003) {{{
		checkDeltasTestCase{
			curSeqNum: 0xfffffffb, minDeltaNum: 0xfffffffe, maxDeltaNum: 0x00000003,
			want: deltasCheckResult{nil, false},
		},
		checkDeltasTestCase{
			curSeqNum: 0xfffffffc, minDeltaNum: 0xfffffffe, maxDeltaNum: 0x00000003,
			want: deltasCheckResult{nil, false},
		},
		checkDeltasTestCase{
			curSeqNum: 0xfffffffd, minDeltaNum: 0xfffffffe, maxDeltaNum: 0x00000003,
			want: deltasCheckResult{snPtr(0xfffffffe), true},
		},
		checkDeltasTestCase{
			curSeqNum: 0xfffffffe, minDeltaNum: 0xfffffffe, maxDeltaNum: 0x00000003,
			want: deltasCheckResult{snPtr(0xffffffff), true},
		},
		checkDeltasTestCase{
			curSeqNum: 0xffffffff, minDeltaNum: 0xfffffffe, maxDeltaNum: 0x00000003,
			want: deltasCheckResult{snPtr(0x00000000), true},
		},
		checkDeltasTestCase{
			curSeqNum: 0x00000000, minDeltaNum: 0xfffffffe, maxDeltaNum: 0x00000003,
			want: deltasCheckResult{snPtr(0x00000001), true},
		},
		checkDeltasTestCase{
			curSeqNum: 0x00000001, minDeltaNum: 0xfffffffe, maxDeltaNum: 0x00000003,
			want: deltasCheckResult{snPtr(0x00000002), true},
		},
		checkDeltasTestCase{
			curSeqNum: 0x00000002, minDeltaNum: 0xfffffffe, maxDeltaNum: 0x00000003,
			want: deltasCheckResult{snPtr(0x00000003), true},
		},
		checkDeltasTestCase{
			curSeqNum: 0x00000003, minDeltaNum: 0xfffffffe, maxDeltaNum: 0x00000003,
			want: deltasCheckResult{nil, true},
		},
		checkDeltasTestCase{
			curSeqNum: 0x00000004, minDeltaNum: 0xfffffffe, maxDeltaNum: 0x00000003,
			want: deltasCheckResult{nil, false},
		},
		checkDeltasTestCase{
			curSeqNum: 0x00000005, minDeltaNum: 0xfffffffe, maxDeltaNum: 0x00000003,
			want: deltasCheckResult{nil, false},
		},
		// }}}
	}

	for i, tc := range testCases {
		got := checkDeltas(tc.curSeqNum, tc.minDeltaNum, tc.maxDeltaNum)
		assert.Equal(t, tc.want, got, "test case #%d", i)
	}
}

func snPtr(sn common.SeqNum) *common.SeqNum {
	return &sn
}

// getSnapshotDelayMock just returns 1 second plus 1 more second for each
// additional attempt.
func getSnapshotDelayMock(firstSyncing bool, fetchSnapshotAttempt int) time.Duration {
	return time.Duration(fetchSnapshotAttempt+1) * 1 * time.Second
}

type updaterMockEventType int

const (
	updaterMockEventTypeGettingSnapshot updaterMockEventType = iota
	updaterMockEventTypeOBUpdate
	updaterMockEventTypeStateUpdate
	updaterMockEventTypeGetSnapshotError
	updaterMockEventTypeInternalEvent
)

type updaterMockEvent struct {
	typ updaterMockEventType

	// orderBookUpdate is relevant for typ == updaterMockEventTypeOBUpdate
	orderBookUpdate *common.OrderBookSnapshot
	// stateUpdate is relevant for typ == updaterMockEventTypeStateUpdate
	stateUpdate *StateUpdate
	// getSnapshotError is relevant for typ == updaterMockEventTypeGetSnapshotError
	getSnapshotError error
	// internalEvent is relevant for typ == updaterMockEventTypeInternalEvent
	internalEvent internalEvent
}

// snapshotGetterMock {{{

var _ OrderBookSnapshotGetter = &snapshotGetterMock{}

type snapshotWithErr struct {
	snapshot common.OrderBookSnapshot
	err      error
}

// snapshotGetterMock implements OrderBookSnapshotGetter; it
// gets snapshot for the specified market from the REST API.
type snapshotGetterMock struct {
	eventsChan   chan updaterMockEvent
	snapshotChan chan snapshotWithErr
}

type snapshotGetterMockParams struct {
	eventsChan chan updaterMockEvent
}

// newSnapshotGetterMock creates a new mocked snapshot getter
func newSnapshotGetterMock(params *snapshotGetterMockParams) *snapshotGetterMock {
	return &snapshotGetterMock{
		eventsChan:   params.eventsChan,
		snapshotChan: make(chan snapshotWithErr, 1),
	}
}

func (sg *snapshotGetterMock) GetOrderBookSnapshot() (common.OrderBookSnapshot, error) {
	snapshotRes := <-sg.snapshotChan
	return snapshotRes.snapshot, snapshotRes.err
}

// }}}

type updaterMocks struct {
	clock      *clock.Mock
	eventsChan chan updaterMockEvent
	sgetter    *snapshotGetterMock
}

func newUpdaterMocks() *updaterMocks {
	c := clock.NewMockOpt(clock.MockOpt{
		Gosched: func() {},
	})
	eventsChan := make(chan updaterMockEvent, 1)
	sgetter := newSnapshotGetterMock(&snapshotGetterMockParams{
		eventsChan: eventsChan,
	})

	c.Set(mustTimeParse("May 1, 2018 at 00:00:00 +0000"))

	return &updaterMocks{
		clock:      c,
		eventsChan: eventsChan,
		sgetter:    sgetter,
	}
}

func (m *updaterMocks) expectNoEvents() error {
	select {
	case e := <-m.eventsChan:
		return errors.Errorf("expected no events, but got %+v", e)
	default:
		return nil
	}
}

func (m *updaterMocks) expectEvent(wantTyp updaterMockEventType, cb func(e updaterMockEvent) error) error {
	select {
	case e := <-m.eventsChan:
		if e.typ != wantTyp {
			return errors.Errorf("expected event of type %v, got %+v", wantTyp, e)
		}

		if cb != nil {
			if err := cb(e); err != nil {
				return errors.Trace(err)
			}
		}

		return nil
	case <-time.After(1 * time.Second):
		return errors.Errorf("expected event of type %v, got nothing", wantTyp)
	}
}

func (m *updaterMocks) expectOrderBookUpdate(want common.OrderBookSnapshot) error {
	err := m.expectEvent(updaterMockEventTypeOBUpdate, func(e updaterMockEvent) error {
		if e.orderBookUpdate.SeqNum != want.SeqNum {
			return errors.Errorf(
				"wanted orderbook update with seqnum %v, got one with %v",
				want.SeqNum, e.orderBookUpdate.SeqNum,
			)
		}

		if err := compareOrders(want.Asks, e.orderBookUpdate.Asks); err != nil {
			return errors.Annotatef(err, "orderbook update with seqnum %v, asks", want.SeqNum)
		}

		if err := compareOrders(want.Bids, e.orderBookUpdate.Bids); err != nil {
			return errors.Annotatef(err, "orderbook update with seqnum %v, bids", want.SeqNum)
		}

		return nil
	})

	if err != nil {
		return errors.Trace(err)
	}

	return nil
}

func (m *updaterMocks) expectStateUpdate(wantSync bool) error {
	err := m.expectEvent(updaterMockEventTypeStateUpdate, func(e updaterMockEvent) error {
		if e.stateUpdate.IsInSync != wantSync {
			return errors.Errorf(
				"wanted state update with IsInSync %v, got %+v", wantSync, e.stateUpdate,
			)
		}

		return nil
	})

	if err != nil {
		return errors.Trace(err)
	}

	return nil
}

func (m *updaterMocks) expectGetSnapshotError() error {
	err := m.expectEvent(updaterMockEventTypeGetSnapshotError, func(e updaterMockEvent) error {
		// TODO: maybe check error msg

		return nil
	})

	if err != nil {
		return errors.Trace(err)
	}

	return nil
}

func (m *updaterMocks) expectInternalEvent(want internalEvent) error {
	err := m.expectEvent(updaterMockEventTypeInternalEvent, func(e updaterMockEvent) error {
		if e.internalEvent != want {
			return errors.Errorf("wanted internal event %v, got %v", want, e.internalEvent)
		}

		return nil
	})

	if err != nil {
		return errors.Trace(err)
	}

	return nil
}

func (m *updaterMocks) gettingSnapshot() {
	m.eventsChan <- updaterMockEvent{
		typ: updaterMockEventTypeGettingSnapshot,
	}
}

func (m *updaterMocks) internalEvent(e internalEvent) {
	m.eventsChan <- updaterMockEvent{
		typ:           updaterMockEventTypeInternalEvent,
		internalEvent: e,
	}
}

func (m *updaterMocks) receiveDelta(updater *OrderBookUpdater, delta common.OrderBookDelta) error {
	updater.ReceiveDelta(delta)

	if err := m.expectInternalEvent(internalEventDeltaHandled); err != nil {
		return errors.Trace(err)
	}

	return nil
}

func (m *updaterMocks) receiveSnapshot(updater *OrderBookUpdater, snapshot common.OrderBookSnapshot) error {
	updater.ReceiveSnapshot(snapshot)

	if err := m.expectInternalEvent(internalEventSnapshotHandled); err != nil {
		return errors.Trace(err)
	}

	return nil
}

const testTimeFmt = "Jan 2, 2006 at 15:04:05 -0700"

func mustTimeParse(s string) time.Time {
	timeval, err := time.Parse(testTimeFmt, s)
	if err != nil {
		panic(err.Error())
	}

	return timeval.UTC()
}

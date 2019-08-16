package orderbooks

import (
	"fmt"
	"testing"

	"github.com/juju/errors"

	"code.cryptowat.ch/cw-sdk-go/common"
)

func TestOrderBook(t *testing.T) {
	if err := testOrderBook(t); err != nil {
		t.Fatal(errors.ErrorStack(err))
	}
}

func testOrderBook(t *testing.T) error {
	var err error
	ob := NewOrderBook(common.OrderBookSnapshot{
		SeqNum: 1,
		Bids: []common.PublicOrder{
			common.PublicOrder{Price: "100", Amount: "1"},
			common.PublicOrder{Price: "92", Amount: "2"},
			common.PublicOrder{Price: "91", Amount: "2"},
			common.PublicOrder{Price: "90", Amount: "3"},
		},
		Asks: []common.PublicOrder{
			common.PublicOrder{Price: "110", Amount: "4"},
			common.PublicOrder{Price: "120", Amount: "5"},
		},
	})

	err = compareSnapshots(
		common.OrderBookSnapshot{
			SeqNum: 1,
			Bids: []common.PublicOrder{
				common.PublicOrder{Price: "100", Amount: "1"},
				common.PublicOrder{Price: "92", Amount: "2"},
				common.PublicOrder{Price: "91", Amount: "2"},
				common.PublicOrder{Price: "90", Amount: "3"},
			},
			Asks: []common.PublicOrder{
				common.PublicOrder{Price: "110", Amount: "4"},
				common.PublicOrder{Price: "120", Amount: "5"},
			},
		},
		ob.GetSnapshot(),
	)
	if err != nil {
		return errors.Trace(err)
	}

	err = ob.ApplyDelta(common.OrderBookDelta{
		SeqNum: 2,
		Bids: common.OrderDeltas{
			Set: []common.PublicOrder{
				common.PublicOrder{Price: "100", Amount: "8"},
				common.PublicOrder{Price: "96", Amount: "6"},
				common.PublicOrder{Price: "95", Amount: "7"},
			},
			Remove: []string{"92"},
		},
		Asks: common.OrderDeltas{
			Set: []common.PublicOrder{
				common.PublicOrder{Price: "110", Amount: "9"},
				common.PublicOrder{Price: "130", Amount: "10"},
			},
		},
	})
	if err != nil {
		return errors.Trace(err)
	}

	err = compareSnapshots(
		common.OrderBookSnapshot{
			SeqNum: 2,
			Bids: []common.PublicOrder{
				common.PublicOrder{Price: "100", Amount: "8"},
				common.PublicOrder{Price: "96", Amount: "6"},
				common.PublicOrder{Price: "95", Amount: "7"},
				common.PublicOrder{Price: "91", Amount: "2"},
				common.PublicOrder{Price: "90", Amount: "3"},
			},
			Asks: []common.PublicOrder{
				common.PublicOrder{Price: "110", Amount: "9"},
				common.PublicOrder{Price: "120", Amount: "5"},
				common.PublicOrder{Price: "130", Amount: "10"},
			},
		},
		ob.GetSnapshot(),
	)
	if err != nil {
		return errors.Trace(err)
	}

	// Try to apply out-of-band delta: should result in an error
	err = ob.ApplyDelta(common.OrderBookDelta{
		SeqNum: 4,
	})
	if errors.Cause(err) != ErrSeqNumMismatch {
		return errors.Errorf("expected ErrSeqNumMismatch, got %v", err)
	}

	ob.ApplySnapshot(common.OrderBookSnapshot{
		SeqNum: 100,
		Bids: []common.PublicOrder{
			common.PublicOrder{Price: "100", Amount: "1"},
		},
		Asks: []common.PublicOrder{
			common.PublicOrder{Price: "110", Amount: "2"},
		},
	})

	err = compareSnapshots(
		common.OrderBookSnapshot{
			SeqNum: 100,
			Bids: []common.PublicOrder{
				common.PublicOrder{Price: "100", Amount: "1"},
			},
			Asks: []common.PublicOrder{
				common.PublicOrder{Price: "110", Amount: "2"},
			},
		},
		ob.GetSnapshot(),
	)
	if err != nil {
		return errors.Trace(err)
	}

	return nil
}

func compareSnapshots(want, got common.OrderBookSnapshot) error {
	if got.SeqNum != want.SeqNum {
		return errors.Errorf(
			"wanted orderbook update with seqnum %v, got one with %v",
			want.SeqNum, got.SeqNum,
		)
	}

	if err := compareOrders(want.Asks, got.Asks); err != nil {
		return errors.Annotatef(err, "orderbook update with seqnum %v, asks", want.SeqNum)
	}

	if err := compareOrders(want.Bids, got.Bids); err != nil {
		return errors.Annotatef(err, "orderbook update with seqnum %v, bids", want.SeqNum)
	}

	return nil
}

func compareOrders(want, got []common.PublicOrder) error {
	if want == nil {
		want = []common.PublicOrder{}
	}

	if got == nil {
		got = []common.PublicOrder{}
	}

	wantStr := fmt.Sprintf("%+v", want)
	gotStr := fmt.Sprintf("%+v", got)

	if wantStr != gotStr {
		return errors.Errorf("want %s, got %s", wantStr, gotStr)
	}

	return nil
}

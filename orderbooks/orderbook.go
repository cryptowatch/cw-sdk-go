package orderbooks

import (
	"sort"

	"github.com/juju/errors"

	"code.cryptowat.ch/cw-sdk-go/common"
)

var (
	// ErrSeqNumMismatch is returned
	ErrSeqNumMismatch = errors.New("seq num mismatch")
)

// OrderBook represents a "live" order book, which is able to receive snapshots
// and deltas.
//
// It is not thread-safe; so if you need to use it from more than one
// goroutine, apply your own synchronization.
type OrderBook struct {
	snapshot common.OrderBookSnapshot
}

func NewOrderBook(snapshot common.OrderBookSnapshot) *OrderBook {
	return &OrderBook{
		snapshot: snapshot,
	}
}

// GetSnapshot returns the snapshot of the current orderbook.
func (ob *OrderBook) GetSnapshot() common.OrderBookSnapshot {
	return ob.snapshot
}

// GetSeqNum is a shortcut for GetSnapshot().SeqNum
func (ob *OrderBook) GetSeqNum() common.SeqNum {
	return ob.snapshot.SeqNum
}

// ApplyDelta applies the given delta (received from the wire) to the current
// orderbook. If the sequence number isn't exactly the old one incremented by
// 1, returns an error without applying delta.
func (ob *OrderBook) ApplyDelta(obd common.OrderBookDelta) error {
	return ob.ApplyDeltaOpt(obd, false)
}

// ApplyDeltaOpt applies the given delta (received from the wire) to the
// current orderbook. If ignoreSeqNum is true, applies the delta even if the
// sequence number isn't exactly the old one incremented by 1.
func (ob *OrderBook) ApplyDeltaOpt(obd common.OrderBookDelta, ignoreSeqNum bool) error {
	// Refuse to apply delta of there is a gap in sequence numbers
	if !ignoreSeqNum && obd.SeqNum-1 != ob.snapshot.SeqNum {
		return ErrSeqNumMismatch
	}

	ob.snapshot.Bids = ordersWithDelta(ob.snapshot.Bids, &obd.Bids, true)
	ob.snapshot.Asks = ordersWithDelta(ob.snapshot.Asks, &obd.Asks, false)

	ob.snapshot.SeqNum = obd.SeqNum

	return nil
}

// ApplySnapshot sets the internal orderbook to the provided snapshot.
func (ob *OrderBook) ApplySnapshot(snapshot common.OrderBookSnapshot) {
	ob.snapshot = snapshot
}

// ordersWithDelta applies given deltas to the slice of orders, and returns a
// newly allocated slice of orders, sorted by price accordingly to reverse
// argument.
func ordersWithDelta(
	orders []common.PublicOrder, deltas *common.OrderDeltas, reverse bool,
) []common.PublicOrder {
	setMap := map[string]common.PublicOrder{}
	removeMap := map[string]struct{}{}

	for _, newOrder := range deltas.Set {
		setMap[newOrder.Price] = newOrder
	}

	for _, removePrice := range deltas.Remove {
		removeMap[removePrice] = struct{}{}
	}

	// At this point we can't know for sure how many orders we'll have in the end
	// (because some of the "Set" deltas can replace existing orders), but we'll
	// allocate it so that it's certainly enough.
	ocap := len(orders) + len(setMap) - len(removeMap)
	if ocap < 0 {
		ocap = 0
	}

	newOrders := make([]common.PublicOrder, 0, ocap)

	// Replace / remove existing orders
	for _, order := range orders {
		if _, ok := removeMap[order.Price]; ok {
			// Need to remove this order, so don't add it
			continue
		}

		if newOrder, ok := setMap[order.Price]; ok {
			// Need to adjust the amount in that order
			order.Amount = newOrder.Amount

			// Also delete the order from setMap, so that we know we already took
			// care of that order.
			delete(setMap, order.Price)
		}

		newOrders = append(newOrders, order)
	}

	// Add new orders (which are still in setMap)
	for _, order := range setMap {
		newOrders = append(newOrders, order)
	}

	// Sort results
	if !reverse {
		sort.Sort(common.PublicOrdersByPrice(newOrders))
	} else {
		sort.Sort(sort.Reverse(common.PublicOrdersByPrice(newOrders)))
	}

	return newOrders
}

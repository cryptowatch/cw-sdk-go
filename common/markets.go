package common

import (
	"encoding/json"
	"fmt"
	"strconv"
	"time"

	"github.com/juju/errors"
)

type MarketID string

func (id MarketID) Int64() (int64, error) {
	if id == "" {
		return 0, nil
	}

	n, err := strconv.ParseInt(string(id), 10, 64)
	if err != nil {
		return 0, errors.Annotatef(err, "invalid market id %q", id)
	}

	return n, nil
}

// MarketUpdate is a container for all market data callbacks. For any MarketUpdate
// intance, it will only ever have one of its properties non-null.
// See OnMarketUpdate.
type MarketUpdate struct {
	OrderBookSnapshot     *OrderBookSnapshot     `json:"OrderBookSnapshot,omitempty"`
	OrderBookDelta        *OrderBookDelta        `json:"OrderBookDelta,omitempty"`
	OrderBookSpreadUpdate *OrderBookSpreadUpdate `json:"OrderBookSpreadUpdate,omitempty"`
	TradesUpdate          *TradesUpdate          `json:"TradesUpdate,omitempty"`
	IntervalsUpdate       *IntervalsUpdate       `json:"IntervalsUpdate,omitempty"`
	SummaryUpdate         *SummaryUpdate         `json:"SummaryUpdate,omitempty"`
	SparklineUpdate       *SparklineUpdate       `json:"SparklineUpdate,omitempty"`
}

func (v MarketUpdate) String() string {
	data, err := json.Marshal(v)
	if err != nil {
		return fmt.Sprintf("[failed to stringify MarketUpdate: %s]", err)
	}

	return string(data)
}

// Market represents a market on Cryptowatch. A market consists of an exchange
// and currency pair. For example, Kraken BTC/USD. IDs are used instead of
// names to avoid inconsistencies associated with name changes.
//
// IDs for exchanges, currency pairs, and markets can be found through the
// following API URLs respectively:
// https://api.cryptowat.ch/exchanges
// https://api.cryptowat.ch/pairs
// https://api.cryptowat.ch/markets
type Market struct {
	ID             MarketID
	ExchangeID     string
	CurrencyPairID string
}

// PublicOrder represents a public order placed on an exchange. They often come
// as a slice of PublicOrder, which come with order book updates.
type PublicOrder struct {
	Price  string
	Amount string
}

// SeqNum is used to make sure order book deltas are processed in order. Each order book delta update has
// the sequence number incremented by 1. Sometimes sequence numbers reset to a smaller value (this happens when we deploy or
// restart our back end for whatever reason). In those cases, the first broadcasted update is a snapshot, so clients should
// not assume they are out of sync when they receive a snapshot with a lower seq number.
type SeqNum uint32

// OrderBookSnapshot represents a full order book snapshot.
type OrderBookSnapshot struct {
	// SeqNum	is the sequence number of the last order book delta received.
	// Since snapshots are broadcast on a 1-minute interval regardless of updates,
	// it's possible this value doesn't change.
	// See the SeqNum definition for more information.
	SeqNum SeqNum

	Bids []PublicOrder
	Asks []PublicOrder
}

// OrderBookDelta represents an order book delta update, which is
// the minimum amount of data necessary to keep a local order book up to date.
// Since order book snapshots are throttled at 1 per minute, subscribing to
// the delta updates is the best way to keep an order book up to date.
type OrderBookDelta struct {
	// SeqNum is used to make sure deltas are processed in order.
	// See the SeqNum definition for more information.
	SeqNum SeqNum

	Bids OrderDeltas
	Asks OrderDeltas
}

// OrderDeltas are used to update an order book, either by setting (adding)
// new PublicOrders, or removing orders at specific prices.
type OrderDeltas struct {
	// Set is a list of orders used to add or replace orders on an order book.
	// Each order in Set is guaranteed to be a different price. For each of them,
	// if the order at that price exists on the book, replace it. If an order
	// at that price does not exist, add it to the book.
	Set []PublicOrder

	// Remove is a list of prices. To apply to an order book, remove all orders
	// of that price from that book.
	Remove []string
}

// OrderBookSpreadUpdate represents the most recent order book spread. It
// consists of the best current bid and as price.
type OrderBookSpreadUpdate struct {
	Timestamp time.Time
	Bid       PublicOrder
	Ask       PublicOrder
}

// TradesUpdate represents the most recent trades that have occurred for a
// particular market.
type TradesUpdate struct {
	Trades []PublicTrade
}

// PublicTrade represents a trade made on an exchange. See TradesUpdate and
// OnTradesUpdate.
type PublicTrade struct {
	// ExternalID is given by the exchange, and not Cryptowatch. NOTE some of
	// these may be "0" since we still use int64 on the back end to represent
	// these IDs, and some are strings.
	ExternalID string
	Timestamp  time.Time
	Price      string
	Amount     string
}

// An interval represetns OHLC data for a particular Period and CloseTime.
type Interval struct {
	Period Period
	OHLC   OHLC

	// CloseTime is the time at which the Interval ended.
	CloseTime time.Time

	// VolumeBase is the amount of volume traded over this Interval, represented
	// in the base currency.
	VolumeBase string

	// VolumeQuote is the amount of volume traded over this Interval, represented
	// in the quote currency.
	VolumeQuote string
}

// Period is the number of seconds in an Interval.
type Period int32

// The following constants are all available Period values for IntervalsUpdate.
const (
	Period1M  Period = 60
	Period3M  Period = 180
	Period5M  Period = 300
	Period15M Period = 900
	Period30M Period = 1800
	Period1H  Period = 3600
	Period2H  Period = 7200
	Period4H  Period = 14400
	Period6H  Period = 21600
	Period12H Period = 43200
	Period1D  Period = 86400
	Period3D  Period = 259200
	Period1W  Period = 604800
)

// PeriodNames contains human-readable names for Period.
// e.g. Period1M = 60 (seconds) = "1m".
var PeriodNames = map[Period]string{
	Period1M:  "1m",
	Period3M:  "3m",
	Period5M:  "5m",
	Period15M: "15m",
	Period30M: "30m",
	Period1H:  "1h",
	Period2H:  "2h",
	Period4H:  "4h",
	Period6H:  "6h",
	Period12H: "12h",
	Period1D:  "1d",
	Period3D:  "3d",
	Period1W:  "1w",
}

// OHLC contains the open, low, high, and close prices for a given Interval.
type OHLC struct {
	Open  string
	High  string
	Low   string
	Close string
}

// IntervalsUpdate represents an update for OHLC data, at all relevant periods.
// Intervals is represented as a slice because more than one interval update
// can occur at the same time for different periods. For example, Period1M and
// Period3M will overlap every 3 minutes, so that IntervalsUpdate will contain
// both intervals.
type IntervalsUpdate struct {
	Intervals []Interval
}

// SummaryUpdate represents recent summary information for a particular market.
type SummaryUpdate struct {
	Last           string
	High           string
	Low            string
	VolumeBase     string
	VolumeQuote    string
	ChangeAbsolute string
	ChangePercent  string
	NumTrades      int32
}

// SparklineUpdate represents the sparkline update for a market at a particular time.
// A sparkline is a very small line chart, typically drawn without axes or coordinates.
// It presents the general shape of the variation in price.
// https://en.wikipedia.org/wiki/Sparkline
type SparklineUpdate struct {
	Timestamp time.Time
	Price     string
}

// PublicOrdersByPrice is the type needed for sorting public orders by price.
type PublicOrdersByPrice []PublicOrder

func (pos PublicOrdersByPrice) Len() int {
	return len(pos)
}

func (pos PublicOrdersByPrice) Less(i, j int) bool {
	// Parsing to float might be not exact, but for the comparison purposes it's
	// fine.
	//
	// Maybe we could do some string padding tricks and compare them
	// lexicographically at some point.
	ifloat, _ := strconv.ParseFloat(pos[i].Price, 64)
	jfloat, _ := strconv.ParseFloat(pos[j].Price, 64)

	return ifloat < jfloat
}

func (pos PublicOrdersByPrice) Swap(i, j int) {
	pos[i], pos[j] = pos[j], pos[i]
}

// Empty returns whether the OrderDeltas doesn't contain any deltas.
func (d OrderDeltas) Empty() bool {
	return len(d.Set) == 0 && len(d.Remove) == 0
}

// Empty returns whether OrderBookDelta doesn't contain any deltas for bids and
// asks.
func (delta OrderBookDelta) Empty() bool {
	return delta.Bids.Empty() && delta.Asks.Empty()
}

// GetDeltasAgainst creates deltas which would have to be applied to oldOrders
// to get newOrders.
func GetDeltasAgainst(oldOrders, newOrders []PublicOrder) OrderDeltas {
	newIndex := publicOrdersMap(newOrders)
	oldIndex := publicOrdersMap(oldOrders)

	deltas := OrderDeltas{}

	// Calculate Set deltas
	for price, amount := range newIndex {
		if otherAmount, exists := oldIndex[price]; !exists || otherAmount != amount {
			deltas.Set = append(deltas.Set, PublicOrder{
				Price:  price,
				Amount: amount,
			})
		}
	}
	// Calculate Remove deltas
	for price := range oldIndex {
		if _, exists := newIndex[price]; !exists {
			deltas.Remove = append(deltas.Remove, price)
		}
	}
	return deltas
}

// publicOrdersMap returns a map from price to amount
func publicOrdersMap(orders []PublicOrder) map[string]string {
	ret := make(map[string]string, len(orders))
	for _, order := range orders {
		ret[order.Price] = order.Amount
	}
	return ret
}

// GetDeltasAgainst creates deltas which would have to be applied to
// oldSnapshot to get s.
func (s *OrderBookSnapshot) GetDeltasAgainst(oldSnapshot OrderBookSnapshot) OrderBookDelta {
	return OrderBookDelta{
		Asks:   GetDeltasAgainst(oldSnapshot.Asks, s.Asks),
		Bids:   GetDeltasAgainst(oldSnapshot.Bids, s.Bids),
		SeqNum: s.SeqNum,
	}
}

func (s *OrderBookSnapshot) Empty() bool {
	return len(s.Bids) == 0 && len(s.Asks) == 0
}

func (s *OrderBookSnapshot) IsValid() bool {
	if len(s.Bids) == 0 || len(s.Asks) == 0 {
		return true
	}

	bidPrice, err := strconv.ParseFloat(s.Bids[0].Price, 64)
	if err != nil {
		return false
	}

	askPrice, err := strconv.ParseFloat(s.Asks[0].Price, 64)
	if err != nil {
		return false
	}

	if bidPrice >= askPrice {
		return false
	}

	return true
}

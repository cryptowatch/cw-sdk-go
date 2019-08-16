package main

import (
	"fmt"
	"sort"
	"strings"

	"github.com/fatih/color"

	"code.cryptowat.ch/cw-sdk-go/common"
)

var (
	red    = color.RedString
	yellow = color.YellowString
	green  = color.GreenString
	blue   = color.BlueString
)

// PrettyDeltaUpdate wraps the protobufOrderBookDeltaUpdate message and provides
// a String method which formats the update in a nice way.
type PrettyDeltaUpdate struct {
	common.OrderBookDelta
}

// PrettyDeltaUpdate's String method formats the pbm.OrderBookDelta
// message to colored, human-readable text.
func (pdu PrettyDeltaUpdate) String() string {
	deltaUpdate := pdu.OrderBookDelta

	type order struct {
		price  string
		amount string
	}

	askSets := []order{}
	for _, ask := range deltaUpdate.Asks.Set {
		askSets = append(askSets, order{red(ask.Price), ask.Amount})
	}
	askRemoves := []string{}
	for _, ask := range deltaUpdate.Asks.Remove {
		askRemoves = append(askRemoves, yellow(ask))
	}

	bidSets := []order{}
	for _, bid := range deltaUpdate.Bids.Set {
		bidSets = append(bidSets, order{green(bid.Price), bid.Amount})
	}
	bidRemoves := []string{}
	for _, bid := range deltaUpdate.Bids.Remove {
		bidRemoves = append(bidRemoves, blue(bid))
	}

	rows := []string{
		fmt.Sprintf("%s / %s / %s / %s --- SeqNum: %d",
			red("Set Ask"), yellow("Remove Ask"),
			green("Set Bid"), blue("Remove Bid"),
			deltaUpdate.SeqNum),
		fmt.Sprintf("%s %v", red("====="), askSets),
		fmt.Sprintf("%s %v", yellow("-----"), askRemoves),
		fmt.Sprintf("%s %v", green("====="), bidSets),
		fmt.Sprintf("%s %v", blue("-----"), bidRemoves),
	}
	return strings.Join(rows, "\n")
}

// OrderBookMirror is meant to hold an accurate reconstruction of the
// orderbook for a particular market as long as it's updated with up-to-date
// consecutive delta messages.
type OrderBookMirror struct {
	Asks   map[string]string
	Bids   map[string]string
	SeqNum common.SeqNum
}

// NewOrderBookMirror builds an OrderBookMirror instance from a rest
// GetOrderBook response.
func NewOrderBookMirror(bookMsg common.OrderBookSnapshot) *OrderBookMirror {
	book := &OrderBookMirror{
		Asks:   map[string]string{},
		Bids:   map[string]string{},
		SeqNum: bookMsg.SeqNum,
	}

	for _, order := range bookMsg.Asks {
		price, amount := order.Price, order.Amount
		book.Asks[price] = amount
	}
	for _, order := range bookMsg.Bids {
		price, amount := order.Price, order.Amount
		book.Bids[price] = amount
	}

	return book
}

// PrettyString formats the orderbook to colored, human-readable text.
func (book *OrderBookMirror) PrettyString() string {
	type order struct {
		price  string
		amount string
	}

	asks := []order{}
	for price, amount := range book.Asks {
		asks = append(asks, order{red(price), amount})
	}
	sort.Slice(asks, func(i, j int) bool {
		return asks[i].price > asks[j].price
	})

	bids := []order{}
	for price, amount := range book.Bids {
		bids = append(bids, order{green(price), amount})
	}
	sort.Slice(bids, func(i, j int) bool {
		// reverse order for bids
		return bids[i].price > bids[j].price
	})

	return fmt.Sprintf("%s / %s --- SeqNum: %d\n%v\n%v", red("Asks"), green("Bids"), book.SeqNum, asks, bids)
}

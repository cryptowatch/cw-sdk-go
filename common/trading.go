package common

import (
	"fmt"
	"strings"
	"time"
)

// OrderSide represents the order side; e.g. "buy" or "sell".
type OrderSide int32

const (
	SellOrder OrderSide = iota
	BuyOrder
)

// OrderSideNames contains human-readable names for OrderSide.
var OrderSideNames = map[OrderSide]string{
	SellOrder: "sell",
	BuyOrder:  "buy",
}

// OrderType represents the type of order; e.g. "market" or "limit". There are
// 13 different types of orders. Those available depend on the exchange. Refer
// to the exchange's documentation for what order types are available.
type OrderType int32

// The following constants define all possible order types.
const (
	MarketOrder OrderType = iota
	LimitOrder
	StopLossOrder
	StopLossLimitOrder
	TakeProfitOrder
	TakeProfitLimitOrder
	StopLossTakeProfitOrder
	StopLossTakeProfitLimitOrder
	TrailingStopLossOrder
	TrailingStopLossLimitOrder
	StopLossAndLimitOrder
	FillOrKillOrder
	SettlePositionOrder
)

// OrderTypeNames contains human-readable names for OrderType.
var OrderTypeNames = map[OrderType]string{
	MarketOrder:                  "market",
	LimitOrder:                   "limit",
	StopLossOrder:                "stop-loss",
	TakeProfitOrder:              "take-profit",
	TakeProfitLimitOrder:         "take-profit-limit",
	StopLossTakeProfitOrder:      "stop-loss-take-profit",
	StopLossTakeProfitLimitOrder: "stop-loss-take-profit-limit",
	TrailingStopLossOrder:        "trailing-stop-loss",
	TrailingStopLossLimitOrder:   "trailing-stop-loss-limit",
	StopLossAndLimitOrder:        "stop-loss-and-limit",
	FillOrKillOrder:              "fill-or-kill",
	SettlePositionOrder:          "settle-position",
}

// FundingType represents the funding type for an order; e.g. "spot" or "margin".
// The funding types available depend on the exchange, as well as your account's
// permissions on the exchange.
type FundingType int32

// The following constants define every possible funding type.
const (
	SpotFunding FundingType = iota
	MarginFunding
	FuturesFunding
)

// FundingTypeNames contains human-readable names for FundingType.
var FundingTypeNames = map[FundingType]string{
	SpotFunding:    "spot",
	MarginFunding:  "margin",
	FuturesFunding: "futures",
}

// PriceParam is used as input for an Order.
type PriceParam struct {
	Value string
	Type  PriceParamType
}

// PriceParamType represents the type of price parameter used in PriceParams.
type PriceParamType int32

// The following constants define every possible PriceParamType
const (
	AbsoluteValuePrice PriceParamType = iota
	RelativeValuePrice
	RelativePercentValuePrice
)

// PriceParams is a list of price parameters that define the input to an order.
// Usually you will just need one PriceParam input, but some order types take
// multiple PriceParam inputs, such as TrailingStopLossOrder.
// TODO document different PriceParam uses
type PriceParams []*PriceParam

// PlaceOrderOpt contains the necessary options for creating a new order with
// the trade client.
// See TradeClient.PlaceOrder.
type PlaceOrderOpt struct {
	MarketID    MarketID
	PriceParams PriceParams
	Amount      string
	OrderSide   OrderSide
	OrderType   OrderType
	FundingType FundingType
	Leverage    string
	ExpireTime  time.Time
}

// CancelOrderOpt contains the necessary options for canceling an existing order with
// the trade client.
// See TradeClient.CancelOrder.
type CancelOrderOpt struct {
	MarketID MarketID
	OrderID  string
}

// PrivateOrder represents an order you have placed on an exchange, either
// through the TradeClient, or on the exchange itself.
type PrivateOrder struct {
	PriceParams PriceParams
	Amount      string
	OrderSide   OrderSide
	OrderType   OrderType
	FundingType FundingType
	ExpireTime  time.Time

	// Set by server and updated internally by client.
	// ID previously was ExternalID.
	ID           string
	Timestamp    time.Time
	Leverage     string
	CurrentStop  string
	InitialStop  string
	AmountFilled string

	// Broker error code; 0 if successful
	Error int32
}

// String implmements the fmt.Stringer interface for PrivateOrder.
func (o PrivateOrder) String() string {
	var priceStr string
	if o.OrderType == MarketOrder {
		priceStr = "n/a"
	} else {
		for _, p := range o.PriceParams {
			priceStr += p.Value + " "
		}
	}

	var expiresStr string
	if o.ExpireTime.IsZero() {
		expiresStr = "n/a"
	} else {
		expiresStr = fmt.Sprintf("%v", o.ExpireTime)
	}

	return fmt.Sprintf("[%v] [%s - %s/%s] id=%s amount=%s amount_filled=%v value=%s expires=%v",
		o.Timestamp, OrderSideNames[o.OrderSide], FundingTypeNames[o.FundingType],
		OrderTypeNames[o.OrderType], o.ID, o.Amount, o.AmountFilled, priceStr, expiresStr,
	)
}

// CacheKey returns the key composed by joining the market ID with the ID.
func (o PrivateOrder) CacheKey(mID MarketID) string {
	return strings.Join([]string{string(mID), o.ID}, "_")
}

// PrivateTrade represents a trade made on your account.
type PrivateTrade struct {
	ExternalID string
	OrderID    string
	Timestamp  time.Time
	Price      string
	Amount     string
	OrderSide  OrderSide
}

// PrivatePosition represents one of your positions on an exchange.
type PrivatePosition struct {
	ExternalID   string
	Timestamp    time.Time
	OrderSide    OrderSide
	AvgPrice     string
	AmountOpen   string
	AmountClosed string
	OrderIDs     []string
	TradeIDs     []string
}

// Balances is a representation of your balances on an exchange.
// It is represented as a map from the FundingType to the associated
// balances.
type Balances map[FundingType][]Balance

// Balance is the amount you have for a particular currency on an exchange.
type Balance struct {
	Currency string
	Amount   string

	// AllBalances grep flag: Ai33fA
	// Asset     string
	// Symbol    string
	// Total     string
	// Available string
}

// AllBalances grep flag: Ai33fA
// ExchangeBalances holds information about balances across all active exchanges.
// type ExchangeBalances map[string]ExchangeBalance

// AllBalances grep flag: Ai33fA
// func (xb ExchangeBalances) Copy() ExchangeBalances {
// 	result := make(ExchangeBalances, len(xb))

// 	for name, bal := range xb {
// 		balCopy := ExchangeBalance{
// 			Name:     bal.Name,
// 			Error:    bal.Error,
// 			Balances: make(Balances, len(bal.Balances)),
// 		}

// 		for ft, bs := range bal.Balances {
// 			bsCopy := make([]Balance, len(bs))
// 			copy(bsCopy, bs)

// 			balCopy.Balances[ft] = bsCopy
// 		}

// 		result[name] = balCopy
// 	}

// 	return result
// }

// AllBalances grep flag: Ai33fA
// ExchangeBalance holds information about balances on an exchange.
// type ExchangeBalance struct {
// 	Name     string
// 	Error    string
// 	Balances Balances
// }

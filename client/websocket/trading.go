package websocket

import (
	"code.cryptowat.ch/cw-sdk-go/common"
)

type tradeModule string

const (
	tradeModuleSession   tradeModule = "session"
	tradeModuleOrders    tradeModule = "orders"
	tradeModuleTrades    tradeModule = "trades"
	tradeModulePositions tradeModule = "positions"

	// Balances grep flag: Ki49fK
	tradeModuleBalances tradeModule = "balances"
)

var tradeModules = [...]tradeModule{
	tradeModuleSession,
	tradeModuleOrders,
	tradeModuleTrades,
	tradeModulePositions,
	// Balances grep flag: Ki49fK
	tradeModuleBalances,
}

type privateOrders []common.PrivateOrder

func (os privateOrders) Len() int {
	return len(os)
}

func (os privateOrders) Less(i, j int) bool {
	return os[j].Timestamp.After(os[i].Timestamp)
}

func (os privateOrders) Swap(i, j int) {
	os[i], os[j] = os[j], os[i]
}

type privateTrades []common.PrivateTrade

func (ts privateTrades) Len() int {
	return len(ts)
}

func (ts privateTrades) Less(i, j int) bool {
	return ts[j].Timestamp.After(ts[i].Timestamp)
}

func (ts privateTrades) Swap(i, j int) {
	ts[i], ts[j] = ts[j], ts[i]
}

type privatePositions []common.PrivatePosition

func (ps privatePositions) Len() int {
	return len(ps)
}

func (ps privatePositions) Less(i, j int) bool {
	return ps[j].Timestamp.After(ps[i].Timestamp)
}

func (ps privatePositions) Swap(i, j int) {
	ps[i], ps[j] = ps[j], ps[i]
}

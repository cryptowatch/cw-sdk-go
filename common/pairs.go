package common

import (
	"encoding/json"
	"fmt"
	"time"
)

type PairID string

// PairUpdate is a container for all pair data callbacks. For any PairUpdate
// instance, it will only ever have one of its properties non-null.
// See OnPairUpdate.
type PairUpdate struct {
	VWAPUpdate        *VWAPUpdate        `json:"VWAPUpdate,omitempty"`
	PerformanceUpdate *PerformanceUpdate `json:"PerformanceUpdate,omitempty"`
	TrendlineUpdate   *TrendlineUpdate   `json:"TrendlineUpdate,omitempty"`
}

func (v PairUpdate) String() string {
	data, err := json.Marshal(v)
	if err != nil {
		return fmt.Sprintf("[failed to stringify PairUpdate: %s]", err)
	}

	return string(data)
}

// Pair represents the currency pair as defined by the Cryptowatch API:
// https://api.cryptowat.ch/pairs
type Pair struct {
	ID PairID
}

// PerformanceWindow represents the time window over which performance is
// calculated.
type PerformanceWindow string

// The following constants represent every possible PerformanceWindow.
const (
	PerfWindow24h PerformanceWindow = "24h"
	PerfWindow1w  PerformanceWindow = "1w"
	PerfWindow1m  PerformanceWindow = "1m"
	PerfWindow3m  PerformanceWindow = "3m"
	PerfWindow6m  PerformanceWindow = "6m"
	PerfWindowYTD PerformanceWindow = "ytd"
	PerfWindow1y  PerformanceWindow = "1y"
	PerfWindow2y  PerformanceWindow = "2y"
	PerfWindow3y  PerformanceWindow = "3y"
	PerfWindow4y  PerformanceWindow = "4y"
	PerfWindow5y  PerformanceWindow = "5y"
)

// PerformanceUpdate represents the most recent performance update for a market
// over a particular window.
// TODO explain calculation
type PerformanceUpdate struct {
	Window      PerformanceWindow
	Performance string
}

// TrendlineUpdate represents the trendline update for a market for a particular
// window.
// TODO explain calculation
type TrendlineUpdate struct {
	Window    PerformanceWindow
	Timestamp time.Time
	Price     string
	Volume    string
}

// VWAPUpdate represents the most recent volume weighted average price update
// for a market at a given time.
// TODO explain calculation
type VWAPUpdate struct {
	VWAP      string
	Timestamp time.Time
}

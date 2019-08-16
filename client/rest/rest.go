/*
Package rest provides a client for using the Cryptowatch REST API.
*/
package rest // import "code.cryptowat.ch/cw-sdk-go/client/rest"

import (
	"encoding/json"
	"fmt"
	"net/http"
	"strconv"
	"time"

	"github.com/juju/errors"

	"code.cryptowat.ch/cw-sdk-go/common"
)

const (
	DefaultRESTURL = "https://api.cryptowat.ch"
)

type CWRESTClient struct {
	params CWRESTClientParams
}

type CWRESTClientParams struct {
	// APIURL is the API URL to use. If empty, production will be used
	// (DefaultRESTURL)
	APIURL string
}

type ExchangeDescr struct {
	ID     int    `json:"id"`
	Symbol string `json:"symbol"`
	Name   string `json:"name"`
	Active bool   `json:"active"`
	Routes struct {
		Markets string `json:"markets"`
	} `json:"routes"`
}

type ExchangeDescrBrief struct {
	ID     int    `json:"id"`
	Symbol string `json:"symbol"`
	Name   string `json:"name"`
	Route  string `json:"route"`
	Active bool   `json:"active"`
}

type MarketDescr struct {
	ID       int    `json:"id"`
	Exchange string `json:"exchange"`
	Pair     string `json:"pair"`
	Active   bool   `json:"active"`
	Route    string `json:"route"`
}

type PairDescr struct {
	ID      int           `json:"id"`
	Symbol  string        `json:"symbol"`
	Route   string        `json:"route"`
	Base    PairSideDescr `json:"base"`
	Quote   PairSideDescr `json:"quote"`
	Markets []MarketDescr `json:"markets"`
}

type PairSideDescr struct {
	ID     int    `json:"id"`
	Symbol string `json:"symbol"`
	Name   string `json:"name"`
	Fiat   bool   `json:"fiat"`
	Route  string `json:"route"`
}

// TODO: rename all those ...Server structs to something like ...JSON.

type exchangesDescrServer struct {
	Result []ExchangeDescrBrief `json:"result"`
}

type exchangeDescrServer struct {
	Result ExchangeDescr `json:"result"`
}

type marketsDescrServer struct {
	Result []MarketDescr `json:"result"`
}

type marketDescrServer struct {
	Result MarketDescr `json:"result"`
	Error  string      `json:"error"`
}

type pairsDescrServer struct {
	Result []PairDescr `json:"result"`
}

type pairDescrServer struct {
	Result PairDescr `json:"result"`
	Error  string    `json:"error"`
}

type ohlcServer struct {
	Result map[string][][]json.Number `json:"result"`
}

type orderbookServer struct {
	Result struct {
		Asks   [][]float32   `json:"asks"`
		Bids   [][]float32   `json:"bids"`
		SeqNum common.SeqNum `json:"seqNum"`
	} `json:"result"`
}

type marketSummariesServer struct {
	Result map[string]marketSummariesItemServer `json:"result"`
}

type marketSummariesItemServer struct {
	Price struct {
		Last   json.Number `json:"last"`
		High   json.Number `json:"high"`
		Low    json.Number `json:"low"`
		Change struct {
			Percentage json.Number `json:"percentage"`
			Absolute   json.Number `json:"absolute"`
		} `json:"change"`
	} `json:"price"`
	Volume      json.Number `json:"volume"`
	VolumeQuote json.Number `json:"volumeQuote"`
}

func NewCWRESTClient(params *CWRESTClientParams) *CWRESTClient {
	if params == nil {
		params = &CWRESTClientParams{}
	}

	c := &CWRESTClient{
		params: *params,
	}

	if c.params.APIURL == "" {
		c.params.APIURL = DefaultRESTURL
	}

	return c
}

func (c *CWRESTClient) GetExchangesIndex() ([]ExchangeDescrBrief, error) {
	resp, err := http.Get(fmt.Sprintf("%s/exchanges", c.params.APIURL))
	if err != nil {
		return nil, errors.Trace(err)
	}

	defer resp.Body.Close()

	res := exchangesDescrServer{}

	dec := json.NewDecoder(resp.Body)
	if err := dec.Decode(&res); err != nil {
		return nil, errors.Trace(err)
	}

	return res.Result, nil
}

func (c *CWRESTClient) GetExchangeDescr(exchangeSymbol string) (*ExchangeDescr, error) {
	resp, err := http.Get(fmt.Sprintf("%s/exchanges/%s", c.params.APIURL, exchangeSymbol))
	if err != nil {
		return nil, errors.Trace(err)
	}

	defer resp.Body.Close()

	res := exchangeDescrServer{}

	dec := json.NewDecoder(resp.Body)
	if err := dec.Decode(&res); err != nil {
		return nil, errors.Trace(err)
	}

	return &res.Result, nil
}

func (c *CWRESTClient) GetExchangeMarketsDescr(exchangeSymbol string) ([]MarketDescr, error) {
	resp, err := http.Get(fmt.Sprintf("%s/markets/%s", c.params.APIURL, exchangeSymbol))
	if err != nil {
		return nil, errors.Trace(err)
	}

	defer resp.Body.Close()

	res := marketsDescrServer{}

	dec := json.NewDecoder(resp.Body)
	if err := dec.Decode(&res); err != nil {
		return nil, errors.Trace(err)
	}

	return res.Result, nil
}

func (c *CWRESTClient) GetMarketsIndex() ([]MarketDescr, error) {
	resp, err := http.Get(fmt.Sprintf("%s/markets", c.params.APIURL))
	if err != nil {
		return nil, errors.Trace(err)
	}

	defer resp.Body.Close()

	res := marketsDescrServer{}

	dec := json.NewDecoder(resp.Body)
	if err := dec.Decode(&res); err != nil {
		return nil, errors.Trace(err)
	}

	return res.Result, nil
}

func (c *CWRESTClient) GetMarketDescr(exchangeSymbol, pairSymbol string) (MarketDescr, error) {
	resp, err := http.Get(fmt.Sprintf("%s/markets/%s/%s", c.params.APIURL, exchangeSymbol, pairSymbol))
	if err != nil {
		return MarketDescr{}, errors.Trace(err)
	}

	defer resp.Body.Close()

	res := marketDescrServer{}

	dec := json.NewDecoder(resp.Body)
	if err := dec.Decode(&res); err != nil {
		return MarketDescr{}, errors.Trace(err)
	}

	if res.Error != "" {
		return MarketDescr{}, errors.New(res.Error)
	}

	return res.Result, nil
}

func (c *CWRESTClient) GetPairsIndex() ([]PairDescr, error) {
	resp, err := http.Get(fmt.Sprintf("%s/pairs", c.params.APIURL))
	if err != nil {
		return nil, errors.Trace(err)
	}

	defer resp.Body.Close()

	res := pairsDescrServer{}

	dec := json.NewDecoder(resp.Body)
	if err := dec.Decode(&res); err != nil {
		return nil, errors.Trace(err)
	}

	return res.Result, nil
}

func (c *CWRESTClient) GetPairDescr(symbol string) (PairDescr, error) {
	resp, err := http.Get(fmt.Sprintf("%s/pairs/%s", c.params.APIURL, symbol))
	if err != nil {
		return PairDescr{}, errors.Trace(err)
	}

	defer resp.Body.Close()

	res := pairDescrServer{}

	dec := json.NewDecoder(resp.Body)
	if err := dec.Decode(&res); err != nil {
		return PairDescr{}, errors.Trace(err)
	}

	return res.Result, nil
}

func (c *CWRESTClient) GetOrderBook(
	exchangeSymbol string, pairSymbol string,
) (common.OrderBookSnapshot, error) {
	var ob common.OrderBookSnapshot

	resp, err := http.Get(fmt.Sprintf("%s/markets/%s/%s/orderbook", c.params.APIURL, exchangeSymbol, pairSymbol))
	if err != nil {
		return common.OrderBookSnapshot{}, errors.Trace(err)
	}

	defer resp.Body.Close()

	res := orderbookServer{}

	dec := json.NewDecoder(resp.Body)
	if err := dec.Decode(&res); err != nil {
		return common.OrderBookSnapshot{}, errors.Trace(err)
	}

	ob.SeqNum = res.Result.SeqNum
	ob.Asks = make([]common.PublicOrder, 0, len(res.Result.Asks))
	ob.Bids = make([]common.PublicOrder, 0, len(res.Result.Bids))

	for i, v := range res.Result.Asks {
		if len(v) != 2 {
			return common.OrderBookSnapshot{}, errors.Errorf("ask #%d: expected tuple of 2 elements, got %v", i, v)
		}

		ob.Asks = append(ob.Asks, common.PublicOrder{
			Price:  float32ToString(v[0]),
			Amount: float32ToString(v[1]),
		})
	}

	for i, v := range res.Result.Bids {
		if len(v) != 2 {
			return common.OrderBookSnapshot{}, errors.Errorf("bid #%d: expected tuple of 2 elements, got %v", i, v)
		}

		ob.Bids = append(ob.Bids, common.PublicOrder{
			Price:  float32ToString(v[0]),
			Amount: float32ToString(v[1]),
		})
	}

	return ob, nil
}

// GetOHLC returns a map from a period (represented as a number of seconds: 60,
// 180, etc) to a slice of OHLC candles for that period, in the time ascending
// order.
func (c *CWRESTClient) GetOHLC(
	exchangeSymbol, pairSymbol string,
) (map[common.Period][]common.Interval, error) {
	resp, err := http.Get(fmt.Sprintf(
		"%s/markets/%s/%s/ohlc",
		c.params.APIURL, exchangeSymbol, pairSymbol,
	))
	if err != nil {
		return nil, errors.Trace(err)
	}

	defer resp.Body.Close()

	srv := ohlcServer{}

	dec := json.NewDecoder(resp.Body)
	if err := dec.Decode(&srv); err != nil {
		return nil, errors.Trace(err)
	}

	ret := make(map[common.Period][]common.Interval, len(srv.Result))
	for srvPeriod, srvCandles := range srv.Result {
		v64, err := strconv.ParseInt(srvPeriod, 10, 64)
		if err != nil {
			return nil, errors.Annotatef(err, "parsing period %q", srvPeriod)
		}

		period := common.Period(v64)

		candles := make([]common.Interval, 0, len(srvCandles))
		for _, srvCandle := range srvCandles {
			if len(srvCandle) < 7 {
				return nil, errors.Errorf("unexpected response from the server: wanted 7 elements, got %v", srvCandle)
			}

			ts, err := srvCandle[0].Int64()
			if err != nil {
				return nil, errors.Annotatef(err, "getting timestamp %q", srvCandle[0].String())
			}

			candle := common.Interval{
				Period:    period,
				CloseTime: time.Unix(ts, 0),
				OHLC: common.OHLC{
					Open:  srvCandle[1].String(),
					High:  srvCandle[2].String(),
					Low:   srvCandle[3].String(),
					Close: srvCandle[4].String(),
				},
				VolumeBase:  srvCandle[5].String(),
				VolumeQuote: srvCandle[6].String(),
			}

			candles = append(candles, candle)
		}

		ret[period] = candles
	}

	return ret, nil
}

// GetMarketSummaries returns a map from market symbol like "<exchange>:<pair>"
// to the corresponding summary.
func (c *CWRESTClient) GetMarketSummaries() (map[string]common.SummaryUpdate, error) {
	resp, err := http.Get(fmt.Sprintf(
		"%s/markets/summaries", c.params.APIURL,
	))
	if err != nil {
		return nil, errors.Trace(err)
	}

	defer resp.Body.Close()

	srv := marketSummariesServer{}

	dec := json.NewDecoder(resp.Body)
	if err := dec.Decode(&srv); err != nil {
		return nil, errors.Trace(err)
	}

	ret := make(map[string]common.SummaryUpdate, len(srv.Result))
	for market, v := range srv.Result {
		summary := common.SummaryUpdate{
			Last:           v.Price.Last.String(),
			High:           v.Price.High.String(),
			Low:            v.Price.Low.String(),
			ChangeAbsolute: v.Price.Change.Absolute.String(),
			ChangePercent:  v.Price.Change.Percentage.String(),
			VolumeBase:     v.Volume.String(),
			VolumeQuote:    v.VolumeQuote.String(),
		}

		ret[market] = summary
	}

	return ret, nil
}

func float32ToString(v float32) string {
	return strconv.FormatFloat(float64(v), 'f', -1, 32)
}

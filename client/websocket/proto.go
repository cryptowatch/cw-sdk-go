package websocket

import (
	"strconv"
	"time"

	"github.com/golang/protobuf/proto"
	"github.com/juju/errors"

	"code.cryptowat.ch/cw-sdk-go/common"
	pbb "code.cryptowat.ch/cw-sdk-go/proto/broker"
	pbc "code.cryptowat.ch/cw-sdk-go/proto/client"
	pbm "code.cryptowat.ch/cw-sdk-go/proto/markets"
	pbs "code.cryptowat.ch/cw-sdk-go/proto/stream"
)

// TODO check if pointers are null

func marketFromProto(m *pbm.Market) common.Market {
	return common.Market{
		ID:             common.MarketID(uint64ToString(m.MarketId)),
		ExchangeID:     uint64ToString(m.ExchangeId),
		CurrencyPairID: uint64ToString(m.CurrencyPairId),
	}
}

func publicOrderFromProto(po *pbm.Order) common.PublicOrder {
	return common.PublicOrder{
		Price:  po.PriceStr,
		Amount: po.AmountStr,
	}
}

func orderBookSnapshotUpdateFromProto(obu *pbm.OrderBookUpdate) common.OrderBookSnapshot {
	bids := make([]common.PublicOrder, len(obu.Bids))
	for i, b := range obu.Bids {
		bids[i] = publicOrderFromProto(b)
	}

	asks := make([]common.PublicOrder, len(obu.Asks))
	for i, a := range obu.Asks {
		asks[i] = publicOrderFromProto(a)
	}

	return common.OrderBookSnapshot{
		SeqNum: common.SeqNum(obu.SeqNum),
		Bids:   bids,
		Asks:   asks,
	}
}

func orderBookDeltaUpdateFromProto(obdu *pbm.OrderBookDeltaUpdate) common.OrderBookDelta {
	bidSet := make([]common.PublicOrder, len(obdu.Bids.Set))
	for i, o := range obdu.Bids.Set {
		bidSet[i] = publicOrderFromProto(o)
	}

	askSet := make([]common.PublicOrder, len(obdu.Asks.Set))
	for i, o := range obdu.Asks.Set {
		askSet[i] = publicOrderFromProto(o)
	}

	return common.OrderBookDelta{
		SeqNum: common.SeqNum(obdu.SeqNum),

		Bids: common.OrderDeltas{
			Set:    bidSet,
			Remove: obdu.Bids.RemoveStr,
		},
		Asks: common.OrderDeltas{
			Set:    askSet,
			Remove: obdu.Asks.RemoveStr,
		},
	}
}

func orderBookSpreadUpdateFromProto(obsu *pbm.OrderBookSpreadUpdate) common.OrderBookSpreadUpdate {
	return common.OrderBookSpreadUpdate{
		Timestamp: time.Unix(0, obsu.Timestamp*int64(time.Millisecond)),
		Bid:       publicOrderFromProto(obsu.Bid),
		Ask:       publicOrderFromProto(obsu.Ask),
	}
}

func tradesUpdateFromProto(tu *pbm.TradesUpdate) common.TradesUpdate {
	pt := make([]common.PublicTrade, len(tu.Trades))

	for i, t := range tu.Trades {
		var timestamp time.Time

		// Eliminate timestamp redundancy
		if t.TimestampNano > 0 {
			timestamp = time.Unix(0, t.TimestampNano)
		} else if t.TimestampMillis > 0 {
			timestamp = unixMillisToTime(t.TimestampMillis)
		} else {
			timestamp = time.Unix(t.Timestamp, 0)
		}

		pt[i] = common.PublicTrade{
			ExternalID: t.ExternalId,
			Timestamp:  timestamp,
			Price:      t.PriceStr,
			Amount:     t.AmountStr,
		}
	}

	return common.TradesUpdate{
		Trades: pt,
	}
}

func intervalsUpdateFromProto(iu *pbm.IntervalsUpdate) common.IntervalsUpdate {
	var is []common.Interval

	for _, i := range iu.Intervals {
		is = append(is, intervalFromProto(i))
	}

	return common.IntervalsUpdate{
		Intervals: is,
	}
}

func intervalFromProto(i *pbm.Interval) common.Interval {
	return common.Interval{
		CloseTime: time.Unix(i.Closetime, 0),
		Period:    common.Period(i.Period),
		OHLC: common.OHLC{
			Open:  i.Ohlc.OpenStr,
			High:  i.Ohlc.HighStr,
			Low:   i.Ohlc.LowStr,
			Close: i.Ohlc.CloseStr,
		},
		VolumeBase:  i.VolumeBaseStr,
		VolumeQuote: i.VolumeQuoteStr,
	}
}

func summaryUpdateFromProto(su *pbm.SummaryUpdate) common.SummaryUpdate {
	return common.SummaryUpdate{
		Last:           su.LastStr,
		High:           su.HighStr,
		Low:            su.LowStr,
		VolumeBase:     su.VolumeBaseStr,
		VolumeQuote:    su.VolumeQuoteStr,
		ChangeAbsolute: su.ChangeAbsoluteStr,
		ChangePercent:  su.ChangePercentStr,
		NumTrades:      su.NumTrades,
	}
}

func sparklineUpdateFromProto(su *pbm.SparklineUpdate) common.SparklineUpdate {
	return common.SparklineUpdate{
		Timestamp: time.Unix(su.Time, 0),
		Price:     su.PriceStr,
	}
}

func vwapUpdateFromProto(vu *pbm.PairVwapUpdate) common.VWAPUpdate {
	return common.VWAPUpdate{
		VWAP:      float64ToString(vu.Vwap),
		Timestamp: time.Unix(vu.Timestamp, 0),
	}
}

func performanceUpdateFromProto(pu *pbm.PairPerformanceUpdate) common.PerformanceUpdate {
	return common.PerformanceUpdate{
		Window:      common.PerformanceWindow(pu.Window),
		Performance: float64ToString(pu.Performance),
	}
}

func trendlineUpdateFromProto(tu *pbm.PairTrendlineUpdate) common.TrendlineUpdate {
	return common.TrendlineUpdate{
		Window:    common.PerformanceWindow(tu.Window),
		Timestamp: time.Unix(tu.Time, 0),
		Price:     tu.Price,
		Volume:    tu.Volume,
	}
}

func privateOrderFromProto(order *pbb.PrivateOrder) common.PrivateOrder {
	var priceParams common.PriceParams
	for _, pp := range order.PriceParams {
		priceParams = append(priceParams, &common.PriceParam{
			Value: pp.ValueString,
			Type:  common.PriceParamType(pp.Type),
		})
	}

	if order.AmountFilledString == "" {
		order.AmountFilledString = "0.0"
	}

	return common.PrivateOrder{
		Timestamp:   time.Unix(order.Time, 0),
		PriceParams: priceParams,
		Amount:      order.AmountParamString,
		OrderSide:   common.OrderSide(order.Side),
		OrderType:   common.OrderType(order.Type),
		FundingType: common.FundingType(order.FundingType),
		ExpireTime:  time.Unix(order.ExpireTime, 0),

		ID:           order.Id,
		Leverage:     order.Leverage,
		CurrentStop:  order.CurrentStopString,
		InitialStop:  order.InitialStopString,
		AmountFilled: order.AmountFilledString,
	}
}

func placeOrderOptToProto(orderOpt common.PlaceOrderOpt) *pbb.PrivateOrder {
	priceParams := make([]*pbb.PrivateOrder_PriceParam, 0, len(orderOpt.PriceParams))
	for _, p := range orderOpt.PriceParams {
		priceParams = append(priceParams, &pbb.PrivateOrder_PriceParam{
			ValueString: p.Value,
			Type:        pbb.PrivateOrder_PriceParamType(p.Type),
		})
	}

	return &pbb.PrivateOrder{
		Side:              int32(orderOpt.OrderSide),
		Type:              pbb.PrivateOrder_Type(orderOpt.OrderType),
		FundingType:       pbb.FundingType(orderOpt.FundingType),
		PriceParams:       priceParams,
		AmountParamString: orderOpt.Amount,
		Leverage:          orderOpt.Leverage,
		ExpireTime:        timeToUnix(orderOpt.ExpireTime),
	}
}

func privateOrderToProto(o common.PrivateOrder) *pbb.PrivateOrder {
	priceParams := []*pbb.PrivateOrder_PriceParam{}
	for _, p := range o.PriceParams {
		priceParams = append(priceParams, &pbb.PrivateOrder_PriceParam{
			ValueString: p.Value,
			Type:        pbb.PrivateOrder_PriceParamType(p.Type),
		})
	}

	return &pbb.PrivateOrder{
		Id:          o.ID,
		Side:        int32(o.OrderSide),
		Type:        pbb.PrivateOrder_Type(o.OrderType),
		FundingType: pbb.FundingType(o.FundingType),
		Time:        o.Timestamp.Unix(),
		PriceParams: priceParams,

		AmountParamString:  o.Amount,
		AmountFilledString: o.AmountFilled,
		ExpireTime:         timeToUnix(o.ExpireTime),
		Leverage:           o.Leverage,
	}
}

func balanceFromProto(balance *pbb.Balance) common.Balance {
	return common.Balance{
		Currency: balance.Currency,
		Amount:   balance.AmountString,

		// AllBalances grep flag: Ai33fA
		// Asset:     balance.Asset,
		// Symbol:    balance.Symbol,
		// Total:     balance.AmountTotal,
		// Available: balance.AmountAvailable,
	}
}

// AllBalances grep flag: Ai33fA
// func exchangeBalancesFromProto(balances []*pbb.Balances) common.ExchangeBalances {
// 	result := make(common.ExchangeBalances)

// 	for _, xbalance := range balances {
// 		xbals, ok := result[xbalance.Name]
// 		if !ok {
// 			xbals = common.ExchangeBalance{
// 				Name:     xbalance.Name,
// 				Error:    xbalance.Error,
// 				Balances: make(common.Balances),
// 			}
// 		}

// 		ft := common.FundingType(xbalance.FundingType)

// 		ftBals, ok := xbals.Balances[ft]
// 		if !ok {
// 			ftBals = make([]common.Balance, 0, len(xbalance.Balances))
// 		}

// 		for _, b := range xbalance.Balances {
// 			ftBals = append(ftBals, balanceFromProto(b))
// 		}

// 		xbals.Balances[ft] = ftBals
// 		result[xbalance.Name] = xbals
// 	}

// 	return result
// }

func balancesToProto(balances common.Balances) []*pbb.Balances {
	var ret []*pbb.Balances

	for ftype, fbals := range balances {
		var balances []*pbb.Balance
		for _, bal := range fbals {
			balances = append(balances, &pbb.Balance{
				Currency:     bal.Currency,
				AmountString: bal.Amount,

				// AllBalances grep flag: Ai33fA
				// Asset:           bal.Asset,
				// Symbol:          bal.Symbol,
				// AmountTotal:     bal.Total,
				// AmountAvailable: bal.Available,
			})
		}
		ret = append(ret, &pbb.Balances{
			FundingType: pbb.FundingType(ftype),
			Balances:    balances,
		})
	}

	return ret
}

func positionFromProto(position *pbb.PrivatePosition) common.PrivatePosition {
	return common.PrivatePosition{
		ExternalID:   position.Id,
		Timestamp:    time.Unix(position.Time, 0),
		OrderSide:    common.OrderSide(position.Side),
		AvgPrice:     position.AvgPriceString,
		AmountOpen:   position.AmountOpenString,
		AmountClosed: position.AmountClosedString,
		OrderIDs:     position.OrderIds,
		TradeIDs:     position.TradeIds,
	}
}

func positionToProto(p common.PrivatePosition) *pbb.PrivatePosition {
	return &pbb.PrivatePosition{
		Id:                 p.ExternalID,
		Time:               p.Timestamp.Unix(),
		Side:               int32(p.OrderSide),
		AvgPriceString:     p.AvgPrice,
		AmountOpenString:   p.AmountOpen,
		AmountClosedString: p.AmountClosed,
		OrderIds:           p.OrderIDs,
		TradeIds:           p.TradeIDs,
	}
}

func tradeFromProto(trade *pbb.PrivateTrade) common.PrivateTrade {
	// Eliminate timestamp redundancy
	var t time.Time
	if trade.TimeMillis > 0 {
		t = unixMillisToTime(trade.TimeMillis)
	} else {
		t = time.Unix(trade.Time, 0)
	}

	return common.PrivateTrade{
		ExternalID: trade.ExternalId,
		OrderID:    trade.OrderId,
		Timestamp:  t,
		OrderSide:  common.OrderSide(trade.Side),
		Price:      trade.PriceString,
		Amount:     trade.AmountString,
	}
}

func tradeToProto(t common.PrivateTrade) *pbb.PrivateTrade {
	return &pbb.PrivateTrade{
		ExternalId:   t.ExternalID,
		OrderId:      t.OrderID,
		Time:         t.Timestamp.Unix(),
		TimeMillis:   t.Timestamp.UnixNano() / int64(time.Millisecond),
		PriceString:  t.Price,
		AmountString: t.Amount,
		Side:         int32(t.OrderSide),
	}
}

func subscriptionResultFromProto(sr *pbs.SubscriptionResult) SubscriptionResult {
	failed := make([]SubscribeError, 0, len(sr.Failed))
	for _, v := range sr.Failed {
		failed = append(failed, SubscribeError{
			Key:          v.Key,
			Error:        v.Error,
			Subscription: subFromProto(v.GetSubscription()),
		})
	}

	return SubscriptionResult{
		Subscriptions: subsFromProto(sr.GetSubscriptions()),
		Failed:        failed,
		Status: SubscriptionStatus{
			Subscriptions: subsFromProto(sr.Status.GetSubscriptions()),
		},
	}
}

func unsubscriptionResultFromProto(sr *pbs.UnsubscriptionResult) UnsubscriptionResult {
	failed := make([]UnsubscribeError, 0, len(sr.Failed))
	for _, v := range sr.Failed {
		failed = append(failed, UnsubscribeError{
			Key:          v.Key,
			Error:        v.Error,
			Subscription: subFromProto(v.GetSubscription()),
		})
	}

	return UnsubscriptionResult{
		Subscriptions: subsFromProto(sr.GetSubscriptions()),
		Failed:        failed,
		Status: SubscriptionStatus{
			Subscriptions: subsFromProto(sr.Status.GetSubscriptions()),
		},
	}
}

func bandwidthFromProto(bu *pbs.BandwidthUpdate) Bandwidth {
	return Bandwidth{
		OK:             bu.Ok,
		BytesRemaining: bu.BytesRemaining,
		BytesUsed:      bu.BytesUsed,
	}
}

func missedMessagesFromProto(mm *pbs.MissedMessages) MissedMessages {
	return MissedMessages{
		NumMissedMessages: mm.NumMissedMessages,
	}
}

func unmarshalAuthnResultStream(data []byte) (*pbs.AuthenticationResult, error) {
	var msg pbs.StreamMessage

	if err := proto.Unmarshal(data, &msg); err != nil {
		return nil, errors.Trace(err)
	}

	authnResult := msg.GetAuthenticationResult()
	if authnResult == nil {
		return nil, errors.Trace(ErrInvalidAuthn)
	}

	return authnResult, nil
}

func unmarshalAuthnResultTrade(data []byte) (*pbs.AuthenticationResult, error) {
	var msg pbb.BrokerUpdateMessage

	if err := proto.Unmarshal(data, &msg); err != nil {
		return nil, errors.Trace(err)
	}

	authnResult := msg.GetAuthenticationResult()
	if authnResult == nil {
		return nil, errors.Trace(ErrInvalidAuthn)
	}

	return authnResult, nil
}

func subsToProto(subs []Subscription) []*pbc.ClientSubscription {
	if len(subs) == 0 {
		return nil
	}

	switch subs[0].(type) {
	case *StreamSubscription:
		return streamSubsToProto(subs)
	case *TradeSubscription:
		return tradeSubsToProto(subs)
	}

	panic(errInvalidSubType)
}

func subsFromProto(subs []*pbc.ClientSubscription) []Subscription {
	if len(subs) == 0 {
		return nil
	}

	switch subs[0].Body.(type) {
	case *pbc.ClientSubscription_StreamSubscription:
		return streamSubsToSubs(streamSubsFromProto(subs))
	case *pbc.ClientSubscription_TradeSubscription:
		return tradeSubsToSubs(tradeSubsFromProto(subs))
	}

	panic(errInvalidSubType)
}

func subFromProto(sub *pbc.ClientSubscription) Subscription {
	switch v := sub.Body.(type) {
	case *pbc.ClientSubscription_StreamSubscription:
		return streamSubFromProto(v)
	case *pbc.ClientSubscription_TradeSubscription:
		return tradeSubFromProto(v)
	}

	panic(errInvalidSubType)
}

func streamSubToProto(sub *StreamSubscription) *pbc.ClientSubscription_StreamSubscription {
	return &pbc.ClientSubscription_StreamSubscription{
		StreamSubscription: &pbc.StreamSubscription{
			Resource: sub.Resource,
		},
	}
}

func streamSubFromProto(sub *pbc.ClientSubscription_StreamSubscription) *StreamSubscription {
	if sub == nil {
		return &StreamSubscription{}
	}

	return &StreamSubscription{
		Resource: sub.StreamSubscription.Resource,
	}
}

func tradeSubFromProto(sub *pbc.ClientSubscription_TradeSubscription) *TradeSubscription {
	if sub == nil {
		return &TradeSubscription{}
	}

	var auth *TradeSessionAuth
	if ta := sub.TradeSubscription.GetAuth(); ta != nil {
		auth = &TradeSessionAuth{
			APIKey:        ta.ApiKey,
			APISecret:     ta.ApiSecret,
			CustomerID:    ta.CustomerId,
			KeyPassphrase: ta.KeyPassphrase,
		}
	}

	return &TradeSubscription{
		MarketID: common.MarketID(sub.TradeSubscription.GetMarketId()),
		Auth:     auth,
	}
}

func streamSubsToProto(subs []Subscription) []*pbc.ClientSubscription {
	ret := make([]*pbc.ClientSubscription, 0, len(subs))

	for _, sub := range subs {
		v, ok := sub.(*StreamSubscription)
		if !ok {
			panic(errInvalidSubType)
		}

		ret = append(ret, &pbc.ClientSubscription{
			Body: streamSubToProto(v),
		})
	}

	return ret
}

func streamSubsFromProto(subs []*pbc.ClientSubscription) []*StreamSubscription {
	ret := make([]*StreamSubscription, 0, len(subs))

	for _, s := range subs {
		v, ok := s.Body.(*pbc.ClientSubscription_StreamSubscription)
		if !ok {
			panic(errInvalidSubType)
		}

		ret = append(ret, streamSubFromProto(v))
	}

	return ret
}

func tradeSubsToProto(subs []Subscription) []*pbc.ClientSubscription {
	ret := make([]*pbc.ClientSubscription, 0, len(subs))

	for _, sub := range subs {
		v, ok := sub.(*TradeSubscription)
		if !ok {
			panic(errInvalidSubType)
		}

		var auth *pbc.TradeSessionAuth

		if v.Auth != nil {
			auth = &pbc.TradeSessionAuth{
				ApiKey:        v.Auth.APIKey,
				ApiSecret:     v.Auth.APISecret,
				CustomerId:    v.Auth.CustomerID,
				KeyPassphrase: v.Auth.KeyPassphrase,
			}
		}

		ret = append(ret, &pbc.ClientSubscription{
			Body: &pbc.ClientSubscription_TradeSubscription{
				TradeSubscription: &pbc.TradeSubscription{
					MarketId: string(v.MarketID),
					Auth:     auth,
				},
			},
		})
	}

	return ret
}

func tradeSubsFromProto(subs []*pbc.ClientSubscription) []*TradeSubscription {
	ret := make([]*TradeSubscription, 0, len(subs))

	for _, s := range subs {
		v, ok := s.Body.(*pbc.ClientSubscription_TradeSubscription)
		if !ok {
			panic(errInvalidSubType)
		}

		ret = append(ret, tradeSubFromProto(v))
	}

	return ret
}

func unixMillisToTime(unixMillis int64) time.Time {
	secs := unixMillis / 1000
	ns := (unixMillis - secs*1000 /*ms*/) * 1000 /*ns*/
	return time.Unix(secs, ns)
}

// timeToUnix is like t.Unix(), but it returns 0 if t has zero value.
func timeToUnix(t time.Time) int64 {
	if t.IsZero() {
		return 0
	}

	return t.Unix()
}

func float32ToString(v float32) string {
	return strconv.FormatFloat(float64(v), 'f', -1, 32)
}

func float64ToString(v float64) string {
	return strconv.FormatFloat(float64(v), 'f', -1, 64)
}

func uint64ToString(u uint64) string {
	return strconv.FormatUint(u, 10)
}

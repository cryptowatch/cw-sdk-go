package main

import (
	"fmt"
	"strings"

	"github.com/gdamore/tcell"
	"github.com/rivo/tview"

	"code.cryptowat.ch/cw-sdk-go/common"
)

type MarketView struct {
	market MarketDescr

	app    *tview.Application
	uiFlex *tview.Flex

	statusTextView   *tview.TextView
	priceTextView    *tview.TextView
	balancesTextView *tview.TextView
	tradesList       *tview.List
	ordersList       *tview.List

	ready    bool
	trades   []common.PrivateTrade
	orders   []common.PrivateOrder
	balances common.Balances

	spread struct {
		ask common.PublicOrder
		bid common.PublicOrder
	}
}

func NewMarketView(market MarketDescr, app *tview.Application) *MarketView {
	mv := &MarketView{
		market: market,
		app:    app,
	}

	mv.statusTextView = tview.NewTextView()
	mv.priceTextView = tview.NewTextView()
	mv.balancesTextView = tview.NewTextView()
	mv.tradesList = tview.NewList().SetCurrentItem(-1).ShowSecondaryText(true)
	mv.ordersList = tview.NewList().SetCurrentItem(-1).ShowSecondaryText(true)

	mv.uiFlex = tview.NewFlex().SetDirection(tview.FlexRow).
		AddItem(mv.statusTextView, 1, 0, false).
		AddItem(
			tview.NewFrame(mv.priceTextView).
				AddText("    === Price ===", true, tview.AlignLeft, tcell.ColorYellow).
				SetBorders(0, 1, 0, 0, 0, 0),
			3, 0, false,
		).
		AddItem(
			tview.NewFrame(mv.balancesTextView).
				AddText("    === Balances ===", true, tview.AlignLeft, tcell.ColorYellow).
				SetBorders(0, 1, 0, 0, 0, 0),
			4, 0, false,
		).
		AddItem(
			tview.NewFrame(mv.ordersList).
				AddText("    === Orders ===", true, tview.AlignLeft, tcell.ColorYellow).
				SetBorders(0, 0, 0, 0, 0, 0),
			0, 1, true,
		).
		AddItem(
			tview.NewFrame(mv.tradesList).
				AddText("    === Trades ===", true, tview.AlignLeft, tcell.ColorYellow).
				SetBorders(0, 0, 0, 0, 0, 0),
			0, 1, true,
		)

	mv.uiFlex.SetBorder(true)
	mv.uiFlex.SetTitle(fmt.Sprintf("%s %s%s", market.Exchange, market.Base, market.Quote))

	mv.SetReady(false)

	return mv
}

func (mv *MarketView) SetReady(ready bool) {
	mv.app.QueueUpdateDraw(func() {
		mv.ready = ready

		statusStr := "not ready"
		if mv.ready {
			statusStr = "ready"
		}

		mv.statusTextView.SetText(fmt.Sprintf("Market client status: %s", statusStr))
	})
}

func (mv *MarketView) SetTrades(newTrades []common.PrivateTrade, add bool) {
	mv.app.QueueUpdateDraw(func() {
		if !add {
			mv.trades = nil
			mv.tradesList.Clear()
		}

		mv.trades = append(mv.trades, newTrades...)

		for _, trade := range newTrades {
			mv.tradesList.AddItem(
				fmt.Sprintf("* %s   %s", trade.Price, trade.Amount),
				fmt.Sprintf("  %s", trade.Timestamp),
				0,
				nil,
			)
		}

		mv.tradesList.SetCurrentItem(-1)
	})
}

func (mv *MarketView) SetOrders(orders []common.PrivateOrder) {
	mv.app.QueueUpdateDraw(func() {
		mv.orders = orders
		mv.ordersList.Clear()

		for _, order := range mv.orders {
			var priceStr string
			if order.OrderType == common.MarketOrder {
				priceStr = "n/a"
			} else {
				for _, p := range order.PriceParams {
					priceStr += p.Value + " "
				}
			}

			mv.ordersList.AddItem(
				fmt.Sprintf("* %s  %s", priceStr, order.Amount),
				fmt.Sprintf("  %s", order.Timestamp),
				0,
				nil,
			)
		}

		mv.ordersList.SetCurrentItem(-1)
	})
}

func (mv *MarketView) SetBalances(balances common.Balances) {
	mv.app.QueueUpdateDraw(func() {
		mv.balances = balances

		var baseBalance, quoteBalance string
		for _, b := range balances[common.SpotFunding] {
			if b.Currency == strings.ToLower(mv.market.Base) {
				baseBalance = b.Amount
			}

			switch b.Currency {
			case strings.ToLower(mv.market.Base):
				baseBalance = b.Amount
			case strings.ToLower(mv.market.Quote):
				quoteBalance = b.Amount
			}
		}

		mv.balancesTextView.SetText(fmt.Sprintf(
			"%s: %s\n%s: %s",
			mv.market.Base, baseBalance,
			mv.market.Quote, quoteBalance,
		))
	})
}

func (mv *MarketView) SetSpread(bid, ask common.PublicOrder) {
	mv.app.QueueUpdateDraw(func() {
		mv.spread.ask = ask
		mv.spread.bid = bid

		mv.priceTextView.SetText(fmt.Sprintf("  %s ... %s", bid.Price, ask.Price))
	})
}

func (mv *MarketView) FocusOrdersList(
	selectedFunc func(order common.PrivateOrder),
	cancelFunc func(),
) {
	mv.ordersList.SetCurrentItem(0)
	mv.ordersList.SetSelectedFunc(func(idx int, text string, secondaryText string, shortcut rune) {
		selectedFunc(mv.orders[idx])

		// Dirty hack to unselect an item in the list; apparently
		// SetCurrentItem(-1) hack only works on a brand new list.
		// TODO: find a better way, probably modify tview
		mv.SetOrders(mv.orders)
	})
	mv.ordersList.SetDoneFunc(func() {
		cancelFunc()

		// Dirty hack to unselect an item in the list
		// SetCurrentItem(-1) hack only works on a brand new list.
		// TODO: find a better way, probably modify tview
		mv.SetOrders(mv.orders)
	})
	mv.app.SetFocus(mv.ordersList)
}

func (mv *MarketView) GetUIPrimitive() tview.Primitive {
	return mv.uiFlex
}

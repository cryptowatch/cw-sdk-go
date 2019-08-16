package main

import (
	"github.com/rivo/tview"

	"code.cryptowat.ch/cw-sdk-go/common"
)

const (
	pageNameMarketSelector = "market_selector"
	pageNamePlaceOrderForm = "place_order_form"
	pageNameMessage        = "message"
)

type MainViewParams struct {
	App *tview.Application

	Markets []MarketDescr

	// OnPlaceOrderRequest is called whenever the user requests placing an order
	// via the UI.
	OnPlaceOrderRequest  OnPlaceOrderRequestCallback
	OnCancelOrderRequest OnCancelOrderRequestCallback
}

type OnPlaceOrderRequestCallback func(orderOpts common.PlaceOrderOpt)
type OnCancelOrderRequestCallback func(orderOpts common.CancelOrderOpt)

type MainView struct {
	params    MainViewParams
	rootPages *tview.Pages

	marketViewsByID map[common.MarketID]*MarketView
	marketDescrByID map[common.MarketID]MarketDescr
}

func NewMainView(params *MainViewParams) *MainView {
	mv := &MainView{
		params:          *params,
		marketViewsByID: map[common.MarketID]*MarketView{},
		marketDescrByID: map[common.MarketID]MarketDescr{},
	}

	rootPages := tview.NewPages()

	marketViews := []*MarketView{}

	for _, market := range mv.params.Markets {
		marketView := NewMarketView(market, mv.params.App)
		mv.marketViewsByID[market.ID] = marketView
		mv.marketDescrByID[market.ID] = market
		marketViews = append(marketViews, marketView)
	}

	mainFlex := tview.NewFlex().SetDirection(tview.FlexRow)
	columnFlex := tview.NewFlex()

	for _, mv := range marketViews {
		columnFlex.AddItem(mv.GetUIPrimitive(), 0, 1, true)
	}

	mainFlex.AddItem(columnFlex, 0, 1, false)

	var bottomForm *tview.Form
	bottomForm = tview.NewForm().
		AddButton("Place order", func() {
			msv := NewMarketSelectorView(mv, &MarketSelectorParams{
				Title: "Place order on which market?",
				OnSelected: func(marketID common.MarketID) bool {
					pov := NewPlaceOrderView(mv, &PlaceOrderViewParams{
						Market: mv.marketDescrByID[marketID],
					})

					pov.Show()
					return true
				},
			})
			msv.Show()
		}).
		AddButton("Cancel order", func() {
			msv := NewMarketSelectorView(mv, &MarketSelectorParams{
				Title: "Cancel order on which market?",
				OnSelected: func(marketID common.MarketID) bool {

					// Even though we're in the UI loop right now, we can't invoke
					// FocusOrdersList right here, because when OnSelected returns, we
					// hide the modal window, and focus will be moved back to the bottom
					// menu. We need to call FocusOrdersList _after_ that.
					mv.params.App.QueueUpdateDraw(func() {
						mv.marketViewsByID[marketID].FocusOrdersList(
							func(order common.PrivateOrder) {
								// TODO: confirm
								mv.params.OnCancelOrderRequest(common.CancelOrderOpt{
									MarketID: marketID,
									OrderID:  order.ID,
								})
								mv.params.App.SetFocus(bottomForm)
							},
							func() {
								mv.params.App.SetFocus(bottomForm)
							},
						)
					})
					return true
				},
			})
			msv.Show()
		}).
		AddButton("Enough trading", func() {
			params.App.Stop()
		})

	mainFlex.AddItem(bottomForm, 3, 1, true)

	rootPages.AddPage("mainFlex", mainFlex, true, true)

	mv.rootPages = rootPages

	return mv
}

func (mv *MainView) SetMarketReady(marketID common.MarketID, ready bool) {
	mv.marketViewsByID[marketID].SetReady(ready)
}

func (mv *MainView) SetMarketTrades(
	marketID common.MarketID, newTrades []common.PrivateTrade, add bool,
) {
	mv.marketViewsByID[marketID].SetTrades(newTrades, add)
}

func (mv *MainView) SetMarketOrders(marketID common.MarketID, orders []common.PrivateOrder) {
	mv.marketViewsByID[marketID].SetOrders(orders)
}

func (mv *MainView) SetMarketBalances(marketID common.MarketID, balances common.Balances) {
	mv.marketViewsByID[marketID].SetBalances(balances)
}

func (mv *MainView) SetMarketSpread(marketID common.MarketID, bid, ask common.PublicOrder) {
	mv.marketViewsByID[marketID].SetSpread(bid, ask)
}

func (mv *MainView) GetUIPrimitive() tview.Primitive {
	return mv.rootPages
}

func (mv *MainView) SetOnPlaceOrderRequestCallback(cb OnPlaceOrderRequestCallback) {
	mv.params.OnPlaceOrderRequest = cb
}

func (mv *MainView) SetOnCancelOrderRequestCallback(cb OnCancelOrderRequestCallback) {
	mv.params.OnCancelOrderRequest = cb
}

type MessageboxParams struct {
	Buttons         []string
	OnButtonPressed func(label string, idx int)
}

func (mv *MainView) ShowMessagebox(
	msgID, title, message string, params *MessageboxParams,
) {
	var msgvErr *MessageView

	if params == nil {
		params = &MessageboxParams{
			Buttons: []string{"OK"},
			OnButtonPressed: func(label string, idx int) {
				msgvErr.Hide()
			},
		}
	}

	mv.params.App.QueueUpdateDraw(func() {
		msgvErr = NewMessageView(mv, &MessageViewParams{
			MessageID:       msgID,
			Title:           title,
			Message:         message,
			Buttons:         params.Buttons,
			OnButtonPressed: params.OnButtonPressed,

			Width: 60,
		})
		msgvErr.Show()
	})
}

func (mv *MainView) HideMessagebox(msgID string) {
	mv.params.App.QueueUpdateDraw(func() {
		mv.hideModal(pageNameMessage + msgID)
	})
}

func (mv *MainView) showModal(name string, primitive tview.Primitive, width, height int) {
	// Returns a new primitive which puts the provided primitive in the center and
	// sets its size to the given width and height.
	modal := func(p tview.Primitive, width, height int) tview.Primitive {
		return tview.NewGrid().
			SetColumns(0, width, 0).
			SetRows(0, height, 0).
			AddItem(p, 1, 1, 1, 1, 0, 0, true)
	}

	mv.rootPages.AddPage(name, modal(primitive, width, height), true, true)

	mv.params.App.SetFocus(primitive)
}

func (mv *MainView) hideModal(name string) {
	mv.rootPages.RemovePage(name)
}

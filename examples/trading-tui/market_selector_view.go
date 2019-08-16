package main

import (
	"fmt"

	"github.com/rivo/tview"

	"code.cryptowat.ch/cw-sdk-go/common"
)

type MarketSelectorParams struct {
	Title string
	// OnSelected is a callback which is called when a market is selected.
	// It should return true if the market selector dialog should be closed.
	OnSelected func(marketID common.MarketID) bool
}

type MarketSelectorView struct {
	mainView *MainView
	list     *tview.List
}

func NewMarketSelectorView(
	mainView *MainView, params *MarketSelectorParams,
) *MarketSelectorView {
	msv := &MarketSelectorView{
		mainView: mainView,
	}

	msv.list = tview.NewList().ShowSecondaryText(false)
	msv.list.SetBorder(true).SetBorderPadding(1, 1, 1, 1).SetTitle(params.Title)
	msv.list.SetTitleAlign(tview.AlignLeft)
	msv.list.SetDoneFunc(func() {
		msv.Hide()
	})

	for _, market := range msv.mainView.params.Markets {
		// NOTE: we need to allocate it in this scope, because we use it in the
		// function literal below.
		marketID := market.ID

		msv.list.AddItem(
			fmt.Sprintf("%s %s%s", market.Exchange, market.Base, market.Quote),
			"",
			0,
			func() {
				shouldClose := params.OnSelected(marketID)
				if shouldClose {
					msv.Hide()
				}
			},
		)
	}

	return msv
}

func (msv *MarketSelectorView) Show() {
	msv.mainView.showModal(pageNameMarketSelector, msv.list, 40, 10)
}

func (msv *MarketSelectorView) Hide() {
	msv.mainView.hideModal(pageNameMarketSelector)
}

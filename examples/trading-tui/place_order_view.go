package main

import (
	"fmt"
	"strconv"

	"github.com/rivo/tview"

	"code.cryptowat.ch/cw-sdk-go/common"
)

const (
	actionIdxBuy = iota
	actionIdxSell
)

var (
	// NOTE: those should be in the order of actionIdx.... above.
	actionNames = []string{"Buy", "Sell"}
)

const (
	orderTypeIdxMarket = iota
	orderTypeIdxLimit
)

var (
	// NOTE: those should be in the order of orderTypeIdx.... above.
	orderTypeNames = []string{"Market", "Limit"}
)

const (
	labelPrice = "Price"
)

type PlaceOrderViewParams struct {
	Market MarketDescr
}

type PlaceOrderView struct {
	params   PlaceOrderViewParams
	mainView *MainView
	form     *tview.Form

	// Selected values

	actionIdx    int
	orderTypeIdx int
	amount       string
	price        string
}

func NewPlaceOrderView(
	mainView *MainView, params *PlaceOrderViewParams,
) *PlaceOrderView {
	pov := &PlaceOrderView{
		params:   *params,
		mainView: mainView,

		actionIdx:    actionIdxBuy,
		orderTypeIdx: orderTypeIdxMarket,
		amount:       "0.0",
		price:        "0.0",
	}

	pov.form = tview.NewForm()
	pov.form.SetBorder(true).SetTitle(fmt.Sprintf("Place order on %s", params.Market))
	pov.form.SetTitleAlign(tview.AlignLeft)
	pov.form.SetCancelFunc(func() {
		pov.Hide()
	})

	pov.form.AddDropDown(
		"Action", actionNames, pov.actionIdx,
		func(option string, optionIndex int) {
			pov.actionIdx = optionIndex
		},
	)

	pov.form.AddDropDown(
		"Type", orderTypeNames, pov.orderTypeIdx,
		func(option string, optionIndex int) {
			pov.orderTypeIdx = optionIndex

			pov.applyPriceField()
		},
	)

	pov.form.AddInputField(
		"Amount", pov.amount, 0,
		func(text string, lastChar rune) bool {
			_, err := strconv.ParseFloat(text, 64)
			return err == nil || err == strconv.ErrRange
		},
		func(text string) {
			pov.amount = text
		},
	)

	pov.form.AddInputField(
		labelPrice, pov.price, 0,
		func(text string, lastChar rune) bool {
			// Don't accept any changes if the order type is "Market"
			// TODO: it doesn't help when the user hits backspace.
			if pov.orderTypeIdx == orderTypeIdxMarket {
				return false
			}

			_, err := strconv.ParseFloat(text, 64)
			return err == nil || err == strconv.ErrRange
		},
		func(text string) {
			if pov.orderTypeIdx == orderTypeIdxLimit {
				pov.price = text
			}
		},
	)

	pov.applyPriceField()

	pov.form.
		AddButton("Place order", func() {
			var orderSide common.OrderSide
			switch pov.actionIdx {
			case actionIdxBuy:
				orderSide = common.BuyOrder
			case actionIdxSell:
				orderSide = common.SellOrder
			default:
				panic(fmt.Sprintf("invalid action idx: %v", pov.actionIdx))
			}

			var orderType common.OrderType
			switch pov.orderTypeIdx {
			case orderTypeIdxMarket:
				orderType = common.MarketOrder
			case orderTypeIdxLimit:
				orderType = common.LimitOrder
			default:
				panic(fmt.Sprintf("invalid order type idx: %v", pov.orderTypeIdx))
			}

			pov.mainView.params.OnPlaceOrderRequest(
				common.PlaceOrderOpt{
					PriceParams: common.PriceParams{
						&common.PriceParam{
							Value: pov.price,
							Type:  common.AbsoluteValuePrice,
						},
					},
					MarketID:    pov.params.Market.ID,
					Amount:      pov.amount,
					OrderSide:   orderSide,
					OrderType:   orderType,
					FundingType: common.SpotFunding,
				},
			)

			pov.Hide()
		}).
		AddButton("Cancel", func() {
			pov.Hide()
		})

	return pov
}

func (pov *PlaceOrderView) applyPriceField() {
	priceFormItem := pov.form.GetFormItemByLabel(labelPrice)
	priceInput := priceFormItem.(*tview.InputField)

	if pov.orderTypeIdx == orderTypeIdxMarket {
		priceInput.SetText("n/a")
	} else {
		priceInput.SetText(pov.price)
	}
}

func (pov *PlaceOrderView) Show() {
	pov.mainView.showModal(pageNamePlaceOrderForm, pov.form, 40, 13)
}

func (pov *PlaceOrderView) Hide() {
	pov.mainView.hideModal(pageNamePlaceOrderForm)
}

# Orderbook Delta Feed

This example subscribes to `markets:86:book:deltas` and shows how to use the resulting feed in conjunction with the REST API. It is recommended to hit the REST API for a full order book snapshot in case of a lost message in the delta feed. To specify a different market use the flags `--exchange` and `--pair`.

`main.go` subscribes to changes in an order book and locally applies them to a full book, making it continuously mirror the full book of the market.

`orderbook.go` contains the order book type definition, accompanying methods and some pretty-print functions.


## Run

```bash
# build the example app
make orderbook

# run the app
./bin/orderbook --exchange=kraken --pair=btceur
```

![](https://github.com/cryptowatch/cw-sdk-go/blob/master/examples/orderbook/screenshot.png?raw=true)

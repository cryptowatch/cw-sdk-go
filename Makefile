BASE_PATH := $(shell dirname $(realpath $(lastword $(MAKEFILE_LIST))))
COVER_OUT := cover.out

.DEFAULT_GOAL := help

all: clean test stream-client trade-client firehose kraken-trades orderbook print-quotes trading-tui ## Clean, run tests and build everything

stream-client: ## Build stream-client
	go build -race -o bin/stream-client ./cmd/stream-client

trade-client: ## Build trade-client
	go build -race -o bin/trade-client ./cmd/trade-client

firehose: ## Build firehose example
	go build -race -o bin/firehose ./examples/firehose

kraken-trades: ## Build kraken-trades example
	go build -race -o bin/kraken-trades ./examples/kraken-trades

orderbook: ## Build orderbook example
	go build -race -o bin/orderbook ./examples/orderbook

print-quotes: ## Build print-quotes example
	go build -race -o bin/print-quotes ./examples/print-quotes

trading-tui: ## Build trading-tui
	go build -race -o bin/trading-tui ./examples/trading-tui

test: ## Run tests
	go test -count=1 ./... -coverprofile=$(COVER_OUT)

cover: ## Show test coverage
	@if [ -f $(COVER_OUT) ]; then \
		go tool cover -func=$(COVER_OUT); \
		rm -f $(COVER_OUT); \
	else \
		echo "$(COVER_OUT) is missing. Please run 'make test'"; \
	fi

clean: ## Remove binaries
	@rm -rf bin
	@find $(BASE_PATH) -name ".DS_Store" -depth -exec rm {} \;

help: ## Show help message
	@grep -E '^[a-zA-Z_-]+:.*?## .*$$' $(MAKEFILE_LIST) | sort | awk 'BEGIN {FS = ":.*?## "}; {printf "\033[36m%-30s\033[0m %s\n", $$1, $$2}'

.PHONY: all \
        stream-client \
        trade-client \
        firehose kraken-trades \
        print-quotes orderbook \
        trading-tui \
        test cover \
        clean \
        help

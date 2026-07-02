PLUGIN_NAME    := vault-plugin-secrets-pingfederate
BIN_DIR        := bin
PLUGIN_DIR     ?= ./vault-plugins
PLUGIN_BIN     := $(BIN_DIR)/$(PLUGIN_NAME)

.PHONY: all build test test-race vet fmt fmt-check tidy clean dev-mount

all: fmt-check vet test build

build:
	@mkdir -p $(BIN_DIR)
	go build -o $(PLUGIN_BIN) ./cmd/$(PLUGIN_NAME)

test:
	go test ./...

test-race:
	go test -race ./...

vet:
	go vet ./...

fmt:
	gofmt -w .

fmt-check:
	@out=$$(gofmt -l .); if [ -n "$$out" ]; then echo "gofmt needed on:"; echo "$$out"; exit 1; fi

tidy:
	go mod tidy

clean:
	rm -rf $(BIN_DIR)

# Build the plugin into a directory a local dev Vault can register from.
# Usage: make dev-mount PLUGIN_DIR=/path/to/vault/plugins
dev-mount: build
	@mkdir -p $(PLUGIN_DIR)
	cp $(PLUGIN_BIN) $(PLUGIN_DIR)/$(PLUGIN_NAME)
	@echo "Copied $(PLUGIN_NAME) to $(PLUGIN_DIR)."
	@echo "See README.md for register + enable commands."

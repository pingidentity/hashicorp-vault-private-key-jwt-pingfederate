PLUGIN_NAME    := vault-plugin-secrets-pingfederate
BIN_DIR        := bin
PLUGIN_DIR     ?= ./vault-plugins
PLUGIN_BIN     := $(BIN_DIR)/$(PLUGIN_NAME)

# Release build targets. Override GOOS/GOARCH to cross-compile for other hosts.
RELEASE_OS     ?= linux
RELEASE_ARCH   ?= amd64
RELEASE_BIN    := $(PLUGIN_NAME)-$(RELEASE_OS)-$(RELEASE_ARCH)
# Pick whichever SHA-256 tool the host provides (Linux: sha256sum, macOS: shasum).
SHA256         := $(shell command -v sha256sum >/dev/null 2>&1 && echo "sha256sum" || echo "shasum -a 256")

.PHONY: all build test test-race vet fmt fmt-check tidy clean dev-mount release

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
	rm -f $(PLUGIN_NAME)-*-* $(PLUGIN_NAME)-*-*.sha256

# Build a release plugin binary and its SHA-256 checksum file.
# Produces, for the default linux/amd64:
#   vault-plugin-secrets-pingfederate-linux-amd64
#   vault-plugin-secrets-pingfederate-linux-amd64.sha256
# Cross-compile elsewhere with, e.g.: make release RELEASE_OS=darwin RELEASE_ARCH=arm64
release:
	GOOS=$(RELEASE_OS) GOARCH=$(RELEASE_ARCH) CGO_ENABLED=0 \
		go build -trimpath -ldflags="-s -w" -o $(RELEASE_BIN) ./cmd/$(PLUGIN_NAME)
	$(SHA256) $(RELEASE_BIN) > $(RELEASE_BIN).sha256
	@echo "Built $(RELEASE_BIN) and $(RELEASE_BIN).sha256"

# Build the plugin into a directory a local dev Vault can register from.
# Usage: make dev-mount PLUGIN_DIR=/path/to/vault/plugins
dev-mount: build
	@mkdir -p $(PLUGIN_DIR)
	cp $(PLUGIN_BIN) $(PLUGIN_DIR)/$(PLUGIN_NAME)
	@echo "Copied $(PLUGIN_NAME) to $(PLUGIN_DIR)."
	@echo "See README.md for register + enable commands."

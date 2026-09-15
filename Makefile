# xoxproxy build entrypoints. Direct `go` commands work everywhere; this
# file exists so CI and release builds are reproducible and inject version
# metadata consistently.

BINARY  := xoxproxy
MODULE  := github.com/xoxproxy/xoxproxy
VERSION ?= $(shell git describe --tags --always --dirty 2>/dev/null || echo dev)
COMMIT  ?= $(shell git rev-parse --short HEAD 2>/dev/null || echo unknown)

LDFLAGS := -s -w \
	-X $(MODULE)/internal/buildinfo.Version=$(VERSION) \
	-X $(MODULE)/internal/buildinfo.GitCommit=$(COMMIT) \
	-X $(MODULE)/internal/buildinfo.GoVersion=$(shell go version | cut -d' ' -f3)

# Frontend build tooling (Phase 8). pnpm is required locally; CI never
# builds the frontend — the committed internal/api/static/ is embedded.
WEB_DIR := web
STATIC_DIR := internal/api/static

.PHONY: build test cover lint fmt vet tidy clean web release \
	release-linux-amd64 release-linux-arm64

build: ## Build the control plane binary into ./bin
	go build -trimpath -ldflags '$(LDFLAGS)' -o bin/$(BINARY) ./cmd/$(BINARY)

web: ## Build the dashboard SPA into internal/api/static (committed)
	cd $(WEB_DIR) && pnpm install --frozen-lockfile
	cd $(WEB_DIR) && APP_VERSION=$(VERSION) pnpm run build
	rm -rf $(STATIC_DIR)
	cp -r $(WEB_DIR)/dist $(STATIC_DIR)

test: ## Run all tests with race detection
	go test -race -count=1 ./...

test-security: ## Run only the security attack suite (docs/SECURITY-TESTING.md)
	go test -count=1 -run TestSecurity ./...

cover: ## Run tests with coverage report
	go test -race -count=1 -coverprofile=coverage.out ./...
	go tool cover -func=coverage.out | tail -1

vet: ## Standard static analysis
	go vet ./...

lint: ## golangci-lint (install: https://golangci-lint.run)
	golangci-lint run

fmt: ## Format all Go sources
	gofmt -w -l .

tidy: ## Sync go.mod/go.sum
	go mod tidy

clean: ## Remove build artifacts
	rm -rf bin dist coverage.out coverage.html
	# NOTE: internal/api/static is NOT removed — it is committed source
	# (the embedded dashboard build), not a disposable artifact.

# --- release builds: static, cross-compiled for supported VPS platforms ---
# CGO is disabled by design: the SQLite driver (modernc.org/sqlite, Phase 3)
# is pure Go, so release binaries are fully static and reproducible.
# Artifacts are tarballs named the way install.sh expects:
# xoxproxy-<os>-<arch>.tar.gz containing the bare binary.
release: release-linux-amd64 release-linux-arm64 ## Build all release artifacts

release-linux-amd64:
	CGO_ENABLED=0 GOOS=linux GOARCH=amd64 \
		go build -trimpath -ldflags '$(LDFLAGS)' -o dist/xoxproxy ./cmd/$(BINARY)
	tar -czf dist/$(BINARY)-linux-amd64.tar.gz -C dist xoxproxy
	rm dist/xoxproxy

release-linux-arm64:
	CGO_ENABLED=0 GOOS=linux GOARCH=arm64 \
		go build -trimpath -ldflags '$(LDFLAGS)' -o dist/xoxproxy ./cmd/$(BINARY)
	tar -czf dist/$(BINARY)-linux-arm64.tar.gz -C dist xoxproxy
	rm dist/xoxproxy

help: ## Show available targets
	@grep -E '^[a-zA-Z_-]+:.*?## ' $(MAKEFILE_LIST) | awk 'BEGIN{FS=":.*?## "}{printf "  %-22s %s\n", $$1, $$2}'

.DEFAULT_GOAL := build

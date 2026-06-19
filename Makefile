# secret-share - build orchestrator. Prefer these targets over raw go/bun.

APP        := secret-share
PKG        := github.com/YouSysAdmin/secret-share
VERSION    := $(shell git describe --tags --always --dirty 2>/dev/null || echo devel)
LDFLAGS    := -s -w -X $(PKG)/pkg/version.Version=$(VERSION)
BIN        := bin/$(APP)
GO         ?= go
BUN        ?= bun

.PHONY: all build frontend run dev seed test test-go test-frontend lint fmt clean \
        build-linux-amd64 build-linux-arm64 build-darwin-arm64 release docker

all: build

## frontend: install deps and build the SvelteKit SPA into frontend/dist (embedded).
frontend:
	cd frontend && $(BUN) install && $(BUN) run build

## build: build the frontend then the Go binary (embeds frontend/dist).
build: frontend
	CGO_ENABLED=0 $(GO) build -ldflags "$(LDFLAGS)" -o $(BIN) ./cmd/$(APP)

## build-go: build only the Go binary (assumes frontend/dist is already built).
build-go:
	CGO_ENABLED=0 $(GO) build -ldflags "$(LDFLAGS)" -o $(BIN) ./cmd/$(APP)

build-linux-amd64: frontend
	GOOS=linux GOARCH=amd64 CGO_ENABLED=0 $(GO) build -ldflags "$(LDFLAGS)" -o bin/$(APP)-linux-amd64 ./cmd/$(APP)

build-linux-arm64: frontend
	GOOS=linux GOARCH=arm64 CGO_ENABLED=0 $(GO) build -ldflags "$(LDFLAGS)" -o bin/$(APP)-linux-arm64 ./cmd/$(APP)

build-darwin-arm64: frontend
	GOOS=darwin GOARCH=arm64 CGO_ENABLED=0 $(GO) build -ldflags "$(LDFLAGS)" -o bin/$(APP)-darwin-arm64 ./cmd/$(APP)

## release: cross-compile static binaries for the common targets.
release: build-linux-amd64 build-linux-arm64 build-darwin-arm64

## run: run the built binary with the default config.
run: build
	$(BIN) serve

## dev: run from source with the dev config (auth disabled, bolt).
dev: frontend
	$(GO) run ./cmd/$(APP) serve --config dev/config.yaml

## test: run Go and frontend tests.
test: test-go test-frontend

test-go:
	$(GO) test ./...

test-frontend:
	cd frontend && $(BUN) run test

## lint: frontend eslint (Go is covered by go vet in test).
lint:
	$(GO) vet ./...
	cd frontend && $(BUN) run lint

fmt:
	gofmt -w $(shell find . -name '*.go' -not -path './vendor/*')

## docker: build the container image.
docker:
	docker build -t $(APP):$(VERSION) -t $(APP):latest .

clean:
	rm -rf bin frontend/dist frontend/.svelte-kit

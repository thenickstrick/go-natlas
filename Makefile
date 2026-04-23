# Convenience targets. Run `make help` for a list.

GO         ?= go
BIN        := bin
VERSION    ?= $(shell git describe --tags --always --dirty 2>/dev/null || echo dev)
LDFLAGS    := -s -w -X main.Version=$(VERSION)
COMPOSE    := docker compose -f deploy/docker-compose.yml

.PHONY: help
help:
	@awk 'BEGIN {FS = ":.*##"} /^[a-zA-Z_-]+:.*##/ {printf "  \033[36m%-20s\033[0m %s\n", $$1, $$2}' $(MAKEFILE_LIST)

.PHONY: all
all: build ## Build every binary

.PHONY: build
build: $(BIN)/natlas-server $(BIN)/natlas-agent $(BIN)/natlas-admin ## Build every binary

$(BIN)/natlas-server: $(shell find cmd/natlas-server internal -name '*.go') go.mod go.sum
	@mkdir -p $(BIN)
	$(GO) build -trimpath -ldflags "$(LDFLAGS)" -o $@ ./cmd/natlas-server

$(BIN)/natlas-agent: $(shell find cmd/natlas-agent internal -name '*.go') go.mod go.sum
	@mkdir -p $(BIN)
	$(GO) build -trimpath -ldflags "$(LDFLAGS)" -o $@ ./cmd/natlas-agent

$(BIN)/natlas-admin: $(shell find cmd/natlas-admin internal -name '*.go') go.mod go.sum
	@mkdir -p $(BIN)
	$(GO) build -trimpath -ldflags "$(LDFLAGS)" -o $@ ./cmd/natlas-admin

.PHONY: test
test: ## Run all unit tests
	$(GO) test ./...

.PHONY: test-integration
test-integration: ## Run integration tests (requires docker)
	$(GO) test -tags=integration ./...

.PHONY: vet
vet: ## go vet ./...
	$(GO) vet ./...

.PHONY: lint
lint: ## Run golangci-lint if installed
	@command -v golangci-lint >/dev/null 2>&1 && golangci-lint run || echo "golangci-lint not installed; skipping"

.PHONY: tidy
tidy: ## go mod tidy
	$(GO) mod tidy

.PHONY: fmt
fmt: ## gofmt
	$(GO) fmt ./...

.PHONY: up
up: ## Start dev stack (pg, opensearch, garage, jaeger, otel, maildev, server, agent)
	$(COMPOSE) up -d --build

.PHONY: down
down: ## Stop dev stack
	$(COMPOSE) down

.PHONY: nuke
nuke: ## Stop dev stack AND delete all volumes
	$(COMPOSE) down -v

.PHONY: logs
logs: ## Tail dev stack logs
	$(COMPOSE) logs -f

.PHONY: ps
ps: ## List dev stack containers
	$(COMPOSE) ps

.PHONY: clean
clean: ## Delete build artifacts
	rm -rf $(BIN)

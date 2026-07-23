.PHONY: build clean test test-ci install help

# Binary name
BINARY_NAME=tufcli

# Build directory
BUILD_DIR=build

# Go parameters
GOCMD=go
GOBUILD=$(GOCMD) build
GOCLEAN=$(GOCMD) clean
GOTEST=$(GOCMD) test
GOGET=$(GOCMD) get
GOMOD=$(GOCMD) mod

help: ## Display this help message
	@echo "Available targets:"
	@grep -E '^[a-zA-Z_-]+:.*?## .*$$' $(MAKEFILE_LIST) | sort | awk 'BEGIN {FS = ":.*?## "}; {printf "  %-15s %s\n", $$1, $$2}'

build: ## Build the binary
	$(GOBUILD) -o $(BINARY_NAME) -v .

clean: ## Remove build artifacts
	$(GOCLEAN)
	rm -f $(BINARY_NAME)
	rm -rf $(BUILD_DIR)

test: ## Run tests
	$(GOTEST) -v ./...

test-ci: ## Run tests with race detector and coverage (CI)
	$(GOTEST) -v -race -coverprofile=coverage.out -covermode=atomic -coverpkg=./internal/... ./...

install: ## Install dependencies
	$(GOMOD) download
	$(GOMOD) tidy

run: build ## Build and run the binary
	./$(BINARY_NAME)

deps: ## Update dependencies
	$(GOGET) -u ./...
	$(GOMOD) tidy

fmt: ## Format Go code
	$(GOCMD) fmt ./...

fmt-check: ## Check Go code formatting
	@unformatted=$$(gofmt -l $$(find . -name '*.go' -not -path './vendor/*')); \
	if [ -n "$$unformatted" ]; then \
		echo "Unformatted files:"; \
		echo "$$unformatted"; \
		exit 1; \
	fi

vet: ## Run go vet
	$(GOCMD) vet ./...

lint: vet fmt-check ## Run all linters
	golangci-lint run

mod-tidy-check: ## Check that go.mod and go.sum are tidy
	$(GOMOD) tidy
	@if ! git diff --quiet go.mod go.sum; then \
		echo "go.mod or go.sum is not tidy. Run 'go mod tidy' and commit the changes."; \
		git diff go.mod go.sum; \
		exit 1; \
	fi

all: clean install build test ## Clean, install deps, build, and test

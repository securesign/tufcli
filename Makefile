.PHONY: build clean test install help

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

vet: ## Run go vet
	$(GOCMD) vet ./...

lint: ## Run golangci-lint (requires golangci-lint installed)
	golangci-lint run

all: clean install build test ## Clean, install deps, build, and test

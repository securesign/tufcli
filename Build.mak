FIPS_MODULE ?= v1.0.0

.PHONY: cross-platform
cross-platform: tufcli-darwin-arm64 tufcli-darwin-amd64 tufcli-windows ## Build all cross-platform (non-Linux) binaries

.PHONY: tufcli-darwin-arm64
tufcli-darwin-arm64: ## Build for macOS arm64 (Apple Silicon)
	env CGO_ENABLED=0 GOFIPS140=$(FIPS_MODULE) GOOS=darwin GOARCH=arm64 go build -buildvcs=false -tags=no_openssl -o tufcli_darwin_arm64 -trimpath .

.PHONY: tufcli-darwin-amd64
tufcli-darwin-amd64: ## Build for macOS amd64 (Intel)
	env CGO_ENABLED=0 GOFIPS140=$(FIPS_MODULE) GOOS=darwin GOARCH=amd64 go build -buildvcs=false -tags=no_openssl -o tufcli_darwin_amd64 -trimpath .

.PHONY: tufcli-windows
tufcli-windows: ## Build for Windows amd64
	env CGO_ENABLED=0 GOFIPS140=$(FIPS_MODULE) GOOS=windows GOARCH=amd64 go build -buildvcs=false -tags=no_openssl -o tufcli_windows_amd64.exe -trimpath .

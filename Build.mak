FIPS_MODULE ?= v1.0.0
ZIG ?= zig
ZIG_CC ?= zig-cc
ZIG_CXX ?= zig-cxx
CROSS_TAGS ?= netgo,osusergo,no_openssl

.PHONY: cross-platform
cross-platform: tufcli-darwin-arm64 tufcli-darwin-amd64 tufcli-windows ## Build all cross-platform (non-Linux) binaries

.PHONY: tufcli-darwin-arm64
tufcli-darwin-arm64: ## Build for macOS arm64 (Apple Silicon)
	env CGO_ENABLED=1 CC="$(ZIG_CC) -target aarch64-macos" CXX="$(ZIG_CXX) -target aarch64-macos" GOFIPS140=$(FIPS_MODULE) GOOS=darwin GOARCH=arm64 go build -buildvcs=false -tags=$(CROSS_TAGS) -ldflags '-s -extldflags "-undefined dynamic_lookup"' -o tufcli_darwin_arm64 -trimpath .

.PHONY: tufcli-darwin-amd64
tufcli-darwin-amd64: ## Build for macOS amd64 (Intel)
	env CGO_ENABLED=1 CC="$(ZIG_CC) -target x86_64-macos" CXX="$(ZIG_CXX) -target x86_64-macos" GOFIPS140=$(FIPS_MODULE) GOOS=darwin GOARCH=amd64 go build -buildvcs=false -tags=$(CROSS_TAGS) -ldflags '-s -extldflags "-undefined dynamic_lookup"' -o tufcli_darwin_amd64 -trimpath .

.PHONY: tufcli-windows
tufcli-windows: ## Build for Windows amd64
	env CGO_ENABLED=1 CC="$(ZIG) cc -target x86_64-windows-gnu" CXX="$(ZIG) c++ -target x86_64-windows-gnu" GOFIPS140=$(FIPS_MODULE) GOOS=windows GOARCH=amd64 go build -buildvcs=false -tags=$(CROSS_TAGS) -o tufcli_windows_amd64.exe -trimpath .

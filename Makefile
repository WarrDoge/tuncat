BINARY  ?= tuncat
GOFLAGS ?= -trimpath -ldflags="-s -w"

.DEFAULT_GOAL := help

.PHONY: help build test cross-build fmt lint clean install

help:  # Show this help
	@echo "Targets:"
	@awk 'BEGIN {FS = ":.*#"; printf ""} /^[a-zA-Z0-9_%-]+:.*?#/ { printf "  \033[36m%-18s\033[0m %s\n", $$1, $$2 }' $(MAKEFILE_LIST)
build:  # Build the binary
	go build $(GOFLAGS) -o $(BINARY) ./cmd/tuncat

test:  # Run tests
	go test -v ./...

cross-build:  # Verify Linux, macOS, and Windows builds
	GOOS=linux GOARCH=amd64 go build ./...
	GOOS=linux GOARCH=arm64 go build ./...
	GOOS=darwin GOARCH=amd64 go build ./...
	GOOS=darwin GOARCH=arm64 go build ./...
	GOOS=windows GOARCH=amd64 go build ./...

fmt:  # Format Go source files
	gofmt -w .

lint:  # Run go vet and staticcheck
	go vet ./...
	staticcheck ./...

clean:  # Remove built artifacts
	rm -f $(BINARY)

install: build  # Install binary (requires sudo)
	sudo install -m 0755 $(BINARY) /usr/local/bin/$(BINARY)

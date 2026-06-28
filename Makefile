.PHONY: build build-all remote-build test lint clean run help

# Build variables
BINARY_NAME=houndoom
BUILD_DIR=bin
PKG=./cmd/scanner
# Bundled scanner binaries for agentless remote-scan delivery.
REMOTE_DIST=internal/remote/binaries/dist
REMOTE_STAGE=$(BUILD_DIR)/remote-stage
VERSION?=1.0.0
COMMIT=$(shell git rev-parse --short HEAD 2>/dev/null || echo "unknown")
BUILD_TIME=$(shell date -u +"%Y-%m-%dT%H:%M:%SZ")
LDFLAGS=-ldflags "-X main.version=$(VERSION) -X main.commit=$(COMMIT) -X main.buildTime=$(BUILD_TIME)"

# Go parameters
GOCMD=go
GOBUILD=$(GOCMD) build
GOCLEAN=$(GOCMD) clean
GOTEST=$(GOCMD) test
GOGET=$(GOCMD) get
GOMOD=$(GOCMD) mod
GOFMT=$(GOCMD) fmt
GOVET=$(GOCMD) vet

help: ## Show this help message
	@echo 'Usage: make [target]'
	@echo ''
	@echo 'Available targets:'
	@awk 'BEGIN {FS = ":.*?## "} /^[a-zA-Z_-]+:.*?## / {printf "  %-15s %s\n", $$1, $$2}' $(MAKEFILE_LIST)

build: ## Build the binary for current platform
	@echo "Building $(BINARY_NAME)..."
	@mkdir -p $(BUILD_DIR)
	$(GOBUILD) $(LDFLAGS) -o $(BUILD_DIR)/$(BINARY_NAME) $(PKG)
	@echo "Build complete: $(BUILD_DIR)/$(BINARY_NAME)"

remote-build: ## Build native control-plane with embedded linux scanners (for remote-scan)
	@echo "Staging linux target binaries..."
	@mkdir -p $(REMOTE_STAGE) $(REMOTE_DIST)
	@# The scanner carries //go:embed dist, so the target binaries must be built
	@# while dist/ holds only the README — otherwise arm64 embeds amd64 and the
	@# artifacts bloat recursively. Stage them, then drop into dist/.
	@find $(REMOTE_DIST) -type f ! -name 'README.md' -delete
	GOOS=linux GOARCH=amd64 $(GOBUILD) $(LDFLAGS) -o $(REMOTE_STAGE)/$(BINARY_NAME)-linux-amd64 $(PKG)
	GOOS=linux GOARCH=arm64 $(GOBUILD) $(LDFLAGS) -o $(REMOTE_STAGE)/$(BINARY_NAME)-linux-arm64 $(PKG)
	@cp $(REMOTE_STAGE)/$(BINARY_NAME)-linux-* $(REMOTE_DIST)/
	@echo "Building native control-plane with embedded scanners..."
	@mkdir -p $(BUILD_DIR)
	$(GOBUILD) $(LDFLAGS) -o $(BUILD_DIR)/$(BINARY_NAME) $(PKG)
	@echo "Remote-capable build complete: $(BUILD_DIR)/$(BINARY_NAME)"
	@echo "Run: $(BUILD_DIR)/$(BINARY_NAME) remote-scan --host user@host --path /var/www --plan"

build-all: ## Build for all platforms (Linux, Windows, macOS)
	@echo "Building for all platforms..."
	@mkdir -p $(BUILD_DIR)

	@echo "Building for Linux amd64..."
	GOOS=linux GOARCH=amd64 $(GOBUILD) $(LDFLAGS) -o $(BUILD_DIR)/$(BINARY_NAME)-linux-amd64 $(PKG)

	@echo "Building for Linux arm64..."
	GOOS=linux GOARCH=arm64 $(GOBUILD) $(LDFLAGS) -o $(BUILD_DIR)/$(BINARY_NAME)-linux-arm64 $(PKG)

	@echo "Building for Windows amd64..."
	GOOS=windows GOARCH=amd64 $(GOBUILD) $(LDFLAGS) -o $(BUILD_DIR)/$(BINARY_NAME)-windows-amd64.exe $(PKG)

	@echo "Building for macOS amd64..."
	GOOS=darwin GOARCH=amd64 $(GOBUILD) $(LDFLAGS) -o $(BUILD_DIR)/$(BINARY_NAME)-darwin-amd64 $(PKG)

	@echo "Building for macOS arm64..."
	GOOS=darwin GOARCH=arm64 $(GOBUILD) $(LDFLAGS) -o $(BUILD_DIR)/$(BINARY_NAME)-darwin-arm64 $(PKG)

	@echo "Build complete for all platforms!"

test: ## Run tests
	@echo "Running tests..."
	$(GOTEST) -v -race -coverprofile=coverage.txt -covermode=atomic ./...
	@echo "Tests complete!"

test-coverage: ## Run tests with coverage report
	@echo "Running tests with coverage..."
	$(GOTEST) -v -race -coverprofile=coverage.out ./...
	$(GOCMD) tool cover -html=coverage.out -o coverage.html
	@echo "Coverage report generated: coverage.html"

bench: ## Run benchmarks
	@echo "Running benchmarks..."
	$(GOTEST) -bench=. -benchmem ./...

lint: ## Run linter
	@echo "Running linter..."
	@which golangci-lint > /dev/null || (echo "Installing golangci-lint..." && go install github.com/golangci/golangci-lint/cmd/golangci-lint@latest)
	golangci-lint run ./...
	@echo "Linting complete!"

fmt: ## Format code
	@echo "Formatting code..."
	$(GOFMT) ./...
	@echo "Formatting complete!"

vet: ## Run go vet
	@echo "Running go vet..."
	$(GOVET) ./...
	@echo "Vetting complete!"

deps: ## Download dependencies
	@echo "Downloading dependencies..."
	$(GOMOD) download
	$(GOMOD) tidy
	@echo "Dependencies downloaded!"

clean: ## Clean build artifacts
	@echo "Cleaning..."
	$(GOCLEAN)
	rm -rf $(BUILD_DIR)
	@# Drop staged scanner binaries but keep the README that holds dist/ present.
	find $(REMOTE_DIST) -type f ! -name 'README.md' -delete 2>/dev/null || true
	rm -f coverage.txt coverage.out coverage.html
	@echo "Clean complete!"

run: build ## Build and run the scanner
	@echo "Running $(BINARY_NAME)..."
	./$(BUILD_DIR)/$(BINARY_NAME) --help

run-scan: build ## Build and run a test scan
	@echo "Running test scan..."
	./$(BUILD_DIR)/$(BINARY_NAME) scan . --mode=fast

install: build ## Install the binary to GOPATH/bin
	@echo "Installing $(BINARY_NAME)..."
	cp $(BUILD_DIR)/$(BINARY_NAME) $(GOPATH)/bin/
	@echo "Installation complete!"

docker-build: ## Build Docker image
	@echo "Building Docker image..."
	docker build -t houndoom:$(VERSION) .
	@echo "Docker build complete!"

docker-run: docker-build ## Run in Docker container
	@echo "Running in Docker..."
	docker run --rm -v $(PWD):/scan houndoom:$(VERSION) scan /scan

release: ## Create a release (requires VERSION environment variable)
	@echo "Creating release $(VERSION)..."
	@mkdir -p $(BUILD_DIR)/release
	@make build-all
	@cd $(BUILD_DIR) && \
		tar -czf release/$(BINARY_NAME)-$(VERSION)-linux-amd64.tar.gz $(BINARY_NAME)-linux-amd64 && \
		tar -czf release/$(BINARY_NAME)-$(VERSION)-linux-arm64.tar.gz $(BINARY_NAME)-linux-arm64 && \
		tar -czf release/$(BINARY_NAME)-$(VERSION)-darwin-amd64.tar.gz $(BINARY_NAME)-darwin-amd64 && \
		tar -czf release/$(BINARY_NAME)-$(VERSION)-darwin-arm64.tar.gz $(BINARY_NAME)-darwin-arm64 && \
		zip -q release/$(BINARY_NAME)-$(VERSION)-windows-amd64.zip $(BINARY_NAME)-windows-amd64.exe
	@echo "Release $(VERSION) created in $(BUILD_DIR)/release/"

.DEFAULT_GOAL := help

.PHONY: build build-license-gen clean test test-coverage dev-setup fmt lint lambda-package docker-build docker-build-multiarch docs-serve help

VERSION ?= $(shell git describe --tags --always --dirty 2>/dev/null || echo "dev")
COMMIT  ?= $(shell git rev-parse --short HEAD 2>/dev/null || echo "none")
DATE    ?= $(shell date -u +"%Y-%m-%dT%H:%M:%SZ")
RELEASE_SIG ?= $(shell cat release.sig 2>/dev/null || echo "none")

LDFLAGS := -s -w \
	-X github.com/divmora/otel-aws-log-processor/pkg/version.Version=$(VERSION) \
	-X github.com/divmora/otel-aws-log-processor/pkg/version.GitCommit=$(COMMIT) \
	-X github.com/divmora/otel-aws-log-processor/pkg/version.BuildDate=$(DATE)

ifneq ($(strip $(RELEASE_SIG)),none)
LDFLAGS += -X github.com/divmora/otel-aws-log-processor/pkg/version.ReleaseSignature=$(RELEASE_SIG)
endif

# Build all binaries to bin/
build:
	@echo "Building binaries to bin/..."
	@mkdir -p bin
	@go build -ldflags="$(LDFLAGS)" -o bin/otel-aws-log-processor ./cmd/lambda
	@go build -ldflags="$(LDFLAGS)" -o bin/license-gen ./cmd/license-gen
	@echo "✓ Build complete! Binaries in ./bin/"

# Build license generator CLI
build-license-gen:
	@echo "Building license-gen CLI..."
	@mkdir -p bin
	@go build -ldflags="$(LDFLAGS)" -o bin/license-gen ./cmd/license-gen
	@echo "✓ license-gen built in ./bin/license-gen"

# Sign release metadata for binary provenance
sign-release: build-license-gen
	@bin/license-gen sign-release --version=$(VERSION) --commit=$(COMMIT) --build-date=$(DATE) --out-file=release.sig

# Clean build artifacts
clean:
	@echo "Cleaning build artifacts..."
	@rm -rf bin/ dist/
	@rm -f bootstrap lambda.zip release.sig coverage.out coverage.txt
	@echo "✓ Clean complete!"

# Run tests
test:
	@go test -v ./...

# Run tests with coverage
test-coverage:
	@go test -coverprofile=coverage.out ./...
	@go tool cover -func=coverage.out

# Build Lambda deployment package
lambda-package:
	@echo "Building Lambda bootstrap binary..."
	@mkdir -p bin
	@GOOS=linux GOARCH=arm64 CGO_ENABLED=0 go build -trimpath -ldflags="$(LDFLAGS)" -o bin/bootstrap ./cmd/lambda
	@echo "Creating Lambda deployment package..."
	@if [ -f release.sig ]; then cp release.sig bin/; cd bin && zip -j ../lambda.zip bootstrap release.sig; else cd bin && zip -j ../lambda.zip bootstrap; fi
	@echo "✓ Lambda package created: lambda.zip"

# Install development dependencies
dev-setup:
	@go mod download
	@go install golang.org/x/tools/gopls@latest

# Format code
fmt:
	@go fmt ./...

# Lint code (requires golangci-lint)
lint:
	@golangci-lint run

# Build local Docker image
docker-build:
	@docker build --provenance=false --no-cache -t otel-aws-log-processor:latest .

# Build multi-architecture Docker image
docker-build-multiarch:
	@docker buildx build --platform linux/amd64,linux/arm64 -t otel-aws-log-processor:latest .

PORT ?= 3000

# Serve documentation locally
docs-serve:
	@echo "Serving documentation at http://localhost:$(PORT)..."
	@python3 -m http.server $(PORT) --directory docs

help:
	@echo "Available targets:"
	@echo "  make build                  - Build all binaries to bin/"
	@echo "  make clean                  - Remove build artifacts"
	@echo "  make test                   - Run unit tests"
	@echo "  make test-coverage          - Run unit tests with coverage profile"
	@echo "  make lambda-package         - Build AWS Lambda zip package"
	@echo "  make dev-setup              - Install dev dependencies"
	@echo "  make fmt                    - Format Go code"
	@echo "  make lint                   - Lint Go code"
	@echo "  make docker-build           - Build Docker image locally"
	@echo "  make docker-build-multiarch - Build multi-arch Docker image"
	@echo "  make docs-serve             - Serve documentation locally on port $(PORT)"

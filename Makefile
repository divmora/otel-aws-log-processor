.PHONY: build clean test test-coverage dev-setup fmt lint lambda-package docker-build docker-build-multiarch docs-serve help

# Build all binaries to bin/
build:
	@echo "Building binaries to bin/..."
	@mkdir -p bin
	@go build -o bin/otel-aws-log-processor ./cmd/lambda
	@echo "✓ Build complete! Binaries in ./bin/"

# Clean build artifacts
clean:
	@echo "Cleaning build artifacts..."
	@rm -rf bin/ dist/
	@rm -f bootstrap lambda.zip coverage.out coverage.txt
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
	@GOOS=linux GOARCH=arm64 CGO_ENABLED=0 go build -trimpath -ldflags="-s -w" -o bin/bootstrap ./cmd/lambda
	@echo "Creating Lambda deployment package..."
	@cd bin && zip -j ../lambda.zip bootstrap
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

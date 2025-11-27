.PHONY: help build test clean migrate-build example-build all install-deps

# Default target
help:
	@echo "Available targets:"
	@echo "  make build           - Build the migration CLI tool"
	@echo "  make test            - Run tests"
	@echo "  make clean           - Clean build artifacts"
	@echo "  make migrate-build   - Build migration tool"
	@echo "  make example-build   - Build example application"
	@echo "  make all             - Build everything"
	@echo "  make install-deps    - Download dependencies"

# Download dependencies
install-deps:
	go mod download
	go mod tidy

# Build migration tool
migrate-build:
	@echo "Building migration tool..."
	cd cmd/goauthx-migrate && go build -o ../../bin/goauthx-migrate

# Build example
example-build:
	@echo "Building example..."
	cd examples/basic-nethttp && go build -o ../../bin/example-app

# Build all
build: migrate-build example-build
	@echo "Build complete!"

# Build everything
all: install-deps build
	@echo "All done!"

# Run tests
test:
	go test -v -race ./...

# Clean build artifacts
clean:
	rm -rf bin/
	go clean

# Format code
fmt:
	go fmt ./...

# Run linter (requires golangci-lint)
lint:
	golangci-lint run

# Generate documentation
docs:
	@echo "Documentation is in docs/ directory"
	@echo "View README.md for quick start"

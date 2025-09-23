# Makefile for go-which-pgp
# Variables
GO := go
GOLANGCI_LINT := golangci-lint
TIMEOUT := 30s
FUZZ_TIME := 1m
PACKAGE := ./...

# Default target
.DEFAULT_GOAL := help

# Help target - shows available commands
.PHONY: help
help: ## Show this help message
	@echo "Available targets:"
	@grep -E '^[a-zA-Z_-]+:.*?## .*$$' $(MAKEFILE_LIST) | awk 'BEGIN {FS = ":.*?## "}; {printf "  \033[36m%-15s\033[0m %s\n", $$1, $$2}'

# Test targets
.PHONY: test
test: test-unit test-race test-lint test-fuzz ## Run all tests (unit, race, lint, fuzz)

.PHONY: test-unit
test-unit: ## Run unit tests with coverage
	@echo "Running unit tests with coverage..."
	$(GO) test -v -cover -timeout $(TIMEOUT) $(PACKAGE)

.PHONY: test-race
test-race: ## Run tests with race condition detection
	@echo "Running tests with race condition detection..."
	$(GO) test -race -v -timeout $(TIMEOUT) $(PACKAGE)

.PHONY: test-lint
test-lint: ## Run linter checks
	@echo "Running linter checks..."
	$(GOLANGCI_LINT) run

.PHONY: test-fuzz
test-fuzz: ## Run fuzzing tests for 1 minute
	@echo "Running fuzzing tests for $(FUZZ_TIME)..."
	@echo "Testing FuzzDetectFlavorFromArmor..."
	$(GO) test -fuzz=FuzzDetectFlavorFromArmor -fuzztime=$(FUZZ_TIME) ./whichpgp
	@echo "Testing FuzzDetectFlavorFromBytes..."
	$(GO) test -fuzz=FuzzDetectFlavorFromBytes -fuzztime=$(FUZZ_TIME) ./whichpgp
	@echo "Testing FuzzDetectFlavorFromReader..."
	$(GO) test -fuzz=FuzzDetectFlavorFromReader -fuzztime=$(FUZZ_TIME) ./whichpgp
	@echo "Testing FuzzDetectFlavorFromString..."
	$(GO) test -fuzz=FuzzDetectFlavorFromString -fuzztime=$(FUZZ_TIME) ./whichpgp

.PHONY: test-fuzz-short
test-fuzz-short: ## Run short fuzzing tests (10 seconds each)
	@echo "Running short fuzzing tests..."
	@echo "Testing FuzzDetectFlavorFromArmor..."
	$(GO) test -fuzz=FuzzDetectFlavorFromArmor -fuzztime=10s ./whichpgp
	@echo "Testing FuzzDetectFlavorFromBytes..."
	$(GO) test -fuzz=FuzzDetectFlavorFromBytes -fuzztime=10s ./whichpgp
	@echo "Testing FuzzDetectFlavorFromReader..."
	$(GO) test -fuzz=FuzzDetectFlavorFromReader -fuzztime=10s ./whichpgp
	@echo "Testing FuzzDetectFlavorFromString..."
	$(GO) test -fuzz=FuzzDetectFlavorFromString -fuzztime=10s ./whichpgp

# Individual test components for debugging
.PHONY: test-examples
test-examples: ## Run only example tests
	@echo "Running example tests..."
	$(GO) test -run Example -v ./whichpgp

.PHONY: test-coverage
test-coverage: ## Generate detailed test coverage report
	@echo "Generating test coverage report..."
	$(GO) test -coverprofile=coverage.out $(PACKAGE)
	$(GO) tool cover -html=coverage.out -o coverage.html
	@echo "Coverage report generated: coverage.html"

# Utility targets
.PHONY: clean
clean: ## Clean test artifacts and coverage files
	@echo "Cleaning test artifacts..."
	$(GO) clean -testcache
	rm -f coverage.out coverage.html

.PHONY: deps
deps: ## Download and verify dependencies
	@echo "Downloading dependencies..."
	$(GO) mod download
	$(GO) mod verify

.PHONY: tidy
tidy: ## Clean up go.mod and go.sum
	@echo "Tidying go modules..."
	$(GO) mod tidy

# Quality assurance targets
.PHONY: qa
qa: deps tidy test ## Run full quality assurance (deps, tidy, all tests)

.PHONY: ci
ci: test ## Run CI pipeline (all tests)

# Check if tools are installed
.PHONY: check-tools
check-tools: ## Check if required tools are installed
	@echo "Checking required tools..."
	@command -v $(GO) >/dev/null 2>&1 || { echo "Go is not installed. Please install Go."; exit 1; }
	@command -v $(GOLANGCI_LINT) >/dev/null 2>&1 || { echo "golangci-lint is not installed. Please install golangci-lint."; exit 1; }
	@echo "All required tools are installed."
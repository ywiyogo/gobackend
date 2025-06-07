.PHONY: build, run, test, test-unit, test-integration, test-integration-verbose, test-integration-coverage, setup-test-env, cleanup-test-env

build:
	@go mod tidy
	@sqlc generate
	@mkdir -p tmp
	@go build -o tmp/main main.go

run:
	@./tmp/main

test: test-unit test-integration

test-unit:
	@echo "Running unit tests..."
	@go test ./internal/... -v

test-integration:
	@echo "Running Docker-based integration tests..."
	@./test/run-docker.sh integration

test-integration-verbose:
	@echo "Running Docker-based integration tests (verbose)..."
	@./test/run-docker.sh -v integration

test-integration-coverage:
	@echo "Running Docker-based integration tests with coverage..."
	@./test/run-docker.sh integration-coverage

setup-test-env:
	@echo "Setting up Docker test environment..."
	@./test/setup-docker.sh

cleanup-test-env:
	@echo "Cleaning up Docker test environment..."
	@./test/setup-docker.sh --cleanup
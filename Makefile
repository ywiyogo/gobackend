.PHONY: build, run, test, unit-test, integration-test, integration-test-verbose, integration-test-coverage, setup-test-env, cleanup-test-env, migrate-up, migrate-down, migrate-status

build:
	@go mod tidy
	@mkdir -p tmp
	@go build -o tmp/main main.go

build-prod:
	@go mod tidy
	@mkdir -p tmp
	@CGO_ENABLED=0 GOOS=linux GOARCH=amd64 GOAMD64=v3 go build -o tmp/gobackend main.go

run:
	@./tmp/main

test: unit-test integration-test

unit-test:
	@echo "Running unit tests..."
	@go test ./internal/... -v

integration-test:
	@echo "Running Docker-based integration tests..."
	@./test/run-docker.sh integration

integration-test-verbose:
	@echo "Running Docker-based integration tests (verbose)..."
	@./test/run-docker.sh -v integration

integration-test-coverage:
	@echo "Running Docker-based integration tests with coverage..."
	@./test/run-docker.sh integration-coverage

integration-test-single:
	@echo "Running single integration test: $(TEST_NAME)..."
	@./test/run-docker.sh integration $(TEST_NAME)

integration-test-single-verbose:
	@echo "Running single integration test (verbose): $(TEST_NAME)..."
	@./test/run-docker.sh -v integration $(TEST_NAME)

setup-test-env:
	@echo "Setting up Docker test environment..."
	@./test/setup-docker.sh

cleanup-test-env:
	@echo "Cleaning up Docker test environment..."
	@./test/setup-docker.sh --cleanup

# Migration targets
migrate-up:
	@echo "Running database migrations..."
	@docker compose up migrate --remove-orphans

migrate-down:
	@echo "Rolling back last migration..."
	@docker compose --profile tools up migrate-down --remove-orphans

migrate-status:
	@echo "Checking migration status..."
	@docker compose exec -T db psql -U $${DB_USER:-postgres} -d $${DB_NAME:-go_multitenant} -c "SELECT version, dirty FROM schema_migrations ORDER BY version DESC LIMIT 5;"

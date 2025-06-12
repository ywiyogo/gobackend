.PHONY: build, run, test, test-unit, test-integration, test-integration-verbose, test-integration-coverage, setup-test-env, cleanup-test-env, migrate-up, migrate-down, migrate-status

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

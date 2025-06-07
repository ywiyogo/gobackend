#!/bin/bash

# Docker-based Test Environment Setup Script
# This script uses Docker Compose to set up a consistent test environment

set -e

# Colors for output
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
BLUE='\033[0;34m'
NC='\033[0m' # No Color

# Function to print colored output
print_status() {
    echo -e "${BLUE}[INFO]${NC} $1"
}

print_success() {
    echo -e "${GREEN}[SUCCESS]${NC} $1"
}

print_warning() {
    echo -e "${YELLOW}[WARNING]${NC} $1"
}

print_error() {
    echo -e "${RED}[ERROR]${NC} $1"
}

# Function to check if a command exists
command_exists() {
    command -v "$1" >/dev/null 2>&1
}

# Function to check if Docker daemon is running
check_docker() {
    if docker info >/dev/null 2>&1; then
        return 0
    else
        return 1
    fi
}

# Function to cleanup Docker services
cleanup() {
    print_status "Cleaning up Docker services..."
    cd "$(dirname "$0")/.."
    docker-compose down --volumes >/dev/null 2>&1 || true
    print_success "Cleanup complete"
}

# Main setup function
main() {
    print_status "Setting up Docker-based test environment for Go backend..."
    
    # Navigate to project root
    cd "$(dirname "$0")/.."
    
    # Check required tools
    print_status "Checking required tools..."
    
    if ! command_exists docker; then
        print_error "Docker is not installed"
        echo "Please install Docker first:"
        echo "  https://docs.docker.com/get-docker/"
        exit 1
    fi
    
    if ! command_exists docker-compose; then
        print_error "Docker Compose is not installed"
        echo "Please install Docker Compose first:"
        echo "  https://docs.docker.com/compose/install/"
        exit 1
    fi
    
    if ! check_docker; then
        print_error "Docker daemon is not running"
        echo "Please start Docker first"
        exit 1
    fi
    
    print_success "Docker tools are available"
    print_success "Docker daemon is running"
    
    # Check if .env file exists
    if [ ! -f .env ]; then
        print_error ".env file not found in project root"
        echo "Please create a .env file with database configuration"
        echo "Example:"
        echo "DB_USER=postgres"
        echo "DB_PASSWORD=postgres2025"
        echo "DB_NAME=gobackend"
        echo "DB_HOST=db"
        echo "DB_PORT=5432"
        echo "OTP_ENABLED=false"
        echo "ENV=development"
        exit 1
    fi
    
    print_success ".env file found"
    
    # Load environment variables
    print_status "Loading environment variables..."
    set -a
    source .env
    set +a
    
    # Validate required environment variables
    if [ -z "$DB_USER" ] || [ -z "$DB_PASSWORD" ] || [ -z "$DB_NAME" ]; then
        print_error "Required database environment variables are missing"
        echo "Please ensure DB_USER, DB_PASSWORD, and DB_NAME are set in .env file"
        exit 1
    fi
    
    # Stop any existing containers
    print_status "Stopping any existing containers..."
    docker-compose down --volumes >/dev/null 2>&1 || true
    
    # Start Docker Compose services (database only for tests)
    print_status "Starting Docker Compose database service..."
    
    if ! docker-compose up -d db; then
        print_error "Failed to start database service"
        docker-compose logs db
        exit 1
    fi
    
    # Wait for database to be ready
    print_status "Waiting for database to be ready..."
    
    timeout=60
    counter=0
    
    while [ $counter -lt $timeout ]; do
        if docker-compose exec -T db pg_isready -U "$DB_USER" -d "$DB_NAME" >/dev/null 2>&1; then
            print_success "Database is ready and accepting connections"
            break
        fi
        
        print_status "Waiting for database... ($counter/$timeout seconds)"
        sleep 2
        counter=$((counter + 2))
    done
    
    if [ $counter -ge $timeout ]; then
        print_error "Database failed to start within $timeout seconds"
        echo "Docker logs:"
        docker-compose logs db
        cleanup
        exit 1
    fi
    
    # Test database connection
    print_status "Testing database connection..."
    if docker-compose exec -T db psql -U "$DB_USER" -d "$DB_NAME" -c "SELECT 1;" >/dev/null 2>&1; then
        print_success "Database connection test successful"
    else
        print_error "Database connection test failed"
        docker-compose logs db
        cleanup
        exit 1
    fi
    
    # Install Go dependencies
    print_status "Installing Go dependencies..."
    if go mod download; then
        print_success "Go dependencies installed successfully"
    else
        print_error "Failed to install Go dependencies"
        cleanup
        exit 1
    fi
    
    # Run database migrations
    print_status "Running database migrations..."
    if command_exists migrate; then
        migrate_cmd="migrate -path internal/db/migrations -database \"postgres://${DB_USER}:${DB_PASSWORD}@localhost:5432/${DB_NAME}?sslmode=disable\" up"
        if eval "$migrate_cmd"; then
            print_success "Database migrations completed successfully"
        else
            print_error "Database migrations failed"
            cleanup
            exit 1
        fi
    else
        print_warning "golang-migrate not found. Installing it..."
        if go install -tags 'postgres' github.com/golang-migrate/migrate/v4/cmd/migrate@latest; then
            print_success "golang-migrate installed successfully"
            migrate_cmd="migrate -path internal/db/migrations -database \"postgres://${DB_USER}:${DB_PASSWORD}@localhost:5432/${DB_NAME}?sslmode=disable\" up"
            if eval "$migrate_cmd"; then
                print_success "Database migrations completed successfully"
            else
                print_error "Database migrations failed"
                cleanup
                exit 1
            fi
        else
            print_error "Failed to install golang-migrate"
            cleanup
            exit 1
        fi
    fi
    
    # Generate database code if sqlc is available
    if command_exists sqlc; then
        print_status "Generating database code with SQLC..."
        if sqlc generate; then
            print_success "SQLC generation successful"
        else
            print_error "SQLC generation failed"
            cleanup
            exit 1
        fi
    else
        print_warning "SQLC not found. Database code generation skipped"
        print_status "Install with: go install github.com/kyleconroy/sqlc/cmd/sqlc@latest"
    fi
    
    # Update environment variables for localhost access
    export DB_HOST=localhost
    
    print_success "Docker-based test environment setup complete!"
    echo ""
    print_status "Database is running on localhost:5432"
    print_status "Container name: $(docker-compose ps -q db)"
    echo ""
    print_status "You can now run tests with:"
    echo "  make test-integration"
    echo "  make test-integration-verbose"
    echo "  ./test/run-docker.sh"
    echo ""
    print_status "To stop the database when done:"
    echo "  docker-compose down"
    echo "  make cleanup-test-env"
    echo ""
    print_warning "Note: The database will continue running until you stop it"
}

# Handle cleanup on script exit if running in cleanup mode
if [ "$1" = "--cleanup" ]; then
    cleanup
    exit 0
fi

# Handle script interruption
trap cleanup INT TERM

# Run main function
main "$@"
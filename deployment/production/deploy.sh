#!/bin/bash

# =============================================================================
# Simple Production Deployment Script for Go Backend
# =============================================================================

set -e  # Exit on any error

# Colors for output
RED='\033[0;31m'
GREEN='\033[0;32m'
BLUE='\033[0;34m'
NC='\033[0m' # No Color

# Configuration
SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
PROJECT_ROOT="$(cd "${SCRIPT_DIR}/../.." && pwd)"

# Default values
HEALTH_CHECK_TIMEOUT=30

# Helper Functions
log_info() {
    echo -e "${BLUE}[INFO]${NC} $1"
}

log_success() {
    echo -e "${GREEN}[SUCCESS]${NC} $1"
}

log_error() {
    echo -e "${RED}[ERROR]${NC} $1"
}

print_banner() {
    echo -e "${BLUE}"
    echo "================================"
    echo "  Production Deployment"
    echo "================================"
    echo -e "${NC}"
}

check_prerequisites() {
    log_info "Checking prerequisites..."

    # Check required commands
    for cmd in docker git; do
        if ! command -v "$cmd" &> /dev/null; then
            log_error "$cmd is required but not installed."
            exit 1
        fi
    done

    # Check if Docker Compose is available (modern way)
    if ! docker compose version &> /dev/null; then
        log_error "Docker Compose is required but not available."
        log_error "Make sure Docker Compose plugin is installed."
        exit 1
    fi

    # Check if .env file exists
    if [[ ! -f ".env" ]]; then
        log_error "Environment file not found. Please copy .env.example to .env"
        exit 1
    fi

    log_success "Prerequisites check passed"
}

pull_latest_changes() {
    log_info "Pulling latest changes..."
    cd "${PROJECT_ROOT}"
    git pull origin master
    log_success "Code updated"
}

pull_and_deploy() {
    log_info "Pulling and deploying..."

    # Ensure we're in the right directory for docker compose
    cd "$SCRIPT_DIR"

    # Stop existing containers
    docker compose down || true

    # Pull latest image and start
    docker compose pull backend
    docker compose up -d

    log_success "Services started"
}

health_check() {
    log_info "Checking health..."

    local count=0
    while [[ $count -lt $HEALTH_CHECK_TIMEOUT ]]; do
        if curl -f -s "http://localhost/health" > /dev/null 2>&1; then
            log_success "Health check passed"
            return 0
        fi
        count=$((count + 1))
        echo -n "."
        sleep 1
    done

    echo
    log_error "Health check failed"
    docker compose ps
    docker compose logs --tail=10
    exit 1
}

show_deployment_info() {
    log_success "Deployment completed!"
    echo
    docker compose ps
    echo
    log_info "Useful commands:"
    echo "  View logs:     docker compose logs -f"
    echo "  Restart:       docker compose restart"
    echo "  Stop:          docker compose down"
}

# Main function
main() {
    print_banner

    echo
    read -p "Deploy to PRODUCTION? (y/N): " -n 1 -r
    echo
    if [[ ! $REPLY =~ ^[Yy]$ ]]; then
        log_info "Deployment cancelled"
        exit 0
    fi

    # Simple deployment steps
    check_prerequisites
    pull_latest_changes
    pull_and_deploy
    health_check
    show_deployment_info

    log_success "🚀 Production deployment completed!"
}

# Run deployment
cd "$SCRIPT_DIR"
main "$@"

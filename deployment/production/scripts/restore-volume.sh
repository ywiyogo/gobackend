#!/bin/bash

# =============================================================================
# PostgreSQL Volume Restore Script
# Restores PostgreSQL data volume from a tar.gz backup file
# =============================================================================

set -e  # Exit on any error

# Colors for output
RED='\033[0;31m'
GREEN='\033[0;32m'
BLUE='\033[0;34m'
YELLOW='\033[1;33m'
NC='\033[0m' # No Color

# Configuration
SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
BACKUP_DIR="${SCRIPT_DIR}/../backups"
COMPOSE_DIR="${SCRIPT_DIR}/.."
VOLUME_NAME="production_gobackend-pgdata"

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

log_warning() {
    echo -e "${YELLOW}[WARNING]${NC} $1"
}

print_banner() {
    echo -e "${BLUE}"
    echo "================================"
    echo "  PostgreSQL Volume Restore"
    echo "================================"
    echo -e "${NC}"
}

# Confirm action
confirm_restore() {
    local backup_file="$1"

    echo -e "${YELLOW}WARNING: This will completely replace the current database with the backup!${NC}"
    echo "Backup file: $backup_file"
    echo "Target volume: $VOLUME_NAME"
    echo
    read -p "Are you sure you want to continue? (yes/no): " -r
    echo

    if [[ ! $REPLY =~ ^[Yy][Ee][Ss]$ ]]; then
        log_info "Restore cancelled by user"
        exit 0
    fi
}

# Stop services that use the database
stop_services() {
    log_info "Stopping services that use the database..."

    cd "$COMPOSE_DIR"

    # Stop backend service
    if docker compose ps backend --format json | jq -e '.State == "running"' > /dev/null 2>&1; then
        log_info "Stopping backend service..."
        docker compose stop backend
    fi

    # Stop database service
    if docker compose ps db --format json | jq -e '.State == "running"' > /dev/null 2>&1; then
        log_info "Stopping database service..."
        docker compose stop db
    fi

    log_success "Services stopped"
}

# Start services after restore
start_services() {
    log_info "Starting services..."

    cd "$COMPOSE_DIR"

    # Start database first
    log_info "Starting database service..."
    docker compose up db -d

    # Wait for database to be healthy
    log_info "Waiting for database to be ready..."
    timeout=60
    while [ $timeout -gt 0 ]; do
        if docker compose ps db --format json | jq -e '.Health == "healthy"' > /dev/null 2>&1; then
            log_success "Database is healthy"
            break
        fi
        sleep 2
        timeout=$((timeout - 2))
    done

    if [ $timeout -le 0 ]; then
        log_error "Database failed to become healthy within timeout"
        exit 1
    fi

    # Start backend service
    log_info "Starting backend service..."
    docker compose up backend -d

    log_success "Services started"
}

# Main restore function
restore_volume() {
    local backup_file="$1"

    print_banner

    log_info "Starting PostgreSQL volume restore..."

    # Validate backup file
    if [[ ! -f "$backup_file" ]]; then
        log_error "Backup file not found: $backup_file"
        exit 1
    fi

    # Check if it's a tar.gz file
    if ! file "$backup_file" | grep -q "gzip compressed"; then
        log_error "Backup file is not a valid gzip archive"
        exit 1
    fi

    # Get backup file info
    BACKUP_SIZE=$(du -h "$backup_file" | cut -f1)
    log_info "Backup file: $backup_file"
    log_info "Backup size: $BACKUP_SIZE"

    # Confirm restore
    confirm_restore "$backup_file"

    # Stop services
    stop_services

    # Remove existing volume
    log_info "Removing existing volume: $VOLUME_NAME"
    if docker volume inspect "$VOLUME_NAME" > /dev/null 2>&1; then
        docker volume rm "$VOLUME_NAME"
        log_success "Existing volume removed"
    else
        log_warning "Volume $VOLUME_NAME does not exist, creating new one"
    fi

    # Create new volume
    log_info "Creating new volume: $VOLUME_NAME"
    docker volume create "$VOLUME_NAME"

    # Restore data from backup
    log_info "Restoring data from backup..."
    docker run --rm \
        -v "$VOLUME_NAME":/data \
        -v "$(dirname "$backup_file")":/backup \
        alpine:latest \
        tar xzf "/backup/$(basename "$backup_file")" -C /data

    log_success "Data restored from backup"

    # Start services
    start_services

    log_success "Volume restore completed successfully!"
}

# List available backups
list_backups() {
    echo -e "${BLUE}Available backups:${NC}"
    echo

    if ls "$BACKUP_DIR"/postgres_volume_backup_*.tar.gz > /dev/null 2>&1; then
        ls -lh "$BACKUP_DIR"/postgres_volume_backup_*.tar.gz | while read -r line; do
            echo "  $line"
        done
    else
        log_warning "No backups found in $BACKUP_DIR"
    fi
}

# Show usage
show_usage() {
    echo "Usage: $0 [OPTIONS] [BACKUP_FILE]"
    echo ""
    echo "Options:"
    echo "  --list              List available backup files"
    echo "  --help              Show this help message"
    echo ""
    echo "Arguments:"
    echo "  BACKUP_FILE         Path to backup file (relative to backups/ directory)"
    echo ""
    echo "Examples:"
    echo "  $0 postgres_volume_backup_20241214_120000.tar.gz"
    echo "  $0 --list"
    echo "  $0 /full/path/to/backup.tar.gz"
}

# Main function
main() {
    local backup_file=""

    # Parse command line arguments
    while [[ $# -gt 0 ]]; do
        case $1 in
            --list)
                list_backups
                exit 0
                ;;
            --help)
                show_usage
                exit 0
                ;;
            -*)
                log_error "Unknown option: $1"
                show_usage
                exit 1
                ;;
            *)
                backup_file="$1"
                shift
                ;;
        esac
    done

    # Check if backup file is provided
    if [[ -z "$backup_file" ]]; then
        log_error "Backup file is required"
        echo
        show_usage
        exit 1
    fi

    # Handle relative paths (assume it's in backups directory)
    if [[ "$backup_file" != /* ]]; then
        backup_file="$BACKUP_DIR/$backup_file"
    fi

    # Change to compose directory
    cd "$COMPOSE_DIR"

    # Run restore
    restore_volume "$backup_file"

    echo
    log_success "🔄 Volume restore completed!"
    echo "  Database has been restored from: $(basename "$backup_file")"
    echo ""
    echo "You can now access your application at:"
    echo "  http://localhost:8090"
}

# Run main function
main "$@"

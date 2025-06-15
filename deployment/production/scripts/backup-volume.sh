#!/bin/bash

# =============================================================================
# PostgreSQL Volume Backup Script
# Backs up the entire PostgreSQL data volume to a tar.gz file
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
TIMESTAMP=$(date +%Y%m%d_%H%M%S)
BACKUP_FILE="postgres_volume_backup_${TIMESTAMP}.tar.gz"

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
    echo "  PostgreSQL Volume Backup"
    echo "================================"
    echo -e "${NC}"
}

# Main backup function
backup_volume() {
    print_banner

    log_info "Starting PostgreSQL volume backup..."

    # Create backup directory if it doesn't exist
    mkdir -p "$BACKUP_DIR"

    # Check if volume exists
    if ! docker volume inspect "$VOLUME_NAME" > /dev/null 2>&1; then
        log_error "Volume $VOLUME_NAME does not exist!"
        exit 1
    fi

    log_info "Backing up volume: $VOLUME_NAME"
    log_info "Backup file: $BACKUP_FILE"

    # Create backup using temporary container
    docker run --rm \
        -v "$VOLUME_NAME":/data \
        -v "$BACKUP_DIR":/backup \
        alpine:latest \
        tar czf "/backup/$BACKUP_FILE" -C /data .

    # Verify backup was created
    if [[ -f "$BACKUP_DIR/$BACKUP_FILE" ]]; then
        BACKUP_SIZE=$(du -h "$BACKUP_DIR/$BACKUP_FILE" | cut -f1)
        log_success "Backup completed successfully!"
        log_info "Backup location: $BACKUP_DIR/$BACKUP_FILE"
        log_info "Backup size: $BACKUP_SIZE"
    else
        log_error "Backup failed - file not created"
        exit 1
    fi

    # List recent backups
    echo
    log_info "Recent backups:"
    ls -lh "$BACKUP_DIR"/postgres_volume_backup_*.tar.gz 2>/dev/null | tail -5 || log_warning "No previous backups found"
}

# Show usage
show_usage() {
    echo "Usage: $0 [OPTIONS]"
    echo ""
    echo "Options:"
    echo "  --help              Show this help message"
    echo ""
    echo "Examples:"
    echo "  $0                  # Create backup with timestamp"
}

# Main function
main() {
    # Parse command line arguments
    while [[ $# -gt 0 ]]; do
        case $1 in
            --help)
                show_usage
                exit 0
                ;;
            *)
                log_error "Unknown option: $1"
                show_usage
                exit 1
                ;;
        esac
    done

    # Change to compose directory
    cd "$COMPOSE_DIR"

    # Run backup
    backup_volume

    echo
    log_success "🗄️  Volume backup completed!"
    echo "  Location: $BACKUP_DIR/$BACKUP_FILE"
    echo ""
    echo "To restore this backup, use:"
    echo "  ./scripts/restore-volume.sh $BACKUP_FILE"
}

# Run main function
main "$@"

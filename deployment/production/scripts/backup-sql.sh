#!/bin/bash

# =============================================================================
# PostgreSQL SQL Dump Backup Script
# Creates logical backups using pg_dump with compression and metadata
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
TIMESTAMP=$(date +%Y%m%d_%H%M%S)
BACKUP_FILE="postgres_dump_${TIMESTAMP}.sql.gz"
METADATA_FILE="postgres_dump_${TIMESTAMP}.metadata.json"
CONTAINER_NAME="production-db-1"

# Load environment variables
if [[ -f "${COMPOSE_DIR}/.env" ]]; then
    set -a
    source "${COMPOSE_DIR}/.env"
    set +a
else
    echo -e "${RED}[ERROR]${NC} .env file not found at ${COMPOSE_DIR}/.env"
    exit 1
fi

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
    echo "  PostgreSQL SQL Dump Backup"
    echo "================================"
    echo -e "${NC}"
}

# Check prerequisites
check_prerequisites() {
    log_info "Checking prerequisites..."

    # Check if docker is available
    if ! command -v docker &> /dev/null; then
        log_error "Docker is required but not installed"
        exit 1
    fi

    # Check if container is running
    if ! docker ps --format "table {{.Names}}" | grep -q "^${CONTAINER_NAME}$"; then
        log_error "Database container '${CONTAINER_NAME}' is not running"
        log_info "Start the database with: docker compose up db -d"
        exit 1
    fi

    # Check if container is healthy
    HEALTH_STATUS=$(docker inspect --format='{{.State.Health.Status}}' "${CONTAINER_NAME}" 2>/dev/null || echo "none")
    if [[ "$HEALTH_STATUS" != "healthy" && "$HEALTH_STATUS" != "none" ]]; then
        log_warning "Database container is not healthy (status: ${HEALTH_STATUS})"
        log_warning "Proceeding anyway, but backup might fail"
    fi

    log_success "Prerequisites check passed"
}

# Create backup metadata
create_metadata() {
    local backup_file="$1"
    local backup_size="$2"

    log_info "Creating backup metadata..."

    # Get database info
    DB_VERSION=$(docker exec "${CONTAINER_NAME}" psql -U "${DB_USER}" -d "${DB_NAME}" -t -c "SELECT version();" | xargs)
    DB_SIZE=$(docker exec "${CONTAINER_NAME}" psql -U "${DB_USER}" -d "${DB_NAME}" -t -c "SELECT pg_size_pretty(pg_database_size('${DB_NAME}'));" | xargs)
    TABLE_COUNT=$(docker exec "${CONTAINER_NAME}" psql -U "${DB_USER}" -d "${DB_NAME}" -t -c "SELECT COUNT(*) FROM information_schema.tables WHERE table_schema = 'public';" | xargs)

    # Create metadata JSON
    cat > "${BACKUP_DIR}/${METADATA_FILE}" << EOF
{
    "backup_info": {
        "timestamp": "${TIMESTAMP}",
        "date": "$(date -u +%Y-%m-%dT%H:%M:%SZ)",
        "backup_file": "${backup_file}",
        "backup_size": "${backup_size}",
        "backup_type": "plain_sql_dump",
        "compression": "gzip"
    },
    "database_info": {
        "host": "${DB_HOST}",
        "port": ${DB_PORT},
        "database": "${DB_NAME}",
        "user": "${DB_USER}",
        "version": "${DB_VERSION}",
        "size": "${DB_SIZE}",
        "table_count": ${TABLE_COUNT}
    },
    "environment": {
        "app_env": "${APP_ENV:-unknown}",
        "container_name": "${CONTAINER_NAME}",
        "script_version": "1.0"
    }
}
EOF

    log_success "Metadata created: ${METADATA_FILE}"
}

# Main backup function
backup_sql() {
    print_banner

    log_info "Starting PostgreSQL SQL dump backup..."

    # Create backup directory
    mkdir -p "$BACKUP_DIR"

    log_info "Database: ${DB_NAME}@${DB_HOST}:${DB_PORT}"
    log_info "User: ${DB_USER}"
    log_info "Backup file: ${BACKUP_FILE}"

    # Perform backup with pg_dump
    # Using plain SQL format with gzip compression for maximum compatibility
    # Plain format works across PostgreSQL versions and is human-readable
    log_info "Creating SQL dump..."
    docker exec "${CONTAINER_NAME}" pg_dump \
        -U "${DB_USER}" \
        -d "${DB_NAME}" \
        --verbose \
        --no-password \
        --format=plain \
        --no-privileges \
        --no-owner \
        | gzip > "${BACKUP_DIR}/${BACKUP_FILE}"

    # Verify backup file was created
    if [[ ! -f "${BACKUP_DIR}/${BACKUP_FILE}" ]]; then
        log_error "Backup file was not created"
        exit 1
    fi

    # Check if backup file is not empty
    if [[ ! -s "${BACKUP_DIR}/${BACKUP_FILE}" ]]; then
        log_error "Backup file is empty"
        rm -f "${BACKUP_DIR}/${BACKUP_FILE}"
        exit 1
    fi

    # Get backup file size
    BACKUP_SIZE=$(du -h "${BACKUP_DIR}/${BACKUP_FILE}" | cut -f1)

    log_success "SQL dump completed"
    log_info "Backup location: ${BACKUP_DIR}/${BACKUP_FILE}"
    log_info "Backup size: ${BACKUP_SIZE}"

    # Create metadata
    create_metadata "${BACKUP_FILE}" "${BACKUP_SIZE}"

    # Test backup integrity (optional)
    if [[ "${TEST_BACKUP:-false}" == "true" ]]; then
        test_backup_integrity "${BACKUP_DIR}/${BACKUP_FILE}"
    fi

    # Cleanup old backups if specified
    if [[ -n "${BACKUP_RETENTION_DAYS}" ]]; then
        cleanup_old_backups
    fi

    # List recent backups
    echo
    log_info "Recent SQL dump backups:"
    ls -lt "${BACKUP_DIR}"/postgres_dump_*.sql.gz 2>/dev/null | head -5 || log_warning "No previous backups found"
}

# Test backup integrity
test_backup_integrity() {
    local backup_file="$1"

    log_info "Testing backup integrity..."

    if gzip -t "$backup_file"; then
        log_success "Backup file integrity test passed"
    else
        log_error "Backup file is corrupted"
        exit 1
    fi
}

# Cleanup old backups
cleanup_old_backups() {
    log_info "Cleaning up backups older than ${BACKUP_RETENTION_DAYS} days..."

    DELETED_COUNT=$(find "${BACKUP_DIR}" -name "postgres_dump_*.sql.gz" -type f -mtime +${BACKUP_RETENTION_DAYS} -delete -print | wc -l)
    DELETED_META_COUNT=$(find "${BACKUP_DIR}" -name "postgres_dump_*.metadata.json" -type f -mtime +${BACKUP_RETENTION_DAYS} -delete -print | wc -l)

    if [[ $DELETED_COUNT -gt 0 || $DELETED_META_COUNT -gt 0 ]]; then
        log_info "Removed $DELETED_COUNT backup files and $DELETED_META_COUNT metadata files"
    else
        log_info "No old backups to remove"
    fi
}

# Show usage
show_usage() {
    echo "Usage: $0 [OPTIONS]"
    echo ""
    echo "Options:"
    echo "  --test              Test backup integrity after creation"
    echo "  --retention DAYS    Remove backups older than DAYS (default: keep all)"
    echo "  --help              Show this help message"
    echo ""
    echo "Environment Variables:"
    echo "  TEST_BACKUP         Set to 'true' to test backup integrity"
    echo "  BACKUP_RETENTION_DAYS  Number of days to keep backups"
    echo ""
    echo "Examples:"
    echo "  $0                          # Create backup"
    echo "  $0 --test                   # Create backup and test integrity"
    echo "  $0 --retention 7            # Create backup and keep only 7 days"
    echo "  TEST_BACKUP=true $0         # Create backup with integrity test"
}

# Main function
main() {
    # Parse command line arguments
    while [[ $# -gt 0 ]]; do
        case $1 in
            --test)
                export TEST_BACKUP=true
                shift
                ;;
            --retention)
                export BACKUP_RETENTION_DAYS="$2"
                shift 2
                ;;
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
    check_prerequisites
    backup_sql

    echo
    log_success "📦 SQL dump backup completed!"
    echo "  Backup: ${BACKUP_DIR}/${BACKUP_FILE}"
    echo "  Metadata: ${BACKUP_DIR}/${METADATA_FILE}"
    echo ""
    echo "To restore this backup, use:"
    echo "  ./scripts/restore-sql.sh ${BACKUP_FILE}"
}

# Run main function
main "$@"

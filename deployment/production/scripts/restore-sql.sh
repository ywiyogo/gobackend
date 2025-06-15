#!/bin/bash

# =============================================================================
# PostgreSQL SQL Dump Restore Script
# Restores database from pg_dump backup files
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
    echo "  PostgreSQL SQL Dump Restore"
    echo "================================"
    echo -e "${NC}"
}

# Confirm action
confirm_restore() {
    local backup_file="$1"

    echo -e "${YELLOW}WARNING: This will completely replace the current database with the backup!${NC}"
    echo "Backup file: $(basename "$backup_file")"
    echo "Target database: ${DB_NAME}@${DB_HOST}:${DB_PORT}"
    echo "Database user: ${DB_USER}"
    echo

    # Show backup metadata if available
    local metadata_file="${backup_file%.sql.gz}.metadata.json"
    if [[ -f "$metadata_file" ]]; then
        echo -e "${BLUE}Backup Information:${NC}"
        if command -v jq &> /dev/null; then
            jq -r '.backup_info | "  Date: \(.date)\n  Size: \(.backup_size)\n  Type: \(.backup_type)"' "$metadata_file"
            jq -r '.database_info | "  Original DB Size: \(.size)\n  Table Count: \(.table_count)"' "$metadata_file"
        else
            echo "  Metadata file: $(basename "$metadata_file")"
        fi
        echo
    fi

    read -p "Are you sure you want to continue? (yes/no): " -r
    echo

    if [[ ! $REPLY =~ ^[Yy][Ee][Ss]$ ]]; then
        log_info "Restore cancelled by user"
        exit 0
    fi
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
        log_warning "Proceeding anyway, but restore might fail"
    fi

    log_success "Prerequisites check passed"
}

# Stop services that use the database
stop_services() {
    log_info "Stopping services that use the database..."

    cd "$COMPOSE_DIR"

    # Stop backend service
    if docker compose ps backend --services 2>/dev/null | grep -q backend; then
        BACKEND_STATUS=$(docker compose ps backend --format json 2>/dev/null | jq -r '.State // empty' || echo "")
        if [[ "$BACKEND_STATUS" == "running" ]]; then
            log_info "Stopping backend service..."
            docker compose stop backend
        fi
    fi

    log_success "Services stopped"
}

# Start services after restore
start_services() {
    log_info "Starting services..."

    cd "$COMPOSE_DIR"

    # Run migrations first
    log_info "Running database migrations..."
    if docker compose ps migrate --services 2>/dev/null | grep -q migrate; then
        docker compose up migrate --remove-orphans
    fi

    # Start backend service
    log_info "Starting backend service..."
    docker compose up backend -d

    # Wait for backend to be healthy
    log_info "Waiting for backend to be ready..."
    timeout=60
    while [ $timeout -gt 0 ]; do
        BACKEND_STATUS=$(docker compose ps backend --format json 2>/dev/null | jq -r '.Health // .State // empty' || echo "")
        if [[ "$BACKEND_STATUS" == "healthy" ]] || [[ "$BACKEND_STATUS" == "running" ]]; then
            log_success "Backend service is ready"
            break
        fi
        sleep 2
        timeout=$((timeout - 2))
    done

    if [ $timeout -le 0 ]; then
        log_warning "Backend service did not become healthy within timeout, but continuing..."
    fi

    log_success "Services started"
}

# Validate backup file
validate_backup() {
    local backup_file="$1"

    log_info "Validating backup file..."

    # Check if file exists
    if [[ ! -f "$backup_file" ]]; then
        log_error "Backup file not found: $backup_file"
        exit 1
    fi

    # Check if it's a gzip file
    if ! file "$backup_file" | grep -q "gzip compressed"; then
        log_error "Backup file is not a valid gzip archive"
        exit 1
    fi

    # Test gzip integrity
    if ! gzip -t "$backup_file"; then
        log_error "Backup file is corrupted (gzip test failed)"
        exit 1
    fi

    # Get backup file info
    BACKUP_SIZE=$(du -h "$backup_file" | cut -f1)
    log_success "Backup file validation passed"
    log_info "Backup size: $BACKUP_SIZE"
}

# Create backup before restore (safety measure)
create_safety_backup() {
    log_info "Creating safety backup of current database..."

    local safety_backup="postgres_safety_backup_$(date +%Y%m%d_%H%M%S).sql.gz"

    docker exec "${CONTAINER_NAME}" pg_dump \
        -U "${DB_USER}" \
        -d "${DB_NAME}" \
        --verbose \
        --no-password \
        --format=custom \
        --compress=9 \
        --no-privileges \
        --no-owner \
        | gzip > "${BACKUP_DIR}/${safety_backup}"

    if [[ -s "${BACKUP_DIR}/${safety_backup}" ]]; then
        log_success "Safety backup created: ${safety_backup}"
        echo "  Location: ${BACKUP_DIR}/${safety_backup}"
    else
        log_error "Failed to create safety backup"
        exit 1
    fi
}

# Main restore function
restore_sql() {
    local backup_file="$1"
    local skip_safety_backup="$2"

    print_banner

    log_info "Starting PostgreSQL SQL dump restore..."
    log_info "Backup file: $(basename "$backup_file")"
    log_info "Target database: ${DB_NAME}@${DB_HOST}:${DB_PORT}"

    # Validate backup
    validate_backup "$backup_file"

    # Confirm restore
    confirm_restore "$backup_file"

    # Stop services
    stop_services

    # Create safety backup unless skipped
    if [[ "$skip_safety_backup" != "true" ]]; then
        create_safety_backup
    fi

    # Drop and recreate database
    log_info "Preparing database for restore..."

    # Terminate active connections
    docker exec "${CONTAINER_NAME}" psql -U "${DB_USER}" -d postgres -c "
        SELECT pg_terminate_backend(pid)
        FROM pg_stat_activity
        WHERE datname = '${DB_NAME}' AND pid <> pg_backend_pid();"

    # Drop database
    log_info "Dropping existing database..."
    docker exec "${CONTAINER_NAME}" dropdb -U "${DB_USER}" --if-exists "${DB_NAME}"

    # Create database
    log_info "Creating fresh database..."
    docker exec "${CONTAINER_NAME}" createdb -U "${DB_USER}" "${DB_NAME}"

    # Restore from backup
    log_info "Restoring data from backup..."

    # Use psql for plain SQL format backups
    gunzip -c "$backup_file" | docker exec -i "${CONTAINER_NAME}" psql \
        -U "${DB_USER}" \
        -d "${DB_NAME}" \
        --quiet

    log_success "Database restore completed"

    # Start services
    start_services

    # Verify restore
    verify_restore

    log_success "SQL dump restore completed successfully!"
}

# Verify restore
verify_restore() {
    log_info "Verifying database restore..."

    # Check if database exists and is accessible
    TABLE_COUNT=$(docker exec "${CONTAINER_NAME}" psql -U "${DB_USER}" -d "${DB_NAME}" -t -c "SELECT COUNT(*) FROM information_schema.tables WHERE table_schema = 'public';" | xargs)

    if [[ "$TABLE_COUNT" -gt 0 ]]; then
        log_success "Database verification passed"
        log_info "Tables found: $TABLE_COUNT"
    else
        log_warning "Database verification: No tables found (this might be expected for empty databases)"
    fi

    # Check database size
    DB_SIZE=$(docker exec "${CONTAINER_NAME}" psql -U "${DB_USER}" -d "${DB_NAME}" -t -c "SELECT pg_size_pretty(pg_database_size('${DB_NAME}'));" | xargs)
    log_info "Database size: $DB_SIZE"
}

# List available backups
list_backups() {
    echo -e "${BLUE}Available SQL dump backups:${NC}"
    echo

    if ls "$BACKUP_DIR"/postgres_dump_*.sql.gz > /dev/null 2>&1; then
        printf "%-35s %-10s %-20s %s\n" "BACKUP FILE" "SIZE" "DATE" "METADATA"
        printf "%s\n" "$(printf '=%.0s' {1..80})"

        ls -lt "$BACKUP_DIR"/postgres_dump_*.sql.gz | while read -r line; do
            backup_file=$(echo "$line" | awk '{print $NF}')
            size=$(echo "$line" | awk '{print $5}')
            date=$(echo "$line" | awk '{print $6, $7, $8}')
            metadata_file="${backup_file%.sql.gz}.metadata.json"

            has_metadata="❌"
            if [[ -f "$metadata_file" ]]; then
                has_metadata="✅"
            fi

            printf "%-35s %-10s %-20s %s\n" "$(basename "$backup_file")" "$size" "$date" "$has_metadata"
        done
    else
        log_warning "No SQL dump backups found in $BACKUP_DIR"
    fi
}

# Show usage
show_usage() {
    echo "Usage: $0 [OPTIONS] [BACKUP_FILE]"
    echo ""
    echo "Options:"
    echo "  --list                    List available backup files"
    echo "  --skip-safety-backup      Skip creating safety backup before restore"
    echo "  --help                    Show this help message"
    echo ""
    echo "Arguments:"
    echo "  BACKUP_FILE              Path to backup file (relative to backups/ directory)"
    echo ""
    echo "Examples:"
    echo "  $0 postgres_dump_20241214_120000.sql.gz"
    echo "  $0 --list"
    echo "  $0 --skip-safety-backup backup.sql.gz"
    echo "  $0 /full/path/to/backup.sql.gz"
}

# Main function
main() {
    local backup_file=""
    local skip_safety_backup="false"

    # Parse command line arguments
    while [[ $# -gt 0 ]]; do
        case $1 in
            --list)
                list_backups
                exit 0
                ;;
            --skip-safety-backup)
                skip_safety_backup="true"
                shift
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
    check_prerequisites
    restore_sql "$backup_file" "$skip_safety_backup"

    echo
    log_success "🔄 SQL dump restore completed!"
    echo "  Database restored from: $(basename "$backup_file")"
    echo ""
    echo "You can now access your application at:"
    echo "  http://localhost:8090"
}

# Run main function
main "$@"

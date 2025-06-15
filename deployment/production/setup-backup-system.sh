#!/bin/bash

# =============================================================================
# Quick Backup System Setup Script
# Initializes backup system with recommended settings
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
SCRIPTS_DIR="${SCRIPT_DIR}/scripts"
BACKUP_DIR="${SCRIPT_DIR}/backups"
LOGS_DIR="${SCRIPT_DIR}/logs"

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
    echo "=========================================="
    echo "      GoBackend Backup System Setup"
    echo "=========================================="
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

    # Check if docker compose is available
    if ! command -v docker &> /dev/null || ! docker compose version &> /dev/null; then
        log_error "Docker Compose is required but not installed"
        exit 1
    fi

    # Check if .env file exists
    if [[ ! -f "${SCRIPT_DIR}/.env" ]]; then
        log_error ".env file not found in ${SCRIPT_DIR}"
        log_info "Please ensure your .env file is properly configured"
        exit 1
    fi

    # Check if database service is defined
    if ! docker compose -f "${SCRIPT_DIR}/docker-compose.yml" config --services | grep -q "db"; then
        log_error "Database service 'db' not found in docker-compose.yml"
        exit 1
    fi

    log_success "Prerequisites check passed"
}

# Setup directories
setup_directories() {
    log_info "Setting up directories..."

    # Create backup directory
    if [[ ! -d "$BACKUP_DIR" ]]; then
        mkdir -p "$BACKUP_DIR"
        log_success "Created backup directory: $BACKUP_DIR"
    fi

    # Create logs directory
    if [[ ! -d "$LOGS_DIR" ]]; then
        mkdir -p "$LOGS_DIR"
        log_success "Created logs directory: $LOGS_DIR"
    fi

    # Set appropriate permissions
    chmod 750 "$BACKUP_DIR"
    chmod 750 "$LOGS_DIR"

    log_success "Directory setup completed"
}

# Make scripts executable
setup_scripts() {
    log_info "Setting up backup scripts..."

    if [[ -d "$SCRIPTS_DIR" ]]; then
        # Make all scripts executable
        chmod +x "$SCRIPTS_DIR"/*.sh
        log_success "Made backup scripts executable"

        # Verify critical scripts exist
        local critical_scripts=("backup-sql.sh" "restore-sql.sh" "backup-volume.sh" "restore-volume.sh")
        for script in "${critical_scripts[@]}"; do
            if [[ -f "$SCRIPTS_DIR/$script" ]]; then
                log_success "✓ $script is available"
            else
                log_error "✗ $script is missing"
                exit 1
            fi
        done
    else
        log_error "Scripts directory not found: $SCRIPTS_DIR"
        exit 1
    fi
}

# Test database connectivity
test_database() {
    log_info "Testing database connectivity..."

    # Change to compose directory
    cd "$SCRIPT_DIR"

    # Start database if not running
    if ! docker compose ps db --format json 2>/dev/null | grep -q running; then
        log_info "Starting database service..."
        docker compose up db -d

        # Wait for database to be ready
        log_info "Waiting for database to be ready..."
        timeout=60
        while [ $timeout -gt 0 ]; do
            if docker compose ps db --format json 2>/dev/null | grep -q healthy; then
                break
            fi
            sleep 2
            timeout=$((timeout - 2))
        done

        if [ $timeout -le 0 ]; then
            log_error "Database failed to start within timeout"
            exit 1
        fi
    fi

    # Test database connectivity
    if docker exec production-db-1 pg_isready -U postgres -d gobackend; then
        log_success "Database connectivity test passed"
    else
        log_error "Database connectivity test failed"
        exit 1
    fi
}

# Run initial backup
run_initial_backup() {
    log_info "Creating initial backup..."

    cd "$SCRIPTS_DIR"

    if "./backup-sql.sh" --test; then
        log_success "Initial backup completed successfully"
    else
        log_error "Initial backup failed"
        exit 1
    fi
}

# Setup automated backups
setup_automation() {
    local schedule="$1"

    if [[ "$schedule" == "none" ]]; then
        log_info "Skipping automated backup setup"
        return
    fi

    log_info "Setting up automated backups with schedule: $schedule"

    cd "$SCRIPTS_DIR"

    if "./setup-automated-backup.sh" setup "$schedule"; then
        log_success "Automated backups configured"
    else
        log_error "Failed to setup automated backups"
        exit 1
    fi
}

# Show system status
show_status() {
    echo
    echo -e "${BLUE}=== Backup System Status ===${NC}"
    echo

    # Backup directory info
    log_info "Backup Directory: $BACKUP_DIR"
    if [[ -d "$BACKUP_DIR" && $(ls -A "$BACKUP_DIR" 2>/dev/null) ]]; then
        echo "  Files: $(ls -1 "$BACKUP_DIR" | wc -l)"
        echo "  Size: $(du -sh "$BACKUP_DIR" 2>/dev/null | cut -f1)"
        echo "  Recent backups:"
        ls -lt "$BACKUP_DIR"/*.gz 2>/dev/null | head -3 | while read -r line; do
            echo "    $(echo "$line" | awk '{print $NF, $5, $6, $7, $8}')"
        done
    else
        echo "  Status: Empty"
    fi

    echo

    # Cron jobs status
    log_info "Automated Backups:"
    if crontab -l 2>/dev/null | grep -q "gobackend-backup"; then
        crontab -l | grep "gobackend-backup" | while read -r line; do
            echo "  $line"
        done
    else
        echo "  Status: Not configured"
    fi

    echo

    # Database status
    log_info "Database Status:"
    if docker compose ps db --format json 2>/dev/null | grep -q running; then
        echo "  Status: Running"
        if docker compose ps db --format json 2>/dev/null | grep -q healthy; then
            echo "  Health: Healthy"
        else
            echo "  Health: Unhealthy"
        fi
    else
        echo "  Status: Not running"
    fi
}

# Show usage
show_usage() {
    echo "Usage: $0 [OPTIONS]"
    echo ""
    echo "Options:"
    echo "  --automation SCHEDULE    Setup automated backups (daily|weekly|monthly|all|none)"
    echo "  --skip-initial-backup    Skip creating initial backup"
    echo "  --status-only           Show system status only"
    echo "  --help                  Show this help message"
    echo ""
    echo "Examples:"
    echo "  $0                              # Basic setup with daily automation"
    echo "  $0 --automation all             # Setup with all backup schedules"
    echo "  $0 --automation none            # Setup without automation"
    echo "  $0 --skip-initial-backup        # Setup without initial backup"
    echo "  $0 --status-only               # Show current status"
}

# Main function
main() {
    local automation_schedule="daily"
    local skip_initial_backup="false"
    local status_only="false"

    # Parse command line arguments
    while [[ $# -gt 0 ]]; do
        case $1 in
            --automation)
                automation_schedule="$2"
                shift 2
                ;;
            --skip-initial-backup)
                skip_initial_backup="true"
                shift
                ;;
            --status-only)
                status_only="true"
                shift
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

    print_banner

    if [[ "$status_only" == "true" ]]; then
        show_status
        exit 0
    fi

    # Run setup steps
    check_prerequisites
    setup_directories
    setup_scripts
    test_database

    if [[ "$skip_initial_backup" != "true" ]]; then
        run_initial_backup
    fi

    setup_automation "$automation_schedule"

    # Show final status
    show_status

    echo
    log_success "🎉 Backup system setup completed!"
    echo
    echo -e "${BLUE}Next Steps:${NC}"
    echo "  1. Review backup files in: $BACKUP_DIR"
    echo "  2. Check automated backup status: ./scripts/setup-automated-backup.sh status"
    echo "  3. Test restore procedure: ./scripts/restore-sql.sh --list"
    echo "  4. Read documentation: ./BACKUP.md"
    echo
    echo -e "${BLUE}Quick Commands:${NC}"
    echo "  • Manual backup:        ./scripts/backup-sql.sh"
    echo "  • List backups:         ./scripts/restore-sql.sh --list"
    echo "  • Check automation:     ./scripts/setup-automated-backup.sh status"
    echo "  • View logs:           ./scripts/setup-automated-backup.sh logs"
    echo
}

# Run main function
main "$@"

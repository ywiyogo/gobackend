#!/bin/bash

# Docker-based Integration Test Runner
# This script sets up Docker environment and runs integration tests

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

# Function to show usage
show_usage() {
    echo "Usage: $0 [OPTIONS] [TEST_TYPE]"
    echo ""
    echo "TEST_TYPE:"
    echo "  unit                    Run unit tests only"
    echo "  integration            Run integration tests (default)"
    echo "  integration-short      Run integration tests in short mode"
    echo "  integration-coverage   Run integration tests with coverage"
    echo "  all                    Run all tests"
    echo ""
    echo "OPTIONS:"
    echo "  -h, --help             Show this help message"
    echo "  -p, --pattern PATTERN  Run tests matching pattern (integration tests only)"
    echo "  -c, --cleanup-only     Only cleanup Docker services"
    echo "  -s, --setup-only       Only setup Docker environment"
    echo "  -k, --keep-running     Keep Docker services running after tests"
    echo "  -v, --verbose          Enable verbose output"
    echo "  -o, --otp              Run with OTP enabled"
    echo "  -n, --no-otp           Run with OTP disabled"
    echo ""
    echo "Examples:"
    echo "  $0                                    # Run integration tests"
    echo "  $0 unit                              # Run unit tests"
    echo "  $0 integration-coverage              # Run integration tests with coverage"
    echo "  $0 integration TestAuthenticationWorkflowWithPassword  # Run specific test"
    echo "  $0 -p TestAuthenticationWorkflow*    # Run specific test pattern"
    echo "  $0 -o                                # Run with OTP enabled"
    echo "  $0 -s                                # Setup environment only"
    echo "  $0 -c                                # Cleanup Docker services only"
    echo "  $0 -k integration                    # Run tests and keep Docker running"
}

# Function to cleanup Docker services
cleanup_docker() {
    print_status "Cleaning up Docker services..."
    cd "$(dirname "$0")/.."
    ./test/setup-docker.sh --cleanup
    print_success "Docker cleanup complete"
}

# Function to setup Docker environment
setup_docker() {
    print_status "Setting up Docker environment..."
    cd "$(dirname "$0")/.."
    ./test/setup-docker.sh
}

# Function to parse test output and extract failed tests
parse_test_results() {
    local output_file="$1"
    local failed_tests=()
    local failed_subtests=()
    local passed_tests=()
    local passed_subtests=()
    local skipped_tests=()
    local skipped_subtests=()
    local error_details=()
    local total_time=""

    # Extract tests, sub-tests, and error details
    local current_failure=""
    local collecting_error=false

    while IFS= read -r line; do
        # Check for test results
        if [[ $line =~ ^---\ FAIL:\ (.+)\ \(([0-9.]+s)\)$ ]]; then
            local test_name="${BASH_REMATCH[1]}"
            local test_time="${BASH_REMATCH[2]}"
            if [[ $test_name == *"/"* ]]; then
                failed_subtests+=("$test_name ($test_time)")
            else
                failed_tests+=("$test_name ($test_time)")
            fi
            current_failure="$test_name"
            collecting_error=true
        elif [[ $line =~ ^---\ PASS:\ (.+)\ \(([0-9.]+s)\)$ ]]; then
            local test_name="${BASH_REMATCH[1]}"
            local test_time="${BASH_REMATCH[2]}"
            if [[ $test_name == *"/"* ]]; then
                passed_subtests+=("$test_name ($test_time)")
            else
                passed_tests+=("$test_name ($test_time)")
            fi
            collecting_error=false
        elif [[ $line =~ ^---\ SKIP:\ (.+)\ \(([0-9.]+s)\)$ ]]; then
            local test_name="${BASH_REMATCH[1]}"
            local test_time="${BASH_REMATCH[2]}"
            if [[ $test_name == *"/"* ]]; then
                skipped_subtests+=("$test_name ($test_time)")
            else
                skipped_tests+=("$test_name ($test_time)")
            fi
            collecting_error=false
        elif [[ $line =~ ^FAIL$ ]] || [[ $line =~ ^PASS$ ]]; then
            collecting_error=false
        elif [[ $line =~ ^(FAIL|ok)[[:space:]]+[^[:space:]]+[[:space:]]+([0-9.]+s)$ ]]; then
            total_time="${BASH_REMATCH[2]}"
            collecting_error=false
        elif [[ "$collecting_error" == "true" ]] && [[ $line =~ "Error Trace:" ]]; then
            # Collect error trace information
            local next_line=""
            local error_msg=""
            read -r next_line
            if [[ $next_line =~ Error:[[:space:]]+(.+)$ ]]; then
                error_msg="${BASH_REMATCH[1]}"
                error_details+=("$current_failure: $error_msg")
            fi
        fi
    done < "$output_file"

    # Print summary
    echo ""
    echo "========================================"
    echo "           TEST RESULTS SUMMARY        "
    echo "========================================"

    local total_passed=$((${#passed_tests[@]} + ${#passed_subtests[@]}))
    local total_failed=$((${#failed_tests[@]} + ${#failed_subtests[@]}))
    local total_skipped=$((${#skipped_tests[@]} + ${#skipped_subtests[@]}))

    if [ $total_passed -gt 0 ]; then
        echo ""
        print_success "PASSED (${total_passed}):"
        for test in "${passed_tests[@]}"; do
            echo "  ✅ $test"
        done
        for test in "${passed_subtests[@]}"; do
            echo "  ✅ $test"
        done
    fi

    if [ $total_skipped -gt 0 ]; then
        echo ""
        print_warning "SKIPPED (${total_skipped}):"
        for test in "${skipped_tests[@]}"; do
            echo "  ⏭️  $test"
        done
        for test in "${skipped_subtests[@]}"; do
            echo "  ⏭️  $test"
        done
    fi

    if [ $total_failed -gt 0 ]; then
        echo ""
        print_error "FAILED (${total_failed}):"
        for test in "${failed_tests[@]}"; do
            echo "  ❌ $test"
        done
        for test in "${failed_subtests[@]}"; do
            echo "  ❌ $test"
        done

        # Show error details if available
        if [ ${#error_details[@]} -gt 0 ]; then
            echo ""
            print_error "ERROR DETAILS:"
            for error in "${error_details[@]}"; do
                echo "  🔍 $error"
            done
        fi

        echo ""
        print_error "🚨 ${total_failed} test(s) failed! Check the output above for details."
        echo ""
        print_status "💡 Quick debugging tips:"
        echo "   • Look for 'Error Trace:' lines in the output above"
        echo "   • Check assertion failures and expected vs actual values"
        echo "   • Review any error logs or stack traces"
        if [ ${#failed_subtests[@]} -gt 0 ]; then
            echo "   • Focus on failed sub-tests to identify specific issues"
        fi
        if [ -n "$total_time" ]; then
            echo "   ⏱️  Total test time: $total_time"
        fi
        return 1
    else
        echo ""
        print_success "🎉 All tests passed!"
        if [ $total_passed -gt 1 ]; then
            echo "   📊 Total: $total_passed tests completed successfully"
        fi
        if [ -n "$total_time" ]; then
            echo "   ⏱️  Total time: $total_time"
        fi
        return 0
    fi
}

# Function to run tests
run_tests() {
    local test_type="$1"
    local test_pattern="$2"
    local temp_output=$(mktemp)

    print_status "Running $test_type tests..."

    cd "$(dirname "$0")/.."

    # Run tests and capture output
    local test_result=0
    case "$test_type" in
        "unit")
            make test-unit 2>&1 | tee "$temp_output"
            test_result=${PIPESTATUS[0]}
            ;;
        "integration")
            if [ -n "$test_pattern" ]; then
                go test ./test/... -v -run "$test_pattern" 2>&1 | tee "$temp_output"
                test_result=${PIPESTATUS[0]}
            else
                go test ./test/... -v 2>&1 | tee "$temp_output"
                test_result=${PIPESTATUS[0]}
            fi
            ;;
        "integration-short")
            make test-integration-short 2>&1 | tee "$temp_output"
            test_result=${PIPESTATUS[0]}
            ;;
        "integration-coverage")
            make test-integration-coverage 2>&1 | tee "$temp_output"
            test_result=${PIPESTATUS[0]}
            ;;
        "all")
            make test 2>&1 | tee "$temp_output"
            test_result=${PIPESTATUS[0]}
            ;;
        *)
            print_error "Unknown test type: $test_type"
            rm -f "$temp_output"
            return 1
            ;;
    esac

    # Parse and display test results summary
    parse_test_results "$temp_output"
    local parse_result=$?

    # Clean up temporary file
    rm -f "$temp_output"

    # Return appropriate exit code
    if [ $test_result -ne 0 ] || [ $parse_result -ne 0 ]; then
        return 1
    fi

    return 0
}

# Main execution function
main() {
    local test_type="integration"
    local test_pattern=""
    local cleanup_only=false
    local setup_only=false
    local keep_running=false
    local verbose=false
    local otp_mode=""

    # Parse command line arguments
    while [[ $# -gt 0 ]]; do
        case $1 in
            -h|--help)
                show_usage
                exit 0
                ;;
            -p|--pattern)
                test_pattern="$2"
                shift 2
                ;;
            -c|--cleanup-only)
                cleanup_only=true
                shift
                ;;
            -s|--setup-only)
                setup_only=true
                shift
                ;;
            -k|--keep-running)
                keep_running=true
                shift
                ;;
            -v|--verbose)
                verbose=true
                shift
                ;;
            -o|--otp)
                otp_mode="true"
                shift
                ;;
            -n|--no-otp)
                otp_mode="false"
                shift
                ;;
            unit|integration|integration-short|integration-coverage|all)
                test_type="$1"
                shift
                # Check if next argument is a test pattern (not starting with -)
                if [[ $# -gt 0 && ! "$1" =~ ^- ]]; then
                    test_pattern="$1"
                    shift
                fi
                ;;
            *)
                print_error "Unknown option: $1"
                show_usage
                exit 1
                ;;
        esac
    done

    # Set verbose mode
    if [ "$verbose" = true ]; then
        set -x
    fi

    # Handle cleanup only mode
    if [ "$cleanup_only" = true ]; then
        cleanup_docker
        exit 0
    fi

    # Set OTP mode if specified
    if [ -n "$otp_mode" ]; then
        export OTP_ENABLED="$otp_mode"
        print_status "OTP mode set to: $otp_mode"
    fi

    print_status "Starting Docker-based test runner..."
    echo "Test type: $test_type"
    if [ -n "$test_pattern" ]; then
        echo "Test pattern: $test_pattern"
    fi
    if [ "$keep_running" = true ]; then
        echo "Docker services will be kept running after tests"
    fi
    echo ""

    # Setup cleanup trap (only if not keeping services running)
    if [ "$keep_running" = false ]; then
        trap cleanup_docker EXIT INT TERM
    fi

    # Setup Docker environment
    setup_docker

    # Handle setup only mode
    if [ "$setup_only" = true ]; then
        print_success "Docker environment setup complete"
        print_warning "Skipping cleanup due to --setup-only flag"
        print_status "Remember to run 'docker compose down' or '$0 -c' when done"
        trap - EXIT INT TERM  # Remove cleanup trap
        exit 0
    fi

    # Wait a moment for database to be fully ready
    print_status "Waiting for database to be fully ready..."
    sleep 3

    # Set environment for localhost database access
    # Load environment variables from .env file
    if [ -f .env ]; then
        set -a
        source .env
        set +a
    fi

    # Override DB_HOST for localhost access
    export DB_HOST=localhost
    export DB_USER="${DB_USER}"
    export DB_PASSWORD="${DB_PASSWORD}"
    export DB_NAME="${DB_NAME}"
    export DB_PORT="${DB_PORT:-5432}"

    # Run tests
    echo ""
    print_status "Docker environment ready, running tests..."
    echo ""

    if run_tests "$test_type" "$test_pattern"; then
        echo ""
        print_success "All tests completed successfully!"

        if [ "$keep_running" = true ]; then
            echo ""
            print_warning "Docker services are still running"
            print_status "To stop them, run: $0 -c"
            print_status "Or: docker compose down"
            trap - EXIT INT TERM  # Remove cleanup trap
        fi
    else
        echo ""
        print_error "Some tests failed"
        exit 1
    fi
}

# Run main function with all arguments
main "$@"

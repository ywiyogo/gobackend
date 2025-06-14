#!/bin/bash

# =============================================================================
# Build and Push Docker Image Script
# Build the Docker image locally and push to registry
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
PROJECT_ROOT="$(cd "${SCRIPT_DIR}/../.." && pwd)"

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
    echo "  Build & Push Docker Image"
    echo "================================"
    echo -e "${NC}"
}

load_env() {
    log_info "Loading production environment variables..."

    if [[ ! -f "${SCRIPT_DIR}/.env" ]]; then
        log_error "Production environment file not found at ${SCRIPT_DIR}/.env"
        log_error "Please copy .env.example to .env and configure it"
        exit 1
    fi

    # Load environment variables
    set -a
    source "${SCRIPT_DIR}/.env"
    set +a

    # Check required variables
    if [[ -z "$DOCKER_USERNAME" ]] || [[ -z "$DOCKER_IMAGE_NAME" ]]; then
        log_error "Missing required Docker configuration in .env file:"
        log_error "  DOCKER_USERNAME, DOCKER_IMAGE_NAME"
        exit 1
    fi

    # Set default tag if not provided
    if [[ -z "$DOCKER_IMAGE_TAG" ]]; then
        DOCKER_IMAGE_TAG="latest"
    fi

    # Construct full image name (Docker Hub format)
    DOCKER_IMAGE="${DOCKER_USERNAME}/${DOCKER_IMAGE_NAME}:${DOCKER_IMAGE_TAG}"

    log_success "Environment loaded"
    echo "  Registry: docker.io (Docker Hub)"
    echo "  Username: ${DOCKER_USERNAME}"
    echo "  Image: ${DOCKER_IMAGE_NAME}:${DOCKER_IMAGE_TAG}"
    echo "  Full image: ${DOCKER_IMAGE}"
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

    # Check Docker daemon
    if ! docker info &> /dev/null; then
        log_error "Docker daemon is not running or not accessible."
        exit 1
    fi

    log_success "Prerequisites check passed"
}

get_git_info() {
    log_info "Getting Git information..."

    cd "$PROJECT_ROOT"

    # Get current branch
    GIT_BRANCH=$(git rev-parse --abbrev-ref HEAD 2>/dev/null || echo "unknown")

    # Get current commit hash
    GIT_COMMIT=$(git rev-parse --short HEAD 2>/dev/null || echo "unknown")

    # Check if working directory is clean
    if ! git diff-index --quiet HEAD -- 2>/dev/null; then
        GIT_DIRTY=true
        log_warning "Working directory has uncommitted changes"
    else
        GIT_DIRTY=false
    fi

    log_info "Git branch: ${GIT_BRANCH}"
    log_info "Git commit: ${GIT_COMMIT}"

    # Optionally tag with commit hash
    if [[ "$1" == "--tag-with-commit" ]]; then
        DOCKER_IMAGE_TAG="${GIT_COMMIT}"
        DOCKER_IMAGE="${DOCKER_USERNAME}/${DOCKER_IMAGE_NAME}:${DOCKER_IMAGE_TAG}"
        log_info "Using commit hash as tag: ${DOCKER_IMAGE_TAG}"
    fi
}

build_image() {
    log_info "Building Docker image..."

    cd "$PROJECT_ROOT"

    # Build the image with build args
    docker build \
        -f deployment/production/Dockerfile \
        -t "${DOCKER_IMAGE}" \
        --build-arg GIT_COMMIT="${GIT_COMMIT}" \
        --build-arg GIT_BRANCH="${GIT_BRANCH}" \
        --build-arg BUILD_DATE="$(date -u +%Y-%m-%dT%H:%M:%SZ)" \
        --build-arg CGO_ENABLED="${CGO_ENABLED:-0}" \
        --build-arg GOOS="${GOOS:-linux}" \
        --build-arg GOARCH="${GOARCH:-amd64}" \
        --build-arg GOAMD64="${GOAMD64:-v3}" \
        .

    log_success "Docker image built: ${DOCKER_IMAGE}"
}

test_image() {
    log_info "Testing Docker image..."

    # Test that the image can start with minimal environment variables
    CONTAINER_ID=$(docker run -d --rm \
        -e DB_USER=test \
        -e DB_PASSWORD=test \
        -e DB_NAME=test \
        -e DB_HOST=localhost \
        -e DB_PORT=5432 \
        -e APP_ENV=test \
        -e PORT=8090 \
        "${DOCKER_IMAGE}")

    # Wait a moment for startup
    sleep 2

    # Check if container is still running
    if docker ps --no-trunc | grep -q "${CONTAINER_ID}"; then
        docker stop "${CONTAINER_ID}" &> /dev/null
        log_success "Image test passed"
    else
        log_error "Image test failed - container exited"
        docker logs "${CONTAINER_ID}" 2>/dev/null || true
        exit 1
    fi
}

docker_login() {
    log_info "Logging into Docker Hub..."

    echo "Please log in to Docker Hub:"
    docker login

    log_success "Docker login successful"
}

push_image() {
    log_info "Pushing Docker image to registry..."

    docker push "${DOCKER_IMAGE}"

    log_success "Docker image pushed: ${DOCKER_IMAGE}"

    # Also tag and push as 'latest' if not already latest
    if [[ "$DOCKER_IMAGE_TAG" != "latest" ]]; then
        LATEST_IMAGE="${DOCKER_USERNAME}/${DOCKER_IMAGE_NAME}:latest"
        docker tag "${DOCKER_IMAGE}" "${LATEST_IMAGE}"
        docker push "${LATEST_IMAGE}"
        log_success "Also pushed as: ${LATEST_IMAGE}"
    fi
}

cleanup() {
    log_info "Cleaning up..."

    # Remove intermediate/dangling images
    docker image prune -f &> /dev/null || true

    log_success "Cleanup completed"
}

show_usage() {
    echo "Usage: $0 [OPTIONS]"
    echo ""
    echo "Options:"
    echo "  --tag-with-commit    Use Git commit hash as image tag"
    echo "  --no-test           Skip image testing"
    echo "  --no-push           Build only, don't push to registry"
    echo "  --help              Show this help message"
    echo ""
    echo "Examples:"
    echo "  $0                          # Build and push with default tag"
    echo "  $0 --tag-with-commit        # Use commit hash as tag"
    echo "  $0 --no-push               # Build only, don't push"
}

main() {
    print_banner

    # Parse command line arguments
    SKIP_TEST=false
    SKIP_PUSH=false
    TAG_WITH_COMMIT=false

    while [[ $# -gt 0 ]]; do
        case $1 in
            --tag-with-commit)
                TAG_WITH_COMMIT=true
                shift
                ;;
            --no-test)
                SKIP_TEST=true
                shift
                ;;
            --no-push)
                SKIP_PUSH=true
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

    # Main workflow
    load_env
    check_prerequisites

    if [[ "$TAG_WITH_COMMIT" == true ]]; then
        get_git_info --tag-with-commit
    else
        get_git_info
    fi

    build_image

    if [[ "$SKIP_TEST" != true ]]; then
        test_image
    fi

    if [[ "$SKIP_PUSH" != true ]]; then
        docker_login
        push_image
    fi

    cleanup

    echo
    log_success "🚀 Build and push completed!"
    echo "  Image: ${DOCKER_IMAGE}"
    if [[ "$SKIP_PUSH" != true ]]; then
        echo "  Registry: docker.io (Docker Hub)"
        echo ""
        echo "You can now deploy this image on your VPS using:"
        echo "  ./deploy.sh"
    fi
}

# Run main function
main "$@"

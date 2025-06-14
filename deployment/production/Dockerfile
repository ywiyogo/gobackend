# Multi-stage build for production
FROM golang:1.24-alpine AS builder

WORKDIR /app

# Build arguments for Go compilation
ARG CGO_ENABLED=0 \
    GOOS=linux \
    GOARCH=amd64 \
    GOAMD64=v3

# Install build dependencies
RUN apk add --no-cache make git

# Copy go mod files first for better caching
COPY go.mod go.sum ./
RUN go mod download

# Copy source code
COPY . .

# Build the application
RUN CGO_ENABLED=${CGO_ENABLED} GOOS=${GOOS} GOARCH=${GOARCH} GOAMD64=${GOAMD64} make build-prod

# Production stage
FROM alpine:latest

# Install ca-certificates and create non-root user for security
RUN apk --no-cache add ca-certificates tzdata && \
    addgroup -g 1001 -S appgroup && \
    adduser -u 1001 -S appuser -G appgroup

WORKDIR /app

# Copy the binary from builder stage with correct ownership
COPY --from=builder --chown=appuser:appgroup /app/tmp/gobackend .

# Switch to non-root user
USER appuser

# Set default PORT if not provided
ENV PORT=8080

EXPOSE ${PORT}

# Health check
HEALTHCHECK --interval=30s --timeout=3s --start-period=5s --retries=3 \
    CMD wget --no-verbose --tries=1 --spider http://localhost:${PORT}/health || exit 1

CMD ["./gobackend"]

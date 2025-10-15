# Multi-stage Dockerfile for Rust Authentication Service
# Optimized for production deployment with enhanced security

ARG RUST_VERSION=1.75
ARG DEBIAN_VERSION=bookworm
ARG RUST_FEATURES=secure

#
# Stage 1: Build Environment
#
FROM rust:${RUST_VERSION}-${DEBIAN_VERSION} as builder

# Install system dependencies required for building
RUN apt-get update && apt-get install -y \
    pkg-config \
    libssl-dev \
    libpq-dev \
    ca-certificates \
    && rm -rf /var/lib/apt/lists/*

# Set working directory
WORKDIR /app

# Copy Cargo files first for better layer caching
COPY Cargo.toml Cargo.lock ./

# Create dummy main.rs to enable dependency caching
RUN mkdir src && echo "fn main() {}" > src/main.rs

# Build dependencies (this layer will be cached unless Cargo.toml changes)
RUN cargo build --release --features ${RUST_FEATURES} && rm -rf src/

# Copy source code and configuration
COPY src/ src/
COPY migrations/ migrations/
COPY config.yml.example ./

# Build the actual application
RUN cargo build --release --features ${RUST_FEATURES}

#
# Stage 2: Runtime Environment (Debian Slim)
#
FROM debian:${DEBIAN_VERSION}-slim as runtime

# Install runtime dependencies only
RUN apt-get update && apt-get install -y \
    ca-certificates \
    libssl3 \
    libpq5 \
    curl \
    && rm -rf /var/lib/apt/lists/* \
    && apt-get clean

# Create non-root user for security
RUN useradd -r -u 1000 -m -c "Auth Service" -d /app -s /sbin/nologin appuser

# Set working directory
WORKDIR /app

# Copy binary from builder stage
COPY --from=builder /app/target/release/rust-auth-service /usr/local/bin/rust-auth-service

# Copy configuration template
COPY --from=builder /app/config.yml.example ./config.yml.example

# Create directories and set permissions
RUN mkdir -p /app/logs /app/data && \
    chown -R appuser:appuser /app && \
    chmod +x /usr/local/bin/rust-auth-service

# Switch to non-root user
USER appuser

# Expose port
EXPOSE 8090

# Health check with improved configuration
HEALTHCHECK --interval=30s --timeout=10s --start-period=5s --retries=3 \
  CMD curl -f http://localhost:8090/health || exit 1

# Environment variables for production
ENV RUST_LOG=info
ENV RUST_BACKTRACE=1
ENV HOST=0.0.0.0
ENV PORT=8090

# Set labels for better image management
LABEL maintainer="Auth Service Team"
LABEL version="1.0.0"
LABEL description="High-performance Rust Authentication Service"
LABEL org.opencontainers.image.source="https://github.com/fahdi/rust-auth-service"
LABEL org.opencontainers.image.documentation="https://github.com/fahdi/rust-auth-service/blob/main/README.md"
LABEL org.opencontainers.image.licenses="MIT"

# Run the application
CMD ["/usr/local/bin/rust-auth-service"]
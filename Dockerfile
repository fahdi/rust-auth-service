# Multi-stage production Dockerfile using official Rust images
FROM rust:1.89-bookworm as builder

# Install build dependencies
RUN apt-get update && apt-get install -y \
    pkg-config \
    libssl-dev \
    ca-certificates \
    && rm -rf /var/lib/apt/lists/*

WORKDIR /app

# Copy dependency files for caching
COPY Cargo.toml Cargo.lock ./

# Create dummy main for dependency caching
RUN mkdir src && echo "fn main() {}" > src/main.rs

# Build dependencies only (cached layer)
RUN cargo build --release && rm -rf src

# Copy actual source code
COPY . .

# Build the application
RUN cargo build --release

# Runtime image using Rust slim (minimal production image)
FROM rust:1.89-slim-bookworm

# Install runtime dependencies
RUN apt-get update && apt-get install -y \
    ca-certificates \
    curl \
    && rm -rf /var/lib/apt/lists/*

WORKDIR /app

# Copy the binary from builder stage
COPY --from=builder /app/target/release/rust-auth-service .
COPY --from=builder /app/config.yml .

# Set permissions
RUN chmod +x rust-auth-service

# Environment variables
ENV RUST_BACKTRACE=1
ENV RUST_LOG=info

# Health check
HEALTHCHECK --interval=30s --timeout=3s --start-period=5s --retries=3 \
    CMD curl --fail http://localhost:8090/health || exit 1

# Expose port
EXPOSE 8090

# Run the application
CMD ["./rust-auth-service"]
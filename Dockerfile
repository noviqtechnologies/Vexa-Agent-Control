# syntax=docker/dockerfile:1
# ─── Stage 1: Build ──────────────────────────────────────────────────────────
FROM rust:1.88-slim-bookworm AS builder

WORKDIR /build

# Install system dependencies needed for compilation
RUN apt-get update && apt-get install -y \
    pkg-config \
    libssl-dev \
    && rm -rf /var/lib/apt/lists/*

# Copy workspace manifests to leverage Docker layer caching for dependencies
COPY Cargo.toml Cargo.lock ./
COPY control-plane/proto/Cargo.toml ./control-plane/proto/Cargo.toml

# Pre-fetch and compile third-party dependencies with dummy source and bench files
RUN mkdir -p src control-plane/proto/src benches && \
    echo "fn main() {}" > src/main.rs && \
    touch src/lib.rs && \
    touch control-plane/proto/src/lib.rs && \
    echo "fn main() {}" > benches/policy_eval.rs && \
    echo "fn main() {}" > benches/proxy_overhead.rs && \
    echo "fn main() {}" > benches/safe_mode.rs && \
    cargo build --release --bin agentcontrol || true && \
    rm -rf src control-plane/proto/src benches

# Copy actual application source code and benchmarks
COPY src/ ./src/
COPY control-plane/proto/src/ ./control-plane/proto/src/
COPY benches/ ./benches/
COPY keys/ ./keys/
COPY policy.example.yaml ./policy.example.yaml

# Invalidate dummy binary and workspace library artifacts, then build actual release binary
RUN rm -rf target/release/deps/agentcontrol* \
           target/release/deps/libagentcontrol* \
           target/release/deps/control_plane_proto* \
           target/release/deps/libcontrol_plane_proto* \
           target/release/.fingerprint/agentcontrol* \
           target/release/.fingerprint/control_plane_proto* \
           target/release/agentcontrol \
           target/release/agentcontrol.d && \
    cargo build --release --bin agentcontrol && \
    cp target/release/agentcontrol /usr/local/bin/agentcontrol

# ─── Stage 2: Runtime ────────────────────────────────────────────────────────
FROM debian:bookworm-slim

WORKDIR /app

# Install runtime dependencies
RUN apt-get update && apt-get install -y \
    ca-certificates \
    && rm -rf /var/lib/apt/lists/*

# Copy compiled binary from the builder's global path
COPY --from=builder /usr/local/bin/agentcontrol /usr/local/bin/agentcontrol

# Copy example policy and docs
COPY policy.example.yaml /app/policy.example.yaml

# Create directory for audit logs with correct permissions
RUN mkdir -p /var/log/agentcontrol && chmod 755 /var/log/agentcontrol

# Non-root user for security
RUN useradd -r -s /bin/false -d /app agentcontrol && \
    chown -R agentcontrol:agentcontrol /app /var/log/agentcontrol
USER agentcontrol

# Default environment
ENV AGENTCONTROL_LISTEN=0.0.0.0:8080 \
    AGENTCONTROL_LOG_PATH=/var/log/agentcontrol/audit.log \
    AGENTCONTROL_MCP_URL=http://mock-mcp:3000 \
    AGENTCONTROL_DRY_RUN=false

# Health check
HEALTHCHECK --interval=10s --timeout=5s --start-period=5s --retries=3 \
    CMD agentcontrol --version || exit 1

EXPOSE 8080

ENTRYPOINT ["agentcontrol"]
CMD ["start"]

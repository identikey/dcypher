# =============================================================================
# recrypt-server Dockerfile
# Multi-stage build: Debian with OpenFHE + liboqs + Rust
# =============================================================================

# -----------------------------------------------------------------------------
# Stage 1: Build OpenFHE from source
# -----------------------------------------------------------------------------
FROM debian:bookworm-slim AS openfhe-builder

RUN apt-get update && apt-get install -y --no-install-recommends \
    build-essential \
    cmake \
    git \
    libomp-dev \
    ca-certificates \
    && rm -rf /var/lib/apt/lists/*

WORKDIR /build

# Copy only OpenFHE source (cached unless submodule changes)
COPY vendor/openfhe-development ./openfhe-development

# Remove .git file (submodule link) - cmake tries git ops otherwise
RUN rm -f openfhe-development/.git && \
    mkdir -p openfhe-development/build openfhe-install && \
    cd openfhe-development/build && \
    cmake .. \
        -DCMAKE_INSTALL_PREFIX=/build/openfhe-install \
        -DCMAKE_BUILD_TYPE=Release \
        -DBUILD_STATIC=ON \
        -DBUILD_UNITTESTS=OFF \
        -DBUILD_EXAMPLES=OFF \
        -DBUILD_BENCHMARKS=OFF \
        -DWITH_OPENMP=ON && \
    make -j$(nproc) && \
    make install

# -----------------------------------------------------------------------------
# Stage 2: Build Rust application
# -----------------------------------------------------------------------------
# Requires Rust 1.85+ for edition 2024
FROM rust:1-bookworm AS rust-builder

RUN apt-get update && apt-get install -y --no-install-recommends \
    build-essential \
    cmake \
    libomp-dev \
    libssl-dev \
    pkg-config \
    libclang-dev \
    protobuf-compiler \
    ninja-build \
    && rm -rf /var/lib/apt/lists/*

WORKDIR /app

# Copy OpenFHE from previous stage
COPY --from=openfhe-builder /build/openfhe-install ./vendor/openfhe-install

# Copy Cargo manifests first for better layer caching
COPY Cargo.toml Cargo.lock ./

# Copy all source (cxx_build needs actual lib.rs, not stubs)
COPY crates ./crates
COPY recrypt-server ./recrypt-server
COPY recrypt-cli ./recrypt-cli

# Fetch dependencies (cached if Cargo.lock unchanged)
RUN cargo fetch --locked

# Build release binaries
RUN cargo build --release --bin recrypt-server --bin recrypt

# Strip binaries for smaller image
RUN strip target/release/recrypt-server target/release/recrypt

# -----------------------------------------------------------------------------
# Stage 3: Minimal runtime image  
# -----------------------------------------------------------------------------
FROM debian:bookworm-slim AS runtime

RUN apt-get update && apt-get install -y --no-install-recommends \
    libgomp1 \
    libssl3 \
    ca-certificates \
    tini \
    wget \
    && rm -rf /var/lib/apt/lists/*

# Create non-root user
RUN groupadd -r recrypt && useradd -r -g recrypt recrypt

WORKDIR /app

# Copy binaries from builder
COPY --from=rust-builder /app/target/release/recrypt-server ./
COPY --from=rust-builder /app/target/release/recrypt ./

# Create data directory for local file storage
RUN mkdir -p /data && chown recrypt:recrypt /data

USER recrypt

# Config via env vars (RECRYPT_ prefix)
ENV RECRYPT_HOST=0.0.0.0
ENV RECRYPT_PORT=7222
ENV RECRYPT_STORAGE__BACKEND=memory

EXPOSE 7222

# Use tini as init for proper signal handling
ENTRYPOINT ["/usr/bin/tini", "--"]
CMD ["./recrypt-server"]

# Health check
HEALTHCHECK --interval=30s --timeout=3s --start-period=5s --retries=3 \
    CMD wget --no-verbose --tries=1 --spider http://localhost:7222/health || exit 1

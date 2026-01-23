# syntax=docker/dockerfile:1

# Build stage - using Debian with musl target for static binary
FROM rust:1.93-trixie AS builder

WORKDIR /app

# Install musl toolchain for static compilation
RUN apt-get update && apt-get install -y \
    musl-tools \
    musl-dev \
    && rm -rf /var/lib/apt/lists/*

# Add musl target
RUN rustup target add x86_64-unknown-linux-musl

# Copy manifests
COPY Cargo.toml Cargo.lock ./
COPY crates/vouch-common/Cargo.toml crates/vouch-common/
COPY crates/vouch-server/Cargo.toml crates/vouch-server/
COPY crates/vouch-cli/Cargo.toml crates/vouch-cli/
COPY crates/vouch-agent/Cargo.toml crates/vouch-agent/

# Build dependencies only (cached layer)
RUN cargo build --release --target x86_64-unknown-linux-musl --package vouch-server 2>/dev/null || true

# Copy actual source code
COPY crates/vouch-common/src crates/vouch-common/src
COPY crates/vouch-server/src crates/vouch-server/src
COPY crates/vouch-server/migrations crates/vouch-server/migrations

# Touch files to ensure rebuild
RUN touch crates/vouch-common/src/lib.rs crates/vouch-server/src/main.rs

# Build the release binary
RUN cargo build --release --target x86_64-unknown-linux-musl --package vouch-server

# Verify it's statically linked
RUN file /app/target/x86_64-unknown-linux-musl/release/vouch-server && \
    ldd /app/target/x86_64-unknown-linux-musl/release/vouch-server 2>&1 || true

# Runtime stage - minimal scratch image
FROM scratch

# Copy CA certificates for HTTPS
COPY --from=builder /etc/ssl/certs/ca-certificates.crt /etc/ssl/certs/

# Copy the static binary
COPY --from=builder /app/target/x86_64-unknown-linux-musl/release/vouch-server /vouch-server

# Environment defaults
ENV VOUCH_LISTEN_ADDR=0.0.0.0:3000
ENV VOUCH_DATABASE_URL=sqlite:/data/vouch.db?mode=rwc

EXPOSE 3000

ENTRYPOINT ["/vouch-server"]

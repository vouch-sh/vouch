# syntax=docker/dockerfile:1

# Build stage - using Debian for glibc build (webauthn-rs requires OpenSSL)
FROM rust:1.93-trixie AS builder

WORKDIR /app

# Install OpenSSL development files
RUN apt-get update && apt-get install -y \
    libssl-dev \
    pkg-config \
    && rm -rf /var/lib/apt/lists/*

# Copy manifests
COPY Cargo.toml Cargo.lock ./
COPY crates/vouch-common/Cargo.toml crates/vouch-common/
COPY crates/vouch-server/Cargo.toml crates/vouch-server/
COPY crates/vouch-cli/Cargo.toml crates/vouch-cli/
COPY crates/vouch-agent/Cargo.toml crates/vouch-agent/

# Build dependencies only (cached layer)
RUN cargo build --release --package vouch-server 2>/dev/null || true

# Copy actual source code
COPY crates/vouch-common/src crates/vouch-common/src
COPY crates/vouch-server/src crates/vouch-server/src
COPY crates/vouch-server/migrations crates/vouch-server/migrations

# Touch files to ensure rebuild
RUN touch crates/vouch-common/src/lib.rs crates/vouch-server/src/main.rs

# Build the release binary
RUN cargo build --release --package vouch-server

# Runtime stage - minimal distroless image with glibc
FROM gcr.io/distroless/cc-debian12:nonroot

# Copy the binary
COPY --from=builder /app/target/release/vouch-server /vouch-server

# Environment defaults
ENV VOUCH_LISTEN_ADDR=0.0.0.0:3000
ENV VOUCH_DATABASE_URL=sqlite:/data/vouch.db?mode=rwc

EXPOSE 3000

ENTRYPOINT ["/vouch-server"]

# syntax=docker/dockerfile:1

# CSS build stage - download and run standalone tailwindcss
FROM debian:trixie-slim AS css-builder

WORKDIR /app

# Download standalone tailwindcss CLI
RUN apt-get update && apt-get install -y curl \
    && rm -rf /var/lib/apt/lists/* \
    && curl -sLO https://github.com/tailwindlabs/tailwindcss/releases/latest/download/tailwindcss-linux-x64 \
    && chmod +x tailwindcss-linux-x64

# Copy files needed for CSS build
COPY crates/vouch-server/tailwind.config.js crates/vouch-server/
COPY crates/vouch-server/styles crates/vouch-server/styles
COPY crates/vouch-server/templates crates/vouch-server/templates
COPY crates/vouch-server/src crates/vouch-server/src

# Build minified CSS
RUN mkdir -p crates/vouch-server/static/css \
    && cd crates/vouch-server \
    && /app/tailwindcss-linux-x64 -i styles/input.css -o static/css/output.css --minify

# Rust build stage
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
COPY crates/vouch-server/templates crates/vouch-server/templates

# Touch files to ensure rebuild
RUN touch crates/vouch-common/src/lib.rs crates/vouch-server/src/main.rs

# Build the release binary
RUN cargo build --release --package vouch-server

# Create empty data directory marker
RUN mkdir -p /data && touch /data/.keep

# Runtime stage - minimal distroless image with glibc
FROM gcr.io/distroless/cc-debian13:nonroot

LABEL org.opencontainers.image.source=https://github.com/vouch-sh/vouch

# Copy the binary
COPY --from=builder /app/target/release/vouch-server /vouch-server

# Copy built CSS
COPY --from=css-builder /app/crates/vouch-server/static/css/output.css /static/css/output.css

# Create data directory with correct ownership
COPY --from=builder --chown=nonroot:nonroot /data /data

# Environment defaults
ENV VOUCH_LISTEN_ADDR=0.0.0.0:3000
ENV VOUCH_DATABASE_URL=sqlite:/data/vouch.db?mode=rwc

EXPOSE 3000

ENTRYPOINT ["/vouch-server"]

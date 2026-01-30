# syntax=docker/dockerfile:1

# CSS build stage - download and run standalone tailwindcss
FROM debian:trixie-slim AS css-builder

# Declare TARGETARCH to receive automatic value from BuildKit
ARG TARGETARCH

WORKDIR /app

# Download standalone tailwindcss CLI with checksum verification
# Checksums for v4.1.8:
#   tailwindcss-linux-x64:   8f84ce810bdff225e599781d1e2daa82b4282229021c867a71b419f59f9aa836
#   tailwindcss-linux-arm64: 28a77d1e59b0e45b41683c1e3947621fdfe73f6895b05db7c34f63f3f4898e8d
RUN apt-get update && apt-get install -y curl \
    && rm -rf /var/lib/apt/lists/* \
    && case "$TARGETARCH" in \
         amd64) \
           BINARY="tailwindcss-linux-x64" \
           CHECKSUM="8f84ce810bdff225e599781d1e2daa82b4282229021c867a71b419f59f9aa836" \
           ;; \
         arm64) \
           BINARY="tailwindcss-linux-arm64" \
           CHECKSUM="28a77d1e59b0e45b41683c1e3947621fdfe73f6895b05db7c34f63f3f4898e8d" \
           ;; \
         *) \
           echo "Unsupported architecture: $TARGETARCH" && exit 1 \
           ;; \
       esac \
    && curl -sLO "https://github.com/tailwindlabs/tailwindcss/releases/download/v4.1.8/${BINARY}" \
    && echo "${CHECKSUM}  ${BINARY}" | sha256sum -c - \
    && chmod +x "${BINARY}" \
    && mv "${BINARY}" tailwindcss

# Copy files needed for CSS build
COPY crates/vouch-server/tailwind.config.js crates/vouch-server/
COPY crates/vouch-server/styles crates/vouch-server/styles
COPY crates/vouch-server/templates crates/vouch-server/templates
COPY crates/vouch-server/src crates/vouch-server/src

# Build minified CSS
RUN mkdir -p crates/vouch-server/static/css \
    && cd crates/vouch-server \
    && /app/tailwindcss -i styles/input.css -o static/css/output.css --minify

# Rust build stage - using musl for static binary
FROM rust:1.93-alpine AS builder

WORKDIR /app

# Install build dependencies for static compilation
RUN apk add --no-cache musl-dev openssl-dev openssl-libs-static pkgconfig

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

# Build the release binary with static linking
ENV OPENSSL_STATIC=1
ENV OPENSSL_LIB_DIR=/usr/lib
ENV OPENSSL_INCLUDE_DIR=/usr/include
RUN cargo build --release --package vouch-server

# Create empty data directory marker
RUN mkdir -p /data && touch /data/.keep

# Runtime stage - minimal static distroless image (no glibc)
FROM gcr.io/distroless/static-debian13:nonroot

WORKDIR /

LABEL org.opencontainers.image.source=https://github.com/vouch-sh/vouch

# Copy the binary
COPY --from=builder /app/target/release/vouch-server /vouch-server

# Copy built static assets (CSS)
COPY --from=css-builder --chown=nonroot:nonroot /app/crates/vouch-server/static /static

# Create data directory with correct ownership
COPY --from=builder --chown=nonroot:nonroot /data /data

# Environment defaults
ENV VOUCH_LISTEN_ADDR=0.0.0.0:3000
ENV VOUCH_DATABASE_URL=sqlite:/data/vouch.db?mode=rwc

EXPOSE 3000

ENTRYPOINT ["/vouch-server"]

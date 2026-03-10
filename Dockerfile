# syntax=docker/dockerfile:1

# CSS build stage - download and run standalone tailwindcss
FROM debian:trixie-slim AS css-builder

# Declare TARGETARCH to receive automatic value from BuildKit
ARG TARGETARCH

WORKDIR /app

# Download standalone tailwindcss CLI with checksum verification
# Checksums for v4.2.1:
#   tailwindcss-linux-x64:   39e8d4e24b3c83b0a6e69e100a972fbc75d5fef8dce47b3ddac3cf92dea81fe3
#   tailwindcss-linux-arm64: d87e6486bb3f70b04ef1dcaacc4ee6548a5a15fbf521b31bc24d2c774f68a951
RUN apt-get update && apt-get install -y curl \
    && rm -rf /var/lib/apt/lists/* \
    && case "$TARGETARCH" in \
         amd64) \
           BINARY="tailwindcss-linux-x64" \
           CHECKSUM="39e8d4e24b3c83b0a6e69e100a972fbc75d5fef8dce47b3ddac3cf92dea81fe3" \
           ;; \
         arm64) \
           BINARY="tailwindcss-linux-arm64" \
           CHECKSUM="d87e6486bb3f70b04ef1dcaacc4ee6548a5a15fbf521b31bc24d2c774f68a951" \
           ;; \
         *) \
           echo "Unsupported architecture: $TARGETARCH" && exit 1 \
           ;; \
       esac \
    && curl -sLO "https://github.com/tailwindlabs/tailwindcss/releases/download/v4.2.1/${BINARY}" \
    && echo "${CHECKSUM}  ${BINARY}" | sha256sum -c - \
    && chmod +x "${BINARY}" \
    && mv "${BINARY}" tailwindcss

# Copy existing static assets (images, webmanifest) first, then CSS build files
COPY crates/vouch-server/static crates/vouch-server/static
COPY crates/vouch-server/tailwind.config.js crates/vouch-server/
COPY crates/vouch-server/styles crates/vouch-server/styles
COPY crates/vouch-server/templates crates/vouch-server/templates
COPY crates/vouch-server/src crates/vouch-server/src

# Build minified CSS
RUN cd crates/vouch-server \
    && /app/tailwindcss -i styles/input.css -o static/css/output.css --minify

# cargo-chef base stage - shared between planner and builder
FROM rust:1.94.0-alpine AS chef
RUN cargo install cargo-chef --locked
WORKDIR /app

# Planner stage - generate dependency recipe from workspace manifests
FROM chef AS planner
COPY Cargo.toml Cargo.lock ./
COPY crates/vouch-common/Cargo.toml crates/vouch-common/
COPY crates/vouch-server/Cargo.toml crates/vouch-server/
COPY crates/vouch-cli/Cargo.toml crates/vouch-cli/
COPY crates/vouch-agent/Cargo.toml crates/vouch-agent/
COPY crates/vouch-tests/Cargo.toml crates/vouch-tests/

# Create dummy source files so cargo metadata can resolve the workspace
RUN mkdir -p crates/vouch-common/src && touch crates/vouch-common/src/lib.rs \
    && mkdir -p crates/vouch-server/src && touch crates/vouch-server/src/lib.rs crates/vouch-server/src/main.rs \
    && mkdir -p crates/vouch-cli/src && touch crates/vouch-cli/src/lib.rs crates/vouch-cli/src/main.rs \
    && mkdir -p crates/vouch-agent/src && touch crates/vouch-agent/src/lib.rs crates/vouch-agent/src/main.rs \
    && mkdir -p crates/vouch-tests/src && touch crates/vouch-tests/src/lib.rs
RUN cargo chef prepare --recipe-path recipe.json

# Rust build stage - using musl for static binary
FROM chef AS builder

# Build argument for reproducible builds
ARG SOURCE_DATE_EPOCH=0

# Install build dependencies for static compilation
# clang is required for FIPS delocator on aarch64 (GCC-generated assembly fails to parse)
RUN apk add --no-cache musl-dev openssl-dev openssl-libs-static pkgconfig cmake go perl clang
ENV AWS_LC_FIPS_SYS_CC=clang
ENV AWS_LC_FIPS_SYS_CXX=clang++

# Cook dependencies (cached until Cargo.toml/Cargo.lock change)
COPY --from=planner /app/recipe.json recipe.json
ENV OPENSSL_STATIC=1
ENV OPENSSL_LIB_DIR=/usr/lib
ENV OPENSSL_INCLUDE_DIR=/usr/include
RUN cargo chef cook --release --package vouch-server --recipe-path recipe.json

# Restore real manifests (cook leaves stubs with placeholder versions)
COPY Cargo.toml Cargo.lock ./
COPY crates/vouch-common/Cargo.toml crates/vouch-common/
COPY crates/vouch-server/Cargo.toml crates/vouch-server/
COPY crates/vouch-cli/Cargo.toml crates/vouch-cli/
COPY crates/vouch-agent/Cargo.toml crates/vouch-agent/
COPY crates/vouch-tests/Cargo.toml crates/vouch-tests/

# Copy actual source code
COPY crates/vouch-common/src crates/vouch-common/src
COPY crates/vouch-server/src crates/vouch-server/src
COPY crates/vouch-server/migrations crates/vouch-server/migrations
COPY crates/vouch-server/templates crates/vouch-server/templates

# Copy built static assets (needed at compile time for rust-embed)
COPY --from=css-builder /app/crates/vouch-server/static crates/vouch-server/static

# Touch files with deterministic timestamp to ensure rebuild
RUN touch -d "@${SOURCE_DATE_EPOCH}" crates/vouch-common/src/lib.rs crates/vouch-server/src/main.rs

# Build the release binary with static linking
RUN cargo build --release --package vouch-server

# Create empty data directory marker
RUN mkdir -p /data && touch /data/.keep

# Runtime stage - minimal static distroless image (no glibc)
FROM gcr.io/distroless/static-debian13:nonroot

WORKDIR /

LABEL org.opencontainers.image.source=https://github.com/vouch-sh/vouch

# Copy the binary (static assets are embedded via rust-embed)
COPY --from=builder /app/target/release/vouch-server /vouch-server

# Create data directory with correct ownership
COPY --from=builder --chown=nonroot:nonroot /data /data

# Environment defaults
ENV VOUCH_LISTEN_ADDR=0.0.0.0:3000
ENV VOUCH_DATABASE_URL=sqlite:/data/vouch.db?mode=rwc

EXPOSE 3000

ENTRYPOINT ["/vouch-server"]

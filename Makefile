# Makefile for vouch

# Load .env file if present (silently skip if not found)
-include .env
export

# Tool binaries
CARGO ?= cargo
DOCKER ?= docker
KAMAL ?= kamal

# Docker image configuration
IMAGE_NAME ?= vouch-sh/vouch
IMAGE_TAG ?= latest

.PHONY: all build test test-integration test-fuzz test-coverage test-mutants run run-agent clean help docker-build docker-run deploy deploy-logs css-dev css-build docs-build docs-serve bake-cli bake-server bake-all

all: build

##@ Build

build: css-build ## Build the vouch binary (includes CSS)
	$(CARGO) build --release

##@ Development

css-dev: ## Watch and rebuild CSS (requires tailwindcss CLI)
	cd crates/vouch-server && tailwindcss -i styles/input.css -o static/css/output.css --watch

css-build: ## Build minified CSS for production
	cd crates/vouch-server && tailwindcss -i styles/input.css -o static/css/output.css --minify

run: ## Run the vouch CLI locally
	RUST_LOG=warn,vouch_cli=trace $(CARGO) run --bin vouch -- ${ARGS}

run-server: css-build ## Run the vouch server locally (loads .env if present)
	RUST_LOG=info,vouch_server=debug,vouch_httpsig=trace $(CARGO) run --bin vouch-server -- ${ARGS}

run-agent:
	RUST_LOG=debug $(CARGO) run --bin vouch-agent -- --verbose --foreground

fmt: ## Format code
	$(CARGO) fmt --all

lint: ## Run clippy lints
	$(CARGO) clippy --all-targets --all-features -- -D warnings

check: ## Run cargo check
	$(CARGO) check

##@ Testing

test: ## Run unit tests (--all-features ensures feature-gated tests like axum middleware are included)
	$(CARGO) test --all-features

test-integration: ## Run integration tests
	$(CARGO) test --package vouch-tests

test-fuzz: ## Run fuzz targets (60s each, requires nightly)
	cargo +nightly fuzz run fuzz_ber_parse -- -max_total_time=60
	cargo +nightly fuzz run fuzz_attestation_object -- -max_total_time=60
	cargo +nightly fuzz run fuzz_cose_key -- -max_total_time=60
	cargo +nightly fuzz run fuzz_httpsig -- -max_total_time=60

test-coverage: ## Generate test coverage report (requires cargo-llvm-cov)
	$(CARGO) llvm-cov --workspace --html
	@echo "Coverage report: target/llvm-cov/html/index.html"

test-mutants: ## Run mutation testing (requires cargo-mutants)
	$(CARGO) mutants --workspace --timeout 60 --output mutants.out

audit: ## Check dependencies for security advisories and license issues
	$(CARGO) deny check advisories licenses sources

##@ Docker

docker-build: ## Build Docker image
	$(DOCKER) build -t $(IMAGE_NAME):$(IMAGE_TAG) .

docker-run: ## Run Docker container locally
	$(DOCKER) run --rm -it \
		-p 3000:3000 \
		-e VOUCH_RP_ID=localhost \
		-e VOUCH_RP_NAME=Vouch \
		-e VOUCH_JWT_SECRET=dev-secret-at-least-32-characters-long \
		-e RUST_LOG=debug \
		-v vouch-data:/data \
		$(IMAGE_NAME):$(IMAGE_TAG)

##@ Deployment (Kamal)

deploy: ## Deploy to production
	$(KAMAL) deploy

deploy-logs: ## View production logs
	$(KAMAL) app logs

##@ Documentation

docs-build: ## Build documentation
	cd docs && mdbook build

docs-serve: ## Serve documentation locally
	cd docs && mdbook serve --open

##@ Cleanup

clean: ## Clean build artifacts
	$(CARGO) clean

docker-clean: ## Remove Docker images
	$(DOCKER) rmi $(IMAGE_NAME):$(IMAGE_TAG) || true
	$(DOCKER) volume rm vouch-data || true

##@ Docker Bake (musl builds)

bake-cli: ## Build CLI+Agent musl binaries via Docker Bake
	$(DOCKER) buildx bake cli

bake-server: ## Build Server musl binary via Docker Bake
	$(DOCKER) buildx bake server

bake-all: ## Build all musl binaries via Docker Bake
	$(DOCKER) buildx bake ci

##@ Help

help: ## Display this help
	@awk 'BEGIN {FS = ":.*##"; printf "\nUsage:\n  make \033[36m<target>\033[0m\n"} /^[a-zA-Z_0-9-]+:.*?##/ { printf "  \033[36m%-20s\033[0m %s\n", $$1, $$2 } /^##@/ { printf "\n\033[1m%s\033[0m\n", substr($$0, 5) } ' $(MAKEFILE_LIST)

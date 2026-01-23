# Makefile for vouch

# Tool binaries
CARGO ?= cargo
DOCKER ?= docker
KAMAL ?= kamal

# Docker image configuration
IMAGE_NAME ?= vouch-sh/server
IMAGE_TAG ?= latest

.PHONY: all build test run clean help docker-build docker-run deploy deploy-setup

all: build

##@ Build

build: ## Build the vouch binary
	$(CARGO) build --release

##@ Development

run: ## Run the vouch CLI locally
	RUST_LOG=info $(CARGO) run --bin vouch

run-server: ## Run the vouch server locally
	RUST_LOG=debug \
	VOUCH_RP_ID=localhost \
	VOUCH_RP_NAME=Vouch \
	VOUCH_JWT_SECRET=dev-secret-at-least-32-characters-long \
	VOUCH_ADMIN_BOOTSTRAP_TOKEN=admin123 \
	$(CARGO) run --bin vouch-server

fmt: ## Format code
	$(CARGO) fmt --all

lint: ## Run clippy lints
	$(CARGO) clippy --all-targets --all-features -- -D warnings

check: ## Run cargo check
	$(CARGO) check

##@ Testing

test: ## Run unit tests
	$(CARGO) test --test unit

##@ Docker

docker-build: ## Build Docker image
	$(DOCKER) build -t $(IMAGE_NAME):$(IMAGE_TAG) .

docker-run: ## Run Docker container locally
	$(DOCKER) run --rm -it \
		-p 3000:3000 \
		-e VOUCH_RP_ID=localhost \
		-e VOUCH_RP_NAME=Vouch \
		-e VOUCH_JWT_SECRET=dev-secret-at-least-32-characters-long \
		-e VOUCH_ADMIN_BOOTSTRAP_TOKEN=admin123 \
		-e RUST_LOG=debug \
		-v vouch-data:/data \
		$(IMAGE_NAME):$(IMAGE_TAG)

##@ Deployment (Kamal)

deploy-setup: ## Initial Kamal setup (run once)
	$(KAMAL) setup

deploy: ## Deploy to production
	$(KAMAL) deploy

deploy-logs: ## View production logs
	$(KAMAL) app logs

deploy-details: ## Show deployment details
	$(KAMAL) details

##@ Cleanup

clean: ## Clean build artifacts
	$(CARGO) clean

docker-clean: ## Remove Docker images
	$(DOCKER) rmi $(IMAGE_NAME):$(IMAGE_TAG) || true
	$(DOCKER) volume rm vouch-data || true

##@ Help

help: ## Display this help
	@awk 'BEGIN {FS = ":.*##"; printf "\nUsage:\n  make \033[36m<target>\033[0m\n"} /^[a-zA-Z_0-9-]+:.*?##/ { printf "  \033[36m%-20s\033[0m %s\n", $$1, $$2 } /^##@/ { printf "\n\033[1m%s\033[0m\n", substr($$0, 5) } ' $(MAKEFILE_LIST)

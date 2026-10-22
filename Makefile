.PHONY: check build test lint fmt entity help \
       check-user-center build-user-center gen-keys bootstrap \
       deploy

help: ## Show this help
	@grep -E '^[a-zA-Z_-]+:.*?## .*$$' $(MAKEFILE_LIST) | \
		awk 'BEGIN {FS = ":.*?## "}; {printf "\033[36m%-30s\033[0m %s\n", $$1, $$2}'

# ── Workspace ──────────────────────────────────────────

check:    ## cargo check (workspace)
	cargo check --workspace

build:    ## cargo build (workspace)
	cargo build --workspace

test:     ## cargo test (workspace)
	cargo test --workspace

lint:     ## clippy (workspace)
	cargo clippy --workspace -- -D warnings

fmt:      ## rustfmt check
	cargo fmt --all -- --check

fmt-fix:  ## rustfmt write
	cargo fmt --all

# ── Codegen ────────────────────────────────────────────

entity:    ## Regenerate SeaORM entities (needs SERVICE and DATABASE_URL)
	@echo "Usage:  make entity SERVICE=user-center DATABASE_URL=postgres://user:pass@host/db"
	@./scripts/generate-entity.sh "$(SERVICE)" "$(DATABASE_URL)"

# ── Bootstrap ────────────────────────────────────────────

KEYS_DIR   ?= services/user-center/config/keys
CONFIG_DIR ?= services/user-center/config

gen-keys:  ## Generate RSA key pair for signing (KEYS_DIR=...)
	@mkdir -p "$(KEYS_DIR)"
	openssl genpkey -algorithm RSA -out "$(KEYS_DIR)/private.pem" -pkeyopt rsa_keygen_bits:2048
	openssl rsa -pubout -in "$(KEYS_DIR)/private.pem" -out "$(KEYS_DIR)/public.pem"
	@echo "Keys generated in $(KEYS_DIR)/"

TARGET ?= x86_64-unknown-linux-musl
SERVICE ?= user-center
BOOTSTRAP ?= false

deploy:   ## Build & package for Linux (TARGET= SERVICE= BOOTSTRAP=true)
	@./scripts/deploy.sh --target "$(TARGET)" --service "$(SERVICE)" $(if $(filter true,$(BOOTSTRAP)),--bootstrap)

bootstrap: ## Run user-center bootstrap (CONFIG_DIR=... TASKS=...)
	@BOOTSTRAP_FILE="$(CONFIG_DIR)/bootstrap.toml"; \
	if [ ! -f "$$BOOTSTRAP_FILE" ]; then \
		if [ -f "$$BOOTSTRAP_FILE.example" ]; then \
			echo "ERROR: $$BOOTSTRAP_FILE not found. Copy and edit the example:"; \
			echo "  cp $$BOOTSTRAP_FILE.example $$BOOTSTRAP_FILE"; \
		else \
			echo "ERROR: $$BOOTSTRAP_FILE not found."; \
		fi; \
		exit 1; \
	fi
	cargo run --bin bootstrap -- --config-dir "$(CONFIG_DIR)" --keys-dir "$(KEYS_DIR)" $(TASKS:%=--only %)

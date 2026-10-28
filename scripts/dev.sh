#!/usr/bin/env bash
# Build the UI and run the local authentication service against configured dependencies.
set -euo pipefail
PROJECT_ROOT="$(cd "$(dirname "$0")/.." && pwd)"
export PERO_RUN_MODE=local
CONFIG_DIR="$PROJECT_ROOT/services/user-center/config"

if [[ ! -f "$CONFIG_DIR/local.toml" ]]; then
    echo "Missing $CONFIG_DIR/local.toml" >&2
    echo "Copy local.toml.example and configure PostgreSQL, Redis and local secrets first." >&2
    exit 1
fi

bash "$PROJECT_ROOT/scripts/build-frontend.sh"
cd "$PROJECT_ROOT/services/user-center"
# Bind only to loopback for local review.
export PERO__SERVER__HOST=127.0.0.1
export PERO__FRONTEND__STATIC_DIR="$PROJECT_ROOT/frontend/dist"
exec cargo run --locked --bin user-center -- --config-dir "$CONFIG_DIR"

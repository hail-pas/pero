#!/usr/bin/env bash
# Run the exact migration code embedded in the release; never execute loose SQL files.
set -euo pipefail
: "${DATABASE_URL:?Set DATABASE_URL to the database to migrate}"
[[ $# -eq 0 ]] || { echo "Usage: $0 (uses DATABASE_URL)" >&2; exit 1; }
SCRIPT_DIR="$(cd "$(dirname "$0")" && pwd)"
if [[ -x "$SCRIPT_DIR/migrate" ]]; then
    exec "$SCRIPT_DIR/migrate"
fi
exec cargo run --quiet --locked --manifest-path "$SCRIPT_DIR/../Cargo.toml" -p user-center --bin migrate

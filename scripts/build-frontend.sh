#!/usr/bin/env bash
set -euo pipefail
PROJECT_ROOT="$(cd "$(dirname "$0")/.." && pwd)"
cd "$PROJECT_ROOT/frontend"
pnpm install --frozen-lockfile
pnpm build
for service in user-center admin; do
    destination="$PROJECT_ROOT/services/$service/ui/static"
    mkdir -p "$destination"
    rm -rf "$destination/assets" "$destination/icons" "$destination/resources"
    cp -R dist/. "$destination/"
done

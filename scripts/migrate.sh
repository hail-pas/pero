#!/usr/bin/env bash
# Initialize a fresh database. Repeated runs verify the applied schema checksum.
set -euo pipefail
: "${DATABASE_URL:?Set DATABASE_URL to the database to migrate}"
PROJECT_DIR="$(cd "$(dirname "$0")/.." && pwd)"
# Accept an explicit directory; packaged runner defaults to adjacent migrations.
SCRIPT_DIR="$(cd "$(dirname "$0")" && pwd)"
if [[ $# -gt 1 ]]; then echo "Usage: $0 [migrations-directory]" >&2; exit 1; fi
if [[ $# -eq 1 ]]; then
    MIGRATIONS_DIR="$1"
elif [[ -z "${MIGRATIONS_DIR:-}" ]]; then
    if [[ -d "$SCRIPT_DIR/migrations" ]]; then
        MIGRATIONS_DIR="$SCRIPT_DIR/migrations"
    else
        MIGRATIONS_DIR="$PROJECT_DIR/services/user-center/migrations"
    fi
fi
[[ -d "$MIGRATIONS_DIR" ]] || { echo "Migration directory not found" >&2; exit 1; }
SQL_FILE=$(mktemp)
trap 'rm -f "$SQL_FILE"' EXIT
{
    printf '%s\n' 'BEGIN;' "SELECT pg_advisory_xact_lock(hashtext('pero-schema-migrations'));" \
        'CREATE TABLE IF NOT EXISTS schema_migrations(version text PRIMARY KEY, checksum text NOT NULL, applied_at timestamptz NOT NULL DEFAULT now());'
    for file in "$MIGRATIONS_DIR"/*.sql; do
        version=$(basename "$file")
        checksum=$(shasum -a 256 "$file" | cut -d ' ' -f 1)
        [[ "$version" =~ ^[0-9]+_[a-z_]+\.sql$ ]] || exit 1
        printf "SELECT NOT EXISTS(SELECT 1 FROM schema_migrations WHERE version='%s') AS apply, NOT EXISTS(SELECT 1 FROM schema_migrations WHERE version='%s' AND checksum <> '%s') AS valid \\gset\n" "$version" "$version" "$checksum"
        printf '%s\n' '\if :valid' '\else' '\echo Migration checksum mismatch; refusing to continue' 'DO $$ BEGIN RAISE EXCEPTION '"'"'Migration checksum mismatch'"'"'; END $$;' '\endif' '\if :apply'
        cat "$file"
        printf "\nINSERT INTO schema_migrations(version,checksum) VALUES('%s','%s');\n" "$version" "$checksum"
        printf '%s\n' '\endif'
    done
    printf '%s\n' 'COMMIT;'
} > "$SQL_FILE"
psql "$DATABASE_URL" -X -v ON_ERROR_STOP=1 -f "$SQL_FILE"

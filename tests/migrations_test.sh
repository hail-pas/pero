#!/usr/bin/env bash
set -euo pipefail
: "${PERO_TEST_DATABASE_URL:?Dedicated test database required}"
[[ "$PERO_TEST_DATABASE_URL" == *127.0.0.1*"/pero_security_test" ]] || exit 1
ROOT="$(cd "$(dirname "$0")/.." && pwd)"
WORK=$(mktemp -d)
SCHEMA="migration_check_$$"
cleanup() {
  psql "$PERO_TEST_DATABASE_URL" -X -v ON_ERROR_STOP=1 -c "DROP SCHEMA IF EXISTS $SCHEMA CASCADE" >/dev/null
  rm -rf "$WORK"
}
trap cleanup EXIT
psql "$PERO_TEST_DATABASE_URL" -X -v ON_ERROR_STOP=1 -c "CREATE SCHEMA $SCHEMA; CREATE TABLE $SCHEMA.schema_migrations(version text PRIMARY KEY, checksum text NOT NULL, applied_at timestamptz NOT NULL DEFAULT now());" >/dev/null
cp "$ROOT/scripts/migrate.sh" "$WORK/migrate.sh"
cp -R "$ROOT/services/user-center/migrations" "$WORK/migrations"
export DATABASE_URL="$PERO_TEST_DATABASE_URL"
export PGOPTIONS="-csearch_path=$SCHEMA,public"
bash "$WORK/migrate.sh" >/dev/null
FIRST=$(psql "$DATABASE_URL" -X -Atc 'SELECT count(*) FROM schema_migrations')
bash "$WORK/migrate.sh" "$WORK/migrations" >/dev/null
[[ $(psql "$DATABASE_URL" -X -Atc 'SELECT count(*) FROM schema_migrations') == "$FIRST" ]]
printf '\n-- modified checksum\n' >> "$WORK/migrations/001_init.sql"
if bash "$WORK/migrate.sh" >/dev/null 2>&1; then echo 'Checksum mismatch accepted' >&2; exit 1; fi
[[ $(psql "$DATABASE_URL" -X -Atc 'SELECT count(*) FROM schema_migrations') == "$FIRST" ]]
echo 'Packaged migrations: initial, repeat and checksum rejection passed'

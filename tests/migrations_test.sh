#!/usr/bin/env bash
set -euo pipefail
: "${PERO_TEST_DATABASE_URL:?Dedicated test database required}"
[[ "$PERO_TEST_DATABASE_URL" == *127.0.0.1*"/pero_security_test" ]] || exit 1
ROOT="$(cd "$(dirname "$0")/.." && pwd)"
SCHEMA="migration_check_$$"
export DATABASE_URL="$PERO_TEST_DATABASE_URL"
export PGOPTIONS="-csearch_path=$SCHEMA,public"
cleanup() {
  psql "$PERO_TEST_DATABASE_URL" -X -v ON_ERROR_STOP=1 -c "DROP SCHEMA IF EXISTS $SCHEMA CASCADE" >/dev/null
}
trap cleanup EXIT
psql "$DATABASE_URL" -X -v ON_ERROR_STOP=1 -c "CREATE SCHEMA $SCHEMA" >/dev/null
cargo build --quiet --locked --manifest-path "$ROOT/Cargo.toml" -p user-center --bin migrate
# SQLx uses URI options rather than libpq's PGOPTIONS.
if [[ "$DATABASE_URL" == *\?* ]]; then separator='&'; else separator='?'; fi
export DATABASE_URL="${DATABASE_URL}${separator}options=-csearch_path%3D${SCHEMA},public"
RUNNER="$ROOT/target/debug/migrate"
"$RUNNER" >/dev/null &
first=$!
"$RUNNER" >/dev/null &
second=$!
wait "$first"
wait "$second"
[[ $(psql "$DATABASE_URL" -X -Atc 'SELECT count(*) FROM schema_migrations') == 1 ]]
"$RUNNER" >/dev/null
psql "$DATABASE_URL" -X -v ON_ERROR_STOP=1 -c "UPDATE schema_migrations SET checksum='tampered'" >/dev/null
if "$RUNNER" >/dev/null 2>&1; then echo 'Checksum mismatch accepted' >&2; exit 1; fi
# Recreate a pristine baseline, then verify unknown versions and schema drift are rejected.
psql "$DATABASE_URL" -X -v ON_ERROR_STOP=1 -c "DROP SCHEMA $SCHEMA CASCADE; CREATE SCHEMA $SCHEMA" >/dev/null
"$RUNNER" >/dev/null
psql "$DATABASE_URL" -X -v ON_ERROR_STOP=1 -c "INSERT INTO schema_migrations(version,checksum) VALUES('999_unknown.sql','unknown')" >/dev/null
if "$RUNNER" >/dev/null 2>&1; then echo 'Unknown version accepted' >&2; exit 1; fi
psql "$DATABASE_URL" -X -v ON_ERROR_STOP=1 -c "DELETE FROM schema_migrations WHERE version='999_unknown.sql'; ALTER TABLE sso_sessions DISABLE TRIGGER session_backchannel_logout" >/dev/null
if "$RUNNER" >/dev/null 2>&1; then echo 'Disabled security trigger accepted' >&2; exit 1; fi
echo 'Migrations: concurrent startup, repeat, checksum, unknown version and schema verification passed'

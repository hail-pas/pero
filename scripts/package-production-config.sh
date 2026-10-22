#!/usr/bin/env bash
# Package private configuration only. Application source is pulled from GitHub on the server.
set -euo pipefail
umask 077
ROOT="$(cd "$(dirname "$0")/.." && pwd)"
CONFIG_DIR="$ROOT/local/deploy/pero/config"
while [[ $# -gt 0 ]]; do
    case "$1" in
        --config-dir)
            [[ $# -ge 2 && -n "$2" ]] || { echo '--config-dir requires a directory' >&2; exit 1; }
            CONFIG_DIR="$2"; shift 2 ;;
        --help|-h)
            echo "Usage: $0 [--config-dir DIR]"
            echo 'Packages config only; requires Python 3.11+ (PERO_PYTHON override). No Rust/Zig/Docker required.'
            exit 0 ;;
        *) echo "Unknown argument: $1" >&2; exit 1 ;;
    esac
done
PYTHON="${PERO_PYTHON:-python3}"
"$PYTHON" -c 'import sys; assert sys.version_info >= (3, 11), "Python 3.11+ required; set PERO_PYTHON"'
CONFIG_DIR="$(cd "$CONFIG_DIR" && pwd)"
for file in production.toml bootstrap.toml keys/private.pem keys/public.pem; do
    test -s "$CONFIG_DIR/$file" || { echo "Missing $CONFIG_DIR/$file" >&2; exit 1; }
done
mkdir -p "$ROOT/deploy"
STAGE="$(mktemp -d "$ROOT/deploy/.pero-config.XXXXXX")"
trap 'rm -rf "$STAGE"' EXIT
mkdir -p "$STAGE/config/keys"
cp "$ROOT/services/user-center/config/default.toml" "$STAGE/config/"
"$PYTHON" "$ROOT/scripts/sync-deploy-config.py" \
    --defaults "$ROOT/services/user-center/config/default.toml" \
    --previous "$CONFIG_DIR/production.toml" --output "$STAGE/config/production.toml"
cp "$CONFIG_DIR/bootstrap.toml" "$STAGE/config/"
cp "$CONFIG_DIR/keys/private.pem" "$CONFIG_DIR/keys/public.pem" "$STAGE/config/keys/"
find "$STAGE/config" -type d -exec chmod 700 {} +
find "$STAGE/config" -type f -exec chmod 600 {} +
ARCHIVE=pero-config.tar.gz
tar -czf "$STAGE/config.tar.gz" -C "$STAGE" config
mv -f "$STAGE/config.tar.gz" "$ROOT/deploy/$ARCHIVE"
chmod 600 "$ROOT/deploy/$ARCHIVE"
(cd "$ROOT/deploy" && shasum -a 256 "$ARCHIVE" > "$ARCHIVE.sha256")
echo "Private config: $ROOT/deploy/$ARCHIVE"
cat "$ROOT/deploy/$ARCHIVE.sha256"
echo 'Transfer over SSH; never commit this archive. Source is built by Docker on the server.'

#!/usr/bin/env bash
set -euo pipefail

usage() {
    cat <<EOF
Usage: $(basename "$0") [OPTIONS]

Options:
  -t, --target TARGET      Target triple (default: x86_64-unknown-linux-musl)
  -s, --service SERVICE    Service to build (default: user-center)
  -b, --bootstrap          Also build the bootstrap binary (default: off)
  -h, --help               Show this help

Examples:
  $(basename "$0")
  $(basename "$0") --target aarch64-unknown-linux-musl
  $(basename "$0") --service admin
  $(basename "$0") --service user-center --bootstrap
EOF
    exit 0
}

TARGET="x86_64-unknown-linux-musl"
SERVICE="user-center"
BOOTSTRAP=false

while [[ $# -gt 0 ]]; do
    case "$1" in
        -t|--target)   TARGET="$2";   shift 2 ;;
        -s|--service)  SERVICE="$2";  shift 2 ;;
        -b|--bootstrap) BOOTSTRAP=true; shift ;;
        -h|--help)     usage ;;
        *) echo "Unknown option: $1"; usage ;;
    esac
done

PROJECT_ROOT="$(cd "$(dirname "$0")/.." && pwd)"
cd "${PROJECT_ROOT}"

SERVICE_DIR="services/${SERVICE}"
if [ ! -d "${SERVICE_DIR}" ]; then
    echo "Error: service directory not found: ${SERVICE_DIR}"
    exit 1
fi

DEPLOY_DIR="deploy/${SERVICE}"
ARCHIVE_NAME="${SERVICE}-${TARGET}.tar.gz"

BINS=("--bin" "${SERVICE}")
if [[ "$SERVICE" == user-center ]]; then BINS+=("--bin" "migrate"); fi
if [ "${BOOTSTRAP}" = true ]; then
    BINS+=("--bin" "bootstrap")
fi

bash scripts/build-frontend.sh

echo "── Building ${SERVICE} (${TARGET}, release) ──"

if ! rustup target list --installed | grep -q "${TARGET}"; then
    echo "Installing target ${TARGET}..."
    rustup target add "${TARGET}"
fi

if ! command -v zig &>/dev/null; then
    echo "Installing zig..."
    brew install zig
fi

if ! command -v cargo-zigbuild &>/dev/null; then
    echo "Installing cargo-zigbuild..."
    cargo install cargo-zigbuild --locked
fi

BUILD_LOG=$(mktemp)
trap 'rm -f "$BUILD_LOG"' EXIT
if ! cargo zigbuild \
    --release \
    --locked \
    -p "${SERVICE}" \
    --target "${TARGET}" \
    --message-format=json-render-diagnostics \
    "${BINS[@]}" > "$BUILD_LOG"; then
    cat "$BUILD_LOG"
    exit 1
fi

echo "── Packaging ──"

rm -rf "${DEPLOY_DIR}"
mkdir -p "${DEPLOY_DIR}"

cp "target/${TARGET}/release/${SERVICE}" "${DEPLOY_DIR}/"
if [ "${BOOTSTRAP}" = true ]; then
    cp "target/${TARGET}/release/bootstrap" "${DEPLOY_DIR}/"
fi

mkdir -p "${DEPLOY_DIR}/ui/static"
cp -R frontend/dist/. "${DEPLOY_DIR}/ui/static/"

if [[ "$SERVICE" == user-center ]]; then
    cp scripts/migrate.sh "${DEPLOY_DIR}/migrate.sh"
    cp "target/${TARGET}/release/migrate" "${DEPLOY_DIR}/migrate"
fi

# Ship public defaults/examples only; operators generate private keys on the destination.
mkdir -p "${DEPLOY_DIR}/config"
cp "${SERVICE_DIR}/config/default.toml" "${DEPLOY_DIR}/config/"
for example in "${SERVICE_DIR}/config/"*.example; do
    [ ! -f "${example}" ] || cp "${example}" "${DEPLOY_DIR}/config/"
done

echo "── Creating archive ──"

rm -f "deploy/${ARCHIVE_NAME}"
mkdir -p deploy
tar -czf "deploy/${ARCHIVE_NAME}" -C deploy "$(basename "${DEPLOY_DIR}")"

SIZE=$(du -h "deploy/${ARCHIVE_NAME}" | cut -f1)
CHECKSUM=$(shasum -a 256 "deploy/${ARCHIVE_NAME}" | cut -d' ' -f1)

echo ""
echo "── Done ──"
echo "  Archive:  deploy/${ARCHIVE_NAME} (${SIZE})"
echo "  SHA256:   ${CHECKSUM}"
echo "  Service:  ${SERVICE}"
echo "  Target:   ${TARGET}"
echo "  Bootstrap: ${BOOTSTRAP}"

#!/usr/bin/env bash
# Build locally and export a Linux amd64 runtime image for a small server.
set -euo pipefail
umask 077
ROOT="$(cd "$(dirname "$0")/.." && pwd)"
IMAGE_TAG="git-$(git -C "$ROOT" rev-parse --short=12 HEAD)"
IMAGE="pero-user-center:$IMAGE_TAG"
ARCHIVE=pero-user-center-linux-amd64.tar.gz
if ! command -v docker >/dev/null && [[ -x "${HOME}/.docker/bin/docker" ]]; then
    export PATH="${HOME}/.docker/bin:${PATH}"
fi
command -v docker >/dev/null || { echo 'Docker not found. Install/start Docker Desktop or another local Docker engine first.' >&2; exit 1; }
docker info >/dev/null || { echo 'Docker engine is unavailable. Start the local Docker engine first.' >&2; exit 1; }
docker buildx version >/dev/null
docker buildx build --platform linux/amd64 --load --pull \
    --build-arg "CARGO_BUILD_JOBS=${PERO_BUILD_JOBS:-2}" \
    -f "$ROOT/deploy/pero/Dockerfile" -t "$IMAGE" "$ROOT"
PLATFORM="$(docker image inspect "$IMAGE" --format '{{.Os}}/{{.Architecture}}')"
[[ "$PLATFORM" == linux/amd64 ]] || { echo "Wrong image platform: $PLATFORM" >&2; exit 1; }
mkdir -p "$ROOT/deploy"
STAGE="$(mktemp -d "$ROOT/deploy/.pero-image.XXXXXX")"
trap 'rm -rf "$STAGE"' EXIT
docker image save --platform linux/amd64 "$IMAGE" | gzip > "$STAGE/$ARCHIVE"
mv -f "$STAGE/$ARCHIVE" "$ROOT/deploy/$ARCHIVE"
(cd "$ROOT/deploy" && shasum -a 256 "$ARCHIVE" > "$ARCHIVE.sha256")
printf 'PERO_IMAGE_TAG=%s\n' "$IMAGE_TAG" > "$STAGE/pero-image.env"
mv -f "$STAGE/pero-image.env" "$ROOT/deploy/pero-image.env"
echo "Image: $IMAGE ($PLATFORM)"
echo "Archive: $ROOT/deploy/$ARCHIVE"
cat "$ROOT/deploy/$ARCHIVE.sha256"
echo 'Upload the archive, checksum, deploy/pero-image.env and deploy/pero/compose.yaml; load the image on the server. Existing production config is reused.'

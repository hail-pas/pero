FROM docker.io/library/node:24-bookworm-slim AS frontend
WORKDIR /frontend
RUN npm install --global pnpm@11.25.0
COPY frontend/package.json frontend/pnpm-lock.yaml frontend/pnpm-workspace.yaml ./
RUN pnpm install --frozen-lockfile
COPY frontend/ ./
RUN pnpm build

# Use Docker's bundled BuildKit frontend; no extra frontend image download is needed.
# Official multi-platform manifest digests prevent stale mirror tags selecting old images.
FROM docker.io/library/rust:1.95.0-bookworm@sha256:6258907abe69656e41cd992e0b705cdcfabcbbe3db374f92ed2d47121282d4a1 AS builder
RUN apt-get update \
    && apt-get install -y --no-install-recommends build-essential cmake pkg-config python3 perl \
    && rm -rf /var/lib/apt/lists/*
WORKDIR /src
COPY Cargo.toml Cargo.lock ./
COPY crates/ crates/
COPY services/ services/
COPY scripts/migrate.sh scripts/
ARG CARGO_BUILD_JOBS=2
RUN --mount=type=cache,target=/usr/local/cargo/registry \
    --mount=type=cache,target=/usr/local/cargo/git \
    --mount=type=cache,target=/src/target \
    (cargo build --release --locked -p user-center --bin user-center --bin bootstrap \
      --target x86_64-unknown-linux-gnu --jobs "$CARGO_BUILD_JOBS" \
      --message-format=json-render-diagnostics > /tmp/build.json \
      || { cat /tmp/build.json; exit 1; }) \
    && mkdir -p /out/ui /out/migrations \
    && cp target/x86_64-unknown-linux-gnu/release/user-center target/x86_64-unknown-linux-gnu/release/bootstrap /out/ \
    && cp services/user-center/migrations/*.sql /out/migrations/ \
    && cp scripts/migrate.sh /out/migrate.sh

FROM docker.io/library/debian:bookworm-slim@sha256:7ff6ba31527b9e336162fa061746c366c4b2032f4d2cff2078bea43f78efe3f8 AS runtime
RUN apt-get update \
    && apt-get install -y --no-install-recommends ca-certificates curl python3 postgresql-client libdigest-sha-perl libgcc-s1 \
    && rm -rf /var/lib/apt/lists/* \
    && groupadd --gid 10001 pero \
    && useradd --uid 10001 --gid 10001 --no-create-home --shell /usr/sbin/nologin pero
WORKDIR /opt/pero
COPY --from=builder /out/ /opt/pero/prd/
COPY --from=frontend /frontend/dist/ /opt/pero/prd/ui/static/
COPY deploy/pero/initialize.py /opt/pero/initialize.py
RUN find /opt/pero/prd -type d -exec chmod 755 {} + \
    && find /opt/pero/prd -type f -exec chmod 644 {} + \
    && chmod 755 /opt/pero/prd/user-center /opt/pero/prd/bootstrap /opt/pero/prd/migrate.sh \
    && mkdir -p /opt/pero/logs/prd \
    && chown -R 10001:10001 /opt/pero/logs
USER 10001:10001
ENV PERO_RUN_MODE=production
ENTRYPOINT ["/opt/pero/prd/user-center"]
CMD ["--config-dir", "/opt/pero/config"]

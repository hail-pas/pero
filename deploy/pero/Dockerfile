# syntax=docker/dockerfile:1
FROM rust:1.95.0-bookworm AS builder
RUN apt-get update \
    && apt-get install -y --no-install-recommends build-essential cmake pkg-config python3 perl \
    && rm -rf /var/lib/apt/lists/*
WORKDIR /src
COPY Cargo.toml Cargo.lock ./
COPY crates/ crates/
COPY services/ services/
COPY scripts/package-ui-assets.py scripts/migrate.sh scripts/
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
    && cp -r services/user-center/ui/static /out/ui/ \
    && python3 scripts/package-ui-assets.py /tmp/build.json /out/ui/static \
    && cp services/user-center/migrations/*.sql /out/migrations/ \
    && cp scripts/migrate.sh /out/migrate.sh

FROM debian:bookworm-slim AS runtime
RUN apt-get update \
    && apt-get install -y --no-install-recommends ca-certificates curl python3 postgresql-client libdigest-sha-perl libgcc-s1 \
    && rm -rf /var/lib/apt/lists/* \
    && groupadd --gid 10001 pero \
    && useradd --uid 10001 --gid 10001 --no-create-home --shell /usr/sbin/nologin pero
WORKDIR /opt/pero
COPY --from=builder /out/ /opt/pero/prd/
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

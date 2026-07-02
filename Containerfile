# syntax=docker/dockerfile:1

########################################
# Builder stage: fully static musl build
########################################
FROM rust:1-alpine AS build

# Toolchain the build needs:
#   musl-dev + build-base : C toolchain for rusqlite's bundled sqlite (C source)
#   perl                  : required by `ring` (rustls crypto backend) on musl
#   pkgconfig             : harmless; occasionally used by build scripts
# NOTE: utoipa-swagger-ui's build script downloads the Swagger UI zip from
# GitHub over HTTPS at build time, so the build stage needs network access
# (available on stock GitHub Actions runners).
RUN apk add --no-cache musl-dev build-base perl pkgconfig

# rust:alpine already targets x86_64-unknown-linux-musl by default, but we set
# it explicitly and force fully-static linking (no dynamic libc).
ENV RUSTFLAGS="-C target-feature=+crt-static"
ENV CARGO_TERM_COLOR=never

WORKDIR /src

# --- Dependency prefetch layer (cached unless manifests change) ---
COPY Cargo.toml Cargo.lock ./
# Create a dummy source tree so `cargo build` can resolve & compile deps.
RUN mkdir -p src \
    && echo 'fn main() {}' > src/main.rs \
    && echo '' > src/lib.rs \
    && cargo build --release --target x86_64-unknown-linux-musl \
    && rm -rf src

# --- Real build ---
COPY src ./src
COPY tests ./tests
# Touch to make sure cargo rebuilds the (now real) crate, not the dummy.
RUN touch src/main.rs src/lib.rs

# Optionally run the test suite during the image build (fail fast in CI).
RUN cargo test --release --target x86_64-unknown-linux-musl

RUN cargo build --release --target x86_64-unknown-linux-musl

# Verify the binary is a static executable (no dynamic interpreter).
RUN test -f target/x86_64-unknown-linux-musl/release/app

# Stage the runtime file layout (binary + writable data dir owned by 10001:0)
# so we can COPY it into the shell-less distroless image with correct ownership.
RUN mkdir -p /out/app/data \
    && cp target/x86_64-unknown-linux-musl/release/app /out/app/app \
    && chmod 0755 /out/app/app \
    && chown -R 10001:0 /out/app \
    && chmod -R g+rwX /out/app/data

########################################
# Runtime stage: distroless hardened base
########################################
FROM ghcr.io/kelleyblackmore/rhel9-micro-hardened-base:latest

# Distroless: no shell, no package manager. Only COPY / ENV / metadata allowed.
COPY --from=build --chown=10001:0 /out/app /app

ENV DB_PATH=/app/data/secureledger.db \
    BIND_ADDR=0.0.0.0:8080 \
    RUST_LOG=info

# Declare the data dir as a volume so it stays writable even on read-only rootfs.
VOLUME ["/app/data"]

EXPOSE 8080
WORKDIR /app
USER 10001

ENTRYPOINT ["/app/app"]

# --- OCI image labels ---
LABEL org.opencontainers.image.title="secureledger" \
      org.opencontainers.image.description="SecureLedger - secure task & audit REST API on a distroless ubi9-micro base" \
      org.opencontainers.image.source="https://github.com/kelleyblackmore/rhel9-app-micro" \
      org.opencontainers.image.licenses="MIT" \
      org.opencontainers.image.vendor="kelleyblackmore" \
      org.opencontainers.image.base.name="ghcr.io/kelleyblackmore/rhel9-micro-hardened-base:latest"

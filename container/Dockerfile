# syntax=docker/dockerfile:1

# ─── SPA builder ──────────────────────────────────────────────────────────────
FROM node:22-alpine AS ui-builder

RUN corepack enable && corepack prepare pnpm@latest --activate

WORKDIR /build
COPY crates/ewqwe-credential-verifier-ui/ui/package.json \
     crates/ewqwe-credential-verifier-ui/ui/pnpm-lock.yaml \
     ./
RUN pnpm install --frozen-lockfile

COPY crates/ewqwe-credential-verifier-ui/ui/ ./
RUN pnpm build

# ─── Dev certificates (signer) ────────────────────────────────────────────────
FROM alpine:3.20 AS cert-builder

RUN apk add --no-cache openssl

WORKDIR /certs
COPY certificates/signer/ ./
RUN sh generate_signer_certs.sh

# ─── Rust builder ──────────────────────────────────────────────────────────────
FROM rust:alpine AS rust-builder

RUN apk add --no-cache pkgconfig openssl-dev musl-dev perl make

WORKDIR /build

# ── Cache layer 1: workspace manifests ─────────────────────────────────────
# Copy only Cargo.toml files first so Docker can cache dependency downloads.
COPY Cargo.toml Cargo.lock ./
COPY crates/ewqwe-logging/Cargo.toml crates/ewqwe-logging/
COPY crates/ewqwe-digital-credential/Cargo.toml crates/ewqwe-digital-credential/
COPY crates/ewqwe-openid4vp/Cargo.toml crates/ewqwe-openid4vp/
COPY crates/ewqwe-credential-verifier-client/Cargo.toml crates/ewqwe-credential-verifier-client/
COPY crates/ewqwe-credential-verifier-ui/Cargo.toml crates/ewqwe-credential-verifier-ui/
COPY crates/ewqwe-credential-verifier-server/Cargo.toml crates/ewqwe-credential-verifier-server/

# Create stub source files so `cargo build` compiles all dependencies.
# The actual source is copied in the next layer.
RUN mkdir -p crates/ewqwe-logging/src && touch crates/ewqwe-logging/src/lib.rs && \
    mkdir -p crates/ewqwe-digital-credential/src && touch crates/ewqwe-digital-credential/src/lib.rs && \
    mkdir -p crates/ewqwe-openid4vp/src && touch crates/ewqwe-openid4vp/src/lib.rs && \
    mkdir -p crates/ewqwe-credential-verifier-client/src && touch crates/ewqwe-credential-verifier-client/src/lib.rs && \
    mkdir -p crates/ewqwe-credential-verifier-ui/src && touch crates/ewqwe-credential-verifier-ui/src/lib.rs && \
    mkdir -p crates/ewqwe-credential-verifier-server/src && \
      printf 'fn main() {}' > crates/ewqwe-credential-verifier-server/src/main.rs

# Build dependencies only — the binary won't link successfully with stubs,
# but all transitive crate dependencies are downloaded and compiled.
RUN --mount=type=cache,target=/usr/local/cargo/registry \
    --mount=type=cache,target=/build/target \
    cargo build -p ewqwe_credential_verifier_server --release 2>/dev/null; true

# ── Cache layer 2: actual source ───────────────────────────────────────────
COPY crates/ crates/

# Copy the built SPA assets into the UI crate so they are available at runtime.
COPY --from=ui-builder /build/dist /build/crates/ewqwe-credential-verifier-ui/ui/dist

RUN --mount=type=cache,target=/usr/local/cargo/registry \
    --mount=type=cache,target=/build/target \
    cargo build -p ewqwe_credential_verifier_server --release && \
    cp target/release/ewqwe_credential_verifier_server /usr/local/bin/

# ─── Runtime image (distroless, Alpine-based) ───────────────────────────────
# Alpine with apk removed: no package manager, no build tools, no package
# indexes — just the application and its runtime data.  The only userland
# binary besides the server is busybox (shell + core utils, ~800 KB), needed
# by the entrypoint script.  The server binary is fully static (openssl
# vendored, musl-linked), so there are no surprise library dependencies.
FROM alpine:3.20

RUN apk add --no-cache ca-certificates tzdata && \
    rm -rf /usr/sbin/apk /etc/apk /var/cache/apk /lib/apk

# Pre-create the issuers CA directory so the server doesn't fail on startup
# when no volume is mounted.
RUN mkdir -p /data/certificates/issuers_cas

COPY --from=rust-builder /usr/local/bin/ewqwe_credential_verifier_server /usr/local/bin/
COPY --from=ui-builder /build/dist /usr/share/ewqwe/ui/dist
COPY --from=cert-builder /certs/*.pem /usr/share/ewqwe/certificates/signer/
COPY container/http-credential-server.toml /etc/ewqwe/credential-server.toml
COPY container/entrypoint.sh /entrypoint.sh
RUN chmod +x /entrypoint.sh

VOLUME ["/data"]
EXPOSE 4043
ENTRYPOINT ["/entrypoint.sh"]

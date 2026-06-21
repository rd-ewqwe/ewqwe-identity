# ewQwe Credential Verifier — Container Image

An OCI container image for the ewQwe Credential Verifier, with its embedded Admin UI,
ready to run with Docker or Podman.

## Quick Start (HTTP — no TLS)

> HTTP mode is intended for local development or operations behind a reverse proxy.
> Set `PUBLIC_ROOT_URL` so the wallet can reach the server (required for QR code
> generation to work). If you want TLS (recommended for production), see below.

This set-up assumes you have a reverse proxy or load balancer in front of the server
that answers requests to `https://verifier.your-domain.com` and forwards them without
TLS to the server's `9888` port.

The repository provides a ready-to-use [NGINX + Certbot reverse proxy](../reverse-proxy/)
that obtains Let's Encrypt TLS certificates automatically and proxies traffic to
the HTTP-mode verifier. See its [README](../reverse-proxy/README.md) for setup
instructions.

```bash
# Build from the repository root
docker build -t ewqwe/credential-verifier -f container/Dockerfile .

# Run (HTTP mode, ephemeral SQLite, public URL via env var)
docker run --rm -p 9888:9888 \
  -e PUBLIC_ROOT_URL="https://verifier.your-domain.com" \
  --name credential-verifier \
  ewqwe/credential-verifier
```

The server starts in **HTTP mode** on port 9888. The Admin UI is available at
`http://localhost:9888` and `https://verifier.your-domain.com`. Complete the one-time
bootstrap to create an admin account.

## Environment Variables

The entrypoint script supports these environment variables:

| Variable | Default | Description |
|---|---|---|
| `PUBLIC_ROOT_URL` | *(none)* | Public URL reachable by wallets, e.g. `https://verifier.example.com`. Required for QR code flows. |
| `HOST_PORT` | `9888` | Port the server listens on. Set to `4043` when using TLS. |
| `RUST_LOG` | *(none)* | Logging filter, e.g. `info,ewqwe_credential_verifier_server=debug`. Overrides the config's `rust_log`. |
| `SESSION_SECRET` | *(auto-generated)* | Hex-encoded session secret (≥ 64 hex chars). Set a fixed value for stable sessions across restarts. |
| `SIGNER_CERT_PATH` | built-in dev cert | Path to signer certificate PEM. Overrides `attestation_issuer_certificate`. |
| `SIGNER_KEY_PATH` | built-in dev key | Path to signer private key PEM. Overrides `attestation_issuer_key`. |
| `ANSI_COLORS` | `false` | Set to `yes`, `true`, or `1` to enable ANSI escape codes in log output. |

### Using with Docker

```bash
docker run --rm -p 9888:9888 \
  -e PUBLIC_ROOT_URL="https://verifier.example.com" \
  -e HOST_PORT=9888 \
  -e RUST_LOG="info,ewqwe_credential_verifier_server=debug" \
  -e SESSION_SECRET="$(openssl rand -hex 32)" \
  -v db-data:/data \
  --name credential-verifier \
  ewqwe/credential-verifier
```

## Signer Certificates (Attestation Signing)

The server signs attestation JWTs using a signer certificate and private key.
The container includes development signer certificates (auto-generated at build
time) at `/usr/share/ewqwe/certificates/signer/`.

**For development / evaluation** — no action needed. The built-in dev certs work
out of the box.

**For production** — provide your own signer certificates:

### Option A: Mount a volume with your certs (Docker, Docker Compose)

```bash
# 1. Place your signer cert+key on the host
mkdir -p /host/path/data/certificates/signer
cp your-signer.cert.pem /host/path/data/certificates/signer/signer.cert.pem
cp your-signer.key.pem  /host/path/data/certificates/signer/signer.key.pem

# 2. Run with volume mount and env vars pointing to the files
docker run -d \
  -p 9888:9888 \
  -e PUBLIC_ROOT_URL="https://verifier.your-domain.com" \
  -e SIGNER_CERT_PATH="/data/certificates/signer/signer.cert.pem" \
  -e SIGNER_KEY_PATH="/data/certificates/signer/signer.key.pem" \
  -v /host/path/data:/data \
  ewqwe/credential-verifier
```

The `-v /host/path/data:/data` mount also persists the SQLite databases, so
the container survives restarts with all data intact.

### Option B: Kubernetes Secrets

In Kubernetes, mount signer certificates as a Secret and use `SIGNER_CERT_PATH` /
`SIGNER_KEY_PATH` env vars to point at the mounted paths. See the
[Kubernetes section](#kubernetes-usage) for a full example.

## TLS Configuration

When the server terminates TLS directly (no reverse proxy in front), add a
`[tls_params]` section to the config and mount your TLS certificate, private key,
and CA chain.

The container always starts in HTTP mode unless `[tls_params]` is present in the
config. The `host_port` should typically be set to `4043` (or another privileged
port) when TLS is enabled.

### Mount TLS certificates (Docker)

```bash
# 1. Prepare TLS certificates on the host
mkdir -p /tmp/ewqwe-data/certificates/tls
cp verifier.example.com.key.pem  /tmp/ewqwe-data/certificates/tls/server.key.pem
cp verifier.example.com.cert.pem /tmp/ewqwe-data/certificates/tls/server.cert.pem
cp ca-cert.pem                   /tmp/ewqwe-data/certificates/tls/ca.pem

# 2. Create a config with [tls_params]
cat > /tmp/ewqwe-data/credential-server.toml << 'EOF'
host_name = "0.0.0.0"
host_port = 4043
public_root_url = "https://verifier.example.com"

issuers_cas_dir = "/data/certificates/issuers_cas"

[tls_params]
server_private_key = "/data/certificates/tls/server.key.pem"
server_certificate = "/data/certificates/tls/server.cert.pem"
server_ca_chain    = "/data/certificates/tls/ca.pem"
client_ca_cert_chain = "/data/certificates/tls/ca.pem"

[openid4vp_config]
transaction_ttl_secs = 300

[openid4vp_config.transaction_store]
backend = "sqlite_file"
path = "/data/transactions.db"

[openid4vp_config.haip_config]
x509_cert_path = "/usr/share/ewqwe/certificates/signer/ewqwe.signer.leaf.fullchain.pem"
x509_key_path = "/usr/share/ewqwe/certificates/signer/ewqwe.signer.leaf.key.pem"

[journal_config]
enabled = true
backend = "sqlite_file"
path = "/data/journal.db"

[verifier_ui]
enabled = true
app_name = "ewQwe Verifier"
session_secret = "<generate with: openssl rand -hex 32>"
ui_dist_path = "/usr/share/ewqwe/ui/dist"

[verifier_ui.db]
backend = "sqlite_file"
path = "/data/verifier_ui.db"

[tracing_config]
with_ansi_colors = false
EOF

# 3. Run with TLS and persistent data
docker run -d \
  --name ewqwe-verifier \
  -p 4043:4043 \
  -v /tmp/ewqwe-data:/data \
  ewqwe/credential-verifier
```

Note that the TOML above sets `public_root_url` directly in the config. You may
also omit it and use the `PUBLIC_ROOT_URL` env var instead.

### TLS certificates from Kubernetes Secrets

In Kubernetes, mount TLS certificates as a Secret and reference their paths in
the `[tls_params]` section of the config. See the [Kubernetes section](#kubernetes-usage)
for a full example.

## Persistent Storage

Mount a directory at `/data` to persist SQLite databases across restarts:

```bash
docker run -v /host/path:/data ewqwe/credential-verifier
```

The container stores these files under `/data`:

| File | Purpose | Survives restart? |
|---|---|---|
| `transactions.db` | OpenID4VP transaction state | ✅ when `/data` is mounted |
| `journal.db` | Verification audit log | ✅ when `/data` is mounted |
| `verifier_ui.db` | Admin UI user accounts and settings | ✅ when `/data` is mounted |

## Custom Configuration

Mount a custom TOML config at `/data/credential-server.toml` to fully override the
default:

```bash
docker run -v /host/path/config.toml:/data/credential-server.toml \
  ewqwe/credential-verifier
```

When a config is mounted at `/data/credential-server.toml`, environment variables
are still applied to it by the entrypoint.

## Kubernetes Usage

When running in Kubernetes, mount certificates as Secrets and databases on a
PersistentVolume. Environment variables drive the configuration without needing
to build a custom image.

> **Replicas:** The open-core version uses SQLite for all stores. SQLite does not
> support concurrent writes from multiple processes, so `replicas: 1` is required.
> For a replicated deployment with PostgreSQL/Redis backends, use the
> [enterprise version](https://ewqwe.eu) of the credential verifier.

### Directory Layout on a Kubernetes Pod

```text
/data/
  credential-server.toml          ← ConfigMap (optional — env vars can drive defaults)
  transactions.db                 ← PersistentVolume
  journal.db                      ← PersistentVolume
  verifier_ui.db                  ← PersistentVolume
  certificates/
    tls/                          ← Secret (kubernetes.io/tls)
      tls.crt                     ← server certificate + intermediates
      tls.key                     ← server private key
      ca.pem                      ← root CA (added separately)
    signer/                       ← Secret (Opaque)
      signer.cert.pem
      signer.key.pem
    issuers_cas/                  ← ConfigMap
      ...
```

### Creating the Secrets

Create the Secrets from your local certificate files using `kubectl`. Do **not**
embed PEM data in YAML manifests — use `kubectl create secret` instead.

```bash
# --- TLS certificates ---
# Use the standard kubernetes.io/tls type. It stores cert as tls.crt and
# key as tls.key — these are the file names seen inside the mounted volume.
kubectl create secret tls ewqwe-tls-certs \
  --cert=verifier.example.com.fullchain.pem \
  --key=verifier.example.com.key.pem

# If you have a separate root CA, add it as a generic secret:
kubectl create secret generic ewqwe-tls-ca \
  --from-file=ca.pem=ca-cert.pem
# Then mount both secrets under /data/certificates/tls/ (use two volumes)

# --- Signer certificates (for attestation signing) ---
kubectl create secret generic ewqwe-signer-certs \
  --from-file=signer.cert.pem=your-signer.cert.pem \
  --from-file=signer.key.pem=your-signer.key.pem \
  --from-file=signer.fullchain.pem=your-signer.fullchain.pem

# --- Session secret (arbitrary hex string ≥ 64 chars) ---
kubectl create secret generic ewqwe-verifier-secrets \
  --from-literal=session-secret="$(openssl rand -hex 32)"
```

> **Why not inline YAML?** Certificate data is sensitive and hard to manage in
> version control. `kubectl create secret` reads the files from disk, keeping
> the PEM content out of your YAML pipelines. The `kubernetes.io/tls` type also
> validates that the cert and key match, catching mismatches early.

### Example Deployment

```yaml
apiVersion: apps/v1
kind: Deployment
metadata:
  name: ewqwe-verifier
spec:
  replicas: 1
  selector:
    matchLabels:
      app: ewqwe-verifier
  template:
    metadata:
      labels:
        app: ewqwe-verifier
    spec:
      containers:
        - name: verifier
          image: ewqwe/credential-verifier:latest
          ports:
            - containerPort: 4043
              name: https
            - containerPort: 9888
              name: http
          env:
            - name: PUBLIC_ROOT_URL
              value: "https://verifier.example.com"
            - name: HOST_PORT
              value: "4043"
            - name: RUST_LOG
              value: "info,ewqwe_credential_verifier_server=debug"
            - name: SESSION_SECRET
              valueFrom:
                secretKeyRef:
                  name: ewqwe-verifier-secrets
                  key: session-secret
            # Signer certificates come from Secrets
            - name: SIGNER_CERT_PATH
              value: "/data/certificates/signer/signer.cert.pem"
            - name: SIGNER_KEY_PATH
              value: "/data/certificates/signer/signer.key.pem"
          volumeMounts:
            - name: config
              mountPath: /data/credential-server.toml
              subPath: credential-server.toml
              readOnly: true
            - name: tls-certs
              mountPath: /data/certificates/tls
              readOnly: true
            - name: signer-certs
              mountPath: /data/certificates/signer
              readOnly: true
            - name: issuers-cas
              mountPath: /data/certificates/issuers_cas
              readOnly: true
            - name: data
              mountPath: /data
      volumes:
        - name: config
          configMap:
            name: ewqwe-verifier-config
        - name: tls-certs
          secret:
            secretName: ewqwe-tls-certs
        - name: signer-certs
          secret:
            secretName: ewqwe-signer-certs
        - name: issuers-cas
          configMap:
            name: ewqwe-issuers-cas
        - name: data
          persistentVolumeClaim:
            claimName: ewqwe-verifier-data
```

### Example Service

Expose the verifier inside the cluster with a Service. Use the appropriate
port depending on whether the server terminates TLS itself or runs behind
a reverse proxy (e.g. an Ingress with cert-manager).

```yaml
apiVersion: v1
kind: Service
metadata:
  name: ewqwe-verifier
spec:
  selector:
    app: ewqwe-verifier
  ports:
    # TLS mode: server terminates HTTPS directly (containerPort 4043)
    - port: 4043
      targetPort: 4043
      name: https
    # HTTP mode: behind a reverse proxy / Ingress (containerPort 9888)
    - port: 9888
      targetPort: 9888
      name: http
```

> Only one port will actually be serving depending on whether `[tls_params]`
> is present in the config. When using an Ingress, point it at the HTTP port
> (9888) and let the Ingress handle TLS termination via cert-manager.

### Example ConfigMap

```yaml
apiVersion: v1
kind: ConfigMap
metadata:
  name: ewqwe-verifier-config
data:
  credential-server.toml: |
    host_name = "0.0.0.0"
    host_port = 4043
    issuers_cas_dir = "/data/certificates/issuers_cas"

    [tls_params]
    server_private_key = "/data/certificates/tls/tls.key"
    # tls.crt should be the full chain (server cert + intermediates + root CA).
    # When the fullchain includes the root, server_ca_chain can point at the
    # same file.  If you have a separate root CA, mount it at ca.pem instead.
    server_certificate = "/data/certificates/tls/tls.crt"
    server_ca_chain    = "/data/certificates/tls/tls.crt"
    client_ca_cert_chain = "/data/certificates/tls/tls.crt"

    [openid4vp_config]
    transaction_ttl_secs = 300

    [openid4vp_config.transaction_store]
    backend = "sqlite_file"
    path = "/data/transactions.db"

    [openid4vp_config.haip_config]
    x509_cert_path = "/data/certificates/signer/signer.fullchain.pem"
    x509_key_path = "/data/certificates/signer/signer.key.pem"

    [journal_config]
    enabled = true
    backend = "sqlite_file"
    path = "/data/journal.db"

    [verifier_ui]
    enabled = true
    app_name = "ewQwe Verifier"
    ui_dist_path = "/usr/share/ewqwe/ui/dist"

    [verifier_ui.db]
    backend = "sqlite_file"
    path = "/data/verifier_ui.db"

    [tracing_config]
    with_ansi_colors = false
```

> **Note:** `public_root_url`, `session_secret`, `rust_log`, `ansi_colors`, and
> signer cert paths are injected from environment variables — you do not need to
> set them in the ConfigMap. Only config values that cannot be driven by env vars
> (like `[tls_params]` paths) need to be in the ConfigMap.

## Building

```bash
# From the repository root
docker build -t ewqwe/credential-verifier -f container/Dockerfile .

# With Podman
podman build -t ewqwe/credential-verifier -f container/Dockerfile .
```

### Build Arguments

None currently. The build auto-generates development signer certificates.

### Optimizing Builds

The `.dockerignore` at the repository root excludes `target/`, `node_modules/`,
and other build artifacts from the Docker context, keeping the build lean.

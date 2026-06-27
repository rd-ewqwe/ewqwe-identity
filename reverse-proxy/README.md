# ewQwe TLS Reverse Proxy

An NGINX + Certbot Docker container that provides automatic TLS termination for
the ewQwe identity stack (credential verifier, demo UIs, etc.).

---

The ewQwe identity system relies on **W3C Digital Credentials** exchanged via
the **OpenID4VP** (OpenID for Verifiable Presentations) protocol.  Wallet
implementations (both mobile and browser-based) **require a TLS‑secured
connection** to the relying party or verifier endpoint.  Concretely:

- [OpenID4VP (draft 24)](https://openid.net/specs/openid-4-verifiable-presentations-1_0.html)
  mandates HTTPS for the `redirect_uri` the wallet calls back to.
- The [W3C VC API](https://www.w3.org/TR/vc-api/) specification expects TLS on
  all verifier endpoints.
- Android and iOS wallet apps block HTTP connections to credential issuer /
  verifier URLs by default.

During development the credential verifier is typically started in **HTTP
mode** (no TLS), or the front‑end SPAs are served by Vite's dev server on
plain HTTP.  The reverse proxy sits in front of these components and adds the
required TLS layer so that physical wallets can communicate with them.

---

## What this is

A single Docker container that bundles:

| Component | Role |
|-----------|------|
| **NGINX** | TLS termination and reverse‑proxy to the upstream backend (credential verifier, SPA, etc.) |
| **Certbot** | Obtains and renews [Let's Encrypt](https://letsencrypt.org/) TLS certificates automatically via the ACME HTTP‑01 challenge. |

At startup the container:

1. Checks whether a certificate already exists (persisted in a Docker volume).
2. If absent, starts a temporary HTTP‑only NGINX so Certbot can complete the
   ACME webroot challenge on port 80.
3. Requests a certificate from Let's Encrypt for the configured domain.
4. Writes the full TLS‑enabled NGINX configuration and starts it.
5. Installs a cron job that checks for renewal twice daily.

Certificate renewal hooks automatically reload NGINX so there is no downtime.

---

## Using

### Prerequisites

- A **public server** with a DNS A/AAAA record pointing to its IP address.
  The domain you intend to use (e.g. `verifier.your-domain.com`) **must resolve** to
  that server before running the container — Let's Encrypt validates domain
  ownership by reaching the server on port 80.
- **Ports 80 and 443** must be reachable from the internet on that server.
  Port 80 is required only during the initial ACME challenge and renewals.
  **Once the certificate has been obtained, close port 80 on your firewall
  / router to prevent abuse** (malicious scanners constantly probe open HTTP
  ports for proxying, DDoS amplification, and other attacks). Certbot will
  temporarily re‑open the ACME challenge path during renewal if needed —
  this is an outbound-initiated process that does not require port 80 to be
  permanently open.
- **Docker** installed on the host.

### Router / firewall configuration

Forward external ports to the container's mapped ports:

| External port | Internal port | Purpose |
|---------------|---------------|---------|
| `80`          | `4080`        | ACME HTTP‑01 challenge + HTTP→HTTPS redirect |
| `443`         | `4043`        | HTTPS (TLS‑terminated traffic) |

Adjust the internal port mapping in
[`reverse_proxy_run.sh`](./reverse_proxy_run.sh) if your host already uses
ports 4080/4043 for something else.

### Build the image

```sh
docker build -t ewqwe-reverse-proxy ./reverse-proxy
```

### Run

The script [`reverse_proxy_run.sh`](./reverse_proxy_run.sh) starts the
container.  It expects three environment variables to be set before
invocation:

| Variable | Example value | Description |
|----------|---------------|-------------|
| `DOMAIN` | `verifier.your-domain.com` | The public hostname for which a certificate will be obtained. |
| `DESTINATION` | `http://192.168.1.10:9888` | Upstream backend URL (the non‑TLS credential verifier or SPA server). Trailing path is forwarded as‑is. |
| `CERTBOT_EMAIL` | `admin@your-domain.com` | Contact e‑mail registered with Let's Encrypt (used for expiry notifications). |

```sh
export DOMAIN=verifier.your-domain.com
export DESTINATION=http://192.168.0.2:9888
export CERTBOT_EMAIL=admin@your-domain.com

./reverse-proxy/reverse_proxy_run.sh
```

The script will abort immediately with a clear error message if any of the
three variables is missing.

### Certificate persistence

A Docker volume named `letsencrypt` is mounted at `/etc/letsencrypt` inside
the container.  This ensures the certificate and account key survive container
restarts without re‑requesting the certificate.  The volume is created
automatically on the first run.

```sh
# List the volume
docker volume inspect letsencrypt

# Remove it if you want to start from scratch (will re‑request a cert)
docker volume rm letsencrypt
```

### Verifying it works

Once the container is running, you can reach the upstream backend through the
proxy:

```sh
curl https://verifier.your-domain.com
```

Or open `https://verifier.your-domain.com` in a browser.

---

## License

AGPL-3.0 — see [LICENSE](LICENSE) at the repository root.

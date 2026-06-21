#!/bin/bash
set -euo pipefail

# ── Required environment variables ──────────────────────────────────────────────
: "${DOMAIN:?DOMAIN environment variable is required (e.g. id.demo.ewqwe.eu)}"
: "${DESTINATION:?DESTINATION environment variable is required (e.g. https://192.168.1.10:9443)}"
: "${CERTBOT_EMAIL:?CERTBOT_EMAIL environment variable is required (e.g. admin@example.com)}"

# ── Pre-flight checks ───────────────────────────────────────────────────────────
# The router must forward ports 80 -> 4080 and 443 -> 4043 on the host running
# this container.  Once the ACME challenge has completed, port 80 should be
# re-closed to prevent abuse.
# The image must be built first with:
#   docker build -t ewqwe-reverse-proxy ./reverse-proxy

mkdir -p /etc/letsencrypt/

docker run -d \
  --name ewqwe-reverse-proxy \
  -p 4080:80 -p 4043:443 \
  -e DOMAIN="${DOMAIN}" \
  -e DESTINATION="${DESTINATION}" \
  -e CERTBOT_EMAIL="${CERTBOT_EMAIL}" \
  -v letsencrypt:/etc/letsencrypt \
  ewqwe-reverse-proxy

echo "✓ Container ewqwe-reverse-proxy started with DOMAIN=${DOMAIN} DESTINATION=${DESTINATION}"

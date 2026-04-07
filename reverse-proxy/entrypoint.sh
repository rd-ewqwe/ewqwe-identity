#!/bin/bash
set -euo pipefail

DOMAIN="id.demo.ewqwe.eu"
CERT_DIR="/etc/letsencrypt/live/${DOMAIN}"

# ── Validate required environment variables ────────────────────────────────────
: "${CERTBOT_EMAIL:?CERTBOT_EMAIL environment variable is required (e.g. admin@example.com)}"
: "${DESTINATION:?DESTINATION environment variable is required (e.g. 192.168.1.100:8443)}"

log() { echo "[entrypoint] $*"; }

# ── Step 1: Obtain initial certificate via ACME webroot ────────────────────────
if [ ! -f "${CERT_DIR}/fullchain.pem" ]; then
    log "No certificate found for ${DOMAIN}."
    log "Starting nginx with HTTP-only config for ACME webroot challenge..."
    nginx -c /etc/nginx/nginx-http.conf

    log "Requesting certificate from Let's Encrypt..."
    certbot certonly \
        --webroot \
        --webroot-path /var/www/certbot \
        --non-interactive \
        --agree-tos \
        --email "${CERTBOT_EMAIL}" \
        -d "${DOMAIN}"

    log "Certificate obtained. Shutting down temporary nginx..."
    nginx -s quit
    # Wait briefly for nginx to fully exit before writing the new config.
    sleep 2
else
    log "Certificate already present at ${CERT_DIR}."
fi

# ── Step 2: Render nginx config (substitute DESTINATION only) ─────────────────
log "Writing nginx config: proxy -> https://${DESTINATION}"
envsubst '${DESTINATION}' < /etc/nginx/nginx.conf.template > /etc/nginx/nginx.conf

# ── Step 3: Install certbot auto-renewal deploy hook ──────────────────────────
# Drop a deploy hook that reloads nginx whenever certbot successfully renews the
# certificate.  Hooks in /etc/letsencrypt/renewal-hooks/deploy/ are called
# automatically by `certbot renew` with no extra flags needed.
cat > /etc/letsencrypt/renewal-hooks/deploy/reload-nginx.sh << 'HOOK'
#!/bin/sh
nginx -s reload
HOOK
chmod 0755 /etc/letsencrypt/renewal-hooks/deploy/reload-nginx.sh

# ── Step 4: Install cron job for twice-daily renewal attempts ─────────────────
# /etc/cron.d files must include the username field.
# Randomise the minute (within 0-59) to spread load across Let's Encrypt servers.
cat > /etc/cron.d/certbot-renew << 'CRON'
23 0,12 * * * root certbot renew --quiet
CRON
chmod 0644 /etc/cron.d/certbot-renew

# Start the cron daemon (daemonises itself).
cron
log "Cron daemon started for certificate renewal."

# ── Step 5: Start nginx as PID 1 ──────────────────────────────────────────────
log "Starting nginx..."
exec nginx -g 'daemon off;'

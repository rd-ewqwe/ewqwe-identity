# TLS reverse proxy for id.demo.ewqwe.eu
#
# Required environment variables at runtime:
#   DESTINATION    – upstream IP:port, e.g. 192.168.1.100:8443
#                    Traffic is forwarded to https://<DESTINATION> with
#                    certificate verification disabled (self-signed certs accepted).
#   CERTBOT_EMAIL  – contact e-mail registered with Let's Encrypt
#
# Ports that must be reachable from the internet for ACME HTTP-01 challenge:
#   80   – HTTP (ACME challenge + redirect to 443)
#   443  – HTTPS (TLS termination)
#
# Persist /etc/letsencrypt as a Docker volume to survive container restarts
# without re-requesting certificates.
#
# Build:
#   docker build --platform linux/amd64 -t ewqwe-reverse-proxy ./reverse-proxy
#
# Run:
#   docker run -d \
#     --platform linux/amd64 \
#     -p 80:80 -p 443:443 \
#     -e DESTINATION=192.168.1.100:8443 \
#     -e CERTBOT_EMAIL=admin@example.com \
#     -v letsencrypt:/etc/letsencrypt \
#     ewqwe-reverse-proxy

FROM --platform=linux/amd64 nginx:stable

RUN apt-get update && \
    apt-get install -y --no-install-recommends \
    certbot \
    python3-certbot-nginx \
    cron \
    gettext-base && \
    apt-get clean && \
    rm -rf /var/lib/apt/lists/*

# Directory served as the ACME webroot for HTTP-01 challenges.
RUN mkdir -p /var/www/certbot

# Directory for certbot deploy hooks (created by certbot on install but we
# ensure it exists so the entrypoint can write into it unconditionally).
RUN mkdir -p /etc/letsencrypt/renewal-hooks/deploy

# Temporary HTTP-only nginx config used solely during initial cert acquisition.
COPY nginx-http.conf      /etc/nginx/nginx-http.conf

# Full nginx config template – ${DESTINATION} is substituted at startup.
COPY nginx.conf.template  /etc/nginx/nginx.conf.template

# Startup script: acquires cert if absent, writes nginx config, starts cron + nginx.
COPY entrypoint.sh        /entrypoint.sh
RUN chmod +x /entrypoint.sh

EXPOSE 80 443

ENTRYPOINT ["/entrypoint.sh"]

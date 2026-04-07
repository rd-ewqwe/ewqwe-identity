#!/bin/bash
set -euo pipefail

# The router must be configured to forward ports 80 to 4080 and 443 to 4043 on the host running this container.
# The image must be built with `docker build -t ewqwe-reverse-proxy .` from the reverse-proxy directory.

mkdir -p /etc/letsencrypt/

docker run --platform linux/amd64 \
  --name ewqwe-reverse-proxy \
  -p 4080:80 -p 4043:443 \
  -e DESTINATION=192.168.1.10:9443 \
  -e CERTBOT_EMAIL=rd@ewqwe.eu \
  -v letsencrypt:/etc/letsencrypt \
  ewqwe-reverse-proxy

#!/bin/sh
# Generate conf/local.yml from environment variables so credentials never
# need to be hardcoded in the image or a mounted config file.
# All values come from Docker env (sourced from .env via docker-compose).
set -e

mkdir -p /usr/src/app/conf

cat > /usr/src/app/conf/local.yml <<EOF
host: 0.0.0.0
port: 8888
api_key_red:  ${CALDERA_API_KEY}
api_key_blue: ${CALDERA_API_KEY}
users:
  red:
    red: ${CALDERA_RED_PASSWORD:-redpassword}
  blue:
    blue: ${CALDERA_BLUE_PASSWORD:-bluepassword}
exfil_dir: /tmp/caldera
plugins:
  - sandcat
  - stockpile
  - atomic
  - compass
  - manx
  - response
  - training
EOF

exec python3 server.py --insecure

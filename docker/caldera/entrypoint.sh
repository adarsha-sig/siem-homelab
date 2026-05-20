#!/bin/sh
# Generate conf/local.yml from environment variables so credentials never
# need to be hardcoded in the image or a mounted config file.
# All values come from Docker env (sourced from .env via docker-compose).
set -e

mkdir -p /usr/src/app/conf

cat > /usr/src/app/conf/local.yml <<EOF
host: 0.0.0.0
port: 8888
ssl: false
ability_refresh: 60
api_key_red:  ${CALDERA_API_KEY}
api_key_blue: ${CALDERA_API_KEY}
# crypt_salt and encryption_key must be non-empty strings; CALDERA will crash
# at startup if either is missing from local.yml. Set stable values in .env so
# encrypted artefacts remain readable across container restarts.
crypt_salt: ${CALDERA_CRYPT_SALT:-homelabsalt}
encryption_key: ${CALDERA_ENCRYPTION_KEY:-homelabkey}
users:
  red:
    red: ${CALDERA_RED_PASSWORD:-redpassword}
  blue:
    blue: ${CALDERA_BLUE_PASSWORD:-bluepassword}
exfil_dir: /tmp/caldera
# app.contact.http is the callback URL Sandcat agents embed at deploy time.
# Set CALDERA_CONTACT_URL in .env to your Mac's LAN IP + host port (8889)
# so agents on the Windows VM know where to phone home.
app.contact.http: ${CALDERA_CONTACT_URL:-http://0.0.0.0:8888}
plugins:
  - sandcat
  - stockpile
  - atomic
  - compass
  - manx
  - response
  - training
EOF

# Do NOT pass --insecure: that flag forces CALDERA to use default.yml and
# ignore local.yml, defeating the env-var config injection above.
exec python3 server.py

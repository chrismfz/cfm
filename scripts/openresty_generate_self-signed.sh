#!/bin/bash

if [ -d "/opt/openresty/nginx/conf" ]; then
    CERT_DIR="/opt/openresty/nginx/conf/selfsigned"
elif [ -d "/usr/local/openresty/nginx/conf" ]; then
    CERT_DIR="/usr/local/openresty/nginx/conf/selfsigned"
else
    echo "ERROR: Could not find OpenResty conf directory"
    exit 1
fi

echo "Creating self-signed cert in: $CERT_DIR"
mkdir -p "$CERT_DIR"

openssl req -x509 -nodes -days 3650 -newkey rsa:2048 \
  -keyout "$CERT_DIR/privkey.pem" \
  -out "$CERT_DIR/fullchain.pem" \
  -subj "/C=GR/ST=State/L=City/O=OpenResty/CN=localhost"

echo "Done: $CERT_DIR/fullchain.pem and $CERT_DIR/privkey.pem created"

#!/usr/bin/env bash
set -euo pipefail

check_file() {
  local conf="$1"
  local cert_root="$2"

  awk -v cert_root="$cert_root" '
  BEGIN { in_server=0; block="" }
  /^[[:space:]]*server[[:space:]]*\{/ {
    in_server=1
    block=$0 "\n"
    next
  }
  in_server {
    block=block $0 "\n"
    if ($0 ~ /^[[:space:]]*}/) {
      if (block ~ /listen[[:space:]]+[0-9]+[[:space:]]+ssl;/) {
        cert_line = "ssl_certificate " cert_root "/fullchain.pem;"
        key_line = "ssl_certificate_key " cert_root "/privkey.pem;"

        if (index(block, cert_line) == 0) {
          print "Missing fallback ssl_certificate in ssl server block for " FILENAME ":" > "/dev/stderr"
          print block > "/dev/stderr"
          exit 1
        }
        if (index(block, key_line) == 0) {
          print "Missing fallback ssl_certificate_key in ssl server block for " FILENAME ":" > "/dev/stderr"
          print block > "/dev/stderr"
          exit 1
        }
        if (block !~ /ssl_certificate_by_lua_block[[:space:]]*\{[[:space:]]*local sc = require "sslcollector"; sc\.set_cert\(\)[[:space:]]*\}/) {
          print "Missing sslcollector dynamic cert hook in ssl server block for " FILENAME ":" > "/dev/stderr"
          print block > "/dev/stderr"
          exit 1
        }
      }
      in_server=0
      block=""
    }
  }
  ' "$conf"
}

check_file "configs/angie-cfm-panel-listeners.conf" "/etc/angie/selfsigned"
check_file "configs/openresty-cfm-panel-listeners.conf" "/usr/local/openresty/nginx/selfsigned"

echo "OK: all listen ... ssl panel server blocks have fallback cert directives and ssl_certificate_by_lua_block."

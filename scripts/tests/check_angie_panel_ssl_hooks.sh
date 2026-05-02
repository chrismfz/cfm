#!/usr/bin/env bash
set -euo pipefail

conf="configs/angie-cfm-panel-listeners.conf"

awk '
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
      if (block !~ /ssl_certificate[[:space:]]+\/etc\/angie\/selfsigned\/fullchain\.pem;/) {
        print "Missing fallback ssl_certificate in ssl server block:" > "/dev/stderr"
        print block > "/dev/stderr"
        exit 1
      }
      if (block !~ /ssl_certificate_key[[:space:]]+\/etc\/angie\/selfsigned\/privkey\.pem;/) {
        print "Missing fallback ssl_certificate_key in ssl server block:" > "/dev/stderr"
        print block > "/dev/stderr"
        exit 1
      }
      if (block !~ /ssl_certificate_by_lua_block[[:space:]]*\{[[:space:]]*local sc = require "sslcollector"; sc\.set_cert\(\)[[:space:]]*\}/) {
        print "Missing sslcollector dynamic cert hook in ssl server block:" > "/dev/stderr"
        print block > "/dev/stderr"
        exit 1
      }
    }
    in_server=0
    block=""
  }
}
' "$conf"

echo "OK: every listen ... ssl panel server has fallback cert directives and ssl_certificate_by_lua_block."

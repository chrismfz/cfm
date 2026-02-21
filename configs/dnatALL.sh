#!/usr/bin/env bash
set -euo pipefail

NFT="${NFT:-nft}"
TABLE_FAMILY="inet"
TABLE_NAME="cfm_redirect"

HTTP_PORT="${HTTP_PORT:-9080}"
HTTPS_PORT="${HTTPS_PORT:-9043}"

table_exists() {
  $NFT list table "$TABLE_FAMILY" "$TABLE_NAME" >/dev/null 2>&1
}

do_status() {
  if table_exists; then
    echo "ON  (tcp/80->:${HTTP_PORT}, tcp+udp/443->:${HTTPS_PORT})"
  else
    echo "OFF"
  fi
}

do_on() {
  if table_exists; then
    echo "Already ON"
    do_status
    return 0
  fi

  $NFT -f - <<EOF
table ${TABLE_FAMILY} ${TABLE_NAME} {
  chain prerouting {
    type nat hook prerouting priority dstnat; policy accept;

    iif "lo" accept

    tcp dport 80  dnat to :${HTTP_PORT}
    tcp dport 443 dnat to :${HTTPS_PORT}
    udp dport 443 dnat to :${HTTPS_PORT}
  }
}
EOF

  do_status
}

do_off() {
  if ! table_exists; then
    echo "Already OFF"
    return 0
  fi
  $NFT delete table "$TABLE_FAMILY" "$TABLE_NAME"
  echo "OFF"
}

cmd="${1:-status}"
case "$cmd" in
  status) do_status ;;
  on)     do_on ;;
  off)    do_off ;;
  *)
    echo "Usage: $0 [status|on|off]"
    echo "Env: HTTP_PORT=9080 HTTPS_PORT=9043"
    exit 1
    ;;
esac

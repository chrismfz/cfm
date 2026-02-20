#!/usr/bin/env bash
set -euo pipefail

NFT="${NFT:-nft}"
TABLE_FAMILY="inet"
TABLE_NAME="cfm_redirect"

HTTP_TARGET="${HTTP_TARGET:-127.0.0.1:9080}"
HTTPS_TARGET="${HTTPS_TARGET:-127.0.0.1:9043}"

table_exists() {
  $NFT list table "$TABLE_FAMILY" "$TABLE_NAME" >/dev/null 2>&1
}

do_status() {
  if table_exists; then
    echo "ON  (tcp/80->${HTTP_TARGET}, tcp+udp/443->${HTTPS_TARGET})"
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

    tcp dport 80  dnat ip to ${HTTP_TARGET}
    tcp dport 443 dnat ip to ${HTTPS_TARGET}
    udp dport 443 dnat ip to ${HTTPS_TARGET}
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
    echo "Env: HTTP_TARGET=IP:PORT, HTTPS_TARGET=IP:PORT"
    exit 1
    ;;
esac

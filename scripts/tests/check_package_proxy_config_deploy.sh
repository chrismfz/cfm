#!/usr/bin/env bash
set -euo pipefail

tmp="$(mktemp -d)"
trap 'rm -rf "$tmp"' EXIT

configs="$tmp/configs"
engine_conf="$tmp/engine-conf"
dst_dir="$tmp/dst"
bin_dir="$tmp/bin"
mkdir -p "$configs" "$engine_conf" "$dst_dir" "$bin_dir"

cat >"$configs/openresty.conf" <<'CONF'
events {}
http { include challenge_waf_bypass.conf; }
CONF
cat >"$configs/trusted_proxies.conf" <<'CONF'
127.0.0.1/32 1;
CONF
cat >"$configs/challenge_waf_bypass.conf" <<'CONF'
4.150.142.218/32 1;
CONF
cat >"$configs/cfm-panel-listeners.conf.in" <<'CONF'
# @ENGINE@ listener template
# Install path: @LISTENER_DEST@
CONF

cat >"$bin_dir/fake-openresty" <<'EOF_FAKE'
#!/bin/sh
printf '%s\n' "$*" > "$FAKE_OPENRESTY_ARGS"
[ "$1" = "-t" ] && [ "$2" = "-c" ] && [ "$3" = "$EXPECTED_MAIN_CONFIG" ]
EOF_FAKE
chmod 0755 "$bin_dir/fake-openresty"

# Load only helper functions so this test can pass temp destinations without
# touching system Angie/OpenResty paths.
awk '/^ANGIE_BIN=/{exit} {print}' scripts/package-proxy-config-deploy.sh >"$tmp/functions.sh"

CFM_CONFIG_DIR="$configs" \
FAKE_OPENRESTY_ARGS="$tmp/openresty.args" \
EXPECTED_MAIN_CONFIG="$configs/openresty.conf" \
sh -c '. "$1"; process_engine OpenResty "$2" "$3" "$4" "$5"' sh \
  "$tmp/functions.sh" \
  "$bin_dir/fake-openresty" \
  "$configs/openresty.conf" \
  "$dst_dir/nginx.conf" \
  "$engine_conf"

actual_args="$(cat "$tmp/openresty.args")"
expected_args="-t -c $configs/openresty.conf"
if [ "$actual_args" != "$expected_args" ]; then
  echo "FAIL: expected fake OpenResty args '$expected_args', got '$actual_args'" >&2
  exit 1
fi

for f in \
  "$engine_conf/trusted_proxies.conf" \
  "$engine_conf/challenge_waf_bypass.conf" \
  "$engine_conf/cfm-panel-listeners.conf" \
  "$dst_dir/nginx.conf"; do
  [ -f "$f" ] || { echo "FAIL: expected deployed file missing: $f" >&2; exit 1; }
done

if rg -n -- '-t[[:space:]]+-c[[:space:]]+.*(trusted_proxies|challenge_waf_bypass|cfm-panel-listeners)\.conf' scripts/package-proxy-config-deploy.sh >/dev/null; then
  echo "FAIL: package proxy helper must not test sidecar include files as standalone configs" >&2
  exit 1
fi

echo "OK: package proxy deploy helper tests only the main engine config"

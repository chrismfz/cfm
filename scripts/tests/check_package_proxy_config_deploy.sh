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

cat >"$bin_dir/systemctl" <<'EOF_SYSTEMCTL'
#!/bin/sh
case "$1 $2 $3" in
  "is-active --quiet openresty.service") exit 0 ;;
  "list-unit-files openresty.service --no-legend") printf '%s\n' "openresty.service enabled"; exit 0 ;;
  "list-unit-files angie.service --no-legend") printf '%s\n' "angie.service disabled"; exit 0 ;;
esac
exit 1
EOF_SYSTEMCTL
chmod 0755 "$bin_dir/systemctl"

# Load only helper functions so this test can pass temp destinations without
# touching system Angie/OpenResty paths.
awk '/^ANGIE_BIN=/{exit} {print}' scripts/package-proxy-config-deploy.sh >"$tmp/functions.sh"

process_output=$(
  PATH="$bin_dir:$PATH" \
  CFM_CONFIG_DIR="$configs" \
  FAKE_OPENRESTY_ARGS="$tmp/openresty.args" \
  EXPECTED_MAIN_CONFIG="$configs/openresty.conf" \
  sh -c '. "$1"; process_engine OpenResty "$2" "$3" "$4" "$5" openresty.service "/usr/local/openresty/sbin/nginx -s reload"' sh \
    "$tmp/functions.sh" \
    "$bin_dir/fake-openresty" \
    "$configs/openresty.conf" \
    "$dst_dir/nginx.conf" \
    "$engine_conf"
)

if ! printf '%s\n' "$process_output" | rg -q 'CFM proxy config: OpenResty service is active: openresty.service'; then
  echo "FAIL: expected active OpenResty service status in output" >&2
  printf '%s\n' "$process_output" >&2
  exit 1
fi

if ! printf '%s\n' "$process_output" | rg -q 'CFM proxy config: deployed OpenResty config; reload with: systemctl reload openresty'; then
  echo "FAIL: expected OpenResty reload guidance in output" >&2
  printf '%s\n' "$process_output" >&2
  exit 1
fi


installed_inactive_output=$(
  PATH="$bin_dir:$PATH" \
  sh -c '. "$1"; report_service_status Angie angie.service; report_reload_command Angie angie.service "angie -s reload"' sh \
    "$tmp/functions.sh"
)

if ! printf '%s\n' "$installed_inactive_output" | rg -q 'CFM proxy config: Angie service is installed but not active: angie.service'; then
  echo "FAIL: expected installed-but-inactive Angie service status in output" >&2
  printf '%s\n' "$installed_inactive_output" >&2
  exit 1
fi

if ! printf '%s\n' "$installed_inactive_output" | rg -q 'CFM proxy config: deployed Angie config; reload with: systemctl reload angie'; then
  echo "FAIL: expected installed Angie service to use systemctl reload guidance" >&2
  printf '%s\n' "$installed_inactive_output" >&2
  exit 1
fi

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

if rg -n 'skipping deploy because another CFM proxy service is active' scripts/package-proxy-config-deploy.sh >/dev/null; then
  echo "FAIL: package proxy helper must deploy all detected engine configs regardless of active service" >&2
  exit 1
fi

echo "OK: package proxy deploy helper tests only the main engine config"

#!/usr/bin/env bash
set -euo pipefail

tmp="$(mktemp -d)"
trap 'rm -rf "$tmp"' EXIT

configs="$tmp/configs"
openresty_conf="$tmp/openresty-conf"
angie_conf="$tmp/angie-conf"
openresty_dst_dir="$tmp/openresty-dst"
angie_dst_dir="$tmp/angie-dst"
bin_dir="$tmp/bin"
mkdir -p "$configs" "$openresty_conf" "$angie_conf" "$openresty_dst_dir" "$angie_dst_dir" "$bin_dir"

cat >"$configs/openresty.conf" <<'CONF'
events {}
http { include challenge_waf_bypass.conf; }
CONF
cat >"$configs/angie.conf" <<'CONF'
events {}
http { include trusted_proxies.conf; }
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
{
  printf '%s\n' "$*"
} >> "$FAKE_OPENRESTY_ARGS"
[ "$1" = "-t" ] && [ "$2" = "-c" ] && [ "$3" = "$EXPECTED_OPENRESTY_MAIN_CONFIG" ] || exit 1
[ "${FAKE_OPENRESTY_FAIL:-0}" = "1" ] && exit 1
exit 0
EOF_FAKE
chmod 0755 "$bin_dir/fake-openresty"

cat >"$bin_dir/fake-angie" <<'EOF_FAKE'
#!/bin/sh
{
  printf '%s\n' "$*"
} >> "$FAKE_ANGIE_ARGS"
[ "$1" = "-t" ] && [ "$2" = "-c" ] && [ "$3" = "$EXPECTED_ANGIE_MAIN_CONFIG" ]
EOF_FAKE
chmod 0755 "$bin_dir/fake-angie"

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

openresty_output=$(
  PATH="$bin_dir:$PATH" \
  CFM_CONFIG_DIR="$configs" \
  FAKE_OPENRESTY_ARGS="$tmp/openresty.args" \
  EXPECTED_OPENRESTY_MAIN_CONFIG="$configs/openresty.conf" \
  sh -c '. "$1"; process_engine OpenResty "$2" "$3" "$4" "$5" openresty.service "/usr/local/openresty/sbin/nginx -s reload"' sh \
    "$tmp/functions.sh" \
    "$bin_dir/fake-openresty" \
    "$configs/openresty.conf" \
    "$openresty_dst_dir/nginx.conf" \
    "$openresty_conf"
)

if ! printf '%s\n' "$openresty_output" | rg -q 'CFM proxy config: testing OpenResty config with: .*/fake-openresty -t -c .*/configs/openresty\.conf'; then
  echo "FAIL: expected OpenResty main config test command in output" >&2
  printf '%s\n' "$openresty_output" >&2
  exit 1
fi

if ! printf '%s\n' "$openresty_output" | rg -q 'CFM proxy config: OpenResty service is active: openresty.service'; then
  echo "FAIL: expected active OpenResty service status in output" >&2
  printf '%s\n' "$openresty_output" >&2
  exit 1
fi

if ! printf '%s\n' "$openresty_output" | rg -q 'CFM proxy config: deployed OpenResty config; reload with: systemctl reload openresty'; then
  echo "FAIL: expected OpenResty reload guidance in output" >&2
  printf '%s\n' "$openresty_output" >&2
  exit 1
fi

angie_output=$(
  PATH="$bin_dir:$PATH" \
  CFM_CONFIG_DIR="$configs" \
  FAKE_ANGIE_ARGS="$tmp/angie.args" \
  EXPECTED_ANGIE_MAIN_CONFIG="$configs/angie.conf" \
  sh -c '. "$1"; process_engine Angie "$2" "$3" "$4" "$5" angie.service "angie -s reload"' sh \
    "$tmp/functions.sh" \
    "$bin_dir/fake-angie" \
    "$configs/angie.conf" \
    "$angie_dst_dir/angie.conf" \
    "$angie_conf"
)

if ! printf '%s\n' "$angie_output" | rg -q 'CFM proxy config: testing Angie config with: .*/fake-angie -t -c .*/configs/angie\.conf'; then
  echo "FAIL: expected Angie main config test command in output" >&2
  printf '%s\n' "$angie_output" >&2
  exit 1
fi

if ! printf '%s\n' "$angie_output" | rg -q 'CFM proxy config: Angie service is installed but not active: angie.service'; then
  echo "FAIL: expected installed-but-inactive Angie service status in output" >&2
  printf '%s\n' "$angie_output" >&2
  exit 1
fi

if ! printf '%s\n' "$angie_output" | rg -q 'CFM proxy config: deployed Angie config; reload with: systemctl reload angie'; then
  echo "FAIL: expected installed Angie service to use systemctl reload guidance" >&2
  printf '%s\n' "$angie_output" >&2
  exit 1
fi

actual_openresty_args="$(cat "$tmp/openresty.args")"
expected_openresty_args="-t -c $configs/openresty.conf"
if [ "$actual_openresty_args" != "$expected_openresty_args" ]; then
  echo "FAIL: expected fake OpenResty args '$expected_openresty_args', got '$actual_openresty_args'" >&2
  exit 1
fi

actual_angie_args="$(cat "$tmp/angie.args")"
expected_angie_args="-t -c $configs/angie.conf"
if [ "$actual_angie_args" != "$expected_angie_args" ]; then
  echo "FAIL: expected fake Angie args '$expected_angie_args', got '$actual_angie_args'" >&2
  exit 1
fi

combined_output="$openresty_output
$angie_output"
if printf '%s\n' "$combined_output" | rg -q -- '-c .*((trusted_proxies|challenge_waf_bypass)\.conf|cfm-panel-listeners\.conf)'; then
  echo "FAIL: helper output must not test sidecar include files with -c" >&2
  printf '%s\n' "$combined_output" >&2
  exit 1
fi

for f in \
  "$openresty_conf/trusted_proxies.conf" \
  "$openresty_conf/challenge_waf_bypass.conf" \
  "$openresty_conf/cfm-panel-listeners.conf" \
  "$openresty_dst_dir/nginx.conf" \
  "$angie_conf/trusted_proxies.conf" \
  "$angie_conf/challenge_waf_bypass.conf" \
  "$angie_conf/cfm-panel-listeners.conf" \
  "$angie_dst_dir/angie.conf"; do
  [ -f "$f" ] || { echo "FAIL: expected deployed file missing: $f" >&2; exit 1; }
done

failure_output=$(
  PATH="$bin_dir:$PATH" \
  CFM_CONFIG_DIR="$configs" \
  FAKE_OPENRESTY_ARGS="$tmp/openresty-fail.args" \
  EXPECTED_OPENRESTY_MAIN_CONFIG="$configs/openresty.conf" \
  FAKE_OPENRESTY_FAIL=1 \
  sh -c '. "$1"; process_engine OpenResty "$2" "$3" "$4" "$5" openresty.service "/usr/local/openresty/sbin/nginx -s reload"' sh \
    "$tmp/functions.sh" \
    "$bin_dir/fake-openresty" \
    "$configs/openresty.conf" \
    "$tmp/fail-dst/nginx.conf" \
    "$tmp/fail-conf"
)

if ! printf '%s\n' "$failure_output" | rg -q 'leaving existing nginx\.conf unchanged'; then
  echo "FAIL: expected OpenResty failure to leave nginx.conf unchanged" >&2
  printf '%s\n' "$failure_output" >&2
  exit 1
fi

if printf '%s\n' "$failure_output" | rg -q 'leaving existing cfm-panel-listeners\.conf unchanged'; then
  echo "FAIL: OpenResty main config failure must not mention leaving cfm-panel-listeners.conf unchanged" >&2
  printf '%s\n' "$failure_output" >&2
  exit 1
fi

if [ -f "$tmp/fail-dst/nginx.conf" ]; then
  echo "FAIL: main OpenResty config should not be deployed after validation failure" >&2
  exit 1
fi

if rg -n -- '-t[[:space:]]+-c[[:space:]]+.*(trusted_proxies|challenge_waf_bypass|cfm-panel-listeners)\.conf' scripts/package-proxy-config-deploy.sh >/dev/null; then
  echo "FAIL: package proxy helper must not test sidecar include files as standalone configs" >&2
  exit 1
fi

if rg -n 'skipping deploy because another CFM proxy service is active' scripts/package-proxy-config-deploy.sh >/dev/null; then
  echo "FAIL: package proxy helper must deploy all detected engine configs regardless of active service" >&2
  exit 1
fi

if ! rg -q '/usr/share/cfm/scripts/package-proxy-config-deploy\.sh' packaging/debian/DEBIAN/postinst; then
  echo "FAIL: Debian postinst must call package proxy config deploy helper" >&2
  exit 1
fi

if ! rg -q '/usr/share/cfm/scripts/package-proxy-config-deploy\.sh' packaging/rpm/SPECS/cfm.spec; then
  echo "FAIL: RPM spec must call package proxy config deploy helper" >&2
  exit 1
fi

echo "OK: package proxy deploy helper tests only the main engine configs"

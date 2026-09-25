#!/usr/bin/env bash
set -euo pipefail

# A guardrail that cannot run its own matcher must FAIL, never report OK.
# check_cli_transport.sh used to pipe `rg ... || true`, so on a runner without
# ripgrep it read zero matches and printed success while a real violation sat
# in the tree (found 2026-09-22).
command -v rg >/dev/null 2>&1 || {
  echo "FAIL: ripgrep (rg) is required by $(basename "$0") and is not installed" >&2
  exit 1
}


tmp="$(mktemp -d)"
trap 'rm -rf "$tmp"' EXIT
# The helper stages inside the engine's own config dir, never under TMPDIR:
# point TMPDIR at a directory that does not exist to prove it.
export TMPDIR="$tmp/no-such-tmpdir"

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

cat >"$bin_dir/check-includes.sh" <<'EOF_CI'
# A real engine test reads every included file: fail if an absolute include is
# missing or marked BROKEN, and record what the staged main included.
check_includes() {
  sed -n 's/^[[:space:]]*include[[:space:]]*\(\/[^;]*\);.*/\1/p' "$1" | while read -r inc; do
    printf 'include %s\n' "$inc" >> "$2"
    [ -f "$inc" ] || exit 1
    ! grep -q BROKEN "$inc" || exit 1
  done
}
EOF_CI

cat >"$bin_dir/fake-openresty" <<'EOF_FAKE'
#!/bin/sh
. "$(dirname "$0")/check-includes.sh"
{
  printf '%s\n' "$*"
} >> "$FAKE_OPENRESTY_ARGS"
[ "$1" = "-t" ] && [ "$2" = "-c" ] && [ -f "$3" ] || exit 1
( check_includes "$3" "$FAKE_OPENRESTY_ARGS.includes" ) || exit 1
[ "${FAKE_OPENRESTY_FAIL:-0}" = "1" ] && exit 1
exit 0
EOF_FAKE
chmod 0755 "$bin_dir/fake-openresty"

cat >"$bin_dir/fake-angie" <<'EOF_FAKE'
#!/bin/sh
. "$(dirname "$0")/check-includes.sh"
{
  printf '%s\n' "$*"
} >> "$FAKE_ANGIE_ARGS"
[ "$1" = "-t" ] && [ "$2" = "-c" ] && [ -f "$3" ] || exit 1
( check_includes "$3" "$FAKE_ANGIE_ARGS.includes" ) || exit 1
EOF_FAKE
chmod 0755 "$bin_dir/fake-angie"

cat >"$bin_dir/systemctl" <<'EOF_SYSTEMCTL'
#!/bin/sh
case "$1 $2 $3" in
  "is-active --quiet angie.service") [ "${FAKE_ANGIE_ACTIVE:-0}" = "1" ] && exit 0 || exit 3 ;;
  "is-active --quiet openresty.service") [ "${FAKE_OPENRESTY_ACTIVE:-0}" = "1" ] && exit 0 || exit 3 ;;
  "list-unit-files angie.service --no-legend") printf '%s\n' "angie.service enabled"; exit 0 ;;
  "list-unit-files openresty.service --no-legend") printf '%s\n' "openresty.service enabled"; exit 0 ;;
esac
exit 1
EOF_SYSTEMCTL
chmod 0755 "$bin_dir/systemctl"

cat >"$bin_dir/openssl" <<'EOF_OPENSSL'
#!/bin/sh
key_file=
cert_file=
while [ "$#" -gt 0 ]; do
  case "$1" in
    -keyout)
      shift
      key_file=$1
      ;;
    -out)
      shift
      cert_file=$1
      ;;
  esac
  shift
done
[ -n "$key_file" ] || exit 1
[ -n "$cert_file" ] || exit 1
mkdir -p "$(dirname "$key_file")" "$(dirname "$cert_file")"
printf '%s\n' 'fake key' >"$key_file"
printf '%s\n' 'fake cert' >"$cert_file"
exit 0
EOF_OPENSSL
chmod 0755 "$bin_dir/openssl"

cat >"$bin_dir/chown" <<'EOF_CHOWN'
#!/bin/sh
exit 0
EOF_CHOWN
chmod 0755 "$bin_dir/chown"

# mv shim: fail a rename whose target ends in $FAKE_MV_FAIL (to exercise the
# rollback), otherwise the real mv. With FAKE_MV_ONCE set to a path, only the
# first such rename fails (the rollback's rename to the same name works).
real_mv=$(command -v mv)
cat >"$bin_dir/mv" <<EOF_MV
#!/bin/sh
for last do :; done
# FAKE_MV_FAIL_FROM: fail a rename whose SOURCE contains it (only when the
# target is a live name, i.e. not *.cfm-restore-failed.*, unless
# FAKE_MV_FAIL_KEEP is also set).
if [ -n "\${FAKE_MV_FAIL_FROM:-}" ]; then
  for a do
    case "\$a" in *"\$FAKE_MV_FAIL_FROM"*)
      [ "\$a" = "\$last" ] && continue
      case "\$last" in *.cfm-restore-failed.*) [ -n "\${FAKE_MV_FAIL_KEEP:-}" ] && exit 1 ;; *) exit 1 ;; esac ;;
    esac
  done
fi
if [ -n "\${FAKE_MV_FAIL:-}" ]; then
  case "\$last" in
    *"\$FAKE_MV_FAIL")
      if [ -z "\${FAKE_MV_ONCE:-}" ] || [ ! -e "\$FAKE_MV_ONCE" ]; then
        [ -n "\${FAKE_MV_ONCE:-}" ] && : >"\$FAKE_MV_ONCE"
        exit 1
      fi ;;
  esac
fi
exec $real_mv "\$@"
EOF_MV
chmod 0755 "$bin_dir/mv"

# install shim: drop -o/-g so the test also runs unprivileged (the CI runner is
# not root); everything else goes to the real install.
real_install=$(command -v install)
cat >"$bin_dir/install" <<EOF_INSTALL
#!/bin/sh
# FAKE_INSTALL_FAIL: fail an install whose target contains it.
for last do :; done
if [ -n "\${FAKE_INSTALL_FAIL:-}" ]; then
  case "\$last" in *"\$FAKE_INSTALL_FAIL"*) exit 1 ;; esac
fi
n=\$#
while [ "\$n" -gt 0 ]; do
  a=\$1; shift; n=\$((n - 1))
  case "\$a" in
    -o|-g) shift; n=\$((n - 1)) ;;
    *) set -- "\$@" "\$a" ;;
  esac
done
exec $real_install "\$@"
EOF_INSTALL
chmod 0755 "$bin_dir/install"

# Load only helper functions so this test can pass temp destinations without
# touching system Angie/OpenResty paths.
awk '/^if ! ensure_fallback_cert_if_missing/{exit} {print}' scripts/package-proxy-config-deploy.sh >"$tmp/functions.sh"

fallback_cert_dir="$tmp/fallback-certs"
fallback_output=$(
  PATH="$bin_dir:/usr/bin:/bin" \
  CFM_CONFIG_DIR="$configs" \
  CFM_FALLBACK_CERT_DIR="$fallback_cert_dir" \
  sh scripts/package-proxy-config-deploy.sh
)

if ! printf '%s\n' "$fallback_output" | rg -q "CFM proxy config: created self-signed fallback cert: $fallback_cert_dir/fullchain\.pem"; then
  echo "FAIL: expected fallback certificate creation log" >&2
  printf '%s\n' "$fallback_output" >&2
  exit 1
fi

for f in "$fallback_cert_dir/fullchain.pem" "$fallback_cert_dir/privkey.pem"; do
  [ -s "$f" ] || { echo "FAIL: expected fallback cert file missing or empty: $f" >&2; exit 1; }
  mode="$(stat -c %a "$f")"
  if [ "$mode" != "640" ]; then
    echo "FAIL: expected fallback cert mode 640 for $f, got $mode" >&2
    exit 1
  fi
done

active_angie_output=$(
  PATH="$bin_dir:$PATH" \
  CFM_CONFIG_DIR="$configs" \
  FAKE_ANGIE_ACTIVE=1 \
  FAKE_OPENRESTY_ACTIVE=0 \
  FAKE_ANGIE_ARGS="$tmp/angie.args" \
  FAKE_OPENRESTY_ARGS="$tmp/openresty.args" \
  sh -c '. "$1";
    process_engine Angie "$2" "$3" "$4" "$5" angie.service "angie -s reload";
    process_engine OpenResty "$6" "$7" "$8" "$9" openresty.service "/usr/local/openresty/sbin/nginx -s reload";
    print_proxy_config_summary' sh \
    "$tmp/functions.sh" \
    "$bin_dir/fake-angie" \
    "$configs/angie.conf" \
    "$angie_dst_dir/angie.conf" \
    "$angie_conf" \
    "$bin_dir/fake-openresty" \
    "$configs/openresty.conf" \
    "$openresty_dst_dir/nginx.conf" \
    "$openresty_conf"
)

if ! printf '%s\n' "$active_angie_output" | rg -q 'CFM proxy config: testing Angie config with: .*/fake-angie -t -c .*/\.cfm-proxy-stage\.[^/]+/main\.conf \(packaged .*/configs/angie\.conf \+ new sidecars\)'; then
  echo "FAIL: expected Angie main config test command in output" >&2
  printf '%s\n' "$active_angie_output" >&2
  exit 1
fi

if ! printf '%s\n' "$active_angie_output" | rg -q 'CFM proxy config: testing OpenResty config with: .*/fake-openresty -t -c .*/\.cfm-proxy-stage\.[^/]+/main\.conf \(packaged .*/configs/openresty\.conf \+ new sidecars\)'; then
  echo "FAIL: expected OpenResty main config test command in output" >&2
  printf '%s\n' "$active_angie_output" >&2
  exit 1
fi

if ! printf '%s\n' "$active_angie_output" | rg -q 'CFM proxy config: Angie service is active: angie.service'; then
  echo "FAIL: expected active Angie service status in output" >&2
  printf '%s\n' "$active_angie_output" >&2
  exit 1
fi

if ! printf '%s\n' "$active_angie_output" | rg -q 'CFM proxy config: OpenResty service is installed but not active: openresty.service'; then
  echo "FAIL: expected installed-but-inactive OpenResty service status in output" >&2
  printf '%s\n' "$active_angie_output" >&2
  exit 1
fi

if printf '%s\n' "$active_angie_output" | rg -q 'deployed OpenResty config; reload with:'; then
  echo "FAIL: inactive OpenResty must not receive direct reload guidance" >&2
  printf '%s\n' "$active_angie_output" >&2
  exit 1
fi

if printf '%s\n' "$active_angie_output" | rg -q 'deployed Angie config; reload with:'; then
  echo "FAIL: Angie must not receive per-engine reload guidance before summary" >&2
  printf '%s\n' "$active_angie_output" >&2
  exit 1
fi

if ! printf '%s\n' "$active_angie_output" | rg -q 'Active edge: Angie'; then
  echo "FAIL: expected final summary to identify Angie as active edge" >&2
  printf '%s\n' "$active_angie_output" >&2
  exit 1
fi

if ! printf '%s\n' "$active_angie_output" | rg -q 'Reload active edge with: systemctl reload angie'; then
  echo "FAIL: expected final summary to reload only Angie" >&2
  printf '%s\n' "$active_angie_output" >&2
  exit 1
fi

for eng in openresty angie; do
  actual_args="$(cat "$tmp/$eng.args")"
  case "$actual_args" in
    "-t -c "*/.cfm-proxy-stage.*/main.conf) ;;
    *) echo "FAIL: expected fake $eng args '-t -c <stage>/main.conf', got '$actual_args'" >&2; exit 1 ;;
  esac
done
for d in "$angie_conf" "$openresty_conf"; do
  if ls -A "$d" | rg -q 'cfm-proxy-stage'; then
    echo "FAIL: staging dir left behind in $d:" >&2; ls -A "$d" >&2; exit 1
  fi
done

combined_output="$active_angie_output"
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

inactive_output=$(
  PATH="$bin_dir:$PATH" \
  CFM_CONFIG_DIR="$configs" \
  FAKE_ANGIE_ACTIVE=0 \
  FAKE_OPENRESTY_ACTIVE=0 \
  FAKE_ANGIE_ARGS="$tmp/angie-inactive.args" \
  FAKE_OPENRESTY_ARGS="$tmp/openresty-inactive.args" \
  sh -c '. "$1";
    process_engine Angie "$2" "$3" "$4" "$5" angie.service "angie -s reload";
    process_engine OpenResty "$6" "$7" "$8" "$9" openresty.service "/usr/local/openresty/sbin/nginx -s reload";
    print_proxy_config_summary' sh \
    "$tmp/functions.sh" \
    "$bin_dir/fake-angie" \
    "$configs/angie.conf" \
    "$tmp/inactive-angie-dst/angie.conf" \
    "$tmp/inactive-angie-conf" \
    "$bin_dir/fake-openresty" \
    "$configs/openresty.conf" \
    "$tmp/inactive-openresty-dst/nginx.conf" \
    "$tmp/inactive-openresty-conf"
)

if ! printf '%s\n' "$inactive_output" | rg -q 'Active edge: none detected'; then
  echo "FAIL: expected inactive-services summary to report no active edge" >&2
  printf '%s\n' "$inactive_output" >&2
  exit 1
fi

if ! printf '%s\n' "$inactive_output" | rg -q 'No active edge reload needed'; then
  echo "FAIL: expected inactive-services summary to skip reload guidance" >&2
  printf '%s\n' "$inactive_output" >&2
  exit 1
fi

both_active_output=$(
  PATH="$bin_dir:$PATH" \
  CFM_CONFIG_DIR="$configs" \
  FAKE_ANGIE_ACTIVE=1 \
  FAKE_OPENRESTY_ACTIVE=1 \
  FAKE_ANGIE_ARGS="$tmp/angie-both-active.args" \
  FAKE_OPENRESTY_ARGS="$tmp/openresty-both-active.args" \
  sh -c '. "$1";
    process_engine Angie "$2" "$3" "$4" "$5" angie.service "angie -s reload";
    process_engine OpenResty "$6" "$7" "$8" "$9" openresty.service "/usr/local/openresty/sbin/nginx -s reload";
    print_proxy_config_summary' sh \
    "$tmp/functions.sh" \
    "$bin_dir/fake-angie" \
    "$configs/angie.conf" \
    "$tmp/both-active-angie-dst/angie.conf" \
    "$tmp/both-active-angie-conf" \
    "$bin_dir/fake-openresty" \
    "$configs/openresty.conf" \
    "$tmp/both-active-openresty-dst/nginx.conf" \
    "$tmp/both-active-openresty-conf"
)

if ! printf '%s\n' "$both_active_output" | rg -q 'Active edge: ambiguous'; then
  echo "FAIL: expected both-active summary to report ambiguity" >&2
  printf '%s\n' "$both_active_output" >&2
  exit 1
fi

if ! printf '%s\n' "$both_active_output" | rg -q 'systemctl reload angie'; then
  echo "FAIL: expected both-active summary to list Angie reload command" >&2
  printf '%s\n' "$both_active_output" >&2
  exit 1
fi

if ! printf '%s\n' "$both_active_output" | rg -q 'systemctl reload openresty'; then
  echo "FAIL: expected both-active summary to list OpenResty reload command" >&2
  printf '%s\n' "$both_active_output" >&2
  exit 1
fi

failure_output=$(
  PATH="$bin_dir:$PATH" \
  CFM_CONFIG_DIR="$configs" \
  FAKE_OPENRESTY_ARGS="$tmp/openresty-fail.args" \
  FAKE_OPENRESTY_FAIL=1 \
  sh -c '. "$1"; process_engine OpenResty "$2" "$3" "$4" "$5" openresty.service "/usr/local/openresty/sbin/nginx -s reload"; print_proxy_config_summary' sh \
    "$tmp/functions.sh" \
    "$bin_dir/fake-openresty" \
    "$configs/openresty.conf" \
    "$tmp/fail-dst/nginx.conf" \
    "$tmp/fail-conf"
)

if ! printf '%s\n' "$failure_output" | rg -q 'leaving existing sidecars and nginx\.conf unchanged'; then
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

if ! printf '%s\n' "$failure_output" | rg -q 'OpenResty: detected, inactive, config deploy failed'; then
  echo "FAIL: expected failed OpenResty deployment state in final summary" >&2
  printf '%s\n' "$failure_output" >&2
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

# ── The live dir is never changed by a failed run ────────────────────────────
# The sidecars are included by the main config. They used to be written into
# the live dir BEFORE the engine test, so a failed test (or main deploy) left
# them live next to the OLD main config and the next edge restart failed on
# them. Now they are staged, tested through a staged main, and renamed in only
# after the test passes.

# mk_pkg DIR LIVE: a packaged config set whose main config includes the three
# sidecars by absolute LIVE path, as the real angie.conf / openresty.conf do.
mk_pkg() {
  mkdir -p "$1"
  cat >"$1/openresty.conf" <<CONF
events {}
http {
    include $2/trusted_proxies.conf;
    geo \$x {
        include $2/challenge_waf_bypass.conf;
    }
    include $2/cfm-panel-listeners.conf;
}
CONF
  printf '%s\n' 'NEW trusted' >"$1/trusted_proxies.conf"
  printf '%s\n' 'NEW bypass' >"$1/challenge_waf_bypass.conf"
  cp "$configs/cfm-panel-listeners.conf.in" "$1/"
}

# seed_live DIR: previous sidecars + main config (panel listeners absent).
seed_live() {
  mkdir -p "$1"
  printf '%s\n' 'OLD trusted' >"$1/trusted_proxies.conf"
  printf '%s\n' 'OLD bypass' >"$1/challenge_waf_bypass.conf"
  printf '%s\n' 'OLD main' >"$1/nginx.conf"
}

snapshot() { (cd "$1" && for f in $(ls -A | sort); do printf '%s:' "$f"; cksum <"$f"; done); }

run_or() { # PKG LIVE [FAIL]   (env: FAKE_MV_FAIL, FAKE_INSTALL_FAIL)
  PATH="$bin_dir:$PATH" CFM_CONFIG_DIR="$1" \
  FAKE_OPENRESTY_ARGS="$tmp/or-$(basename "$2").args" \
  FAKE_OPENRESTY_FAIL="${3:-0}" \
  sh -c '. "$1"; process_engine OpenResty "$2" "$3" "$4" "$5" openresty.service x' sh \
    "$tmp/functions.sh" "$bin_dir/fake-openresty" "$1/openresty.conf" "$2/nginx.conf" "$2" 2>&1
}

assert_untouched() { # LIVE BEFORE WHAT
  [ "$(snapshot "$1")" = "$2" ] || { echo "FAIL: $3: live dir changed" >&2; ls -la "$1" >&2; exit 1; }
}

# 1. A broken NEW sidecar fails the engine test -> live dir byte-identical.
pkg="$tmp/pkg-broken"; live="$tmp/live-broken"
mk_pkg "$pkg" "$live"; printf '%s\n' 'BROKEN bypass' >"$pkg/challenge_waf_bypass.conf"
seed_live "$live"; before=$(snapshot "$live")
out=$(run_or "$pkg" "$live")
assert_untouched "$live" "$before" "broken new sidecar"
printf '%s\n' "$out" | rg -q 'config test failed; leaving existing sidecars and nginx\.conf unchanged' \
  || { echo "FAIL: broken sidecar must be reported" >&2; printf '%s\n' "$out" >&2; exit 1; }
# ...and the test really read the NEW sidecars from the stage, not the live ones.
rg -q "include .*/\.cfm-proxy-stage\.[^/]+/challenge_waf_bypass\.conf" "$tmp/or-live-broken.args.includes" \
  || { echo "FAIL: the engine test must read the staged sidecars" >&2; cat "$tmp/or-live-broken.args.includes" >&2; exit 1; }
if rg -q "^include $live/[a-z_-]+\\.conf\$" "$tmp/or-live-broken.args.includes"; then
  echo "FAIL: the engine test read a LIVE sidecar" >&2; exit 1
fi

# 2. Engine test itself fails -> live dir byte-identical.
pkg="$tmp/pkg-testfail"; live="$tmp/live-testfail"
mk_pkg "$pkg" "$live"; seed_live "$live"; before=$(snapshot "$live")
run_or "$pkg" "$live" 1 >/dev/null
assert_untouched "$live" "$before" "failed engine test"

# 3. A packaged sidecar missing -> live dir byte-identical.
pkg="$tmp/pkg-missing"; live="$tmp/live-missing"
mk_pkg "$pkg" "$live"; rm -f "$pkg/challenge_waf_bypass.conf"
seed_live "$live"; before=$(snapshot "$live")
out=$(run_or "$pkg" "$live")
assert_untouched "$live" "$before" "missing packaged sidecar"
printf '%s\n' "$out" | rg -q 'sidecar staging failed' || { echo "FAIL: missing sidecar must be reported" >&2; printf '%s\n' "$out" >&2; exit 1; }

# 4. The main config can't be written (its dir is a file) -> sidecars untouched.
pkg="$tmp/pkg-maindir"; live="$tmp/live-maindir"
mk_pkg "$pkg" "$live"; seed_live "$live"; before=$(snapshot "$live")
: >"$tmp/not-a-dir"
PATH="$bin_dir:$PATH" CFM_CONFIG_DIR="$pkg" FAKE_OPENRESTY_ARGS="$tmp/or-maindir.args" \
  sh -c '. "$1"; process_engine OpenResty "$2" "$3" "$4" "$5" openresty.service x' sh \
  "$tmp/functions.sh" "$bin_dir/fake-openresty" "$pkg/openresty.conf" "$tmp/not-a-dir/nginx.conf" "$live" >/dev/null 2>&1
assert_untouched "$live" "$before" "unwritable main config"

# 5. A main config that includes a sidecar in a form the helper can't redirect
#    (here `LIVE/./name`) is refused rather than tested against the OLD file.
pkg="$tmp/pkg-relative"; live="$tmp/live-relative"
mk_pkg "$pkg" "$live"; sed -i "s|include $live/trusted_proxies.conf;|include $live/./trusted_proxies.conf;|" "$pkg/openresty.conf"
seed_live "$live"; before=$(snapshot "$live")
out=$(run_or "$pkg" "$live")
assert_untouched "$live" "$before" "unredirectable include"
printf '%s\n' "$out" | rg -q 'cannot redirect; not deploying untested sidecars' \
  || { echo "FAIL: an unredirectable include must be refused" >&2; printf '%s\n' "$out" >&2; exit 1; }

# 6. Success -> new sidecars and main live, byte-identical to the package, the
#    listener header names the LIVE path, and no temp/stage file is left.
pkg="$tmp/pkg-ok"; live="$tmp/live-ok"
mk_pkg "$pkg" "$live"; seed_live "$live"
run_or "$pkg" "$live" >/dev/null
cmp -s "$live/trusted_proxies.conf" "$pkg/trusted_proxies.conf" || { echo "FAIL: new trusted_proxies.conf not live" >&2; exit 1; }
cmp -s "$live/challenge_waf_bypass.conf" "$pkg/challenge_waf_bypass.conf" || { echo "FAIL: new challenge_waf_bypass.conf not live" >&2; exit 1; }
cmp -s "$live/nginx.conf" "$pkg/openresty.conf" || { echo "FAIL: new main config not live" >&2; exit 1; }
rg -q "Install path: $live/cfm-panel-listeners\.conf" "$live/cfm-panel-listeners.conf" \
  || { echo "FAIL: listener header must name the live path" >&2; cat "$live/cfm-panel-listeners.conf" >&2; exit 1; }
got=$(ls -A "$live" | sed 's/\.cfm-prepkg\.[0-9]*$/.cfm-prepkg.TS/' | sort | tr '\n' ' ')
want="cfm-panel-listeners.conf challenge_waf_bypass.conf nginx.conf nginx.conf.cfm-prepkg.TS trusted_proxies.conf "
[ "$got" = "$want" ] || { echo "FAIL: after a deploy the live dir must hold exactly: $want; got: $got" >&2; exit 1; }

# 7. The staged main is the packaged one with ONLY the sidecar include paths
#    moved (a tab-separated include is redirected too).
pkg="$tmp/pkg-same"; live="$tmp/live-same"
mk_pkg "$pkg" "$live"; sed -i "s|    include $live/trusted_proxies.conf;|    include\t$live/trusted_proxies.conf;|" "$pkg/openresty.conf"
seed_live "$live"
st=$(mktemp -d "$tmp/st.XXXXXX"); CFM_CONFIG_DIR="$pkg" sh -c '. "$1"; stage_main_config "$2" "$3" "$4"' sh "$tmp/functions.sh" "$pkg/openresty.conf" "$st" "$live" \
  || { echo "FAIL: a tab-separated include must be redirected, not refused" >&2; exit 1; }
diff <(sed "s|$live/|STAGE/|" "$pkg/openresty.conf") <(sed "s|$st/|STAGE/|" "$st/main.conf") >/dev/null \
  || { echo "FAIL: staged main differs from the packaged one beyond the include paths" >&2; diff "$pkg/openresty.conf" "$st/main.conf" >&2; exit 1; }
rm -rf "$st"

# 8. The main-config rename fails after the sidecars went in -> the sidecars
#    are put back (and one that did not exist before is removed again).
pkg="$tmp/pkg-mainmv"; live="$tmp/live-mainmv"
mk_pkg "$pkg" "$live"; seed_live "$live"; before=$(snapshot "$live")
out=$(FAKE_MV_FAIL=/nginx.conf FAKE_MV_ONCE="$tmp/mv-once-8" run_or "$pkg" "$live")
[ "$(snapshot "$live")" = "$before" ] || { echo "FAIL: failed main rename must roll the sidecars back" >&2; ls -la "$live" >&2; printf '%s\n' "$out" >&2; exit 1; }
printf '%s\n' "$out" | rg -q 'failed to deploy .*nginx\.conf; restoring the previous sidecars' || { echo "FAIL: failed main rename must be reported" >&2; printf '%s\n' "$out" >&2; exit 1; }

# 9. The 2nd sidecar rename fails -> the 1st is put back.
pkg="$tmp/pkg-sidemv"; live="$tmp/live-sidemv"
mk_pkg "$pkg" "$live"; seed_live "$live"; before=$(snapshot "$live")
FAKE_MV_FAIL=/challenge_waf_bypass.conf FAKE_MV_ONCE="$tmp/mv-once-9" run_or "$pkg" "$live" >/dev/null
[ "$(snapshot "$live")" = "$before" ] || { echo "FAIL: failed sidecar rename must roll the earlier ones back" >&2; ls -la "$live" >&2; exit 1; }

# 9b. ...and if putting a renamed-in sidecar back fails too, its previous copy
#     is kept under a name cleanup never removes, and the operator is told.
#     (The 3rd rename fails; restoring the 2nd, challenge_waf_bypass.conf, fails.)
pkg="$tmp/pkg-norestore"; live="$tmp/live-norestore"
mk_pkg "$pkg" "$live"; seed_live "$live"
out=$(FAKE_MV_FAIL=/cfm-panel-listeners.conf FAKE_MV_ONCE="$tmp/mv-once-9b" \
      FAKE_MV_FAIL_FROM=.challenge_waf_bypass.conf.cfm-old run_or "$pkg" "$live")
kept=$(ls "$live" | rg 'challenge_waf_bypass\.conf\.cfm-restore-failed\.' || true)
[ -n "$kept" ] && [ "$(cat "$live/$kept")" = "OLD bypass" ] || { echo "FAIL: an unrestorable sidecar's previous copy must be kept" >&2; ls -la "$live" >&2; exit 1; }
printf '%s\n' "$out" | rg -q "previous copy is .*$kept" || { echo "FAIL: the kept copy must be named in the warning" >&2; printf '%s\n' "$out" >&2; exit 1; }
printf '%s\n' "$out" | rg -q 'a sidecar could not be restored' || { echo "FAIL: the summary must not claim the sidecars were left unchanged" >&2; printf '%s\n' "$out" >&2; exit 1; }
if printf '%s\n' "$out" | rg -q 'leaving existing sidecars'; then echo "FAIL: false 'leaving existing sidecars' after a failed restore" >&2; exit 1; fi
[ "$(cat "$live/trusted_proxies.conf")" = "OLD trusted" ] || { echo "FAIL: the restorable sidecar must still be put back" >&2; exit 1; }

# 9d. A sidecar whose rename failed was never renamed in (live still holds its
#     previous version): it is not "restored", so a failing restore of it can't
#     produce a false "could not restore" alarm.
pkg="$tmp/pkg-notin"; live="$tmp/live-notin"
mk_pkg "$pkg" "$live"; seed_live "$live"; before=$(snapshot "$live")
out=$(FAKE_MV_FAIL=/challenge_waf_bypass.conf FAKE_MV_ONCE="$tmp/mv-once-9d" \
      FAKE_MV_FAIL_FROM=.challenge_waf_bypass.conf.cfm-old run_or "$pkg" "$live")
assert_untouched "$live" "$before" "sidecar that was never renamed in"
if printf '%s\n' "$out" | rg -q 'could not restore'; then echo "FAIL: false 'could not restore' for a sidecar never renamed in" >&2; printf '%s\n' "$out" >&2; exit 1; fi

# 9c. ...and if even keeping it under that name fails, the .cfm-old copy stays
#     (cleanup must not delete the only good copy) and is the one named.
pkg="$tmp/pkg-keepold"; live="$tmp/live-keepold"
mk_pkg "$pkg" "$live"; seed_live "$live"
out=$(FAKE_MV_FAIL=/cfm-panel-listeners.conf FAKE_MV_ONCE="$tmp/mv-once-9c" \
      FAKE_MV_FAIL_FROM=.challenge_waf_bypass.conf.cfm-old FAKE_MV_FAIL_KEEP=1 run_or "$pkg" "$live")
kept=$(ls -A "$live" | rg '^\.challenge_waf_bypass\.conf\.cfm-old\.' || true)
[ -n "$kept" ] && [ "$(cat "$live/$kept")" = "OLD bypass" ] || { echo "FAIL: cleanup deleted the only good copy" >&2; ls -la "$live" >&2; exit 1; }
printf '%s\n' "$out" | rg -q "previous copy is .*$kept" || { echo "FAIL: the kept .cfm-old copy must be named" >&2; printf '%s\n' "$out" >&2; exit 1; }

# 10. The main-config temp can't be written after the sidecar temps were ->
#     live dir byte-identical, no temp / marker / backup / stage left.
pkg="$tmp/pkg-maintmp"; live="$tmp/live-maintmp"
mk_pkg "$pkg" "$live"; seed_live "$live"; before=$(snapshot "$live")
FAKE_INSTALL_FAIL=/.nginx.conf.cfm-new run_or "$pkg" "$live" >/dev/null
assert_untouched "$live" "$before" "main temp write failed after the sidecar temps"

# 11. An include of a sidecar mid-line (`server { include X; }`) in a form the
#     rewrite skips is still caught by the redirect check.
pkg="$tmp/pkg-midline"; live="$tmp/live-midline"
mk_pkg "$pkg" "$live"
sed -i "s|    include $live/cfm-panel-listeners.conf;|    server { include $live/./cfm-panel-listeners.conf; }|" "$pkg/openresty.conf"
seed_live "$live"; before=$(snapshot "$live")
out=$(run_or "$pkg" "$live")
assert_untouched "$live" "$before" "mid-line unredirectable include"
printf '%s\n' "$out" | rg -q 'cannot redirect' || { echo "FAIL: a mid-line unredirectable include must be refused" >&2; printf '%s\n' "$out" >&2; exit 1; }

# 12. A signal that lands after the main config was renamed in (commit done,
#     flag not yet cleared) must NOT roll the sidecars back under the new main.
live="$tmp/live-latesig"; mkdir -p "$live"
printf '%s\n' NEW >"$live/trusted_proxies.conf"; printf '%s\n' NEW >"$live/challenge_waf_bypass.conf"
printf '%s\n' NEW >"$live/cfm-panel-listeners.conf"; printf '%s\n' NEWMAIN >"$live/nginx.conf"
sh -c '. "$1"
  for n in $CFM_SIDECARS; do printf "%s\n" OLD >"$2/.$n.cfm-old.$$"; done
  CFM_COMMIT_LIVE=$2; CFM_COMMIT_MAIN=$2/nginx.conf; CFM_COMMITTING=1
  cleanup_proxy_deploy' sh "$tmp/functions.sh" "$live"
for n in trusted_proxies.conf challenge_waf_bypass.conf cfm-panel-listeners.conf; do
  [ "$(cat "$live/$n")" = NEW ] || { echo "FAIL: a completed commit was rolled back ($n)" >&2; exit 1; }
done
if ls -A "$live" | rg -q 'cfm-old'; then echo "FAIL: backups left after a completed commit" >&2; ls -A "$live" >&2; exit 1; fi

# 13. A failed commit removes the .cfm-prepkg backup it made (the live dir is
#     exactly as it was), while a successful one keeps it (case 6).
pkg="$tmp/pkg-nobak"; live="$tmp/live-nobak"
mk_pkg "$pkg" "$live"; seed_live "$live"; before=$(snapshot "$live")
FAKE_MV_FAIL=/nginx.conf FAKE_MV_ONCE="$tmp/mv-once-13" run_or "$pkg" "$live" >/dev/null
assert_untouched "$live" "$before" "rolled-back commit (incl. its backup)"

echo "OK: package proxy deploy helper tests only the main engine configs, with the new sidecars staged; a failed run leaves the live dir untouched"

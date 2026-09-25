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

# Fake engines: -T = test + print "# configuration file PATH:" for the main
# config and each file it includes (one simple `include PATH;` per line,
# relative to the -c file's dir, globs expanded), failing on a missing file or
# one marked BROKEN. The include FORMS a real engine resolves (globs in the
# live dir, //, ./, comments, two-line includes...) are tested against a REAL
# nginx further down, not against this.
cat >"$bin_dir/fake-dump.sh" <<'EOF_FD'
fake_dump() { # MAIN RECORD
  fd_dir=$(dirname "$1")
  printf '# configuration file %s:\n' "$1"
  sed -n 's/^[[:space:]]*include[[:space:]][[:space:]]*\([^;]*\);.*$/\1/p' "$1" | while read -r inc; do
    case "$inc" in /*) ;; *) inc=$fd_dir/$inc ;; esac
    for f in $inc; do
      printf 'include %s\n' "$f" >> "$2"
      [ -f "$f" ] || exit 1
      ! grep -q BROKEN "$f" || exit 1
      printf '# configuration file %s:\n' "$f"
    done
  done
}
EOF_FD

cat >"$bin_dir/fake-openresty" <<'EOF_FAKE'
#!/bin/sh
. "$(dirname "$0")/fake-dump.sh"
[ "$1" = "-h" ] && { echo "  -T            : test configuration, dump it and exit"; exit 0; }
printf '%s\n' "$*" >> "$FAKE_OPENRESTY_ARGS"
[ "$1" = "-T" ] && [ "$2" = "-c" ] && [ -f "$3" ] || exit 1
fake_dump "$3" "$FAKE_OPENRESTY_ARGS.includes" || exit 1
[ "${FAKE_OPENRESTY_FAIL:-0}" = "1" ] && exit 1
exit 0
EOF_FAKE
chmod 0755 "$bin_dir/fake-openresty"

cat >"$bin_dir/fake-angie" <<'EOF_FAKE'
#!/bin/sh
. "$(dirname "$0")/fake-dump.sh"
[ "$1" = "-h" ] && { echo "  -T            : test configuration, dump it and exit"; exit 0; }
printf '%s\n' "$*" >> "$FAKE_ANGIE_ARGS"
[ "$1" = "-T" ] && [ "$2" = "-c" ] && [ -f "$3" ] || exit 1
fake_dump "$3" "$FAKE_ANGIE_ARGS.includes" || exit 1
EOF_FAKE
chmod 0755 "$bin_dir/fake-angie"

# An engine that passes the test but prints no file list (a dump write that
# failed silently, e.g. on a full disk), and one too old to have -T.
cat >"$bin_dir/fake-nolist" <<'EOF_FAKE'
#!/bin/sh
[ "$1" = "-h" ] && { echo "  -T            : test configuration, dump it and exit"; exit 0; }
exit 0
EOF_FAKE
cat >"$bin_dir/fake-old" <<'EOF_FAKE'
#!/bin/sh
[ "$1" = "-h" ] && { echo "  -t            : test configuration and exit"; exit 0; }
[ "$1" = "-t" ] && exit 0
echo "nginx: invalid option: \"$1\"" >&2; exit 1
EOF_FAKE
chmod 0755 "$bin_dir/fake-nolist" "$bin_dir/fake-old"

# A REAL nginx (CI installs it): the one engine whose include resolution the
# helper's `-T` check must agree with. Wrapped so it logs to stderr and uses a
# scratch prefix and pid path (Ubuntu's build compiles in /run/nginx.pid,
# which -t opens), so it runs unprivileged and touches nothing on the host.
# A guardrail that cannot run its matcher must FAIL (CLAUDE.md §5).
command -v nginx >/dev/null 2>&1 || { echo "FAIL: nginx is required by $(basename "$0") (CI: apt-get install nginx)" >&2; exit 1; }
mkdir -p "$tmp/nginx-prefix/logs"
cat >"$bin_dir/real-nginx" <<EOF_RN
#!/bin/sh
exec $(command -v nginx) -e stderr -p "$tmp/nginx-prefix" -g "pid $tmp/nginx-prefix/nginx.pid;" "\$@"
EOF_RN
chmod 0755 "$bin_dir/real-nginx"

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
$real_mv "\$@" || exit \$?
# FAKE_MV_KILL_AFTER: after a rename whose target ends in it, TERM the helper
# (every time; with FAKE_MV_KILL_ONCE set to a path, only the first time).
if [ -n "\${FAKE_MV_KILL_AFTER:-}" ]; then
  case "\$last" in *"\$FAKE_MV_KILL_AFTER")
    if [ -z "\${FAKE_MV_KILL_ONCE:-}" ] || [ ! -e "\$FAKE_MV_KILL_ONCE" ]; then
      [ -n "\${FAKE_MV_KILL_ONCE:-}" ] && : >"\$FAKE_MV_KILL_ONCE"
      kill -TERM "\$PPID"
    fi ;;
  esac
fi
exit 0
EOF_MV
chmod 0755 "$bin_dir/mv"

# cp shim: FAKE_CP_KILL_AFTER - after a copy whose target contains it, TERM
# the helper (a signal landing right after the main config's backup).
real_cp=$(command -v cp)
cat >"$bin_dir/cp" <<EOF_CP
#!/bin/sh
for last do :; done
$real_cp "\$@" || exit \$?
if [ -n "\${FAKE_CP_KILL_AFTER:-}" ]; then
  case "\$last" in *"\$FAKE_CP_KILL_AFTER"*) kill -TERM "\$PPID" ;; esac
fi
exit 0
EOF_CP
chmod 0755 "$bin_dir/cp"

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
# touching system Angie/OpenResty paths. The helper's top-level
# `deploy_logrotate_config` call is dropped too: run as root it would deploy
# the packaged logrotate config onto the live system (CLAUDE.md §5).
# Only the definitions: cut at the first top-level statement, so sourcing
# functions.sh never runs the live logrotate deploy or takes the live lock.
awk '/^deploy_logrotate_config$/{exit} {print}' scripts/package-proxy-config-deploy.sh >"$tmp/functions.sh"
if rg -q '^(if |trap |acquire_deploy_lock |process_engine |(ensure_fallback_cert_if_missing|deploy_logrotate_config|print_proxy_config_summary)$)' "$tmp/functions.sh"; then
  echo "FAIL: functions.sh runs top-level statements; the cut point moved" >&2; exit 1
fi
rg -q '^deploy_logrotate_config$' "$tmp/functions.sh" && { echo "FAIL: functions.sh still calls deploy_logrotate_config" >&2; exit 1; }

# The fallback cert, via the function: running the whole script here would
# find a real angie/openresty on a host that has one (find_first_executable
# also looks in /usr/sbin, /usr/local/openresty) and deploy into its live dirs.
fallback_cert_dir="$tmp/fallback-certs"
fallback_output=$(
  PATH="$bin_dir:/usr/bin:/bin" \
  CFM_CONFIG_DIR="$configs" \
  CFM_FALLBACK_CERT_DIR="$fallback_cert_dir" \
  sh -c '. "$1"; ensure_fallback_cert_if_missing' sh "$tmp/functions.sh"
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

if ! printf '%s\n' "$active_angie_output" | rg -q 'CFM proxy config: testing Angie config with: .*/fake-angie -T -c .*/\.cfm-proxy-stage\.[^/]+/main\.conf \(packaged .*/configs/angie\.conf \+ new sidecars\)'; then
  echo "FAIL: expected Angie main config test command in output" >&2
  printf '%s\n' "$active_angie_output" >&2
  exit 1
fi

if ! printf '%s\n' "$active_angie_output" | rg -q 'CFM proxy config: testing OpenResty config with: .*/fake-openresty -T -c .*/\.cfm-proxy-stage\.[^/]+/main\.conf \(packaged .*/configs/openresty\.conf \+ new sidecars\)'; then
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
    "-T -c "*/.cfm-proxy-stage.*/main.conf) ;;
    *) echo "FAIL: expected fake $eng args '-T -c <stage>/main.conf', got '$actual_args'" >&2; exit 1 ;;
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
printf '%s\n' "$out" | rg -q 'test read a sidecar other than the new one' \
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

# 12. A signal that lands after the main config was renamed in (commit done,
#     flag not yet cleared) must NOT roll the sidecars back under the new main.
live="$tmp/live-latesig"; mkdir -p "$live"
printf '%s\n' NEW >"$live/trusted_proxies.conf"; printf '%s\n' NEW >"$live/challenge_waf_bypass.conf"
printf '%s\n' NEW >"$live/cfm-panel-listeners.conf"; printf '%s\n' NEWMAIN >"$live/nginx.conf"
sh -c '. "$1"
  for n in $CFM_SIDECARS; do printf "%s\n" OLD >"$2/.$n.cfm-old.$$"; done
  CFM_COMMIT_LIVE=$2; CFM_COMMIT_MAIN_TMP=$2/.nginx.conf.cfm-new.$$; CFM_COMMITTING=1
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

# 14. The SHIPPED configs stage cleanly: exactly their three sidecar includes
#     move, nothing else.
for e in angie:/etc/angie openresty:/usr/local/openresty/nginx/conf; do
  n=${e%%:*}; d=${e#*:}
  st=$(mktemp -d "$tmp/real.XXXXXX")
  sh -c '. "$1"; stage_main_config "$2" "$3" "$4"' sh "$tmp/functions.sh" "configs/$n.conf" "$st" "$d" \
    || { echo "FAIL: shipped configs/$n.conf must stage" >&2; exit 1; }
  [ "$(diff "configs/$n.conf" "$st/main.conf" | rg -c '^>')" = 3 ] \
    || { echo "FAIL: staging configs/$n.conf must change exactly 3 lines" >&2; diff "configs/$n.conf" "$st/main.conf" >&2; exit 1; }
  diff <(sed "s#$d/\(trusted_proxies\|challenge_waf_bypass\|cfm-panel-listeners\)\.conf;#STAGE/\1.conf;#" "configs/$n.conf") \
       <(sed "s|$st/|STAGE/|" "$st/main.conf") >/dev/null \
    || { echo "FAIL: staged configs/$n.conf differs beyond the sidecar includes" >&2; exit 1; }
done

# 15. With a REAL nginx: whatever form the packaged main includes a sidecar
#     in, the deploy happens only if the engine test read the NEW (staged)
#     copies; if it read a live one (glob in the live dir, //, ./, a form the
#     rewrite skips), nothing is deployed. The engine resolves the includes;
#     the helper only reads its -T file list.
#     Sidecars valid for nginx: a comment, a geo list, a comment. (No test
#     config has a server{} block: as root, nginx -t would then create
#     /var/lib/nginx/* temp dirs on the host.)
nx_case() { # NAME EXPECT(deploy|refuse) <http{} body, @L@ = live dir>
  nx_pkg="$tmp/nx-pkg-$1"; nx_live="$tmp/nx-live-$1"; rm -rf "$nx_pkg" "$nx_live"
  mkdir -p "$nx_pkg" "$nx_live"
  printf 'events {}\nhttp {\n%s\n}\n' "$(printf '%s\n' "$3" | sed "s|@L@|$nx_live|g")" >"$nx_pkg/openresty.conf"
  printf '%s\n' '# new trusted' >"$nx_pkg/trusted_proxies.conf"
  printf '%s\n' '192.0.2.1/32 1;' >"$nx_pkg/challenge_waf_bypass.conf"
  cp "$configs/cfm-panel-listeners.conf.in" "$nx_pkg/"
  printf '%s\n' '# OLD trusted' >"$nx_live/trusted_proxies.conf"
  printf '%s\n' '198.51.100.1/32 1;' >"$nx_live/challenge_waf_bypass.conf"
  printf '%s\n' 'OLD main' >"$nx_live/nginx.conf"
  printf '%s\n' '# OLD listeners' >"$nx_live/cfm-panel-listeners.conf"
  nx_before=$(snapshot "$nx_live")
  nx_out=$(PATH="$bin_dir:$PATH" CFM_CONFIG_DIR="$nx_pkg" \
    sh -c '. "$1"; process_engine OpenResty "$2" "$3" "$4" "$5" openresty.service x' sh \
    "$tmp/functions.sh" "$bin_dir/real-nginx" "$nx_pkg/openresty.conf" "$nx_live/nginx.conf" "$nx_live" 2>&1)
  if [ "$2" = deploy ]; then
    cmp -s "$nx_live/nginx.conf" "$nx_pkg/openresty.conf" && cmp -s "$nx_live/trusted_proxies.conf" "$nx_pkg/trusted_proxies.conf" \
      || { echo "FAIL: real nginx, $1: expected a deploy" >&2; printf '%s\n' "$nx_out" >&2; exit 1; }
  else
    [ "$(snapshot "$nx_live")" = "$nx_before" ] || { echo "FAIL: real nginx, $1: the live dir changed" >&2; printf '%s\n' "$nx_out" >&2; exit 1; }
    printf '%s\n' "$nx_out" | rg -q 'test read a sidecar other than the new one' \
      || { echo "FAIL: real nginx, $1: expected 'read a sidecar other than the new one'" >&2; printf '%s\n' "$nx_out" >&2; exit 1; }
  fi
}
G='geo $cfm_x {
    default 0;
    include @L@/challenge_waf_bypass.conf;
}'
nx_case plain deploy "include @L@/trusted_proxies.conf;
$G"
nx_case comment deploy "# operators on plain nginx: include /etc/nginx/trusted_proxies.conf; instead
include @L@/trusted_proxies.conf;  # trailing comment
$G"
# A commented-out sidecar include is not read, so it isn't in -T's list: that
# must not count as "the list is incomplete".
nx_case commented-listeners deploy "include @L@/trusted_proxies.conf;
$G
# include @L@/cfm-panel-listeners.conf;"
nx_case tab deploy "include	@L@/trusted_proxies.conf;
$G"
nx_case relative deploy "include trusted_proxies.conf;
$G"
nx_case glob-live refuse "include @L@/*_proxies.conf;
$G"
nx_case double-slash refuse "include @L@//trusted_proxies.conf;
$G"
nx_case dot-slash refuse "include @L@/./trusted_proxies.conf;
$G"
nx_case twoline-live deploy "include
    @L@/trusted_proxies.conf;
$G"
nx_case bypass-live refuse "include @L@/trusted_proxies.conf;
geo \$cfm_x {
    default 0;
    include @L@//challenge_waf_bypass.conf;
}"
nx_case listeners-live refuse "include @L@/trusted_proxies.conf;
$G
include @L@/./cfm-panel-listeners.conf;"
nx_case semicolon-include refuse "include @L@/trusted_proxies.conf;include @L@/../nx-live-semicolon-include/trusted_proxies.conf;
$G"
# A broken NEW sidecar: the real engine rejects it; live dir unchanged.
nx_pkg="$tmp/nx-pkg-broken"; nx_live="$tmp/nx-live-broken"; rm -rf "$nx_pkg" "$nx_live"; mkdir -p "$nx_pkg" "$nx_live"
printf 'events {}\nhttp {\ninclude %s/trusted_proxies.conf;\n%s\n}\n' "$nx_live" "$(printf '%s\n' "$G" | sed "s|@L@|$nx_live|g")" >"$nx_pkg/openresty.conf"
printf '%s\n' 'this_is_not_a_directive;' >"$nx_pkg/trusted_proxies.conf"
printf '%s\n' '192.0.2.1/32 1;' >"$nx_pkg/challenge_waf_bypass.conf"; cp "$configs/cfm-panel-listeners.conf.in" "$nx_pkg/"
printf '%s\n' '# OLD trusted' >"$nx_live/trusted_proxies.conf"; printf '%s\n' '198.51.100.1/32 1;' >"$nx_live/challenge_waf_bypass.conf"
nx_before=$(snapshot "$nx_live")
PATH="$bin_dir:$PATH" CFM_CONFIG_DIR="$nx_pkg" sh -c '. "$1"; process_engine OpenResty "$2" "$3" "$4" "$5" openresty.service x' sh \
  "$tmp/functions.sh" "$bin_dir/real-nginx" "$nx_pkg/openresty.conf" "$nx_live/nginx.conf" "$nx_live" >/dev/null 2>&1
[ "$(snapshot "$nx_live")" = "$nx_before" ] || { echo "FAIL: real nginx: a broken new sidecar must leave the live dir unchanged" >&2; exit 1; }

# The script's own trap lines (not a copy), for the signal cases below.
# Exactly the EXIT trap, the signal trap and the PIPE-ignore lines: anything else
# in the extract (e.g. the rest of the script, if a line changed shape) must
# never be eval'd here - it would run the real deploy.
TRAPS=$(awk '/^trap cleanup_on_exit EXIT$/{f=1} f&&!/^#/{print; n++} f&&n==3{exit}' scripts/package-proxy-config-deploy.sh)
printf '%s\n' "$TRAPS" | awk 'NR==1&&$0!="trap cleanup_on_exit EXIT"{bad=1} NR==2&&$0!~/^trap .* HUP INT TERM$/{bad=1} NR==3&&$0!="trap '"''"' PIPE"{bad=1} END{exit (bad||NR!=3)}' \
  || { echo "FAIL: could not find the script's three trap lines (not eval'ing anything else):" >&2; printf '%s\n' "$TRAPS" >&2; exit 1; }

# 16. A TERM during the renames rolls back (the exit trap, as in the script),
#     and a second TERM while the rollback runs doesn't cut it short (the shim
#     TERMs again on the rollback's own rename to that name).
pkg="$tmp/pkg-term"; live="$tmp/live-term"
mk_pkg "$pkg" "$live"; seed_live "$live"; before=$(snapshot "$live")
PATH="$bin_dir:$PATH" CFM_CONFIG_DIR="$pkg" FAKE_OPENRESTY_ARGS="$tmp/or-term.args" \
  FAKE_MV_KILL_AFTER=/challenge_waf_bypass.conf \
  TRAPS="$TRAPS" sh -c '. "$1"; eval "$TRAPS"
    process_engine OpenResty "$2" "$3" "$4" "$5" openresty.service x' sh \
  "$tmp/functions.sh" "$bin_dir/fake-openresty" "$pkg/openresty.conf" "$live/nginx.conf" "$live" >/dev/null 2>&1 || true   # the helper exits 1 on TERM, as the script does
assert_untouched "$live" "$before" "TERM during the renames"

# 17. A TERM after the backup, before any rename: nothing deployed, so no
#     .cfm-prepkg backup (or anything else) is left.
pkg="$tmp/pkg-termbak"; live="$tmp/live-termbak"
mk_pkg "$pkg" "$live"; seed_live "$live"; before=$(snapshot "$live")
PATH="$bin_dir:$PATH" CFM_CONFIG_DIR="$pkg" FAKE_OPENRESTY_ARGS="$tmp/or-termbak.args" \
  FAKE_CP_KILL_AFTER=.cfm-prepkg. \
  TRAPS="$TRAPS" sh -c '. "$1"; eval "$TRAPS"
    process_engine OpenResty "$2" "$3" "$4" "$5" openresty.service x' sh \
  "$tmp/functions.sh" "$bin_dir/fake-openresty" "$pkg/openresty.conf" "$live/nginx.conf" "$live" >/dev/null 2>&1 || true   # the helper exits 1 on TERM, as the script does
assert_untouched "$live" "$before" "TERM between the backup and the renames"

# 18. Leftovers of a run killed hard (no trap) are cleared by the next run:
#     a stage dir and .cfm-new temps go; a .cfm-old copy (maybe the only good
#     one) stays.
pkg="$tmp/pkg-stale"; live="$tmp/live-stale"
mk_pkg "$pkg" "$live"; seed_live "$live"
mkdir -p "$live/.cfm-proxy-stage.OLD1"; : >"$live/.cfm-proxy-stage.OLD1/main.conf"
: >"$live/.trusted_proxies.conf.cfm-new.99999"; : >"$live/.cfm-panel-listeners.conf.cfm-absent.99999"
printf '%s\n' keep >"$live/.trusted_proxies.conf.cfm-old.99999"
run_or "$pkg" "$live" >/dev/null
[ ! -e "$live/.cfm-proxy-stage.OLD1" ] && [ ! -e "$live/.trusted_proxies.conf.cfm-new.99999" ] \
  && [ ! -e "$live/.cfm-panel-listeners.conf.cfm-absent.99999" ] \
  || { echo "FAIL: a hard-killed run's stage dir / temps must be cleared" >&2; ls -A "$live" >&2; exit 1; }
[ "$(cat "$live/.trusted_proxies.conf.cfm-old.99999")" = keep ] || { echo "FAIL: a .cfm-old copy must never be removed by the stale sweep" >&2; exit 1; }

# 19. Two engines in one run: the first one's failed-restore state must not
#     leak into the second (a stray .cfm-old left, or a false alarm).
pkgA="$tmp/pkg-twoA"; liveA="$tmp/live-twoA"; pkgB="$tmp/pkg-twoB"; liveB="$tmp/live-twoB"
mk_pkg "$pkgA" "$liveA"; seed_live "$liveA"; mk_pkg "$pkgB" "$liveB"; seed_live "$liveB"
out=$(PATH="$bin_dir:$PATH" FAKE_OPENRESTY_ARGS="$tmp/or-two.args" \
  FAKE_MV_FAIL=/cfm-panel-listeners.conf FAKE_MV_ONCE="$tmp/mv-once-19" \
  FAKE_MV_FAIL_FROM="$liveA/.challenge_waf_bypass.conf.cfm-old" FAKE_MV_FAIL_KEEP=1 \
  sh -c '. "$1"
    CFM_CONFIG_DIR=$4; process_engine OpenResty "$2" "$4/openresty.conf" "$3/nginx.conf" "$3" openresty.service x
    CFM_CONFIG_DIR=$6; process_engine OpenResty "$2" "$6/openresty.conf" "$5/nginx.conf" "$5" openresty.service x' sh \
  "$tmp/functions.sh" "$bin_dir/fake-openresty" "$liveA" "$pkgA" "$liveB" "$pkgB" 2>&1)
cmp -s "$liveB/nginx.conf" "$pkgB/openresty.conf" || { echo "FAIL: the second engine must deploy" >&2; printf '%s\n' "$out" >&2; exit 1; }
if ls -A "$liveB" | rg -q 'cfm-old|cfm-new|cfm-absent'; then echo "FAIL: the first engine's state leaked into the second's cleanup" >&2; ls -A "$liveB" >&2; exit 1; fi
[ "$(printf '%s\n' "$out" | rg -c 'a sidecar could not be restored')" = 1 ] || { echo "FAIL: exactly one engine may report a failed restore" >&2; printf '%s\n' "$out" >&2; exit 1; }

# 20. A direct cleanup (between engines) leaves the signal traps armed: a
#     TERM during the NEXT engine still stops the run (only the exit trap
#     ignores signals).
armed=$(TRAPS="$TRAPS" sh -c '. "$1"; eval "$TRAPS"; cleanup_proxy_deploy; trap' sh "$tmp/functions.sh")
for sig in HUP INT TERM; do
  # the trap line FOR this signal (dash: "... TERM", bash: "... SIGTERM") must
  # carry the exit-1 handler, not '' (ignored)
  printf '%s\n' "$armed" | rg -q "exit 1'? (SIG)?$sig\$" \
    || { echo "FAIL: the $sig trap must stay armed after a direct cleanup; got: $armed" >&2; exit 1; }
done

# 21. Two engines, the first with a failed restore, the second failing
#     harmlessly: the second must say "leaving existing sidecars", not repeat
#     the first one's "could not be restored".
pkgA="$tmp/pkg-r21A"; liveA="$tmp/live-r21A"; pkgB="$tmp/pkg-r21B"; liveB="$tmp/live-r21B"
mk_pkg "$pkgA" "$liveA"; seed_live "$liveA"; mk_pkg "$pkgB" "$liveB"; seed_live "$liveB"
out=$(PATH="$bin_dir:$PATH" FAKE_OPENRESTY_ARGS="$tmp/or-21.args" \
  FAKE_MV_FAIL=/cfm-panel-listeners.conf FAKE_MV_ONCE="$tmp/mv-once-21" \
  FAKE_MV_FAIL_FROM="$liveA/.challenge_waf_bypass.conf.cfm-old" \
  FAKE_INSTALL_FAIL="$liveB/.nginx.conf.cfm-new" \
  sh -c '. "$1"
    CFM_CONFIG_DIR=$4; process_engine OpenResty "$2" "$4/openresty.conf" "$3/nginx.conf" "$3" openresty.service x
    echo ===B===
    CFM_CONFIG_DIR=$6; process_engine OpenResty "$2" "$6/openresty.conf" "$5/nginx.conf" "$5" openresty.service x' sh \
  "$tmp/functions.sh" "$bin_dir/fake-openresty" "$liveA" "$pkgA" "$liveB" "$pkgB" 2>&1)
outB=${out#*===B===}
printf '%s\n' "$outB" | rg -q 'leaving existing sidecars' && ! printf '%s\n' "$outB" | rg -q 'could not be restored' \
  || { echo "FAIL: the second engine's message must not inherit the first one's failed restore" >&2; printf '%s\n' "$out" >&2; exit 1; }

# 22. A .cfm-old copy left by an earlier hard-killed run under the SAME PID is
#     never overwritten: the deploy is refused and the file kept.
pkg="$tmp/pkg-pid"; live="$tmp/live-pid"
mk_pkg "$pkg" "$live"; seed_live "$live"
out=$(PATH="$bin_dir:$PATH" CFM_CONFIG_DIR="$pkg" FAKE_OPENRESTY_ARGS="$tmp/or-pid.args" \
  sh -c '. "$1"; printf "%s\n" precious >"$5/.trusted_proxies.conf.cfm-old.$$"
    process_engine OpenResty "$2" "$3" "$4" "$5" openresty.service x' sh \
  "$tmp/functions.sh" "$bin_dir/fake-openresty" "$pkg/openresty.conf" "$live/nginx.conf" "$live" 2>&1)
kept=$(ls -A "$live" | rg '^\.trusted_proxies\.conf\.cfm-old\.' || true)
[ -n "$kept" ] && [ "$(cat "$live/$kept")" = precious ] || { echo "FAIL: a same-PID .cfm-old copy must be kept" >&2; ls -A "$live" >&2; exit 1; }
[ "$(cat "$live/trusted_proxies.conf")" = "OLD trusted" ] || { echo "FAIL: a same-PID .cfm-old copy must block the deploy" >&2; exit 1; }
printf '%s\n' "$out" | rg -q 'already exists \(from an interrupted earlier run' || { echo "FAIL: the same-PID refusal must be explained" >&2; printf '%s\n' "$out" >&2; exit 1; }

# 23. An engine that passes but lists no files (a dump write that failed
#     silently), or lists only some: nothing deployed - the guard can't see.
pkg="$tmp/pkg-nolist"; live="$tmp/live-nolist"
mk_pkg "$pkg" "$live"; seed_live "$live"; before=$(snapshot "$live")
out=$(PATH="$bin_dir:$PATH" CFM_CONFIG_DIR="$pkg" sh -c '. "$1"; process_engine OpenResty "$2" "$3" "$4" "$5" openresty.service x' sh \
  "$tmp/functions.sh" "$bin_dir/fake-nolist" "$pkg/openresty.conf" "$live/nginx.conf" "$live" 2>&1)
assert_untouched "$live" "$before" "engine that listed no files"
printf '%s\n' "$out" | rg -q 'did not list .*; cannot confirm' || { echo "FAIL: a missing file list must be reported" >&2; printf '%s\n' "$out" >&2; exit 1; }

# 24. An engine without -T (too old): nothing deployed, said plainly.
pkg="$tmp/pkg-old"; live="$tmp/live-old"
mk_pkg "$pkg" "$live"; seed_live "$live"; before=$(snapshot "$live")
out=$(PATH="$bin_dir:$PATH" CFM_CONFIG_DIR="$pkg" sh -c '. "$1"; process_engine OpenResty "$2" "$3" "$4" "$5" openresty.service x' sh \
  "$tmp/functions.sh" "$bin_dir/fake-old" "$pkg/openresty.conf" "$live/nginx.conf" "$live" 2>&1)
assert_untouched "$live" "$before" "engine without -T"
printf '%s\n' "$out" | rg -q 'has no -T option' || { echo "FAIL: an engine without -T must be reported" >&2; printf '%s\n' "$out" >&2; exit 1; }

# 25. Same-PID .cfm-old copies for SEVERAL sidecars: all kept (not only the
#     first one found).
pkg="$tmp/pkg-pid2"; live="$tmp/live-pid2"
mk_pkg "$pkg" "$live"; seed_live "$live"
PATH="$bin_dir:$PATH" CFM_CONFIG_DIR="$pkg" FAKE_OPENRESTY_ARGS="$tmp/or-pid2.args" \
  sh -c '. "$1"; for n in trusted_proxies.conf challenge_waf_bypass.conf; do printf "%s\n" "precious $n" >"$5/.$n.cfm-old.$$"; done
    process_engine OpenResty "$2" "$3" "$4" "$5" openresty.service x' sh \
  "$tmp/functions.sh" "$bin_dir/fake-openresty" "$pkg/openresty.conf" "$live/nginx.conf" "$live" >/dev/null 2>&1
[ "$(ls -A "$live" | rg -c '\.cfm-old\.')" = 2 ] || { echo "FAIL: every same-PID .cfm-old copy must be kept" >&2; ls -A "$live" >&2; exit 1; }

# 26. The run lock: a second run waits, and gives up (no deploy) if the lock
#     stays held.
if command -v flock >/dev/null 2>&1; then
  lk="$tmp/deploy.lock"
  ( flock 8; : >"$lk.held"; exec sleep 30 ) 8>"$lk" &
  holder=$!
  i=0; while [ ! -e "$lk.held" ] && [ "$i" -lt 100 ]; do sleep 0.1; i=$((i + 1)); done
  [ -e "$lk.held" ] || { echo "FAIL: lock holder never took the lock" >&2; kill "$holder" 2>/dev/null; exit 1; }
  rc=0; sh -c '. "$1"; acquire_deploy_lock "$2" 1' sh "$tmp/functions.sh" "$lk" || rc=$?
  if [ "$rc" != 1 ]; then
    echo "FAIL: the lock must not be taken while another run holds it (rc=$rc, want 1)" >&2; kill "$holder" 2>/dev/null; exit 1
  fi
  kill "$holder" 2>/dev/null; wait "$holder" 2>/dev/null || true
  sh -c '. "$1"; acquire_deploy_lock "$2" 1' sh "$tmp/functions.sh" "$lk" \
    || { echo "FAIL: a free lock must be taken" >&2; exit 1; }
fi

# 27. A lock file that cannot be opened: carry on without the lock. exec is a
#     special builtin, so a bare failed "exec 9>" would exit dash right there.
if command -v flock >/dev/null 2>&1; then
  out=$(sh -c '. "$1"; acquire_deploy_lock "$2" 1; echo "still-running rc=$?"' sh "$tmp/functions.sh" "$tmp/functions.sh/no.lock" 2>&1) || true
  case "$out" in
    *"still-running rc=2"*) ;;
    *) echo "FAIL: an unopenable lock file must not end the run: $out" >&2; exit 1 ;;
  esac
fi

# 28. The default lock is in a root-only dir, never world-writable /run/lock
#     (any user could hold it to block every upgrade, or plant a symlink).
rg -q '^CFM_DEPLOY_LOCK=\$\{CFM_DEPLOY_LOCK:-/run/cfm-proxy-config-deploy\.lock\}$' scripts/package-proxy-config-deploy.sh \
  || { echo "FAIL: the default deploy lock must be /run/cfm-proxy-config-deploy.lock" >&2; exit 1; }

# 29. A rollback puts back the very file (same inode, so hard links, xattrs
#     and the SELinux label survive), not a copy of it.
pkg="$tmp/pkg-inode"; live="$tmp/live-inode"
mk_pkg "$pkg" "$live"; seed_live "$live"; ln "$live/trusted_proxies.conf" "$tmp/inode-other-link"
ino=$(stat -c %i "$live/trusted_proxies.conf"); before=$(snapshot "$live")
FAKE_MV_FAIL=/nginx.conf FAKE_MV_ONCE="$tmp/mv-once-29" run_or "$pkg" "$live" >/dev/null
assert_untouched "$live" "$before" "rollback (inode case)"
[ "$(stat -c %i "$live/trusted_proxies.conf")" = "$ino" ] && [ "$(stat -c %h "$live/trusted_proxies.conf")" = 2 ] \
  || { echo "FAIL: a rollback must restore the original file (inode $ino, 2 links), not a copy" >&2; stat "$live/trusted_proxies.conf" >&2; exit 1; }

# 30. A live dir whose path has a sed-special & still deploys (the stage path
#     is the sed replacement). (A space can't work either way: nginx splits an
#     unquoted include on it.)
pkg="$tmp/pkg-amp"; live="$tmp/live&amp"
mk_pkg "$pkg" "$live"; seed_live "$live"
out=$(run_or "$pkg" "$live")
cmp -s "$live/trusted_proxies.conf" "$pkg/trusted_proxies.conf" && cmp -s "$live/nginx.conf" "$pkg/openresty.conf" \
  || { echo "FAIL: a live dir with & in its path must deploy" >&2; printf '%s\n' "$out" >&2; exit 1; }

echo "OK: package proxy deploy helper tests only the main engine configs, with the new sidecars staged; a failed run leaves the live dir untouched"

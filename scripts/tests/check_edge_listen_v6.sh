#!/usr/bin/env bash
# check_edge_listen_v6.sh — the edge's IPv6 listen decision
# (scripts/cfm-edge-listen-v6.sh, docs/edge-ipv6.md).
#
# 1. Parity with the reference confs: in configs/openresty.conf and
#    configs/angie.conf the IPv4 listeners are the ports the script writes
#    ([::]:9080, [::]:9043 ssl + quic), each listener server{} includes its
#    IPv6 file right after its listen lines, through a GLOB (an absent file
#    must mean IPv4 only, not a failed config test), from the conf dir the
#    script writes to for that engine.
# 2. The decision, against a fake /proc/net/if_inet6, a fake ss and a fake
#    engine: auto / on / off / unknown mode, no IPv6 stack, origin not on IPv6
#    (render removes, prestart keeps), a config test that fails with the files
#    (removed again), no engine binary, ss forms, and the exit status (always 0).
# 3. package-proxy-config-deploy.sh deploy_edge_listen_v6: installs the unit and
#    the two drop-ins (systemd reloaded once, not again when unchanged) and runs
#    the script.
set -euo pipefail
cd "$(dirname "$0")/../.."

# A guardrail that cannot run its matcher must FAIL, never report OK.
for tool in awk sed grep sh mktemp; do
  command -v "$tool" >/dev/null 2>&1 || { echo "FAIL: $tool is not installed" >&2; exit 1; }
done

SCRIPT=scripts/cfm-edge-listen-v6.sh
[ -f "$SCRIPT" ] || { echo "FAIL: $SCRIPT missing" >&2; exit 1; }

fails=0
fail() { echo "FAIL: $*" >&2; fails=$((fails + 1)); }
ok() { echo "ok   - $*"; }

# --- 1. parity with the confs ------------------------------------------------
http_port=$(sed -n 's/^V6_HTTP_PORT=\([0-9][0-9]*\)$/\1/p' "$SCRIPT")
https_port=$(sed -n 's/^V6_HTTPS_PORT=\([0-9][0-9]*\)$/\1/p' "$SCRIPT")
[ -n "$http_port" ] && [ -n "$https_port" ] || fail "cannot read V6_HTTP_PORT / V6_HTTPS_PORT from $SCRIPT"

for pair in "configs/openresty.conf|/usr/local/openresty/nginx/conf" "configs/angie.conf|/etc/angie"; do
  conf=${pair%%|*}
  dir=${pair#*|}
  [ -f "$conf" ] || { fail "$conf missing"; continue; }
  # The script's engine table must write to this dir.
  grep -qF "$dir" "$SCRIPT" || fail "$SCRIPT never writes to $dir (the dir $conf includes from)"
  # Each listener server{}: its IPv4 listen lines, then (before the next
  # directive that is not a listen / http2 / http3 / comment / blank) the glob
  # include of its IPv6 file.
  out=$(awk -v hp="$http_port" -v sp="$https_port" -v dir="$dir" '
    function strip(s) { sub(/#.*/, "", s); gsub(/^[ \t]+|[ \t]+$/, "", s); return s }
    {
      l = strip($0)
      if (l == "listen " hp ";") { want = "http"; cnt[want]++; next }
      if (l == "listen " sp " ssl;") { want = "https"; cnt[want]++; next }
      if (want != "") {
        if (l == "" || l ~ /^listen / || l ~ /^http[23] /) next
        wantinc = "include " dir "/cfm-listen-v6-" want ".con[f];"
        if (l == wantinc) { inc[want]++ } else { print "line " NR ": the " want " listener server{} has `" l "` where `" wantinc "` must follow its listen lines" }
        want = ""
      }
      if (l ~ /cfm-listen-v6-/ && l !~ /^include /) print "line " NR ": unexpected reference: " l
      if (l ~ /^include .*cfm-listen-v6-.*\.conf;$/) print "line " NR ": a plain (non-glob) include fails the config test when the file is absent: " l
    }
    END {
      if (cnt["http"] != 1) print "expected exactly one `listen " hp ";` (got " cnt["http"]+0 ")"
      if (cnt["https"] != 1) print "expected exactly one `listen " sp " ssl;` (got " cnt["https"]+0 ")"
      if (inc["http"] != 1) print "the http IPv6 include is missing"
      if (inc["https"] != 1) print "the https IPv6 include is missing"
    }' "$conf")
  if [ -n "$out" ]; then
    while IFS= read -r l; do fail "$conf: $l"; done <<<"$out"
  else
    ok "$conf: listens on $http_port / $https_port and includes the IPv6 files from $dir"
  fi
  # The quic listen the https file mirrors exists in the conf.
  grep -qE "^[[:space:]]*listen ${https_port} quic reuseport;" "$conf" || fail "$conf: no 'listen $https_port quic reuseport;' for the IPv6 file to mirror"
done

# --- 2. the decision -----------------------------------------------------------
tmp=$(mktemp -d)
trap 'rm -rf "$tmp"' EXIT
conf_dir="$tmp/conf"
mkdir -p "$conf_dir" "$tmp/bin"
proc="$tmp/if_inet6"
cfm_conf="$tmp/cfm.conf"

# fake ss: prints $tmp/ss.out, or fails when $tmp/ss.fail exists.
cat >"$tmp/bin/ss" <<EOF
#!/bin/sh
[ -e "$tmp/ss.fail" ] && exit 1
[ "\$1" = "-ltn" ] || exit 2
cat "$tmp/ss.out"
EOF
# fake engine: -t passes unless $tmp/engine.fail ("always") or, with
# "with-v6", only while the IPv6 http file exists.
cat >"$tmp/bin/engine" <<EOF
#!/bin/sh
[ "\$1" = "-t" ] || exit 2
echo "\$*" >> "$tmp/engine.calls"
case "\$(cat "$tmp/engine.fail" 2>/dev/null)" in
  always) exit 1 ;;
  with-v6) [ -e "$conf_dir/cfm-listen-v6-http.conf" ] && exit 1 ;;
esac
exit 0
EOF
chmod 0755 "$tmp/bin/ss" "$tmp/bin/engine"

ss_v6() {
  cat >"$tmp/ss.out" <<'EOF'
State  Recv-Q Send-Q Local Address:Port  Peer Address:PortProcess
LISTEN 0      511          0.0.0.0:80         0.0.0.0:*
LISTEN 0      511          0.0.0.0:443        0.0.0.0:*
LISTEN 0      511             [::]:80            [::]:*
LISTEN 0      511             [::]:443           [::]:*
LISTEN 0      511          0.0.0.0:9043       0.0.0.0:*
EOF
}
ss_v4() {
  cat >"$tmp/ss.out" <<'EOF'
State  Recv-Q Send-Q Local Address:Port  Peer Address:PortProcess
LISTEN 0      511          0.0.0.0:80         0.0.0.0:*
LISTEN 0      511          0.0.0.0:443        0.0.0.0:*
LISTEN 0      511            [::1]:80            [::]:*
LISTEN 0      511 [::ffff:127.0.0.1]:443         [::]:*
LISTEN 0      511             [::]:8080          [::]:*
LISTEN 0      511             [::]:4430          [::]:*
EOF
}

run() { # run ACTION -> output in $tmp/out, exit status checked to be 0
  local rc=0
  CFM_CONF="$cfm_conf" CFM_V6_PROC_FILE="$proc" CFM_SS="$tmp/bin/ss" \
    CFM_EDGE_ENGINES="Test|$tmp/bin/engine|$conf_dir" sh "$SCRIPT" "$@" >"$tmp/out" 2>&1 || rc=$?
  [ "$rc" -eq 0 ] || fail "exit status $rc for '$*' (must always be 0)"
}
present() { [ -f "$conf_dir/cfm-listen-v6-http.conf" ] && [ -f "$conf_dir/cfm-listen-v6-https.conf" ]; }
absent() { [ ! -e "$conf_dir/cfm-listen-v6-http.conf" ] && [ ! -e "$conf_dir/cfm-listen-v6-https.conf" ]; }
expect() { # expect present|absent DESC
  if "$1"; then ok "$2"; else fail "$2 (files $( (present && echo present) || (absent && echo absent) || echo partial)); output: $(cat "$tmp/out")"; fi
}

: >"$proc"
ss_v6
rm -f "$cfm_conf"
run render
expect present "auto (no cfm.conf): kernel IPv6 + origin on [::]:80/443 -> listens"
grep -qxF "listen [::]:$http_port;" "$conf_dir/cfm-listen-v6-http.conf" || fail "http file content: $(cat "$conf_dir/cfm-listen-v6-http.conf")"
grep -qxF "listen [::]:$https_port ssl;" "$conf_dir/cfm-listen-v6-https.conf" || fail "https file lacks the ssl listen"
grep -qxF "listen [::]:$https_port quic reuseport;" "$conf_dir/cfm-listen-v6-https.conf" || fail "https file lacks the quic listen"
grep -q "config test passed" "$tmp/out" || fail "a new file must be proven by the engine test: $(cat "$tmp/out")"
# Listen lines only: check_site_cache_config.sh allows these includes because
# they can carry no cache directive or map.
for f in "$conf_dir"/cfm-listen-v6-*.conf; do
  other=$(grep -vE '^(#.*|listen \[::\]:[0-9]+( ssl| quic reuseport)?;)$' "$f" || true)
  [ -z "$other" ] || fail "$f carries more than listen lines: $other"
done

: >"$tmp/engine.calls"
run render
[ ! -s "$tmp/engine.calls" ] || fail "render with unchanged files ran the engine test again"
grep -q "files unchanged" "$tmp/out" && ok "render: unchanged files are left alone" || fail "unchanged render output: $(cat "$tmp/out")"

ss_v4
run prestart
expect present "prestart: origin not seen on IPv6 (boot order) keeps the files"
grep -q "kept at start" "$tmp/out" || fail "prestart keep message: $(cat "$tmp/out")"
run render
expect absent "render: origin not on IPv6 ([::1], v4-mapped, other ports only) -> removed"
run prestart
expect absent "prestart: origin not on IPv6 and no files -> stays IPv4 only"

ss_v6
printf '# x\nEDGE_LISTEN_V6 = auto\nEDGE_LISTEN_V6 = "off" ; later line wins\n' >"$cfm_conf"
run render
expect absent "EDGE_LISTEN_V6 = \"off\" (last line, quoted, comment) -> IPv4 only"

printf 'EDGE_LISTEN_V6 = On\n' >"$cfm_conf"
ss_v4
run render
expect present "EDGE_LISTEN_V6 = on (any case): kernel IPv6, origin not checked -> listens"

rm -f "$proc"
run prestart
expect absent "no IPv6 stack (if_inet6 absent): prestart removes even kept files"
: >"$proc"

printf 'EDGE_LISTEN_V6 = yes\n' >"$cfm_conf"
ss_v6
run render
expect absent "unknown mode reads as off"
grep -q 'not off/auto/on' "$tmp/out" || fail "unknown mode warning: $(cat "$tmp/out")"

rm -f "$cfm_conf"
ss_v6
: >"$tmp/ss.fail"
run render
expect absent "ss failing -> unknown -> IPv4 only"
rm -f "$tmp/ss.fail"

printf 'with-v6' >"$tmp/engine.fail"
run render
expect absent "config test fails only with the IPv6 files -> removed again"
grep -q 'failed with the IPv6 listens' "$tmp/out" || fail "revert message: $(cat "$tmp/out")"
printf 'always' >"$tmp/engine.fail"
run render
expect absent "config test fails either way -> IPv4 only, not blamed on IPv6"
grep -q 'with or without' "$tmp/out" || fail "either-way message: $(cat "$tmp/out")"
rm -f "$tmp/engine.fail"

run render
expect present "back to a good state"
printf 'with-v6' >"$tmp/engine.fail"
run prestart
expect absent "prestart re-tests kept files and drops them when the test fails"
rm -f "$tmp/engine.fail"

# ss forms that must NOT count, each alone next to a good one: a ::1-only
# listener and a v4-mapped one serve no global IPv6 address.
for bad in '[::1]:80' '[::ffff:127.0.0.1]:80'; do
  printf 'State  Recv-Q Send-Q Local Address:Port  Peer Address:PortProcess\nLISTEN 0 511 %s [::]:*\nLISTEN 0 511 [::]:443 [::]:*\n' "$bad" >"$tmp/ss.out"
  run render
  expect absent "ss: $bad is not an IPv6 origin listener"
done

# ss forms: a dual-stack *:80 and specific IPv6 addresses count.
cat >"$tmp/ss.out" <<'EOF'
State  Recv-Q Send-Q Local Address:Port  Peer Address:PortProcess
LISTEN 0      511                *:80               *:*
LISTEN 0      511  [2001:db8::1]:443             [::]:*
EOF
run render
expect present "ss: *:80 and [2001:db8::1]:443 count as IPv6 origin listeners"

# No engine binary: nothing can prove the files.
rc=0
CFM_CONF="$cfm_conf" CFM_V6_PROC_FILE="$proc" CFM_SS="$tmp/bin/ss" \
  CFM_EDGE_ENGINES="Test|$tmp/bin/none|$conf_dir" sh "$SCRIPT" render >"$tmp/out" 2>&1 || rc=$?
[ "$rc" -eq 0 ] || fail "exit $rc without an engine binary"
rm -f "$conf_dir"/cfm-listen-v6-*.conf
CFM_CONF="$cfm_conf" CFM_V6_PROC_FILE="$proc" CFM_SS="$tmp/bin/ss" \
  CFM_EDGE_ENGINES="Test|$tmp/bin/none|$conf_dir" sh "$SCRIPT" render >"$tmp/out" 2>&1 || true
expect absent "no engine binary to test with -> IPv4 only"

run status
expect absent "status changes nothing"
grep -q 'wants IPv6' "$tmp/out" || fail "status output: $(cat "$tmp/out")"
run bogus-action
ok "an unknown action exits 0"

# Missing conf dir: skipped, exit 0.
rc=0
CFM_CONF="$cfm_conf" CFM_V6_PROC_FILE="$proc" CFM_SS="$tmp/bin/ss" \
  CFM_EDGE_ENGINES="Test|$tmp/bin/engine|$tmp/nope" sh "$SCRIPT" render >"$tmp/out" 2>&1 || rc=$?
[ "$rc" -eq 0 ] && [ ! -e "$tmp/nope" ] && ok "missing conf dir: skipped" || fail "missing conf dir: rc=$rc"

# --- 3. package deploy hook ----------------------------------------------------
awk '/^deploy_logrotate_config$/{exit} {print}' scripts/package-proxy-config-deploy.sh >"$tmp/functions.sh"
grep -q '^deploy_edge_listen_v6()' "$tmp/functions.sh" || fail "deploy_edge_listen_v6 is not defined before the first top-level call"
grep -qxF 'deploy_edge_listen_v6' scripts/package-proxy-config-deploy.sh || fail "package-proxy-config-deploy.sh never calls deploy_edge_listen_v6"
units="$tmp/units"
cat >"$tmp/bin/systemctl" <<EOF
#!/bin/sh
echo "\$*" >> "$tmp/systemctl.calls"
EOF
chmod 0755 "$tmp/bin/systemctl"
rm -f "$conf_dir"/cfm-listen-v6-*.conf
: >"$tmp/systemctl.calls"
deploy() {
  CFM_CONFIG_DIR="$PWD/configs" CFM_SYSTEMD_UNIT_DIR="$units" CFM_SYSTEMCTL="$tmp/bin/systemctl" \
    CFM_EDGE_LISTEN_V6_SCRIPT="$PWD/$SCRIPT" CFM_CONF="$cfm_conf" CFM_V6_PROC_FILE="$proc" \
    CFM_SS="$tmp/bin/ss" CFM_EDGE_ENGINES="Test|$tmp/bin/engine|$conf_dir" \
    bash -c '. "$1"; deploy_edge_listen_v6' sh "$tmp/functions.sh" >"$tmp/out" 2>&1
}
deploy
for f in cfm-edge-listen-v6.service openresty.service.d/cfm-listen-v6.conf angie.service.d/cfm-listen-v6.conf; do
  [ -f "$units/$f" ] || fail "deploy did not install $units/$f"
done
cmp -s configs/cfm-edge-listen-v6.service "$units/cfm-edge-listen-v6.service" || fail "unit content differs"
cmp -s configs/cfm-edge-listen-v6-dropin.conf "$units/openresty.service.d/cfm-listen-v6.conf" || fail "drop-in content differs"
[ "$(grep -c daemon-reload "$tmp/systemctl.calls")" -eq 1 ] || fail "daemon-reload count after first deploy: $(cat "$tmp/systemctl.calls")"
expect present "deploy runs the script (render)"
deploy
[ "$(grep -c daemon-reload "$tmp/systemctl.calls")" -eq 1 ] && ok "unchanged units: no second daemon-reload" || fail "daemon-reload ran again for unchanged units"

# The unit runs prestart, ignores failure, and the drop-in is Wants + After.
grep -qxF 'ExecStart=-/bin/sh /usr/share/cfm/scripts/cfm-edge-listen-v6.sh prestart' configs/cfm-edge-listen-v6.service || fail "unit ExecStart"
grep -qxF 'Type=oneshot' configs/cfm-edge-listen-v6.service || fail "unit Type"
grep -q '^\[Install\]' configs/cfm-edge-listen-v6.service && fail "the unit must have no [Install] (only the edge pulls it in)"
grep -qxF 'Wants=cfm-edge-listen-v6.service' configs/cfm-edge-listen-v6-dropin.conf || fail "drop-in Wants"
grep -qxF 'After=cfm-edge-listen-v6.service' configs/cfm-edge-listen-v6-dropin.conf || fail "drop-in After"
grep -q '^Requires=' configs/cfm-edge-listen-v6-dropin.conf && fail "drop-in must not Require (the edge must start if the unit fails)"

if [ "$fails" -ne 0 ]; then
  echo "[edge-listen-v6] FAILED: $fails check(s)" >&2
  exit 1
fi
echo "[edge-listen-v6] OK: confs and script agree on ports/includes; the decision (auto/on/off, no IPv6 stack, origin, failed test, prestart keep) and the deploy hook behave."

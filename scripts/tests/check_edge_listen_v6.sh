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

# The default is the same in the script (no key = ...) and the reference cfm.conf.
sdef=$(sed -n 's/^        "") echo \([a-z]*\) ;;$/\1/p' "$SCRIPT")
cdef=$(sed -n 's/^EDGE_LISTEN_V6 = \([a-z]*\)$/\1/p' configs/cfm.conf)
if [ -n "$sdef" ] && [ "$sdef" = "$cdef" ]; then ok "default EDGE_LISTEN_V6 = $sdef in the script and configs/cfm.conf"; else fail "default differs: script '$sdef', configs/cfm.conf '$cdef'"; fi

# --- 2. the decision -----------------------------------------------------------
tmp=$(mktemp -d)
trap 'rm -rf "$tmp"' EXIT
conf_dir="$tmp/conf"
mkdir -p "$conf_dir" "$tmp/bin"
main_conf="$conf_dir/nginx.conf"
printf 'http {\n  server {\n    listen 9080;\n    include %s/cfm-listen-v6-http.con[f];\n  }\n}\n' "$conf_dir" >"$main_conf"
proc="$tmp/if_inet6"
cfm_conf="$tmp/cfm.conf"

# fake ss: `-lntp` prints $tmp/ss.tcp, `-lnup` $tmp/ss.udp; fails when
# $tmp/ss.fail exists.
cat >"$tmp/bin/ss" <<EOF
#!/bin/sh
[ -e "$tmp/ss.fail" ] && exit 1
case "\$1" in
  -lntp) cat "$tmp/ss.tcp" ;;
  -lnup) cat "$tmp/ss.udp" 2>/dev/null; exit 0 ;;
  *) exit 2 ;;
esac
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
# fake cfm: `realip --json` answers from $tmp/realip ("trusted", "untrusted",
# anything else = no verdict); it records whether the IPv6 files existed when
# it was asked (the trust must be read WITH them in place).
cat >"$tmp/bin/cfm" <<EOF
#!/bin/sh
[ "\$1 \$2" = "realip --json" ] || exit 2
[ -e "$conf_dir/cfm-listen-v6-http.conf" ] && echo files >> "$tmp/realip.calls" || echo nofiles >> "$tmp/realip.calls"
case "\$(cat "$tmp/realip" 2>/dev/null)" in
  trusted) echo '{"edge_active":true,"ok":true,"probe":{"panel":"cpanel","stack":"apache","trusted":true,"edge_ipv6":true}}' ;;
  untrusted) echo '{"edge_active":true,"ok":false,"probe":{"panel":"cpanel","stack":"apache","trusted":false,"edge_ipv6":true}}'; exit 1 ;;
  *) echo 'garbage' ;;
esac
EOF
chmod 0755 "$tmp/bin/ss" "$tmp/bin/engine" "$tmp/bin/cfm"

hdr='State  Recv-Q Send-Q Local Address:Port  Peer Address:PortProcess'
ss_v6() { # origin on [::]:80/443, the edge on IPv4 (and its own IPv6) only
  printf '%s\n' "$hdr" \
    'LISTEN 0 511 0.0.0.0:80 0.0.0.0:* users:(("httpd",pid=10,fd=3))' \
    'LISTEN 0 511 [::]:80 [::]:* users:(("httpd",pid=10,fd=4))' \
    'LISTEN 0 511 [::]:443 [::]:* users:(("httpd",pid=10,fd=5))' \
    'LISTEN 0 511 0.0.0.0:9043 0.0.0.0:* users:(("nginx",pid=20,fd=6))' \
    'LISTEN 0 511 [::]:9043 [::]:* users:(("nginx",pid=20,fd=7))' >"$tmp/ss.tcp"
  printf '%s\n' 'State Recv-Q Send-Q Local Address:Port Peer Address:PortProcess' \
    'UNCONN 0 0 [::]:9043 [::]:* users:(("nginx",pid=20,fd=8))' >"$tmp/ss.udp"
}
ss_v4() { # origin on IPv4 only (+ ::1, v4-mapped and other ports, which do not count)
  printf '%s\n' "$hdr" \
    'LISTEN 0 511 0.0.0.0:80 0.0.0.0:* users:(("httpd",pid=10,fd=3))' \
    'LISTEN 0 511 0.0.0.0:443 0.0.0.0:* users:(("httpd",pid=10,fd=4))' \
    'LISTEN 0 511 [::1]:80 [::]:* users:(("httpd",pid=10,fd=5))' \
    'LISTEN 0 511 [::ffff:127.0.0.1]:443 [::]:* users:(("httpd",pid=10,fd=6))' \
    'LISTEN 0 511 [::]:8080 [::]:* users:(("httpd",pid=10,fd=7))' >"$tmp/ss.tcp"
  : >"$tmp/ss.udp"
}

ENGINES="Test|$tmp/bin/engine|$conf_dir|$main_conf"
run() { # run ACTION -> output in $tmp/out, exit status checked to be 0
  local rc=0
  CFM_CONF="$cfm_conf" CFM_V6_PROC_FILE="$proc" CFM_SS="$tmp/bin/ss" CFM_BIN="$tmp/bin/cfm" \
    CFM_EDGE_ENGINES="$ENGINES" sh "$SCRIPT" "$@" >"$tmp/out" 2>&1 || rc=$?
  [ "$rc" -eq 0 ] || fail "exit status $rc for '$*' (must always be 0)"
}
present() { [ -f "$conf_dir/cfm-listen-v6-http.conf" ] && [ -f "$conf_dir/cfm-listen-v6-https.conf" ]; }
absent() { [ ! -e "$conf_dir/cfm-listen-v6-http.conf" ] && [ ! -e "$conf_dir/cfm-listen-v6-https.conf" ]; }
expect() { # expect present|absent DESC
  if "$1"; then ok "$2"; else fail "$2 (files $( (present && echo present) || (absent && echo absent) || echo partial)); output: $(cat "$tmp/out")"; fi
}
says() { grep -q -- "$1" "$tmp/out" || fail "expected '$1' in: $(cat "$tmp/out")"; }

: >"$proc"
ss_v6
printf 'trusted' >"$tmp/realip"
rm -f "$cfm_conf"
run render
expect absent "no EDGE_LISTEN_V6 in cfm.conf -> off (the default)"

printf 'EDGE_LISTEN_V6=auto\r\n' >"$cfm_conf"
run render
expect present "EDGE_LISTEN_V6=auto with CRLF line ending (no spaces) reads as auto"
rm -f "$conf_dir"/cfm-listen-v6-*.conf
printf 'EDGE_LISTEN_V6=auto\n' >"$cfm_conf"
: >"$tmp/realip.calls"
run render
expect present "auto: kernel IPv6, ports free, origin on [::]:80/443, ::1 trusted -> listens"
grep -qx files "$tmp/realip.calls" || fail "cfm realip must be asked with the IPv6 files in place: $(cat "$tmp/realip.calls")"
grep -qxF "listen [::]:$http_port;" "$conf_dir/cfm-listen-v6-http.conf" || fail "http file content: $(cat "$conf_dir/cfm-listen-v6-http.conf")"
grep -qxF "listen [::]:$https_port ssl;" "$conf_dir/cfm-listen-v6-https.conf" || fail "https file lacks the ssl listen"
grep -qxF "listen [::]:$https_port quic reuseport;" "$conf_dir/cfm-listen-v6-https.conf" || fail "https file lacks the quic listen"
says "config test passed"
# Listen lines only: check_site_cache_config.sh allows these includes because
# they can carry no cache directive or map.
for f in "$conf_dir"/cfm-listen-v6-*.conf; do
  other=$(grep -vE '^(#.*|listen \[::\]:[0-9]+( ssl| quic reuseport)?;)$' "$f" || true)
  [ -z "$other" ] || fail "$f carries more than listen lines: $other"
done

: >"$tmp/engine.calls"
run render
[ ! -s "$tmp/engine.calls" ] || fail "render with unchanged files ran the engine test again"
says "files unchanged"
ok "render: unchanged files are left alone (the edge's own [::]:9043 does not count as taken)"

printf 'untrusted' >"$tmp/realip"
run render
expect absent "auto: the origin does not trust ::1 -> removed (IPv6 visitors would be localhost)"
says "cfm realip fix"
printf 'garbage' >"$tmp/realip"
run render
expect absent "auto: cfm realip gives no verdict -> IPv4 only"
printf 'trusted' >"$tmp/realip"
run render
expect present "back on"
rc=0
CFM_CONF="$cfm_conf" CFM_V6_PROC_FILE="$proc" CFM_SS="$tmp/bin/ss" CFM_BIN="$tmp/bin/no-cfm" \
  CFM_EDGE_ENGINES="$ENGINES" sh "$SCRIPT" prestart >"$tmp/out" 2>&1 || rc=$?
[ "$rc" -eq 0 ] || fail "exit $rc without cfm"
expect absent "auto: no cfm binary to ask -> IPv4 only, even at start"
run render

# A taken IPv6 edge port (nginx -t does not bind): never listen.
ss_v6
printf '%s\n' 'LISTEN 0 100 *:9080 *:* users:(("java",pid=30,fd=9))' >>"$tmp/ss.tcp"
run render
expect absent "a non-edge listener on *:9080 -> IPv4 only (the edge start would fail)"
says "held by java"
ss_v6
printf '%s\n' 'UNCONN 0 0 [::]:9043 [::]:* users:(("someudp",pid=31,fd=3))' >>"$tmp/ss.udp"
run prestart
expect absent "a non-edge UDP listener on [::]:9043 -> IPv4 only"
ss_v6
printf '%s\n' 'LISTEN 0 100 [::]:9043 [::]:*' >>"$tmp/ss.tcp"
run render
expect absent "an IPv6 listener on 9043 with no owner shown -> treated as taken"
ss_v6
run render
expect present "ports free again -> listens"

ss_v4
run prestart
expect present "prestart: ss ran and showed no IPv6 origin (boot order) -> keeps the files"
says "kept at start"
run render
expect absent "render: origin not on IPv6 ([::1], v4-mapped, other ports only) -> removed"
run prestart
expect absent "prestart: origin not on IPv6 and no files -> stays IPv4 only"

ss_v6
run render
expect present "back on"
: >"$tmp/ss.fail"
run prestart
expect absent "prestart: ss failing is an unknown, not 'origin not up yet' -> removed"
rm -f "$tmp/ss.fail"

printf 'EDGE_LISTEN_V6 = auto\nEDGE_LISTEN_V6 = "off" ; later line wins\n' >"$cfm_conf"
run render
expect absent "EDGE_LISTEN_V6 = \"off\" (last line, quoted, comment) -> IPv4 only"

printf 'EDGE_LISTEN_V6 = On\n' >"$cfm_conf"
ss_v4
printf 'untrusted' >"$tmp/realip"
run render
expect present "on (any case): origin and trust not required"
says "does not trust ::1"
printf 'trusted' >"$tmp/realip"

rm -f "$proc"
run prestart
expect absent "no IPv6 stack (if_inet6 absent): prestart removes even kept files"
: >"$proc"

printf 'EDGE_LISTEN_V6 = yes\n' >"$cfm_conf"
ss_v6
run render
expect absent "unknown mode reads as off"
says 'not off/auto/on'

printf 'EDGE_LISTEN_V6 = auto\n' >"$cfm_conf"
printf 'with-v6' >"$tmp/engine.fail"
run render
expect absent "config test fails only with the IPv6 files -> removed again"
says 'failed with the IPv6 listens'
printf 'always' >"$tmp/engine.fail"
run render
expect absent "config test fails either way -> IPv4 only, not blamed on IPv6"
says 'with or without'
rm -f "$tmp/engine.fail"

run render
expect present "back to a good state"
printf 'with-v6' >"$tmp/engine.fail"
run prestart
expect absent "prestart re-tests kept files and drops them when the test fails"
rm -f "$tmp/engine.fail"

# ss forms: a dual-stack *:80 and a specific IPv6 address count; ::1-only and
# v4-mapped do not, each alone next to a good one.
printf '%s\n' "$hdr" 'LISTEN 0 511 *:80 *:* users:(("httpd",pid=1,fd=3))' \
  'LISTEN 0 511 [2001:db8::1]:443 [::]:* users:(("httpd",pid=1,fd=4))' >"$tmp/ss.tcp"
: >"$tmp/ss.udp"
run render
expect present "ss: *:80 and [2001:db8::1]:443 count as IPv6 origin listeners"
for bad in '[::1]:80' '[::ffff:127.0.0.1]:80'; do
  printf '%s\n' "$hdr" "LISTEN 0 511 $bad [::]:* users:((\"httpd\",pid=1,fd=3))" \
    'LISTEN 0 511 [::]:443 [::]:* users:(("httpd",pid=1,fd=4))' >"$tmp/ss.tcp"
  run render
  expect absent "ss: $bad is not an IPv6 origin listener"
done
ss_v6

# The live main config must include the files, or they listen nowhere.
run render
expect present "back on"
cp "$main_conf" "$tmp/main.bak"
printf 'http { server { listen 9080; } }\n' >"$main_conf"
run render
expect absent "main config without the include (old conf / refused deploy) -> removed"
says 'does not include'
printf 'http { server { listen 9080; # include %s/cfm-listen-v6-http.con[f];\n } }\n' "$conf_dir" >"$main_conf"
run render
expect absent "a commented-out include does not count"
cp "$tmp/main.bak" "$main_conf"

# No engine binary: nothing can prove new files.
rm -f "$conf_dir"/cfm-listen-v6-*.conf
CFM_CONF="$cfm_conf" CFM_V6_PROC_FILE="$proc" CFM_SS="$tmp/bin/ss" CFM_BIN="$tmp/bin/cfm" \
  CFM_EDGE_ENGINES="Test|$tmp/bin/none|$conf_dir|$main_conf" sh "$SCRIPT" render >"$tmp/out" 2>&1 || fail "exit status without an engine binary"
expect absent "no engine binary to test with -> IPv4 only"

run status
expect absent "status changes nothing"
says 'wants IPv6'
run bogus-action
ok "an unknown action exits 0"

rc=0
CFM_CONF="$cfm_conf" CFM_V6_PROC_FILE="$proc" CFM_SS="$tmp/bin/ss" CFM_BIN="$tmp/bin/cfm" \
  CFM_EDGE_ENGINES="Test|$tmp/bin/engine|$tmp/nope|$tmp/nope/nginx.conf" sh "$SCRIPT" render >"$tmp/out" 2>&1 || rc=$?
[ "$rc" -eq 0 ] && [ ! -e "$tmp/nope" ] && ok "missing conf dir: skipped" || fail "missing conf dir: rc=$rc"

# The default engine table points at each engine's real main config.
grep -qF "'OpenResty|%s|%s|%s\\n' \"\$e_bin\" /usr/local/openresty/nginx/conf /usr/local/openresty/nginx/conf/nginx.conf" "$SCRIPT" || fail "OpenResty engine row"
grep -qF "'Angie|%s|%s|%s\\n' \"\$e_bin\" /etc/angie /etc/angie/angie.conf" "$SCRIPT" || fail "Angie engine row"

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
    CFM_SS="$tmp/bin/ss" CFM_BIN="$tmp/bin/cfm" CFM_EDGE_ENGINES="$ENGINES" \
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

# Package removal (not upgrade) removes the units, the drop-ins and the
# generated files, so a leftover IPv6 listen never outlives its guard.
for pkg in packaging/debian/DEBIAN/postrm packaging/rpm/SPECS/cfm.spec; do
  for f in /etc/systemd/system/cfm-edge-listen-v6.service \
    /etc/systemd/system/openresty.service.d/cfm-listen-v6.conf \
    /etc/systemd/system/angie.service.d/cfm-listen-v6.conf \
    /usr/local/openresty/nginx/conf/cfm-listen-v6-http.conf /usr/local/openresty/nginx/conf/cfm-listen-v6-https.conf \
    /etc/angie/cfm-listen-v6-http.conf /etc/angie/cfm-listen-v6-https.conf; do
    grep -qE "^[[:space:]]*(rm -f )?$(printf '%s' "$f" | sed 's/[.]/\\./g')( \\\\)?( \\|\\| true)?$" "$pkg" \
      || fail "$pkg does not remove $f on package removal"
  done
done

if [ "$fails" -ne 0 ]; then
  echo "[edge-listen-v6] FAILED: $fails check(s)" >&2
  exit 1
fi
echo "[edge-listen-v6] OK: confs and script agree on ports/includes; the decision (off default, auto/on, IPv6 stack, taken ports, origin, ::1 trust, main-conf include, failed test, prestart keep), the deploy hook and package removal behave."

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
# 2. The decision, against a fake /proc/net/if_inet6, /proc/net/tcp6 + udp6,
#    ss, systemctl and engine: the default (off until IPv6 /64 grouping) and
#    EDGE_LISTEN_V6 (read as Go reads it: scripts/tests/fixtures/
#    edge_listen_v6_mode.txt), no IPv6 stack, taken ports (by kernel uid),
#    origin not on IPv6 (render removes, prestart keeps), the ::1 trust, a
#    config test that fails with the files (removed again), the reload and
#    listen check after a render, no engine binary, ss forms, the exit
#    status (always 0), and the empty logs cfm-edge's config test creates
#    (removed again unless cfm-edge may run).
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

for pair in "configs/openresty.conf|/usr/local/openresty/nginx/conf" "configs/angie.conf|/etc/angie" "configs/cfm-edge.conf|/etc/cfm-edge"; do
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

# The default (no EDGE_LISTEN_V6 in cfm.conf) is ONE switch on each side:
# the script's V6_DEFAULT and Go's edgeIPv6Default (internal/originrealip),
# off/false until IPv6 /64 grouping lands, then auto/true together. The
# reference cfm.conf sets no active key and carries the opposite of the
# default commented out (the opt-in now, the kill switch later).
sdef=$(sed -n 's/^V6_DEFAULT=\([a-z]*\)$/\1/p' "$SCRIPT")
gdef=$(sed -n 's/^const edgeIPv6Default = \([a-z]*\)$/\1/p' internal/originrealip/probe.go)
case "$sdef/$gdef" in
  off/false) want_commented='# EDGE_LISTEN_V6 = on' ;;
  auto/true) want_commented='# EDGE_LISTEN_V6 = off' ;;
  *) want_commented=''; fail "V6_DEFAULT ('$sdef', $SCRIPT) and edgeIPv6Default ('$gdef', probe.go) disagree or are missing" ;;
esac
if [ -n "$want_commented" ]; then
  ok "default: V6_DEFAULT=$sdef, edgeIPv6Default=$gdef"
  grep -qxF "$want_commented" configs/cfm.conf || fail "configs/cfm.conf: '$want_commented' (commented) is missing"
fi
if grep -qE '^[[:space:]]*EDGE_LISTEN_V6[[:space:]]*=' configs/cfm.conf; then
  fail "configs/cfm.conf sets EDGE_LISTEN_V6 (it must stay commented: the default lives in the code)"
else
  ok "configs/cfm.conf: no active EDGE_LISTEN_V6 line"
fi

# The EDGE_LISTEN_V6 reading: the same fixture Go's TestEdgeListenV6ModeFixture
# runs, so the script and `cfm realip` can never read a value differently.
fx=scripts/tests/fixtures/edge_listen_v6_mode.txt
[ -f "$fx" ] || fail "$fx missing"
fxdir=$(mktemp -d)
nfx=0
while IFS= read -r fxl; do
  case $fxl in '#'* | '') continue ;; esac
  fx_want=${fxl%%	*}
  fx_body=${fxl#*	}
  [ "$fx_want" = default ] && fx_want=$sdef
  [ "$fx_want" = on ] && fx_want=auto
  printf '%b\n' "$fx_body" >"$fxdir/cfm.conf"
  fx_got=$(CFM_CONF="$fxdir/cfm.conf" sh "$SCRIPT" mode 2>/dev/null)
  nfx=$((nfx + 1))
  [ "$fx_got" = "$fx_want" ] || fail "mode for $(printf '%s' "$fx_body"): got '$fx_got', want '$fx_want'"
done <"$fx"
rm -f "$fxdir/cfm.conf"; rmdir "$fxdir"
[ "$nfx" -ge 20 ] && ok "EDGE_LISTEN_V6 reading: $nfx fixture cases" || fail "only $nfx fixture cases read from $fx"

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
# "trusted-old" = a cfm without the IPv6 pass, anything else = no verdict), in
# the exact shape internal/originrealip runCLI prints; it records whether the
# IPv6 files existed when it was asked (they must NOT: the trust is decided
# before they are written, so no reload can catch an untrusting origin).
cat >"$tmp/bin/cfm" <<EOF
#!/bin/sh
if [ "\$1 \$2" = "realip v6-bindcheck" ]; then
  shift 2
  echo "\$*" >> "$tmp/bind.calls"
  case "\$(cat "$tmp/bind" 2>/dev/null)" in
    taken) echo "IPv6 tcp port 9080 is taken: bind: address already in use"; exit 1 ;;
    old) echo 'unknown subcommand "v6-bindcheck"'; exit 2 ;;
    *) echo ok; exit 0 ;;
  esac
fi
[ "\$1 \$2" = "realip --json" ] || exit 2
[ -e "$conf_dir/cfm-listen-v6-http.conf" ] && echo files >> "$tmp/realip.calls" || echo nofiles >> "$tmp/realip.calls"
case "\$(cat "$tmp/realip" 2>/dev/null)" in
  trusted) echo '{"edge_active":true,"ok":true,"probe":{"panel":"cpanel","stack":"apache","trusted":true,"directive":"RemoteIP{Internal,Trusted}Proxy 127.0.0.1","edge_ipv6":true}}' ;;
  untrusted) echo '{"edge_active":true,"ok":false,"probe":{"panel":"cpanel","stack":"apache","trusted":false,"note":"x","edge_ipv6":true}}'; exit 1 ;;
  trusted-old) echo '{"edge_active":true,"ok":true,"probe":{"panel":"cpanel","stack":"apache","trusted":true}}' ;;
  *) echo 'garbage' ;;
esac
EOF
chmod 0755 "$tmp/bin/ss" "$tmp/bin/engine" "$tmp/bin/cfm"

# /proc/net/if_inet6 with a global address (scope 00), as on qualityweb.
v6_global() {
  printf '%s\n' 'fe80000000000000e6434bfffe54ef2f 05 40 20 80     eno4' \
    '2a14428000010001e6434bfffe54ef2f 05 40 00 00     eno4' \
    '00000000000000000000000000000001 01 80 10 80       lo' >"$proc"
}
# fake /proc/net/tcp6 and udp6 (the edge's ports are judged from the kernel's
# uid column, never from the names ss prints): p6 FILE ADDR PORT STATE UID.
mkdir -p "$tmp/proc/net"
p6h='  sl  local_address                         remote_address                        st tx_queue rx_queue tr tm->when retrnsmt   uid  timeout inode'
any6=00000000000000000000000000000000
lo6=00000000000000000000000001000000
p6() {
  printf '   0: %s:%04X 00000000000000000000000000000000:0000 %s 00000000:00000000 00:00000000 00000000 %5s        0 4242 1 0000000000000000 100 0 0 10 0\n' \
    "$2" "$3" "$4" "$5" >>"$tmp/proc/net/$1"
}
proc_edge() { # the edge (root) on its own [::]:9043 tcp + udp, the origin on [::]:80
  printf '%s\n' "$p6h" >"$tmp/proc/net/tcp6"
  printf '%s\n' "$p6h" >"$tmp/proc/net/udp6"
  p6 tcp6 $any6 9043 0A 0
  p6 tcp6 $any6 80 0A 0
  p6 udp6 $any6 9043 07 0
  # connections the edge accepted on its [::]:9043: owned by the WORKER that
  # accepted them (speedhost: uid 969), not by root
  p6 tcp6 2A144280000100010000000000000002 9043 01 969
  p6 tcp6 2A144280000100010000000000000002 9043 06 0
}
# fake systemctl for the edge unit: is-active while $tmp/edge.active exists;
# reload fails with $tmp/reload.fail, and with $tmp/reload.listens (and the
# IPv6 files written) the "edge" then listens on [::]:9080 and [::]:9043.
cat >"$tmp/bin/edgectl" <<EOF
#!/bin/sh
echo "\$*" >> "$tmp/edgectl.calls"
case "\$1" in
  is-active)
    # cfm-edge's state as \`systemctl is-active cfm-edge.service\` prints it
    # (\$tmp/cfmedge.state, default inactive): the log cleanup reads it.
    if [ "\$2" = cfm-edge.service ]; then
      st=\$(cat "$tmp/cfmedge.state" 2>/dev/null || echo inactive)
      echo "\$st"; [ "\$st" = active ]; exit
    fi
    [ -e "$tmp/edge.active" ] ;;
  reload)
    [ -e "$tmp/reload.fail" ] && exit 1
    if [ -e "$tmp/reload.listens" ] && [ -e "$conf_dir/cfm-listen-v6-http.conf" ]; then
      printf '   1: $any6:2378 $any6:0000 0A 00000000:00000000 00:00000000 00000000     0        0 1 1\n' >>"$tmp/proc/net/tcp6"
    fi
    exit 0 ;;
  *) exit 2 ;;
esac
EOF
chmod 0755 "$tmp/bin/edgectl"
export CFM_SYSTEMCTL="$tmp/bin/edgectl" CFM_V6_CONFIRM_TRIES=1
hdr='State  Recv-Q Send-Q Local Address:Port  Peer Address:PortProcess'
ss_v6() { # origin on [::]:80/443, the edge on IPv4 (and its own IPv6) only
  proc_edge
  printf '%s\n' "$hdr" \
    'LISTEN 0 511 0.0.0.0:80 0.0.0.0:* users:(("httpd",pid=10,fd=3))' \
    'LISTEN 0 511 [::]:80 [::]:* users:(("httpd",pid=10,fd=4))' \
    'LISTEN 0 511 [::]:443 [::]:* users:(("httpd",pid=10,fd=5))' \
    'LISTEN 0 511 0.0.0.0:9043 0.0.0.0:* users:(("nginx",pid=20,fd=6))' \
    'LISTEN 0 511 [::]:9043 [::]:* users:(("nginx",pid=21,fd=7),("nginx",pid=20,fd=7))' >"$tmp/ss.tcp"
  printf '%s\n' 'State Recv-Q Send-Q Local Address:Port Peer Address:PortProcess' \
    'UNCONN 0 0 [::]:9043 [::]:* users:(("nginx",pid=20,fd=8))' >"$tmp/ss.udp"
}
ss_v4() { # origin on IPv4 only (+ ::1, v4-mapped and other ports, which do not count)
  proc_edge
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
  CFM_CONF="$cfm_conf" CFM_V6_PROC_FILE="$proc" CFM_PROC_ROOT="$tmp/proc" CFM_SS="$tmp/bin/ss" CFM_BIN="$tmp/bin/cfm" \
    CFM_EDGE_ENGINES="$ENGINES" sh "$SCRIPT" "$@" >"$tmp/out" 2>&1 || rc=$?
  [ "$rc" -eq 0 ] || fail "exit status $rc for '$*' (must always be 0)"
}
present() { [ -f "$conf_dir/cfm-listen-v6-http.conf" ] && [ -f "$conf_dir/cfm-listen-v6-https.conf" ]; }
absent() { [ ! -e "$conf_dir/cfm-listen-v6-http.conf" ] && [ ! -e "$conf_dir/cfm-listen-v6-https.conf" ]; }
expect() { # expect present|absent DESC
  if "$1"; then ok "$2"; else fail "$2 (files $( (present && echo present) || (absent && echo absent) || echo partial)); output: $(cat "$tmp/out")"; fi
}
says() { grep -q -- "$1" "$tmp/out" || fail "expected '$1' in: $(cat "$tmp/out")"; }

v6_global
ss_v6
printf 'trusted' >"$tmp/realip"
printf 'EDGE_LISTEN_V6=off\r\n' >"$cfm_conf"
run render
expect absent "EDGE_LISTEN_V6=off with a CRLF line ending (no spaces) -> IPv4 only"
cp configs/cfm.conf "$cfm_conf"
run render
expect absent "the reference cfm.conf (nothing set): V6_DEFAULT=off until /64 grouping -> IPv4 only"
says "EDGE_LISTEN_V6 is off"
printf 'EDGE_LISTEN_V6 = on\n' >"$cfm_conf"
: >"$tmp/realip.calls"
run render
expect present "EDGE_LISTEN_V6 = on: kernel IPv6, ports free, origin on [::]:80/443, ::1 trusted -> listens"
[ "$(cat "$tmp/realip.calls")" = nofiles ] || fail "cfm realip must be asked BEFORE the IPv6 files are written: $(cat "$tmp/realip.calls")"
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
expect absent "on: the origin does not trust ::1 -> removed (IPv6 visitors would be localhost)"
says "cfm realip fix"
printf 'garbage' >"$tmp/realip"
run render
expect absent "on: cfm realip gives no verdict -> IPv4 only"
printf 'trusted-old' >"$tmp/realip"
run render
expect absent "on: a trusted verdict without edge_ipv6 (a cfm unaware of the IPv6 hop) -> IPv4 only"
rm -f "$conf_dir"/cfm-listen-v6-*.conf
: >"$tmp/realip.calls"
printf 'untrusted' >"$tmp/realip"
run render
grep -qx files "$tmp/realip.calls" && fail "an untrusting origin must never see the IPv6 files written (reload window)"
expect absent "untrusted: nothing was written"
printf 'trusted' >"$tmp/realip"
run render
expect present "back on"
printf 'garbage' >"$tmp/realip"
run prestart
expect present "prestart: cfm realip gives no verdict at start (boot) -> keeps files a render approved"
says "gave no verdict at start"
printf 'untrusted' >"$tmp/realip"
run prestart
expect absent "prestart: a definite untrusted verdict removes approved files (not readiness: IPv6 visitors would be ::1 to the origin)"
says "does not trust"
rm -f "$conf_dir"/cfm-listen-v6-*.conf
run prestart
expect absent "prestart: untrusted and no approved files -> nothing written"
printf 'trusted' >"$tmp/realip"
CFM_CONF="$cfm_conf" CFM_V6_PROC_FILE="$proc" CFM_PROC_ROOT="$tmp/proc" CFM_SS="$tmp/bin/ss" CFM_BIN="$tmp/bin/no-cfm" \
  CFM_EDGE_ENGINES="$ENGINES" sh "$SCRIPT" render >"$tmp/out" 2>&1 || true
expect absent "render: no cfm binary to ask -> IPv4 only"
run render

# A taken IPv6 edge port (nginx -t ignores a port in use): never listen. Judged from
# the kernel's socket uid (/proc/net/tcp6, udp6), never from ss's names.
ss_v6
p6 tcp6 $any6 9080 0A 1001
run render
expect absent "a tenant socket (uid 1001) listening on [::]:9080 -> taken (the edge start would fail)"
says "uid 1001"
run prestart
expect absent "the same at start"
ss_v6
p6 tcp6 $lo6 9080 0A 1001
run render
expect absent "a tenant on [::1]:9080 -> taken (it fails the edge's [::]:9080 bind too)"
ss_v6
printf '%s\n' "$p6h" >"$tmp/proc/net/udp6"
p6 udp6 $any6 9043 07 1001
run render
expect absent "a tenant's udp [::]:9043 (no edge socket there) -> taken"
ss_v6
p6 tcp6 $any6 9080 0A 1001
printf '%s\n' 'LISTEN 0 100 [::]:9080 [::]:* users:(("nginx\",pid=1,fd=3),(\"x",pid=999,fd=3))' >>"$tmp/ss.tcp"
run render
expect absent "a tenant naming itself nginx\",pid=1 in ss: the kernel uid (1001) decides -> taken"
ss_v6
rm -f "$tmp/proc/net/udp6"
run render
expect absent "an unreadable /proc/net/udp6 -> treated as taken"
says "cannot read"
ss_v6
p6 tcp6 $any6 9080 01 1001
run render
expect absent "a tenant's connected (non-LISTEN) socket from port 9080 -> taken (it holds the port all the same)"
says "uid 1001"

# A socket that is bound and never listens is not in /proc/net/tcp6 at all:
# the ports with no root socket are really bound by `cfm realip v6-bindcheck`.
ss_v6
: >"$tmp/bind.calls"
run render
expect present "free ports: the bind test passes -> listens"
[ "$(cat "$tmp/bind.calls")" = "tcp:9080" ] || fail "bind test args (the edge's root tcp+udp 9043 skip it): $(cat "$tmp/bind.calls")"
printf 'taken' >"$tmp/bind"
run render
expect absent "a port the bind test cannot bind (a bound-only tenant socket) -> taken"
says "is taken"
run prestart
expect absent "the same at start"
printf 'old' >"$tmp/bind"
run render
expect absent "a cfm without v6-bindcheck (older) -> cannot test, taken"
says "cannot test-bind"
rm -f "$tmp/bind"
CFM_CONF="$cfm_conf" CFM_V6_PROC_FILE="$proc" CFM_PROC_ROOT="$tmp/proc" CFM_SS="$tmp/bin/ss" CFM_BIN="$tmp/bin/no-cfm" \
  CFM_EDGE_ENGINES="$ENGINES" sh "$SCRIPT" render >"$tmp/out" 2>&1 || true
expect absent "no cfm binary: cannot test-bind -> IPv4 only"
says "cannot test-bind"
ss_v6
p6 tcp6 $any6 9080 0A 0
p6 tcp6 $any6 9080 01 0
: >"$tmp/bind.calls"
run render
expect present "root sockets on every port (the edge's own, and its accepted connections) -> no bind test needed"
[ ! -s "$tmp/bind.calls" ] || fail "bind test ran for root-held ports: $(cat "$tmp/bind.calls")"
ss_v6
p6 tcp6 $any6 9080 01 0
printf 'taken' >"$tmp/bind"
run render
expect absent "a root socket on 9080 that is not LISTEN is not the edge's listener: the bind test still decides"
ss_v6
p6 tcp6 2A144280000100010000000000000002 9080 0A 0
printf 'taken' >"$tmp/bind"
run render
expect absent "a root listener on one address only (not [::]) is not the edge's: the bind test decides"
rm -f "$tmp/bind"
ss_v6
p6 tcp6 $any6 9080 0A 0
p6 tcp6 2A144280000100010000000000000002 9080 01 969
p6 tcp6 $any6 9043 01 65534
run render
expect present "the edge's [::] listeners with worker-owned accepted connections (uid 969, 65534) -> the edge's, IPv6 stays"
run prestart
expect present "the same at start"
rm -f "$tmp/bind"
ss_v6
run render

# A render that writes the files reloads a RUNNING edge and confirms the IPv6
# listen (a later reload would leave a window for another process to take the
# port); prestart never reloads (the edge is about to start).
rm -f "$conf_dir"/cfm-listen-v6-*.conf
ss_v6
: >"$tmp/edge.active"
: >"$tmp/reload.listens"
: >"$tmp/edgectl.calls"
run render
expect present "running edge: render reloads it and confirms the IPv6 listen"
says "reloaded test.service"
[ "$(grep -cx 'reload test.service' "$tmp/edgectl.calls")" -eq 1 ] || fail "reload calls: $(cat "$tmp/edgectl.calls")"
run render
[ "$(grep -cx 'reload test.service' "$tmp/edgectl.calls")" -eq 1 ] && ok "unchanged files: no second reload" || fail "reloaded for unchanged files"
: >"$tmp/edgectl.calls"
run prestart
expect present "prestart keeps the confirmed files"
grep -q reload "$tmp/edgectl.calls" && fail "prestart must never reload the edge"
rm -f "$conf_dir"/cfm-listen-v6-*.conf "$tmp/reload.listens"
ss_v6
: >"$tmp/edgectl.calls"
run render
expect absent "reloaded but no IPv6 listen appeared -> files removed"
says "does not listen on IPv6"
[ "$(grep -cx 'reload test.service' "$tmp/edgectl.calls")" -eq 2 ] && ok "... and the edge reloaded back" || fail "no reload back: $(cat "$tmp/edgectl.calls")"
: >"$tmp/reload.fail"
run render
expect absent "systemctl reload failing -> files removed"
rm -f "$tmp/reload.fail"
# Files that existed with another body, no IPv6 listen after the reload: the
# reload back is the only one (no second reload for the removal).
run render
printf '# an older body\n' >>"$conf_dir/cfm-listen-v6-http.conf"
: >"$tmp/edgectl.calls"
run render
expect absent "changed files, reloaded, no IPv6 listen -> removed"
[ "$(grep -cx 'reload test.service' "$tmp/edgectl.calls")" -eq 2 ] && ok "... reload + reload back, no third reload" || fail "reload count: $(cat "$tmp/edgectl.calls")"
# A listener already there before the reload proves nothing about it.
ss_v6
p6 tcp6 $any6 9080 0A 0
: >"$tmp/edgectl.calls"
run render
expect present "IPv6 listeners there before the reload: kept, the listen not taken as proof"
says "listened on IPv6 before the reload"
# A render that removes files a running edge listens with reloads it.
printf 'untrusted' >"$tmp/realip"
: >"$tmp/edgectl.calls"
run render
expect absent "render: the origin no longer trusts ::1 -> removed"
grep -qx 'reload test.service' "$tmp/edgectl.calls" && ok "... and the running edge reloaded (no IPv6 visitor reaches it as ::1 meanwhile)" || fail "no reload after removing live files: $(cat "$tmp/edgectl.calls")"
: >"$tmp/edgectl.calls"
run render
grep -q reload "$tmp/edgectl.calls" && fail "reloaded with no files to remove"
printf 'trusted' >"$tmp/realip"
rm -f "$tmp/edge.active"
ss_v6
run render
expect present "edge not running: files written, apply at its next start"
says "not running"
printf 'untrusted' >"$tmp/realip"
: >"$tmp/edgectl.calls"
run render
expect absent "removed while the edge is not running"
grep -q reload "$tmp/edgectl.calls" && fail "reloaded an edge that is not running"
printf 'trusted' >"$tmp/realip"
run render

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

for v in off '"off" ; note' OFF no false 0 disabled; do
  printf 'EDGE_LISTEN_V6 = auto\nEDGE_LISTEN_V6 = %s\n' "$v" >"$cfm_conf"
  run render
  expect absent "EDGE_LISTEN_V6 = $v (last line) -> IPv4 only"
  run render
done
printf 'EDGE_LISTEN_V6 = off\nEDGE_LISTEN_V6 = auto\n' >"$cfm_conf"
run render
expect present "a later on line wins over off"
for v in on Yes true 1 auto enabled; do
  printf 'EDGE_LISTEN_V6 = %s\n' "$v" >"$cfm_conf"
  rm -f "$conf_dir"/cfm-listen-v6-*.conf
  run render
  expect present "EDGE_LISTEN_V6 = $v allows IPv6"
done
printf 'EDGE_LISTEN_V6 = maybe\n' >"$cfm_conf"
run render
expect absent "an unknown value reads as off"
says 'not on/off'
printf '# EDGE_LISTEN_V6 = on\n' >"$cfm_conf"
run render
expect absent "a commented key leaves the default (off)"
printf 'EDGE_LISTEN_V6 = on\n' >"$cfm_conf"

rm -f "$proc"
run prestart
expect absent "no IPv6 stack (if_inet6 absent): prestart removes even kept files"
run render
: >"$proc"
run render
expect absent "IPv6 stack but no global address (empty if_inet6, as on earth) -> IPv4 only"
v6_global
run render
printf '%s\n' 'fe80000000000000e6434bfffe54ef2f 05 40 20 80     eno4' '00000000000000000000000000000001 01 80 10 80       lo' >"$proc"
run prestart
expect present "prestart: no global address YET (SLAAC at boot) keeps approved files"
says "kept at start: no global IPv6 address"
run render
expect absent "render: link-local and ::1 only -> IPv4 only"
run prestart
expect absent "prestart: no global address and no approved files -> nothing written"
v6_global
v6_global

rm -f "$cfm_conf"
ss_v6
run render
expect absent "no cfm.conf at all -> the default (off)"
printf 'EDGE_LISTEN_V6 = on\n' >"$cfm_conf"
rm -f "$conf_dir"/cfm-listen-v6-*.conf
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
CFM_CONF="$cfm_conf" CFM_V6_PROC_FILE="$proc" CFM_PROC_ROOT="$tmp/proc" CFM_SS="$tmp/bin/ss" CFM_BIN="$tmp/bin/cfm" \
  CFM_EDGE_ENGINES="Test|$tmp/bin/none|$conf_dir|$main_conf" sh "$SCRIPT" render >"$tmp/out" 2>&1 || fail "exit status without an engine binary"
expect absent "no engine binary to test with -> IPv4 only"

run status
expect absent "status changes nothing"
says 'wants IPv6'
run bogus-action
ok "an unknown action exits 0"

rc=0
CFM_CONF="$cfm_conf" CFM_V6_PROC_FILE="$proc" CFM_PROC_ROOT="$tmp/proc" CFM_SS="$tmp/bin/ss" CFM_BIN="$tmp/bin/cfm" \
  CFM_EDGE_ENGINES="Test|$tmp/bin/engine|$tmp/nope|$tmp/nope/nginx.conf" sh "$SCRIPT" render >"$tmp/out" 2>&1 || rc=$?
[ "$rc" -eq 0 ] && [ ! -e "$tmp/nope" ] && ok "missing conf dir: skipped" || fail "missing conf dir: rc=$rc"

# The default engine table points at each engine's real main config.
grep -qF "'OpenResty|%s|%s|%s\\n' \"\$e_bin\" /usr/local/openresty/nginx/conf /usr/local/openresty/nginx/conf/nginx.conf" "$SCRIPT" || fail "OpenResty engine row"
grep -qF "'Angie|%s|%s|%s\\n' \"\$e_bin\" /etc/angie /etc/angie/angie.conf" "$SCRIPT" || fail "Angie engine row"
grep -qF "'cfm-edge|%s|%s|%s\\n' \"\$e_bin\" /etc/cfm-edge /etc/cfm-edge/nginx.conf" "$SCRIPT" || fail "cfm-edge engine row"

# cfm-edge's config test creates its logs (nginx -t opens every access_log /
# error_log it names). prestart walks every engine (systemd does not tell it
# which edge unit is starting), so each openresty / angie start tests an idle
# cfm-edge that has IPv6 files: the EMPTY logs that test created must go
# again, or internal/edgelog (newest mtime wins) reads cfm-edge's empty logs
# instead of the live edge's. Kept: files that were there, files with
# content, and everything while cfm-edge may run (a unit not
# inactive/failed/unknown, or a cfm-edge process).
cel="$tmp/cfmedge-logs"
# fake cfm-edge: offers -e in its -h only with $tmp/cfmedge.has_e; with
# $tmp/cfmedge.warn and no -e, the test's [warn] lands in error.log (a build
# whose startup error log is that file, as nginx.org's --error-log-path).
cat >"$tmp/bin/cfm-edge" <<EOF_CFMEDGE
#!/bin/sh
if [ "\$1" = "-h" ]; then
  echo 'Usage: cfm-edge [-?hvVtTq] [-s signal] [-p prefix]'
  [ -e "$tmp/cfmedge.has_e" ] && echo '  -e filename   : set error log file (default: /var/log/cfm-edge/error.log)'
  exit 0
fi
echo "\$*" >> "$tmp/cfmedge.calls"
noe=1
if [ "\$1" = "-e" ]; then
  [ -e "$tmp/cfmedge.has_e" ] || exit 2
  noe=0; shift 2
fi
[ "\$1" = "-t" ] || exit 2
[ -d "\${CFM_CFMEDGE_LOG_DIR:-/nonexistent}" ] || exit 0
: >>"\$CFM_CFMEDGE_LOG_DIR/error.log"
[ "\$noe" = 1 ] && [ -e "$tmp/cfmedge.warn" ] && echo '[warn] conflicting server name' >>"\$CFM_CFMEDGE_LOG_DIR/error.log"
: >>"\$CFM_CFMEDGE_LOG_DIR/access.log"
printf 'x\n' >>"\$CFM_CFMEDGE_LOG_DIR/written.log"
case "\$(cat "$tmp/engine.fail" 2>/dev/null)" in
  always) exit 1 ;;
  with-v6) [ -e "$conf_dir/cfm-listen-v6-http.conf" ] && exit 1 ;;
esac
exit 0
EOF_CFMEDGE
chmod 0755 "$tmp/bin/cfm-edge"
cel_reset() {
  rm -rf "$cel" "$cel.real"; mkdir -p "$cel"
  : >"$cel/old-empty.log"; printf 'old\n' >"$cel/old-full.log"
  rm -f "$tmp/cfmedge.state"; rm -rf "$tmp/proc/4242"
}
cel_list() { (cd "$cel" && find . -maxdepth 1 -type f | sort | tr '\n' ' '); }
cel_run() { # cel_run ACTION: the cfm-edge engine, its logs in $cel
  local rc=0
  CFM_CONF="$cfm_conf" CFM_V6_PROC_FILE="$proc" CFM_PROC_ROOT="$tmp/proc" CFM_SS="$tmp/bin/ss" CFM_BIN="$tmp/bin/cfm" \
    CFM_CFMEDGE_LOG_DIR="$cel" CFM_EDGE_ENGINES="cfm-edge|$tmp/bin/cfm-edge|$conf_dir|$main_conf" \
    sh "$SCRIPT" "$@" >"$tmp/out" 2>&1 || rc=$?
  [ "$rc" -eq 0 ] || fail "exit status $rc for cfm-edge '$*' (must always be 0)"
}
printf 'EDGE_LISTEN_V6 = on\n' >"$cfm_conf"
printf 'trusted' >"$tmp/realip"
rm -f "$tmp/engine.fail" "$tmp/edge.active"
ss_v6
run render
expect present "cfm-edge log cleanup: files approved by a render"
cel_reset
: >"$tmp/cfmedge.calls"
cel_run prestart
expect present "prestart on an idle cfm-edge: files kept, config test passed"
[ -s "$tmp/cfmedge.calls" ] || fail "prestart did not config-test cfm-edge (the premise of the log cleanup)"
[ "$(cel_list)" = "./old-empty.log ./old-full.log ./written.log " ] \
  && ok "prestart, cfm-edge inactive: only the EMPTY logs its test created are removed" \
  || fail "prestart, cfm-edge inactive: left $(cel_list); output: $(cat "$tmp/out")"
says "removed $cel/error.log (empty, created by its config test"
for st in active activating reloading deactivating; do
  cel_reset; printf '%s' "$st" >"$tmp/cfmedge.state"
  cel_run prestart
  [ -f "$cel/error.log" ] && [ -f "$cel/access.log" ] \
    && ok "prestart, cfm-edge.service $st: its new empty logs are kept (it may hold them open)" \
    || fail "prestart, cfm-edge.service $st: a cfm-edge that may run lost its new empty log; left $(cel_list)"
done
for st in failed unknown; do
  cel_reset; printf '%s' "$st" >"$tmp/cfmedge.state"
  cel_run prestart
  [ ! -e "$cel/error.log" ] && ok "prestart, cfm-edge.service $st: the test-created logs are removed" \
    || fail "prestart, cfm-edge.service $st: left $(cel_list)"
done
cel_reset; mkdir -p "$tmp/proc/4242"; printf 'cfm-edge\n' >"$tmp/proc/4242/comm"
cel_run prestart
[ -f "$cel/error.log" ] && ok "prestart, a cfm-edge process outside systemd: its logs are kept" \
  || fail "prestart, a cfm-edge process (comm) outside systemd lost its new empty log"
cel_reset; mkdir -p "$tmp/proc/4242"; printf 'cfm-edge-x\n' >"$tmp/proc/4242/comm"
cel_run prestart
[ ! -e "$cel/error.log" ] && ok "prestart, a process named cfm-edge-x is not cfm-edge (exact comm match)" \
  || fail "prestart: a cfm-edge-x process kept the test-created logs"
cel_reset; mv "$cel" "$cel.real"; ln -s "$cel.real" "$cel"
cel_run prestart
[ ! -e "$cel.real/error.log" ] && [ -f "$cel.real/old-empty.log" ] && ok "prestart, a symlinked cfm-edge log dir is cleaned like a plain one" \
  || fail "prestart, a symlinked cfm-edge log dir: $(ls -A "$cel.real" | tr '\n' ' ')"
rm -f "$cel"; cel_reset
cel_run render
expect present "render, cfm-edge: files unchanged"
[ "$(cel_list)" = "./old-empty.log ./old-full.log " ] || fail "render with unchanged files ran cfm-edge's test (or created logs): $(cel_list)"
rm -f "$conf_dir"/cfm-listen-v6-*.conf
cel_reset
cel_run render
expect present "render, cfm-edge: files written, config test passed"
[ "$(cel_list)" = "./old-empty.log ./old-full.log ./written.log " ] \
  && ok "render, cfm-edge inactive: the test-created empty logs are removed" || fail "render: left $(cel_list)"
cel_reset; printf 'with-v6' >"$tmp/engine.fail"
cel_run prestart
expect absent "prestart, cfm-edge: the test fails with the files -> removed"
[ ! -e "$cel/error.log" ] && [ ! -e "$cel/access.log" ] && ok "... and the logs of both of its config tests are removed" \
  || fail "prestart, failed test: left $(cel_list)"
rm -f "$tmp/engine.fail"
run render
cel_reset
cel_run deploy
expect present "deploy, cfm-edge: kept"
[ ! -e "$cel/error.log" ] && ok "deploy, cfm-edge inactive: the test-created empty logs are removed" || fail "deploy: left $(cel_list)"
# A build that offers -e: the test runs with -e /dev/null, so its warnings
# never fill error.log (a non-empty file would be kept, and read as the
# newest edge log). One that does not: plain -t (an unknown -e would fail
# every test and remove the IPv6 files).
cel_reset; : >"$tmp/cfmedge.has_e"; : >"$tmp/cfmedge.warn"; : >"$tmp/cfmedge.calls"
cel_run prestart
expect present "prestart, cfm-edge offering -e: config test passed"
grep -qx -- '-e /dev/null -t -q' "$tmp/cfmedge.calls" || fail "cfm-edge offering -e was not tested with -e /dev/null: $(cat "$tmp/cfmedge.calls")"
[ ! -e "$cel/error.log" ] && ok "a warning of cfm-edge's test (-e /dev/null) leaves no error.log behind" \
  || fail "with -e: error.log left ($(wc -c <"$cel/error.log") bytes)"
rm -f "$tmp/cfmedge.has_e"; cel_reset; : >"$tmp/cfmedge.calls"
cel_run prestart
expect present "prestart, cfm-edge without -e: config test passed"
grep -q -- '-e' "$tmp/cfmedge.calls" && fail "a cfm-edge without -e was passed -e: $(cat "$tmp/cfmedge.calls")"
[ -s "$cel/error.log" ] && ok "without -e, a warning fills error.log and it is kept (content is never removed)" \
  || fail "without -e: a non-empty error.log was removed"
rm -f "$tmp/cfmedge.warn"
rm -rf "$cel"
cel_run prestart
[ ! -e "$cel" ] && ok "a missing cfm-edge log dir: no error, nothing created" || fail "a missing cfm-edge log dir was created"
# dash applies redirections in order: 2>/dev/null must come before the <,
# or a process exiting mid-scan prints "cannot open" into the journal.
grep -qF 'read -r cmr_comm 2>/dev/null <"$cmr_f"' "$SCRIPT" \
  && ok "the /proc comm read silences its own open error (dash order)" \
  || fail "$SCRIPT: the comm read must be: read -r cmr_comm 2>/dev/null <\"\$cmr_f\""
# Another engine's test is not wrapped: an empty file appearing in the
# cfm-edge log dir meanwhile is not its to remove.
cel_reset
cat >"$tmp/bin/other-engine" <<EOF_OTHER
#!/bin/sh
[ "\$1" = "-t" ] || exit 2
: >>"$cel/error.log"
exit 0
EOF_OTHER
chmod 0755 "$tmp/bin/other-engine"
CFM_CONF="$cfm_conf" CFM_V6_PROC_FILE="$proc" CFM_PROC_ROOT="$tmp/proc" CFM_SS="$tmp/bin/ss" CFM_BIN="$tmp/bin/cfm" \
  CFM_CFMEDGE_LOG_DIR="$cel" CFM_EDGE_ENGINES="Other|$tmp/bin/other-engine|$conf_dir|$main_conf" sh "$SCRIPT" prestart >"$tmp/out" 2>&1 || true
[ -f "$cel/error.log" ] && ok "another engine's config test leaves the cfm-edge log dir alone" || fail "another engine's test removed a cfm-edge log"
rm -rf "$cel"; rm -f "$conf_dir"/cfm-listen-v6-*.conf

# --- 3. package deploy hook ----------------------------------------------------
awk '/^deploy_logrotate_config$/{exit} {print}' scripts/package-proxy-config-deploy.sh >"$tmp/functions.sh"
grep -q '^deploy_edge_listen_v6()' "$tmp/functions.sh" || fail "deploy_edge_listen_v6 is not defined before the first top-level call"
grep -qxF 'deploy_edge_listen_v6' scripts/package-proxy-config-deploy.sh || fail "package-proxy-config-deploy.sh never calls deploy_edge_listen_v6"
units="$tmp/units"
cat >"$tmp/bin/systemctl" <<EOF
#!/bin/sh
echo "\$*" >> "$tmp/systemctl.calls"
[ "\$1" = is-active ] && exit 3
exit 0
EOF
chmod 0755 "$tmp/bin/systemctl"
rm -f "$conf_dir"/cfm-listen-v6-*.conf
: >"$tmp/systemctl.calls"
deploy() {
  CFM_CONFIG_DIR="$PWD/configs" CFM_SYSTEMD_UNIT_DIR="$units" CFM_SYSTEMCTL="$tmp/bin/systemctl" \
    CFM_EDGE_LISTEN_V6_SCRIPT="$PWD/$SCRIPT" CFM_CONF="$cfm_conf" CFM_V6_PROC_FILE="$proc" CFM_PROC_ROOT="$tmp/proc" \
    CFM_SS="$tmp/bin/ss" CFM_BIN="$tmp/bin/cfm" CFM_EDGE_ENGINES="$ENGINES" \
    bash -c '. "$1"; deploy_edge_listen_v6' sh "$tmp/functions.sh" >"$tmp/out" 2>&1
}
deploy
for f in cfm-edge-listen-v6.service openresty.service.d/cfm-listen-v6.conf angie.service.d/cfm-listen-v6.conf cfm-edge.service.d/cfm-listen-v6.conf; do
  [ -f "$units/$f" ] || fail "deploy did not install $units/$f"
done
cmp -s configs/cfm-edge-listen-v6.service "$units/cfm-edge-listen-v6.service" || fail "unit content differs"
cmp -s configs/cfm-edge-listen-v6-dropin.conf "$units/openresty.service.d/cfm-listen-v6.conf" || fail "drop-in content differs"
[ "$(grep -c daemon-reload "$tmp/systemctl.calls")" -eq 1 ] || fail "daemon-reload count after first deploy: $(cat "$tmp/systemctl.calls")"
expect absent "deploy runs the script (deploy): it never turns IPv6 on"
says "turn it on with"
run render
expect present "render turns it on"
: >"$tmp/edge.active"
deploy
expect present "deploy keeps files a render approved"
grep -vx daemon-reload "$tmp/systemctl.calls" | grep -q reload && fail "deploy reloaded the edge: $(cat "$tmp/systemctl.calls")"
ss_v4
deploy
expect present "deploy: the origin not on IPv6 (restarting during the upgrade) -> kept"
ss_v6
deploy
expect present "deploy: the edge's [::] listeners with worker-owned accepted connections -> kept"
printf '# an older body\n' >>"$conf_dir/cfm-listen-v6-http.conf"
cp "$conf_dir/cfm-listen-v6-http.conf" "$tmp/http.old"
deploy
cmp -s "$conf_dir/cfm-listen-v6-http.conf" "$tmp/http.old" && ok "deploy never rewrites a kept file whose body differs" || fail "deploy rewrote a kept file"
says "differ from this version"
rm -f "$tmp/edge.active"
run render
expect present "render rewrites the old body"
printf 'untrusted' >"$tmp/realip"
deploy
expect absent "deploy: a definite untrusted verdict removes the files"
says "reload it to apply"
grep -vx daemon-reload "$tmp/systemctl.calls" | grep -q reload && fail "deploy reloaded the edge: $(cat "$tmp/systemctl.calls")"
printf 'trusted' >"$tmp/realip"
rm -f "$tmp/edge.active"
[ "$(grep -c daemon-reload "$tmp/systemctl.calls")" -eq 1 ] && ok "unchanged units: no second daemon-reload" || fail "daemon-reload ran again for unchanged units"

# The unit runs prestart, ignores failure, and the drop-in is Wants + After.
grep -qxF 'ExecStart=-/bin/sh /usr/share/cfm/scripts/cfm-edge-listen-v6.sh prestart' configs/cfm-edge-listen-v6.service || fail "unit ExecStart"
grep -qxF 'Type=oneshot' configs/cfm-edge-listen-v6.service || fail "unit Type"
grep -q '^\[Install\]' configs/cfm-edge-listen-v6.service && fail "the unit must have no [Install] (only the edge pulls it in)"
grep -qxF 'Wants=cfm-edge-listen-v6.service' configs/cfm-edge-listen-v6-dropin.conf || fail "drop-in Wants"
grep -qxF 'After=cfm-edge-listen-v6.service' configs/cfm-edge-listen-v6-dropin.conf || fail "drop-in After"
grep -q '^Requires=' configs/cfm-edge-listen-v6-dropin.conf && fail "drop-in must not Require (the edge must start if the unit fails)"

# Package removal (not upgrade) removes the units, the drop-ins and the
# generated files, so a leftover IPv6 listen never outlives its guard. Only on
# removal: on an rpm upgrade the OLD package's %postun runs after the new
# %post, so an unconditional rm would delete what the upgrade just deployed.
rmsect=$(awk '/^%postun$/{p=1; next} /^%(changelog|files|pre|post|preun|install|build|prep|description|check)([[:space:]]|$)/{p=0} p' packaging/rpm/SPECS/cfm.spec | awk '/^if \[ "\$1" -eq 0 \]; then$/{p=1; next} /^fi$/{p=0} p')
printf '%s\n' "$rmsect" | grep -q 'cfm-listen-v6' || fail "cfm.spec: the cleanup is not inside %postun's 'if [ \"\$1\" -eq 0 ]; then' (removal only)"
rmsect=$(awk '/^case "\$1" in$/{p=1} p{print} /^esac$/{p=0}' packaging/debian/DEBIAN/postrm | awk '/^    remove\|purge\)$/{p=1; next} /^        ;;$/{p=0} p')
printf '%s\n' "$rmsect" | grep -q 'cfm-listen-v6' || fail "postrm: the cleanup is not inside the 'remove|purge)' branch (removal only)"
for pkg in packaging/debian/DEBIAN/postrm packaging/rpm/SPECS/cfm.spec; do
  for f in /etc/systemd/system/cfm-edge-listen-v6.service \
    /etc/systemd/system/openresty.service.d/cfm-listen-v6.conf \
    /etc/systemd/system/angie.service.d/cfm-listen-v6.conf \
    /etc/systemd/system/cfm-edge.service.d/cfm-listen-v6.conf \
    /usr/local/openresty/nginx/conf/cfm-listen-v6-http.conf /usr/local/openresty/nginx/conf/cfm-listen-v6-https.conf \
    /etc/angie/cfm-listen-v6-http.conf /etc/angie/cfm-listen-v6-https.conf \
    /etc/cfm-edge/cfm-listen-v6-http.conf /etc/cfm-edge/cfm-listen-v6-https.conf; do
    grep -qE "^[[:space:]]*(rm -f )?$(printf '%s' "$f" | sed 's/[.]/\\./g')( \\\\)?( \\|\\| true)?$" "$pkg" \
      || fail "$pkg does not remove $f on package removal"
  done
done

if [ "$fails" -ne 0 ]; then
  echo "[edge-listen-v6] FAILED: $fails check(s)" >&2
  exit 1
fi
echo "[edge-listen-v6] OK: confs and script agree on ports/includes; the decision (default + opt-in, on/off forms, IPv6 stack, taken ports, origin, ::1 trust, main-conf include, failed test, prestart keep), the deploy hook and package removal behave."

#!/bin/sh
# cfm-edge-listen-v6.sh — decide whether the edge (OpenResty / Angie / the
# cfm-edge package; "edge" in this script's name is the role) listens
# on IPv6, and write or remove the two listen sidecars the main config
# includes (docs/edge-ipv6.md):
#
#   <engine conf dir>/cfm-listen-v6-http.conf    listen [::]:9080;
#   <engine conf dir>/cfm-listen-v6-https.conf   listen [::]:9043 ssl; + quic
#
# configs/openresty.conf and configs/angie.conf (and cfm-edge.conf, rendered
# from openresty.conf) include them through a glob
# (cfm-listen-v6-http.con[f]), so an ABSENT file is fine and means IPv4 only.
# That is the fail-safe state: anything unknown removes the files.
#
# Why it is not a static `listen [::]` in the reference conf: on a host
# without an IPv6 stack (ipv6.disable=1) that listen fails the config test and
# the edge does not start. So this runs before every edge start
# (cfm-edge-listen-v6.service, pulled in by a drop-in on openresty.service /
# angie.service / cfm-edge.service) and from the package deploy, and decides
# from the host:
#
# Whether a node may listen on IPv6 at all is EDGE_LISTEN_V6 in cfm.conf: on
# (yes / true / 1 / auto) or off (no / false / 0 / disabled); absent, it is
# V6_DEFAULT below. V6_DEFAULT is off until per-IP defences group IPv6 by /64
# (docs/ROADMAP.md §9c): today bans, rate limits and scoring key on the full
# address, so a direct IPv6 client rotating inside its /64 evades them, while
# an edge without IPv6 refuses it and the browser falls back to IPv4, where
# they hold. Then V6_DEFAULT becomes auto and no node needs the key. Where it
# is allowed, the edge listens on IPv6 by itself where ALL of these hold, and
# stays on IPv4 otherwise:
#   - the host has a global IPv6 address (/proc/net/if_inet6, scope 00);
#   - nothing but the edge holds [::]:9080 / [::]:9043 (tcp) or [::]:9043
#     (udp) — `nginx -t` ignores a port in use (EADDRINUSE), so a taken port would pass the test
#     and then fail the edge's START;
#   - the origin listens on IPv6 on both 80 and 443 (ss): an IPv6 visitor's
#     hop goes to the IPv6 address it came to;
#   - `cfm realip` (asked before the files are written; it requires ::1 as
#     soon as the host can do IPv6) says the origin trusts the edge for the
#     IPv6 hop too: that hop comes from ::1, and an origin trusting only
#     127.0.0.1 would see every IPv6 visitor as ::1, i.e. as localhost
#     (`Require local`, apps that trust localhost, one login-limiter bucket
#     for all of them). `cfm realip fix` writes it (Apache / nginx).
#
# The reference cfm.conf carries the key commented out (`# EDGE_LISTEN_V6 =
# on`, the opt-in while V6_DEFAULT is off).
#
# After a change it runs the engine's own config test and, if that fails with
# the IPv6 files in place, removes them again. Files are removed too when the
# engine's live main config does not include them (an older main config, or a
# refused package deploy): there they listen nowhere and would only make
# `cfm realip` demand a ::1 trust nothing uses. It never fails its caller: the
# exit status is always 0 (the edge must start, on IPv4, whatever happens
# here). A `render` that writes the files reloads a running edge at once and
# confirms the IPv6 listen (reload_and_confirm); a `render` that removes files
# a running edge listens with reloads it too (reload_after_remove). prestart
# and deploy never reload.
#
# Usage: cfm-edge-listen-v6.sh [render|prestart|deploy|status]
#   render    (default; by hand, the installers) decide and write/remove the
#             files for every engine found; the ONLY action that turns IPv6 on
#             for a running edge (it reloads it and confirms the listen)
#   prestart  (cfm-edge-listen-v6.service, before every edge start) the same,
#             except that files a render already approved are KEPT when the
#             only reasons against them are about readiness, which at boot are
#             often not there yet: no global IPv6 address yet (SLAAC / the
#             network still coming up), the origin not seen on IPv6 (it can
#             start after the edge), and `cfm realip` giving no verdict (it
#             cannot see the running origin yet). Otherwise a reboot
#             would silently put the edge back on IPv4 until the next render.
#             The reasons that would break the start, or that the operator
#             chose, still remove them: EDGE_LISTEN_V6 not allowing it, no
#             IPv6 stack at all, a taken port, ss failing, a main config
#             without the include, a failed config test, and a definite "the
#             origin does not trust ::1" from cfm realip. An origin that stops
#             listening on IPv6 for good keeps the edge's IPv6 until the next
#             render (by hand).
#             It walks EVERY engine, whichever edge unit is starting: the
#             oneshot is pulled in by the drop-in on each edge unit, and
#             systemd tells it nothing about which one (no argument, no
#             environment; only a template unit per edge could), and the walk
#             is also what removes a stopped or removed engine's stale files.
#             So the start of openresty / angie config-tests an idle cfm-edge
#             that has IPv6 files, and that test creates cfm-edge's logs: the
#             empty ones it created are removed again (engine_test).
#   deploy    (the package deploy, package-proxy-config-deploy.sh) prestart's
#             keep / remove rules, but it never writes files that are not
#             there (it tells the operator to run render) and never reloads
#   status    print the decision per engine, change nothing
#
# Test seams (scripts/tests/check_edge_listen_v6.sh): CFM_CONF,
# CFM_V6_PROC_FILE, CFM_SS, CFM_BIN, CFM_PROC_ROOT, CFM_SYSTEMCTL,
# CFM_V6_CONFIRM_TRIES, CFM_CFMEDGE_LOG_DIR, CFM_EDGE_ENGINES
# ("Name|binary|confdir|mainconf" per line; the name cfm-edge gets the log
# cleanup of engine_test).

# C locale: [[:space:]] is ASCII whitespace only, as Go's edgeIPv6Wanted
# reads it (a UTF-8 locale's sed would also trim U+2000.. and U+3000).
LC_ALL=C
export LC_ALL

CFM_CONF=${CFM_CONF:-/etc/cfm/cfm.conf}
CFM_V6_PROC_FILE=${CFM_V6_PROC_FILE:-/proc/net/if_inet6}
CFM_SS=${CFM_SS:-ss}
CFM_BIN=${CFM_BIN:-/usr/bin/cfm}
CFM_PROC_ROOT=${CFM_PROC_ROOT:-/proc}
CFM_SYSTEMCTL=${CFM_SYSTEMCTL:-systemctl}
CFM_V6_CONFIRM_TRIES=${CFM_V6_CONFIRM_TRIES:-10}

# The edge's listener ports (configs/openresty.conf / angie.conf `listen 9080;`
# and `listen 9043 ssl;`). check_edge_listen_v6.sh pins them to the confs.
V6_HTTP_PORT=9080
V6_HTTPS_PORT=9043

# The decision with no EDGE_LISTEN_V6 in cfm.conf: off until IPv6 /64
# grouping lands (see the header), then auto. internal/originrealip
# edgeIPv6Default is the same switch; check_edge_listen_v6.sh pins them equal.
V6_DEFAULT=off

V6_HTTP_FILE=cfm-listen-v6-http.conf
V6_HTTPS_FILE=cfm-listen-v6-https.conf

log() { echo "CFM edge IPv6 listen: $*"; }

# mode: EDGE_LISTEN_V6 from cfm.conf (last uncommented line wins; an inline ;
# or # comment and quotes stripped; case-insensitive): "auto" for on / yes /
# true / 1 / auto / enable / enabled, "off" for off / no / false / 0 /
# disable / disabled, V6_DEFAULT when absent; anything else reads as off (an
# unknown never turns a listen on). Same reading as internal/originrealip
# edgeIPv6Wanted.
mode() {
    m_val=""
    if [ -r "$CFM_CONF" ]; then
        # Value: cut at the first ; or #, trim whitespace (CR included), then
        # strip ONE matching pair of quotes. internal/originrealip
        # edgeIPv6Wanted reads it the same way; both run
        # scripts/tests/fixtures/edge_listen_v6_mode.txt.
        m_val=$(sed -n 's/^[[:space:]]*EDGE_LISTEN_V6[[:space:]]*=//p' "$CFM_CONF" |
            sed 's/[;#].*$//; s/^[[:space:]]*//; s/[[:space:]]*$//' |
            sed -e 's/^"\(.*\)"$/\1/' -e t -e 's/^'"'"'\(.*\)'"'"'$/\1/' |
            tail -n 1 | tr 'A-Z' 'a-z')
    fi
    case $m_val in
        "") echo "$V6_DEFAULT" ;;
        on | yes | true | 1 | auto | enable | enabled) echo auto ;;
        off | no | false | 0 | disable | disabled) echo off ;;
        *)
            log "WARNING: EDGE_LISTEN_V6 = \"$m_val\" in $CFM_CONF is not on/off; treating it as off" >&2
            echo off
            ;;
    esac
}

# kernel_has_v6: the kernel has an IPv6 stack (/proc/net/if_inet6 exists; it
# is absent with ipv6.disable=1, where a [::] listen cannot even be opened).
kernel_has_v6() {
    [ -e "$CFM_V6_PROC_FILE" ]
}

# host_has_global_v6: an interface carries a global IPv6 address (scope 00;
# the file is empty with disable_ipv6=1 everywhere, as on earth). Without one
# no IPv6 visitor can reach the node; internal/originrealip hostCanIPv6 reads
# it the same way.
host_has_global_v6() {
    [ -r "$CFM_V6_PROC_FILE" ] && awk '$4 == "00" { f = 1 } END { exit f ? 0 : 1 }' "$CFM_V6_PROC_FILE"
}

# ss_v6_listeners PROTO PORT: (the origin check, 80 / 443: ports a tenant
# cannot bind, so the names ss prints do not matter here; the edge's own ports
# are checked from /proc, edge_port_taken) from `ss -l<n><t|u>p`, print the owner of every
# IPv6 listener on PORT: `[::]`, a specific `[2001:db8::1]`, or `*` (a
# dual-stack socket, as iproute2 >= 4.18 prints it: EL8+, Debian 10+; older ss
# printed `*` for IPv4-any too). ::1 and v4-mapped addresses serve no global
# IPv6 address and are skipped. Prints `-` for an owner ss did not show.
# Returns 2 when ss itself failed (an unknown, never a "no").
ss_v6_listeners() {
    case $1 in tcp) svl_opt=-lntp ;; *) svl_opt=-lnup ;; esac
    svl_out=$("$CFM_SS" "$svl_opt" 2>/dev/null) || return 2
    printf '%s\n' "$svl_out" | awk -v port="$2" '
        $1 == "State" || $1 == "Netid" { next }
        {
            a = $4
            n = length(port) + 1
            if (substr(a, length(a) - n + 1) != ":" port) next
            h = substr(a, 1, length(a) - n)
            if (!(h == "*" || (h ~ /^\[.*\]$/ && h != "[::1]" && h !~ /^\[::ffff:/))) next
            # Every owner: name:pid,name:pid (a socket shared by the master
            # and its workers lists them all); "-" when ss showed none.
            o = ""
            rest = $0
            while (match(rest, /\("[^"]*",pid=[0-9]+/)) {
                m = substr(rest, RSTART + 2, RLENGTH - 2)
                sub(/",pid=/, ":", m)
                o = o (o == "" ? "" : ",") m
                rest = substr(rest, RSTART + RLENGTH)
            }
            print (o == "" ? "-" : o)
        }'
    return 0
}

# origin_has_v6 PORT: 0 an IPv6 origin listener on PORT, 1 none, 2 ss failed.
origin_has_v6() {
    ohv=$(ss_v6_listeners tcp "$1") || return 2
    [ -n "$ohv" ]
}

# edge_port_taken: 0 when an IPv6 socket on one of the edge's ports (tcp
# 9080 / 9043, udp 9043) could make the edge's `listen [::]` fail, the reason
# on stdout; 1 when the ports are the edge's or free.
#  - /proc/net/tcp6 and udp6, never ss: ss prints a process's name raw, so a
#    tenant naming itself `nginx",pid=1` passes as root's PID 1 (proved), and
#    a name was never proof anyway. The kernel's uid column is the socket's
#    owner and cannot be forged. A root LISTEN on [::]:PORT (udp: a root
#    socket on [::]:PORT) is taken as the edge's own. On tcp, while it holds
#    the port nothing else can bind it: every other socket on the port is a
#    connection it accepted, owned by the WORKER that accepted it (nobody /
#    cfm / nginx, not root: speedhost's edge, uid 969), and does not count.
#    On udp a tenant CAN co-bind it with SO_REUSEADDR (proved); such a socket
#    cannot stop the edge's own later bind (nginx sets SO_REUSEADDR too), so
#    it is ignored here; at a cold start it counts as taken. (It can take the
#    edge's QUIC datagrams, IPv4 too: docs/ROADMAP.md §9c.) Leftovers of a
#    stopped edge (FIN_WAIT, TIME_WAIT) have no owner and read uid 0. With no root listener, a socket on the port owned
#    by anyone but root counts as taken, in ANY state and on any address, ::1
#    and v4-mapped included (a tenant that bound the port and connected out
#    holds it too).
#  - A port with no root socket is then really bound, by `cfm realip
#    v6-bindcheck` (IPv6-only, as nginx's listen [::]): a socket that is bound
#    and never listens is not in /proc/net/tcp6 at all, yet it makes the
#    edge's bind fail, and `nginx -t` ignores a port in use, so the start would fail,
#    IPv4 included. A cfm that cannot run the check (absent, older, no answer)
#    counts as taken; so does an unreadable table.
edge_port_taken() {
    ept_free=""
    for ept in "tcp6 $V6_HTTP_PORT" "tcp6 $V6_HTTPS_PORT" "udp6 $V6_HTTPS_PORT"; do
        ept_proto=${ept%% *}
        ept_port=${ept#* }
        ept_file=$CFM_PROC_ROOT/net/$ept_proto
        if [ ! -r "$ept_file" ]; then
            echo "cannot read $ept_file: cannot tell whether $ept_proto port $ept_port is free"
            return 0
        fi
        ept_res=$(awk -v hexport="$(printf '%04X' "$ept_port")" -v proto="$ept_proto" '
            NR == 1 { next }
            {
                n = split($2, a, ":")
                if (n != 2 || toupper(a[2]) != hexport) next
                if ($8 == "0" && a[1] == "00000000000000000000000000000000" && (proto == "udp6" || $4 == "0A")) root = 1
                else if ($8 != "0" && u == "") u = $8
            }
            END { if (root) print "root"; else if (u != "") print "uid " u }' "$ept_file") || {
            echo "cannot parse $ept_file"
            return 0
        }
        case $ept_res in
            uid\ *)
                echo "IPv6 ${ept_proto%6} port $ept_port is held by a socket of uid ${ept_res#uid }, not by the edge (root): the edge could not start with an IPv6 listen there"
                return 0
                ;;
            root) ;;
            *) ept_free="$ept_free ${ept_proto%6}:$ept_port" ;;
        esac
    done
    [ -n "$ept_free" ] || return 1
    if [ ! -x "$CFM_BIN" ]; then
        echo "cannot test-bind the IPv6 ports ($CFM_BIN missing)"
        return 0
    fi
    # shellcheck disable=SC2086
    if ept_out=$("$CFM_BIN" realip v6-bindcheck $ept_free 2>&1); then
        return 1
    fi
    case $ept_out in
        *"is taken"*) echo "$(printf '%s' "$ept_out" | tail -n 1): the edge could not start with an IPv6 listen there" ;;
        *) echo "cannot test-bind the IPv6 ports ($CFM_BIN realip v6-bindcheck:$(printf '%s' "$ept_out" | tail -n 1 | cut -c1-120 | sed 's/^/ /'))" ;;
    esac
    return 0
}

# realip_v6_trusted: `cfm realip` says the origin trusts the edge for the IPv6
# hop too. It is asked BEFORE the files are written (so no reload can catch the
# edge on IPv6 with an untrusting origin): a host that can do IPv6 already
# makes it require ::1 (internal/originrealip edgeIPv6: kernel IPv6 + the
# origin on IPv6 on 80 and 443, where EDGE_LISTEN_V6 allows it), and its JSON
# then says "edge_ipv6":true. A verdict without that key is from a
# cfm that does not know about the IPv6 hop: no verdict. 0 yes, 1 no, 2
# cannot tell.
realip_v6_trusted() {
    [ -x "$CFM_BIN" ] || return 2
    rvt_out=$("$CFM_BIN" realip --json 2>/dev/null)
    case $rvt_out in
        *'"edge_ipv6":true'*) ;;
        *) return 2 ;;
    esac
    case $rvt_out in
        *'"trusted":true'*) return 0 ;;
        *'"trusted":false'*) return 1 ;;
    esac
    return 2
}

# want_v6 MODE: 0 (yes), 1 (no), or 3 (no, for a readiness reason only: no
# global IPv6 address yet, or ss ran and showed no IPv6 origin listener; a
# prestart keeps approved files on it), with the reason on stdout. The ::1 trust is checked
# later, with the files in place (realip_v6_trusted).
want_v6() {
    case $1 in
        off)
            echo "EDGE_LISTEN_V6 is off (set EDGE_LISTEN_V6 = on in $CFM_CONF to allow IPv6; docs/edge-ipv6.md)"
            return 1
            ;;
    esac
    if ! kernel_has_v6; then
        echo "no IPv6 stack in the kernel ($CFM_V6_PROC_FILE absent)"
        return 1
    fi
    if wv_taken=$(edge_port_taken); then
        echo "$wv_taken"
        return 1
    fi
    if ! host_has_global_v6; then
        echo "no global IPv6 address on this host ($CFM_V6_PROC_FILE)"
        return 3
    fi
    for wv_port in 80 443; do
        origin_has_v6 "$wv_port"
        case $? in
            1)
                echo "the origin does not listen on IPv6 on $wv_port"
                return 3
                ;;
            2)
                echo "ss failed, cannot tell whether the origin listens on IPv6"
                return 1
                ;;
        esac
    done
    echo "the kernel has IPv6, the ports are free and the origin listens on IPv6 on 80 and 443"
    return 0
}

http_body() {
    printf '%s\n' "# generated by cfm (scripts/cfm-edge-listen-v6.sh); do not edit: see docs/edge-ipv6.md" \
        "listen [::]:$V6_HTTP_PORT;"
}
https_body() {
    printf '%s\n' "# generated by cfm (scripts/cfm-edge-listen-v6.sh); do not edit: see docs/edge-ipv6.md" \
        "listen [::]:$V6_HTTPS_PORT ssl;" \
        "listen [::]:$V6_HTTPS_PORT quic reuseport;"
}

# put_file DIR NAME BODYFN: write DIR/NAME atomically if its content differs.
# Returns 0 when it changed the file, 1 when it was already so, 2 on failure.
put_file() {
    pf_dst=$1/$2
    pf_tmp=$1/.$2.cfm-new.$$
    "$3" > "$pf_tmp" 2>/dev/null || { rm -f "$pf_tmp"; return 2; }
    if [ -f "$pf_dst" ] && [ "$(cat "$pf_dst")" = "$(cat "$pf_tmp")" ]; then
        rm -f "$pf_tmp"
        return 1
    fi
    chmod 0644 "$pf_tmp" 2>/dev/null
    mv -f "$pf_tmp" "$pf_dst" 2>/dev/null || { rm -f "$pf_tmp"; return 2; }
    return 0
}

# remove_files DIR: remove both; 0 when something was removed.
remove_files() {
    rf_changed=1
    for rf_name in $V6_HTTP_FILE $V6_HTTPS_FILE; do
        if [ -e "$1/$rf_name" ] || [ -L "$1/$rf_name" ]; then
            rm -f "$1/$rf_name" && rf_changed=0
        fi
    done
    return $rf_changed
}

# drop ENGINE DIR WHY: remove the files and say so (or that there were none).
drop() {
    if remove_files "$2"; then
        log "$1: IPv4 only ($3): removed the IPv6 listen files"
    else
        log "$1: IPv4 only ($3)"
    fi
}

# engine_test NAME BIN: the engine's own config test of its live config.
# cfm-edge's is wrapped (cfmedge_test_logs_snapshot / _drop): `nginx -t`
# creates every access_log/error_log file its config names.
engine_test() {
    if [ "$1" != cfm-edge ]; then
        "$2" -t -q >/dev/null 2>&1
        return
    fi
    cfmedge_test_logs_snapshot
    "$2" -t -q >/dev/null 2>&1
    et_rc=$?
    cfmedge_test_logs_drop
    return $et_rc
}

# The cfm-edge config test and its logs. On a node prepared with
# install-edge.sh whose live edge is still OpenResty or Angie, every edge start
# runs this script (prestart walks every engine, see the header), and with
# cfm-edge's IPv6 files in place it config-tests the idle cfm-edge: without
# this, each openresty/angie start left fresh EMPTY files in /var/log/cfm-edge,
# and internal/edgelog (the newest mtime wins) then read cfm-edge's empty logs
# instead of the live edge's (edge_error_tail, ip_forensics, whats_wrong).
# The rule is the package deploy's (package-proxy-config-deploy.sh
# snapshot_cfmedge_logs / cfm_edge_may_run / drop_test_created_cfmedge_logs)
# and install-edge.sh's: remember what was there before the test, then remove
# only the EMPTY regular files that were not, and nothing while cfm-edge may
# be running (its own new empty log is then the live one). A file that was
# already there, or one with content, is never touched. Test seam:
# CFM_CFMEDGE_LOG_DIR (the deploy's name).
CFM_CFMEDGE_LOG_DIR=${CFM_CFMEDGE_LOG_DIR:-/var/log/cfm-edge}
ctl_taken=0
cfmedge_test_logs_snapshot() {
    # The trailing / makes find list a symlinked log dir's files. No snapshot
    # (the dir missing or unreadable) means nothing is dropped afterwards.
    ctl_taken=0
    ctl_before=$(find "$CFM_CFMEDGE_LOG_DIR/" -maxdepth 1 -type f 2>/dev/null) && ctl_taken=1
}

# cfm_edge_may_run: true unless cfm-edge.service is plainly down and no
# cfm-edge process exists. `is-active --quiet` alone reads a unit that is
# still `activating` (or `reloading`, `deactivating`) as down, and a cfm-edge
# started after the snapshot holds its new, still-empty logs open: removing
# them would send its log lines to deleted files. A process outside systemd
# is found by its comm (as `pgrep -x cfm-edge` matches it; nginx's process
# title rewrites argv, never comm), read with the shell's own `read`, no fork
# per process.
cfm_edge_may_run() {
    case $("$CFM_SYSTEMCTL" is-active cfm-edge.service 2>/dev/null) in
        inactive | failed | unknown | "") ;;
        *) return 0 ;;
    esac
    for cmr_f in "$CFM_PROC_ROOT"/[0-9]*/comm; do
        [ -r "$cmr_f" ] || continue
        cmr_comm=""
        read -r cmr_comm <"$cmr_f" 2>/dev/null || true
        [ "$cmr_comm" = cfm-edge ] && return 0
    done
    return 1
}

cfmedge_test_logs_drop() {
    [ "$ctl_taken" -eq 1 ] || return 0
    ctl_taken=0
    ctl_new=""
    ctl_list=$(find "$CFM_CFMEDGE_LOG_DIR/" -maxdepth 1 -type f 2>/dev/null) || true
    # A name with a newline in it splits into pieces: only a piece that is a
    # direct entry of the log dir (and an empty regular file, no symlink) is
    # ever a candidate.
    ctl_nl='
'
    while IFS= read -r ctl_f; do
        case $ctl_f in
            "$CFM_CFMEDGE_LOG_DIR"/*/* | "") continue ;;
            "$CFM_CFMEDGE_LOG_DIR"/*) ;;
            *) continue ;;
        esac
        printf '%s\n' "$ctl_before" | grep -qxF -- "$ctl_f" && continue
        [ -f "$ctl_f" ] && [ ! -L "$ctl_f" ] && [ ! -s "$ctl_f" ] || continue
        ctl_new="$ctl_new$ctl_f$ctl_nl"
    done <<EOF_CTL
$ctl_list
EOF_CTL
    [ -n "$ctl_new" ] || return 0
    cfm_edge_may_run && return 0
    while IFS= read -r ctl_f; do
        [ -n "$ctl_f" ] || continue
        if rm -f -- "$ctl_f"; then
            log "cfm-edge: removed $ctl_f (empty, created by its config test; cfm-edge.service not active, no cfm-edge process)"
        fi
    done <<EOF_CTL
$ctl_new
EOF_CTL
    return 0
}

# main_includes MAINCONF: the live main config includes the IPv6 http file.
main_includes() {
    [ -f "$1" ] && grep -q '^[^#]*include[[:space:]].*cfm-listen-v6-http\.con' "$1" 2>/dev/null
}

# v6_listening: root IPv6 listeners on both edge tcp ports (/proc/net/tcp6).
v6_listening() {
    for vl_port in $V6_HTTP_PORT $V6_HTTPS_PORT; do
        awk -v hexport="$(printf '%04X' "$vl_port")" '
            NR > 1 && $4 == "0A" && $8 == "0" { n = split($2, a, ":"); if (n == 2 && toupper(a[2]) == hexport) f = 1 }
            END { exit f ? 0 : 1 }' "$CFM_PROC_ROOT/net/tcp6" 2>/dev/null || return 1
    done
    return 0
}

# reload_and_confirm ENGINE DIR WHY: a render that just wrote the files reloads
# a RUNNING edge at once, then checks it really listens on IPv6. Left for a
# later reload, the window lets another process take [::]:9080 first; every
# reload after that would fail to bind and nginx would silently keep its old
# config (certificates, panel listeners) until a restart. If the listen does
# not appear, the files are removed and the edge reloaded back.
reload_and_confirm() {
    rc_unit=$(unit_of "$1")
    if ! "$CFM_SYSTEMCTL" is-active --quiet "$rc_unit" 2>/dev/null; then
        log "$1: listening on IPv6 too ($3); config test passed ($rc_unit not running: applies at its next start)"
        return 0
    fi
    # Listeners already there before the reload (a hand-added listen, files
    # that existed with other content) would "confirm" a reload that failed:
    # then the listen proves nothing, and says so.
    rc_pre=0
    v6_listening && rc_pre=1
    if ! "$CFM_SYSTEMCTL" reload "$rc_unit" >/dev/null 2>&1; then
        log "WARNING: $1: systemctl reload $rc_unit failed; removed the IPv6 listen files (IPv4 only from its next successful reload or start)"
        remove_files "$2"
        return 0
    fi
    if [ "$rc_pre" -eq 1 ]; then
        log "$1: listening on IPv6 too ($3); reloaded $rc_unit (it listened on IPv6 before the reload, so the listen cannot confirm it: check the edge's error log)"
        return 0
    fi
    rc_i=0
    while [ "$rc_i" -lt "$CFM_V6_CONFIRM_TRIES" ]; do
        if v6_listening; then
            log "$1: listening on IPv6 too ($3); reloaded $rc_unit and it listens on [::]:$V6_HTTP_PORT and [::]:$V6_HTTPS_PORT"
            return 0
        fi
        rc_i=$((rc_i + 1))
        sleep 1
    done
    log "WARNING: $1: reloaded $rc_unit but it does not listen on IPv6 (a port taken meanwhile?); removed the IPv6 listen files and reloaded back, IPv4 only"
    remove_files "$2"
    "$CFM_SYSTEMCTL" reload "$rc_unit" >/dev/null 2>&1 || true
    re_reloaded=1
    return 0
}

# unit_of ENGINE: its systemd unit (OpenResty -> openresty.service).
unit_of() {
    printf '%s.service' "$(printf '%s' "$1" | tr 'A-Z' 'a-z')"
}

# reload_after_remove ENGINE: a render removed files a running edge was
# listening with: reload it now, or IPv6 visitors keep reaching an origin
# that (for one) no longer trusts ::1 until some later reload. Removing a
# listen cannot make a reload fail to bind.
reload_after_remove() {
    rar_unit=$(unit_of "$1")
    "$CFM_SYSTEMCTL" is-active --quiet "$rar_unit" 2>/dev/null || return 0
    if "$CFM_SYSTEMCTL" reload "$rar_unit" >/dev/null 2>&1; then
        log "$1: reloaded $rar_unit: it no longer listens on IPv6"
    else
        log "WARNING: $1: systemctl reload $rar_unit failed; it may still listen on IPv6 until its next reload or restart"
    fi
}

render_engine() {
    re_name=$1
    re_bin=$2
    re_dir=$3
    re_main=$4
    re_mode=$5
    re_action=$6

    if [ ! -d "$re_dir" ]; then
        log "$re_name: config dir $re_dir missing; skipping"
        return 0
    fi
    if ! main_includes "$re_main"; then
        drop "$re_name" "$re_dir" "its live main config $re_main does not include the IPv6 listen files"
        return 0
    fi
    if [ "$re_mode" != off ] && { [ -z "$re_bin" ] || [ ! -x "$re_bin" ]; }; then
        drop "$re_name" "$re_dir" "no engine binary (engine not installed?)"
        return 0
    fi
    re_kept=0
    [ "$re_action" != render ] && [ -f "$re_dir/$V6_HTTP_FILE" ] && [ -f "$re_dir/$V6_HTTPS_FILE" ] && re_kept=1
    re_reason=$(want_v6 "$re_mode")
    re_want=$?
    if [ "$re_want" -eq 3 ] && [ "$re_kept" -eq 1 ]; then
        # Not ready yet (boot): keep what the last render approved; the
        # config test still applies.
        re_reason="kept at start: $re_reason"
        re_want=0
    fi
    if [ "$re_want" -ne 0 ]; then
        drop "$re_name" "$re_dir" "$re_reason"
        return 0
    fi

    # The ::1 trust, asked before anything is written (see realip_v6_trusted).
    realip_v6_trusted
    re_trust=$?
    if [ "$re_trust" -eq 2 ] && [ "$re_kept" -eq 1 ]; then
        # No verdict at boot (cfm realip may read the origin before it runs):
        # keep what the last render approved. A definite "not trusted" (1) is
        # not readiness: it removes the files, or every IPv6 visitor would
        # reach the origin as ::1 (localhost) until the next render.
        log "$re_name: cfm realip gave no verdict at start; keeping the IPv6 listen files the last render approved"
        re_trust=0
    fi
    case $re_trust in
        0) ;;
        1)
            drop "$re_name" "$re_dir" "the origin does not trust the edge's IPv6 hop from ::1 (cfm realip); run: cfm realip fix"
            return 0
            ;;
        *)
            drop "$re_name" "$re_dir" "cannot tell whether the origin trusts ::1 ($CFM_BIN realip --json gave no IPv6-aware verdict)"
            return 0
            ;;
    esac

    if [ "$re_action" = deploy ] && [ "$re_kept" -eq 0 ]; then
        # The package deploy never turns IPv6 on: it must not reload the edge,
        # and files written without a reload leave a window for another
        # process to take the port (render reloads and confirms at once).
        log "$re_name: IPv4 only for now: IPv6 is allowed and the host is ready; turn it on with: sh $0 render (it reloads the edge)"
        return 0
    fi

    if [ "$re_action" = deploy ]; then
        # Kept files only, and never rewritten: a changed body would apply at
        # some later reload, the window render's reload-and-confirm closes.
        for re_pair in "$V6_HTTP_FILE http_body" "$V6_HTTPS_FILE https_body"; do
            if [ "$(cat "$re_dir/${re_pair%% *}" 2>/dev/null)" != "$(${re_pair#* })" ]; then
                log "$re_name: the IPv6 listen files differ from this version's; kept as they are: apply with: sh $0 render (it reloads the edge)"
                break
            fi
        done
        if engine_test "$re_name" "$re_bin"; then
            log "$re_name: listening on IPv6 too ($re_reason); kept, config test passed"
            return 0
        fi
        remove_files "$re_dir"
        log "WARNING: $re_name: the config test fails with the kept IPv6 listens; removed them (applies at the next reload)"
        return 0
    fi

    re_changed=0
    for re_pair in "$V6_HTTP_FILE http_body" "$V6_HTTPS_FILE https_body"; do
        # shellcheck disable=SC2086
        put_file "$re_dir" $re_pair
        case $? in
            0) re_changed=1 ;;
            2)
                drop "$re_name" "$re_dir" "cannot write ${re_pair%% *} in $re_dir"
                return 0
                ;;
        esac
    done

    if [ "$re_changed" -eq 0 ] && [ "$re_action" != prestart ]; then
        log "$re_name: listening on IPv6 too ($re_reason); files unchanged"
        return 0
    fi
    if engine_test "$re_name" "$re_bin"; then
        if [ "$re_action" = render ] && [ "$re_changed" -eq 1 ]; then
            reload_and_confirm "$re_name" "$re_dir" "$re_reason"
        else
            log "$re_name: listening on IPv6 too ($re_reason); config test passed (applies at the next start or reload)"
        fi
        return 0
    fi
    remove_files "$re_dir"
    if engine_test "$re_name" "$re_bin"; then
        log "WARNING: $re_name: the config test failed with the IPv6 listens; removed them, IPv4 only"
    else
        log "WARNING: $re_name: the config test fails with or without the IPv6 listens (not caused by them); left IPv4 only"
    fi
    return 0
}

status_engine() {
    se_live=no
    [ -f "$3/$V6_HTTP_FILE" ] && [ -f "$3/$V6_HTTPS_FILE" ] && se_live=yes
    if ! main_includes "$4"; then
        log "$1: IPv4 only (its live main config $4 does not include the IPv6 listen files); files present: $se_live"
        return 0
    fi
    se_reason=$(want_v6 "$5")
    se_want=$?
    if [ "$se_want" -eq 0 ]; then
        log "$1: wants IPv6 ($se_reason; the ::1 trust and the config test are checked when it renders); files present: $se_live"
    else
        log "$1: IPv4 only ($se_reason); files present: $se_live"
    fi
}

first_executable() {
    for fe in "$@"; do
        if [ -x "$fe" ]; then
            printf '%s\n' "$fe"
            return 0
        fi
    done
    return 1
}

engines() {
    if [ -n "${CFM_EDGE_ENGINES:-}" ]; then
        printf '%s\n' "$CFM_EDGE_ENGINES"
        return 0
    fi
    # An engine is listed when its binary OR its conf dir exists: a removed
    # engine's leftover files must still be cleaned up (they would keep
    # `cfm realip` demanding ::1); with no binary they are always removed.
    e_bin=$(first_executable /usr/local/openresty/nginx/sbin/nginx /usr/bin/openresty /usr/local/openresty/bin/openresty || true)
    if [ -n "$e_bin" ] || [ -d /usr/local/openresty/nginx/conf ]; then
        printf 'OpenResty|%s|%s|%s\n' "$e_bin" /usr/local/openresty/nginx/conf /usr/local/openresty/nginx/conf/nginx.conf
    fi
    e_bin=$(first_executable /usr/sbin/angie /sbin/angie || true)
    if [ -n "$e_bin" ] || [ -d /etc/angie ]; then
        printf 'Angie|%s|%s|%s\n' "$e_bin" /etc/angie /etc/angie/angie.conf
    fi
    # cfm-edge (chrismfz/cfm-edge): its unit is cfm-edge.service (unit_of).
    e_bin=$(first_executable /usr/sbin/cfm-edge || true)
    if [ -n "$e_bin" ] || [ -d /etc/cfm-edge ]; then
        printf 'cfm-edge|%s|%s|%s\n' "$e_bin" /etc/cfm-edge /etc/cfm-edge/nginx.conf
    fi
    return 0
}

main() {
    action=${1:-render}
    case $action in
        render | prestart | deploy | status) ;;
        mode)
            # Test seam: the EDGE_LISTEN_V6 reading alone (check_edge_listen_v6.sh).
            mode
            return 0
            ;;
        *)
            echo "usage: $0 [render|prestart|deploy|status]" >&2
            return 0
            ;;
    esac
    m=$(mode)
    engines | while IFS='|' read -r e_name e_bin e_dir e_main; do
        [ -n "$e_name" ] || continue
        if [ "$action" = status ]; then
            status_engine "$e_name" "$e_bin" "$e_dir" "$e_main" "$m"
        else
            e_had=0
            [ -f "$e_dir/$V6_HTTP_FILE" ] && e_had=1
            re_reloaded=0
            render_engine "$e_name" "$e_bin" "$e_dir" "$e_main" "$m" "$action"
            if [ "$e_had" -eq 1 ] && [ ! -f "$e_dir/$V6_HTTP_FILE" ]; then
                if [ "$action" = render ] && [ "$re_reloaded" -eq 0 ]; then
                    reload_after_remove "$e_name"
                elif [ "$action" = deploy ]; then
                    log "$e_name: removed IPv6 listen files a running edge may still listen with: reload it to apply (systemctl reload $(unit_of "$e_name"))"
                fi
            fi
        fi
    done
    return 0
}

main "$@"
exit 0

#!/bin/sh
# cfm-edge-listen-v6.sh — decide whether the edge (OpenResty / Angie) listens
# on IPv6, and write or remove the two listen sidecars the main config
# includes (docs/edge-ipv6.md):
#
#   <engine conf dir>/cfm-listen-v6-http.conf    listen [::]:9080;
#   <engine conf dir>/cfm-listen-v6-https.conf   listen [::]:9043 ssl; + quic
#
# configs/openresty.conf and configs/angie.conf include them through a glob
# (cfm-listen-v6-http.con[f]), so an ABSENT file is fine and means IPv4 only.
# That is the fail-safe state: anything unknown removes the files.
#
# Why it is not a static `listen [::]` in the reference conf: on a host
# without an IPv6 stack (ipv6.disable=1) that listen fails the config test and
# the edge does not start. So this runs before every edge start
# (cfm-edge-listen-v6.service, pulled in by a drop-in on openresty.service /
# angie.service) and from the package deploy, and decides from the host:
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
#     (udp) — `nginx -t` does not bind, so a taken port would pass the test
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
# here). It does not reload the edge: a change applies at the next start or
# reload.
#
# Usage: cfm-edge-listen-v6.sh [render|prestart|status]
#   render    (default; the package deploy, or by hand) decide and write/remove
#             the files for every engine found
#   prestart  (cfm-edge-listen-v6.service, before every edge start) the same,
#             except that files a render already approved are KEPT when the
#             only reasons against them are about readiness, which at boot are
#             often not there yet: no global IPv6 address yet (SLAAC / the
#             network still coming up), the origin not seen on IPv6 (it can
#             start after the edge), and `cfm realip` not confirming the ::1
#             trust (it cannot see the running origin yet). Otherwise a reboot
#             would silently put the edge back on IPv4 until the next render.
#             The reasons that would break the start, or that the operator
#             chose, still remove them: EDGE_LISTEN_V6 not allowing it, no IPv6 stack at all,
#             a taken port, ss failing, a main config without the include, a
#             failed config test. A change on the origin side for good (trust
#             removed, no more IPv6) keeps the edge's IPv6 until the next
#             render (package upgrade, or by hand), and `cfm realip` warns
#             meanwhile ("logs ::1 for every IPv6 visitor").
#   status    print the decision per engine, change nothing
#
# Test seams (scripts/tests/check_edge_listen_v6.sh): CFM_CONF,
# CFM_V6_PROC_FILE, CFM_SS, CFM_BIN, CFM_PROC_ROOT, CFM_EDGE_ENGINES
# ("Name|binary|confdir|mainconf" per line).

CFM_CONF=${CFM_CONF:-/etc/cfm/cfm.conf}
CFM_V6_PROC_FILE=${CFM_V6_PROC_FILE:-/proc/net/if_inet6}
CFM_SS=${CFM_SS:-ss}
CFM_BIN=${CFM_BIN:-/usr/bin/cfm}
CFM_PROC_ROOT=${CFM_PROC_ROOT:-/proc}

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
        m_val=$(sed -n 's/^[[:space:]]*EDGE_LISTEN_V6[[:space:]]*=[[:space:]]*//p' "$CFM_CONF" |
            sed 's/[[:space:]]*[;#].*$//; s/^"\(.*\)"$/\1/; s/^'"'"'\(.*\)'"'"'$/\1/; s/[[:space:]]*$//' |
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

# ss_v6_listeners PROTO PORT: from `ss -l<n><t|u>p`, print the owner of every
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

# owned_by_edge OWNERS: one of the processes holding the socket (name:pid,…)
# is the edge's master: named nginx / openresty / angie AND running as root
# (real uid 0 in /proc/PID/status). The name alone is not enough: any process
# can call itself "nginx" (/proc/self/comm, or exec a file of that name), and
# a tenant holding [::]:9080 under that name would otherwise make the script
# write a listen the edge then cannot bind, failing its whole start, IPv4
# included. A tenant cannot run as root. (Not the systemd cgroup: an edge
# master started by hand, as on rigel, lives in a session scope.)
owned_by_edge() {
    obe_list=$(printf '%s' "$1" | tr ',' ' ')
    for obe in $obe_list; do
        obe_name=${obe%%:*}
        obe_pid=${obe##*:}
        case $obe_name in nginx | openresty | angie) ;; *) continue ;; esac
        case $obe_pid in '' | *[!0-9]*) continue ;; esac
        obe_uid=$(awk '$1 == "Uid:" { print $2; exit }' "$CFM_PROC_ROOT/$obe_pid/status" 2>/dev/null)
        [ "$obe_uid" = 0 ] && return 0
    done
    return 1
}

# edge_port_taken: 0 when something other than the edge holds an IPv6
# listener on the edge's ports (see owned_by_edge), or ss could not tell; the
# reason on stdout.
edge_port_taken() {
    for ept in "tcp $V6_HTTP_PORT" "tcp $V6_HTTPS_PORT" "udp $V6_HTTPS_PORT"; do
        # shellcheck disable=SC2086
        ept_owners=$(ss_v6_listeners $ept) || {
            echo "ss failed: cannot tell whether ${ept#* }/${ept%% *} is free on IPv6"
            return 0
        }
        for ept_o in $ept_owners; do
            if ! owned_by_edge "$ept_o"; then
                echo "IPv6 ${ept%% *} port ${ept#* } is held by ${ept_o} (name:pid; - = unknown), not by the edge's root master: the edge could not start with it"
                return 0
            fi
        done
    done
    return 1
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
engine_test() {
    "$2" -t -q >/dev/null 2>&1
}

# main_includes MAINCONF: the live main config includes the IPv6 http file.
main_includes() {
    [ -f "$1" ] && grep -q '^[^#]*include[[:space:]].*cfm-listen-v6-http\.con' "$1" 2>/dev/null
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
    [ "$re_action" = prestart ] && [ -f "$re_dir/$V6_HTTP_FILE" ] && [ -f "$re_dir/$V6_HTTPS_FILE" ] && re_kept=1
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
    if [ "$re_trust" -ne 0 ] && [ "$re_kept" -eq 1 ]; then
        # At boot cfm realip may read the origin before it runs; keep what the
        # last render approved (cfm realip warns if the trust is really gone).
        log "$re_name: cfm realip could not confirm the ::1 trust at start; keeping the IPv6 listen files the last render approved"
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
        log "$re_name: listening on IPv6 too ($re_reason); config test passed (applies at the next start or reload)"
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
    return 0
}

main() {
    action=${1:-render}
    case $action in
        render | prestart | status) ;;
        *)
            echo "usage: $0 [render|prestart|status]" >&2
            return 0
            ;;
    esac
    m=$(mode)
    engines | while IFS='|' read -r e_name e_bin e_dir e_main; do
        [ -n "$e_name" ] || continue
        if [ "$action" = status ]; then
            status_engine "$e_name" "$e_bin" "$e_dir" "$e_main" "$m"
        else
            render_engine "$e_name" "$e_bin" "$e_dir" "$e_main" "$m" "$action"
        fi
    done
    return 0
}

main "$@"
exit 0

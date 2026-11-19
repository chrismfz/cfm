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
#   [cfm.conf] EDGE_LISTEN_V6 = auto (default) | on | off
#     off   never listen on IPv6 (files removed)
#     auto  listen when the kernel has an IPv6 stack (/proc/net/if_inet6)
#           AND the origin listens on IPv6 on both 80 and 443 (ss): the
#           origin hop of an IPv6 visitor goes to the IPv6 address it came to
#     on    listen whenever the kernel has an IPv6 stack (origin not checked)
#
# After any change it runs the engine's own config test and, if that fails
# with the IPv6 files in place, removes them again. It never fails its caller:
# the exit status is always 0 (the edge must start, on IPv4, whatever happens
# here). It does not reload the edge: a change applies at the next start or
# reload.
#
# Usage: cfm-edge-listen-v6.sh [render|prestart|status]
#   render    (default; the package deploy, or by hand) decide and write/remove
#             the files for every engine found
#   prestart  (cfm-edge-listen-v6.service, before every edge start) the same,
#             except that "the origin is not listening on IPv6" never REMOVES
#             files that are already there: at boot the edge can start before
#             Apache/LiteSpeed, and that would drop IPv6 until the next
#             restart. The safety reasons (off, no IPv6 stack, a failed config
#             test) still remove them.
#   status    print the decision per engine, change nothing
#
# Test seams (scripts/tests/check_edge_listen_v6.sh): CFM_CONF,
# CFM_V6_PROC_FILE, CFM_SS, CFM_EDGE_ENGINES ("Name|binary|confdir" per line).

CFM_CONF=${CFM_CONF:-/etc/cfm/cfm.conf}
CFM_V6_PROC_FILE=${CFM_V6_PROC_FILE:-/proc/net/if_inet6}
CFM_SS=${CFM_SS:-ss}

# The edge's listener ports (configs/openresty.conf / angie.conf `listen 9080;`
# and `listen 9043 ssl;`). check_edge_listen_v6.sh pins them to the confs.
V6_HTTP_PORT=9080
V6_HTTPS_PORT=9043

V6_HTTP_FILE=cfm-listen-v6-http.conf
V6_HTTPS_FILE=cfm-listen-v6-https.conf

log() { echo "CFM edge IPv6 listen: $*"; }

# mode: EDGE_LISTEN_V6 from cfm.conf, the last uncommented line wins. A value
# that is not off/auto/on reads as off (an unknown never turns a listen on).
mode() {
    m_val=""
    if [ -r "$CFM_CONF" ]; then
        m_val=$(sed -n 's/^[[:space:]]*EDGE_LISTEN_V6[[:space:]]*=[[:space:]]*//p' "$CFM_CONF" |
            sed 's/[[:space:]]*[;#].*$//; s/^"\(.*\)"$/\1/; s/^'"'"'\(.*\)'"'"'$/\1/; s/[[:space:]]*$//' |
            tail -n 1 | tr 'A-Z' 'a-z')
    fi
    case $m_val in
        "") echo auto ;;
        off | auto | on) echo "$m_val" ;;
        *)
            log "WARNING: EDGE_LISTEN_V6 = \"$m_val\" in $CFM_CONF is not off/auto/on; treating it as off" >&2
            echo off
            ;;
    esac
}

# kernel_has_v6: the IPv6 stack is loaded (the file is absent with
# ipv6.disable=1). net.ipv6.conf.*.disable_ipv6=1 keeps the file and a
# [::] bind still works, so it is not a reason to skip.
kernel_has_v6() {
    [ -e "$CFM_V6_PROC_FILE" ]
}

# origin_has_v6 PORT: something listens on an IPv6 address other than ::1 on
# PORT (the origin: the edge itself is on 9080/9043). `[::]:80`, a specific
# `[2001:db8::1]:80`, or `*:80` (a dual-stack socket). A missing or failing ss
# is an unknown, which reads as NO.
origin_has_v6() {
    ohv_out=$("$CFM_SS" -ltn 2>/dev/null) || return 1
    printf '%s\n' "$ohv_out" | awk -v port="$1" '
        NR == 1 && $1 == "State" { next }
        {
            a = $4
            n = length(port) + 1
            if (substr(a, length(a) - n + 1) != ":" port) next
            h = substr(a, 1, length(a) - n)
            if (h == "*" || (h ~ /^\[.*\]$/ && h != "[::1]" && h !~ /^\[::ffff:/)) { found = 1 }
        }
        END { exit found ? 0 : 1 }'
}

# want_v6 MODE: 0 (yes), 1 (no), or 3 (no, only because the origin was not
# seen listening on IPv6), with the reason on stdout.
want_v6() {
    case $1 in
        off)
            echo "EDGE_LISTEN_V6 = off"
            return 1
            ;;
    esac
    if ! kernel_has_v6; then
        echo "no IPv6 stack in the kernel ($CFM_V6_PROC_FILE absent)"
        return 1
    fi
    if [ "$1" = on ]; then
        echo "EDGE_LISTEN_V6 = on and the kernel has IPv6"
        return 0
    fi
    if ! origin_has_v6 80 || ! origin_has_v6 443; then
        echo "auto: the origin does not listen on IPv6 on both 80 and 443 (or ss is unavailable)"
        return 3
    fi
    echo "auto: the kernel has IPv6 and the origin listens on IPv6 on 80 and 443"
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

# engine_test NAME BIN: the engine's own config test of its live config.
engine_test() {
    "$2" -t -q >/dev/null 2>&1
}

render_engine() {
    re_name=$1
    re_bin=$2
    re_dir=$3
    re_mode=$4
    re_action=$5

    if [ ! -d "$re_dir" ]; then
        log "$re_name: config dir $re_dir missing; skipping"
        return 0
    fi
    re_reason=$(want_v6 "$re_mode")
    re_want=$?

    if [ "$re_want" -eq 3 ] && [ "$re_action" = prestart ] &&
        [ -f "$re_dir/$V6_HTTP_FILE" ] && [ -f "$re_dir/$V6_HTTPS_FILE" ]; then
        # The origin may simply not be up yet (boot): keep the decision the
        # last full render made, but still prove the config tests with it.
        re_reason="kept at start: $re_reason"
        re_want=0
    fi
    if [ "$re_want" -ne 0 ]; then
        if remove_files "$re_dir"; then
            log "$re_name: IPv4 only ($re_reason): removed the IPv6 listen files"
        else
            log "$re_name: IPv4 only ($re_reason)"
        fi
        return 0
    fi

    re_changed=0
    for re_pair in "$V6_HTTP_FILE http_body" "$V6_HTTPS_FILE https_body"; do
        # shellcheck disable=SC2086
        put_file "$re_dir" $re_pair
        case $? in
            0) re_changed=1 ;;
            2)
                log "WARNING: $re_name: cannot write ${re_pair%% *} in $re_dir; staying on IPv4 only"
                remove_files "$re_dir"
                return 0
                ;;
        esac
    done
    if [ "$re_changed" -eq 0 ] && [ "$re_action" != prestart ]; then
        log "$re_name: listening on IPv6 too ($re_reason); files unchanged"
        return 0
    fi
    if [ -z "$re_bin" ] || [ ! -x "$re_bin" ]; then
        log "WARNING: $re_name: no engine binary to test the config with; staying on IPv4 only"
        remove_files "$re_dir"
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
    se_reason=$(want_v6 "$4")
    se_want=$?
    se_live=no
    [ -f "$3/$V6_HTTP_FILE" ] && [ -f "$3/$V6_HTTPS_FILE" ] && se_live=yes
    if [ "$se_want" -eq 0 ]; then
        log "$1: wants IPv6 ($se_reason); files present: $se_live"
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
    e_bin=$(first_executable /usr/local/openresty/nginx/sbin/nginx /usr/bin/openresty /usr/local/openresty/bin/openresty || true)
    [ -n "$e_bin" ] && printf 'OpenResty|%s|%s\n' "$e_bin" /usr/local/openresty/nginx/conf
    e_bin=$(first_executable /usr/sbin/angie /sbin/angie || true)
    [ -n "$e_bin" ] && printf 'Angie|%s|%s\n' "$e_bin" /etc/angie
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
    engines | while IFS='|' read -r e_name e_bin e_dir; do
        [ -n "$e_name" ] || continue
        if [ "$action" = status ]; then
            status_engine "$e_name" "$e_bin" "$e_dir" "$m"
        else
            render_engine "$e_name" "$e_bin" "$e_dir" "$m" "$action"
        fi
    done
    return 0
}

main "$@"
exit 0

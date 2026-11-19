#!/usr/bin/env bash
# check_logrotate_coverage.sh — verify every log file CFM writes gets rotated.
#
# Two modes:
#
#   (no args)   repo/CI mode. Extracts every log path CFM configures (edge
#               access_log/error_log, Apache CustomLog, *_LOG_FILE keys in
#               cfm.conf, the systemd stdout/stderr files, the rsyslog LSM
#               target) and asserts each one is either covered by
#               configs/logrotate-cfm or lives in a directory documented as
#               vendor-rotated. Also asserts we never list a vendor-globbed
#               path ourselves — logrotate rejects duplicate entries.
#
#   --host      live-server mode. Same path list, but checked against the
#               actual /etc/logrotate.d on this machine, with on-disk sizes,
#               so you can see at a glance what is and is not rotated.
#
# Exit non-zero when a configured log path has no rotation.

set -uo pipefail

REPO_ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/../.." && pwd)"
CONFIGS="$REPO_ROOT/configs"
OURS="$CONFIGS/logrotate-cfm"

# Directories rotated by somebody else's logrotate config. Adding any of these
# to configs/logrotate-cfm produces "duplicate log entry for ..." and breaks
# the run instead of adding rotation. Keep in sync with the header comment in
# configs/logrotate-cfm.
VENDOR_DIRS=(
    /var/log/angie
    /var/log/cfm-edge
    /var/log/nginx
    /var/log/apache2
    /var/log/httpd
    /usr/local/apache/logs
)

red()  { printf '\033[31m%s\033[0m\n' "$*"; }
grn()  { printf '\033[32m%s\033[0m\n' "$*"; }
ylw()  { printf '\033[33m%s\033[0m\n' "$*"; }

# ---------------------------------------------------------------------------
# Collect every log path CFM configures.
# Commented-out directives count: they are documented opt-ins an operator can
# enable, and a path that is rotated only when someone remembers to update
# this file is exactly the failure we are guarding against.
# ---------------------------------------------------------------------------
collect_configured_paths() {
    {
        # nginx/OpenResty/Angie access_log + error_log
        grep -rhoE '^[[:space:]]*#?[[:space:]]*(access_log|error_log)[[:space:]]+(/[^[:space:];]+)' \
            "$CONFIGS"/*.conf 2>/dev/null |
            grep -oE '/[^[:space:];]+'

        # Apache CustomLog / ErrorLog
        grep -rhoE '^[[:space:]]*#?[[:space:]]*(CustomLog|ErrorLog)[[:space:]]+(/[^[:space:]]+)' \
            "$CONFIGS"/*.conf 2>/dev/null |
            grep -oE '/[^[:space:]]+'

        # cfm.conf log-file keys (quoted or bare)
        grep -rhoE '^[[:space:]]*[A-Z_]*LOG_FILE[[:space:]]*=[[:space:]]*"?/[^"[:space:];#]+' \
            "$CONFIGS"/cfm.conf 2>/dev/null |
            grep -oE '/[^"[:space:];#]+'

        # systemd stdout/stderr capture
        grep -rhoE 'Standard(Output|Error)=append:/[^[:space:]]+' \
            "$CONFIGS"/cfm.service 2>/dev/null |
            grep -oE '/[^[:space:]]+'

        # rsyslog LSM sink
        grep -rhoE '^[^#]*[[:space:]]/var/log/cfm/[^[:space:]]+' \
            "$CONFIGS"/rsyslog/*.conf 2>/dev/null |
            grep -oE '/var/log/cfm/[^[:space:]]+'

        # Go-side defaults: paths the daemon falls back to when the matching
        # cfm.conf key is absent (e.g. SMTP_LOG_FILE) plus legacy locations the
        # status API still reads. These never appear in configs/, so a
        # configs-only scan misses them — that is how /var/log/cfm.smtp.log
        # went unrotated.
        grep -rhoE '"/var/log/cfm[./][^"]*\.log"' \
            --include="*.go" "$REPO_ROOT/internal" "$REPO_ROOT/cmd" 2>/dev/null |
            tr -d '"'
    } |
        # Filter by what a path IS, not by its extension. An earlier version
        # kept only *.log / *_log, which meant a log file named anything else
        # (say /var/log/cfm/audit.json) was invisible to this check AND to the
        # *.log globs in configs/logrotate-cfm — uncovered, with nothing
        # failing. /dev/stdout and friends are the only real non-files here;
        # `access_log off` and `syslog:...` never start with / so they are
        # already excluded by the patterns above.
        grep -vE '^/dev/' |
        sort -u
}

# ---------------------------------------------------------------------------
# Parse the path patterns out of a logrotate config file: every token starting
# with / that appears before the opening brace of a block.
# ---------------------------------------------------------------------------
logrotate_patterns() {
    local file="$1"
    [ -r "$file" ] || return 0
    # Strip comments, then keep lines outside { ... } bodies.
    awk '
        { sub(/#.*/, "") }
        /\{/ { inblock = 1 }
        /\}/ { inblock = 0; next }
        {
            line = $0
            if (inblock && line !~ /\{/) next
            sub(/\{.*/, "", line)
            n = split(line, tok, /[[:space:]]+/)
            for (i = 1; i <= n; i++)
                if (substr(tok[i], 1, 1) == "/") print tok[i]
        }
    ' "$file"
}

path_matches_any() {
    local path="$1"; shift
    local pat
    for pat in "$@"; do
        # shellcheck disable=SC2053  # glob match is the point
        [[ "$path" == $pat ]] && return 0
    done
    return 1
}

in_vendor_dir() {
    local path="$1" dir
    for dir in "${VENDOR_DIRS[@]}"; do
        [[ "$path" == "$dir"/* ]] && return 0
    done
    return 1
}

# ---------------------------------------------------------------------------
# configs/cfm-logrotate.cron TSV step: run it against a temp tree. It deletes
# only cPanel's dated copies older than a day, keeps a distro logrotate
# generation and an operator's own copy, keeps one compressed copy of an
# oversized live file and truncates it, and runs even when logrotate-cfm is
# absent (a node without an edge).
# ---------------------------------------------------------------------------
cron_tsv_selftest() {
    local cron="$REPO_ROOT/configs/cfm-logrotate.cron" d f rc=0
    d=$(mktemp -d)
    f="$d/access_cfm_tsv.log"
    head -c 2000 /dev/zero > "$f"
    : > "$f.2026_11_10";    touch -d '3 days ago' "$f.2026_11_10"
    : > "$f.2026_11_10.01"; touch -d '3 days ago' "$f.2026_11_10.01"
    : > "$f.2026_11_17"
    : > "$f.1.gz";          touch -d '3 days ago' "$f.1.gz"
    : > "$f.incident";      touch -d '3 days ago' "$f.incident"
    CFM_TSV_LOGS="$f" CFM_TSV_MAX_BYTES=1000 CFM_LOGROTATE_CONF="$d/none" sh "$cron" || rc=1
    [ ! -e "$f.2026_11_10" ] && [ ! -e "$f.2026_11_10.01" ] || { red "FAIL: cron kept a cPanel copy older than a day"; rc=1; }
    [ -e "$f.2026_11_17" ] || { red "FAIL: cron deleted a cPanel copy younger than a day"; rc=1; }
    [ -e "$f.1.gz" ] && [ -e "$f.incident" ] || { red "FAIL: cron deleted a file that is not a cPanel dated copy"; rc=1; }
    [ "$(stat -c %s "$f")" -eq 0 ] || { red "FAIL: cron did not truncate the oversized live log"; rc=1; }
    [ "$(gzip -dc "$f.cfm-prev.gz" 2>/dev/null | wc -c)" -eq 2000 ] || { red "FAIL: cron did not keep the live log as .cfm-prev.gz"; rc=1; }
    rm -rf "$d"
    [ "$rc" -eq 0 ] && grn "OK: cfm-logrotate.cron TSV step (temp tree)."
    return "$rc"
}

# ---------------------------------------------------------------------------
# configs/cfm-logrotate.cron hourly pass: it hands logrotate the cfm-edge
# package's own config too (its `maxsize` needs the hourly pass, and the
# package rotates /var/log/cfm-edge itself, so logrotate-cfm must not), but
# only when that file exists. A fake logrotate on PATH records its arguments.
# ---------------------------------------------------------------------------
cron_edge_conf_selftest() {
    local cron="$REPO_ROOT/configs/cfm-logrotate.cron" d rc=0
    d=$(mktemp -d)
    mkdir -p "$d/bin"
    printf '#!/bin/sh\nprintf "%%s\\n" "$@" > "%s/args"\n' "$d" > "$d/bin/logrotate"
    chmod +x "$d/bin/logrotate"
    : > "$d/logrotate-cfm"
    PATH="$d/bin:$PATH" CFM_TSV_LOGS="$d/none.log" CFM_LOGROTATE_CONF="$d/logrotate-cfm" \
        CFM_EDGE_LOGROTATE_CONF="$d/cfm-edge" sh "$cron" || rc=1
    [ "$(cat "$d/args" 2>/dev/null)" = "$d/logrotate-cfm" ] || { red "FAIL: without /etc/logrotate.d/cfm-edge the hourly pass must run logrotate-cfm alone"; rc=1; }
    : > "$d/cfm-edge"
    PATH="$d/bin:$PATH" CFM_TSV_LOGS="$d/none.log" CFM_LOGROTATE_CONF="$d/logrotate-cfm" \
        CFM_EDGE_LOGROTATE_CONF="$d/cfm-edge" sh "$cron" || rc=1
    [ "$(cat "$d/args" 2>/dev/null)" = "$(printf '%s\n%s' "$d/logrotate-cfm" "$d/cfm-edge")" ] || { red "FAIL: with cfm-edge installed the hourly pass must also run its logrotate config"; rc=1; }
    rm -rf "$d"
    [ "$rc" -eq 0 ] && grn "OK: cfm-logrotate.cron runs cfm-edge's own config hourly when present."
    return "$rc"
}

# ---------------------------------------------------------------------------
# Repo / CI mode
# ---------------------------------------------------------------------------
repo_mode() {
    local fail=0
    local -a ours
    mapfile -t ours < <(logrotate_patterns "$OURS")

    if [ "${#ours[@]}" -eq 0 ]; then
        red "FAIL: no log patterns parsed out of $OURS"
        return 1
    fi

    echo "== configs/logrotate-cfm covers =="
    printf '  %s\n' "${ours[@]}"
    echo

    # 1. We must not claim a vendor-owned path (logrotate duplicate entry).
    local pat
    for pat in "${ours[@]}"; do
        if in_vendor_dir "$pat"; then
            red "FAIL: $pat is in a vendor-rotated directory."
            red "      logrotate errors with 'duplicate log entry' when two configs"
            red "      list the same file. Drop it and verify with --host instead."
            fail=1
        fi
    done

    # 2. Every configured log path must be covered by us or by a vendor.
    echo "== configured log paths =="
    local p status
    while read -r p; do
        [ -n "$p" ] || continue
        if path_matches_any "$p" "${ours[@]}"; then
            status="cfm"
            printf '  %-52s %s\n' "$p" "logrotate-cfm"
        elif in_vendor_dir "$p"; then
            status="vendor"
            printf '  %-52s %s\n' "$p" "vendor logrotate (verify with --host)"
        else
            status="none"
            printf '  %-52s %s\n' "$p" "NOT ROTATED"
            fail=1
        fi
    done < <(collect_configured_paths)
    echo

    if [ "$fail" -ne 0 ]; then
        red "FAIL: at least one CFM log path has no rotation."
        red "      Add it to configs/logrotate-cfm, or — if its directory is"
        red "      rotated by the distro/panel package — to VENDOR_DIRS here and"
        red "      to the header comment in configs/logrotate-cfm."
        return 1
    fi

    grn "OK: every configured CFM log path is rotated."
    cron_tsv_selftest || return 1
    cron_edge_conf_selftest || return 1
    return 0
}

# ---------------------------------------------------------------------------
# Live host mode
# ---------------------------------------------------------------------------
host_mode() {
    local fail=0
    local -a host_pats=() src_files=()
    local f

    # Overridable so the check can be exercised against a fixture directory.
    local lrd="${CFM_LOGROTATE_D:-/etc/logrotate.d}"

    shopt -s nullglob
    for f in "$lrd"/* /etc/logrotate.conf; do
        [ -f "$f" ] || continue
        local -a p
        mapfile -t p < <(logrotate_patterns "$f")
        local one
        for one in "${p[@]}"; do
            host_pats+=("$one")
            src_files+=("$f")
        done
    done
    shopt -u nullglob

    if [ "${#host_pats[@]}" -eq 0 ]; then
        red "No logrotate configuration found under $lrd — nothing rotates."
        fail=1
    fi

    printf '%-52s %-10s %s\n' "LOG PATH" "SIZE" "ROTATED BY"
    printf '%-52s %-10s %s\n' "--------" "----" "----------"

    local p size i
    local -a dups=()
    while read -r p; do
        [ -n "$p" ] || continue
        if [ -e "$p" ]; then
            size="$(du -h "$p" 2>/dev/null | cut -f1)"
        else
            size="-"
        fi

        # Collect EVERY config that claims this path, not just the first: two
        # configs declaring the same file is a hard logrotate error
        # ("duplicate log entry"), and comparing raw patterns would miss it —
        # /var/log/angie/*.log and /var/log/angie/access.log are different
        # strings that collide once logrotate expands the glob.
        local -a owners=()
        for i in "${!host_pats[@]}"; do
            # shellcheck disable=SC2053  # glob match is the point
            if [[ "$p" == ${host_pats[$i]} ]]; then
                owners+=("$(basename "${src_files[$i]}")")
            fi
        done

        if [ "${#owners[@]}" -gt 1 ]; then
            printf '%-52s %-10s %s\n' "$p" "$size" "DUPLICATE: ${owners[*]}"
            dups+=("$p")
            fail=1
        elif [ "${#owners[@]}" -eq 1 ]; then
            printf '%-52s %-10s %s\n' "$p" "$size" "${owners[0]}"
        elif [ -e "$p" ]; then
            # Only a log that actually exists on this host is a live problem.
            printf '%-52s %-10s %s\n' "$p" "$size" "*** NOT ROTATED ***"
            fail=1
        else
            printf '%-52s %-10s %s\n' "$p" "$size" "not rotated (file absent)"
        fi
    done < <(collect_configured_paths)

    echo
    if [ "${#dups[@]}" -gt 0 ]; then
        red "Declared by more than one logrotate config. logrotate reports"
        red "'duplicate log entry' and aborts the run, so these do not rotate:"
        printf '  %s\n' "${dups[@]}"
        echo
    fi

    # A path logrotate.service may not write is "covered" yet never rotated:
    # EL9 runs it with ProtectSystem=full, /usr read-only, and the OpenResty
    # logs live under /usr/local (configs/cfm-logrotate-systemd.conf).
    # Only where the logs really are under a tree ProtectSystem makes read-only
    # (a logs dir symlinked into /var/log needs nothing), and any listed entry
    # that is that dir or a parent of it opens it.
    local orlogs=/usr/local/openresty/nginx/logs real ps rw e ok
    real="$(readlink -f "$orlogs" 2>/dev/null)"
    if [ -n "$real" ] && [ -d "$real" ] && command -v systemctl >/dev/null 2>&1; then
        ps="$(systemctl show logrotate.service -p ProtectSystem --value 2>/dev/null)"
        rw="$(systemctl show logrotate.service -p ReadWritePaths --value 2>/dev/null)"
        case "$ps:$real" in
            full:/usr/*|full:/boot/*|full:/efi/*|full:/etc/*|strict:/*|yes:/usr/*|yes:/boot/*|yes:/efi/*)
                ok=0
                for e in $rw; do
                    e="${e#[-+]}"
                    case "$real/" in "${e%/}/"*) ok=1 ;; esac
                done
                if [ "$ok" -eq 0 ]; then
                    red "logrotate.service has ProtectSystem=$ps and nothing in ReadWritePaths opens $real:"
                    red "the daily run cannot rotate the OpenResty logs (Read-only file system)."
                    red "Install /etc/systemd/system/logrotate.service.d/cfm-openresty.conf"
                    red "(configs/cfm-logrotate-systemd.conf) and run systemctl daemon-reload."
                    echo
                    fail=1
                fi
                ;;
        esac
    fi

    echo "Dry-run the CFM config with:"
    echo "  logrotate -d $lrd/logrotate-cfm"
    echo

    if [ "$fail" -ne 0 ]; then
        red "FAIL: some CFM logs on this host are not rotated."
        return 1
    fi
    grn "OK: every CFM log present on this host is covered by a logrotate config."
    return 0
}

case "${1:-}" in
    --host) host_mode ;;
    "")     repo_mode ;;
    *)
        echo "usage: $0 [--host]" >&2
        exit 2
        ;;
esac

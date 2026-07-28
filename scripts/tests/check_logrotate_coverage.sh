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

# lib.sh — shared helpers for the cfm-lsm PoC harness.
#
# Sourced by run-all.sh and by each scenarios/*.sh directly so a
# scenario can be re-run standalone for debugging. No side effects on
# source — everything is functions / variable defaults.

# Defaults. Each can be overridden via environment.
: "${LSM_LOG:=/var/log/cfm/lsm.log}"
: "${TEST_USER:=cfmpoc}"
: "${TEST_UID:=}"          # auto-allocated by ensure_test_user when empty
: "${POC_TMPDIR:=/tmp/cfmpoc}"
: "${HELPERS_DIR:=}"       # set by run-all.sh; scenarios resolve relative
: "${LISTENER_PORT:=4444}"
: "${EXPECT_TIMEOUT:=10}"
: "${VERBOSE:=0}"

# Resolve HELPERS_DIR if a scenario is invoked standalone (run-all.sh sets it).
if [ -z "$HELPERS_DIR" ]; then
    _lib_dir="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
    HELPERS_DIR="$_lib_dir/helpers"
fi

# Colour codes — fall back to no colour when stdout is not a TTY.
if [ -t 1 ]; then
    C_RED=$'\033[31m'
    C_GREEN=$'\033[32m'
    C_YELLOW=$'\033[33m'
    C_BOLD=$'\033[1m'
    C_RESET=$'\033[0m'
else
    C_RED=""
    C_GREEN=""
    C_YELLOW=""
    C_BOLD=""
    C_RESET=""
fi

# logging primitives — every scenario uses these for uniform output.
say()  { printf '%s\n' "$*"; }
note() { printf '%s%s%s\n' "$C_BOLD" "$*" "$C_RESET"; }
warn() { printf '%s[warn]%s %s\n' "$C_YELLOW" "$C_RESET" "$*" >&2; }
fail() { printf '%s[FAIL]%s %s\n' "$C_RED"    "$C_RESET" "$*" >&2; }
pass() { printf '%s[PASS]%s %s\n' "$C_GREEN"  "$C_RESET" "$*"; }
trace() { [ "$VERBOSE" -ge 1 ] && printf '%s+ %s%s\n' "$C_YELLOW" "$*" "$C_RESET" >&2 || true; }

# require_root — bail unless euid is 0.
require_root() {
    if [ "$(id -u)" -ne 0 ]; then
        fail "this harness must run as root (need to su to a watched uid, drop setuid binaries, etc)"
        exit 2
    fi
}

# require_cfm_lsm_monitor — verify cfm-lsm is loaded and not in enforce
# mode (enforce mode blocks the syscall, which makes "did the rule
# fire" verification unreliable from userspace).
require_cfm_lsm_monitor() {
    if [ ! -e "$LSM_LOG" ]; then
        fail "$LSM_LOG does not exist — is cfm-lsm enabled? Try 'cfm lsm enable'."
        exit 2
    fi
    if ! command -v cfm >/dev/null 2>&1; then
        warn "cfm CLI not on PATH; skipping enforce-mode preflight"
        return 0
    fi
    if [ "${ALLOW_ENFORCE:-0}" = "1" ]; then
        return 0
    fi
    # cfm lsm status emits a human table; grep for "enforce" lines that
    # are not the conf header.
    if cfm lsm status 2>/dev/null | grep -qE 'mode=enforce|\(enforce\)'; then
        fail "one or more policies are in enforce mode — pass --allow-enforce to override"
        exit 2
    fi
}

# ensure_test_user — create a low-uid throwaway user that the
# web-class scenarios run as. Idempotent.
#
# Picks an unused uid ≥ 1000 if TEST_UID is unset so the user falls
# into the watched-uid fallback range without colliding with a real
# account. Tracks "we created this" in /var/run/cfmpoc.created so
# cleanup_test_user only deletes users we owned.
ensure_test_user() {
    if id -u "$TEST_USER" >/dev/null 2>&1; then
        return 0
    fi
    if [ -z "$TEST_UID" ]; then
        # Find an unused uid in [1500, 1599]. Avoids 1000 (often the
        # primary admin) and keeps the range tight for readability.
        for candidate in $(seq 1500 1599); do
            if ! getent passwd "$candidate" >/dev/null; then
                TEST_UID="$candidate"
                break
            fi
        done
        if [ -z "$TEST_UID" ]; then
            fail "no free uid in 1500-1599 — set TEST_UID explicitly"
            exit 2
        fi
    fi
    useradd -u "$TEST_UID" -M -N -s /bin/bash "$TEST_USER" >/dev/null
    mkdir -p /var/run
    : > /var/run/cfmpoc.created
    trace "created throwaway user $TEST_USER (uid=$TEST_UID)"
}

cleanup_test_user() {
    if [ -f /var/run/cfmpoc.created ] && id -u "$TEST_USER" >/dev/null 2>&1; then
        userdel "$TEST_USER" 2>/dev/null || true
        rm -f /var/run/cfmpoc.created
    fi
}

# ensure_tmpdir — per-run scratch directory. Cleaned on harness exit.
ensure_tmpdir() {
    mkdir -p "$POC_TMPDIR"
    chmod 1777 "$POC_TMPDIR"
}

cleanup_tmpdir() {
    if [ -d "$POC_TMPDIR" ]; then
        rm -rf "$POC_TMPDIR" 2>/dev/null || true
    fi
}

# mark_log_position — snapshot how many lines lsm.log has right now.
# expect_event reads only lines added after this mark, so we don't
# false-pass on stale events left by other PoCs in the same run.
mark_log_position() {
    if [ -e "$LSM_LOG" ]; then
        wc -l < "$LSM_LOG" | awk '{print $1}'
    else
        echo 0
    fi
}

# expect_event POLICY_ID [PID_HINT]
#
# Tails lsm.log starting from the line index in $1 (the value returned
# by mark_log_position before the trigger ran) and waits up to
# EXPECT_TIMEOUT seconds for a line matching:
#   policy=POLICY_ID
# When PID_HINT is given, the matched line must contain pid=PID_HINT
# too — that prevents false-passes from concurrent unrelated events
# during the wait window.
#
# Returns 0 on match, 1 on timeout, 2 on bad args.
expect_event() {
    local start_pos="$1"
    local policy="$2"
    local pid_hint="${3:-}"
    if [ -z "$start_pos" ] || [ -z "$policy" ]; then
        warn "expect_event: bad args (start_pos=$start_pos policy=$policy)"
        return 2
    fi
    local deadline=$(( $(date +%s) + EXPECT_TIMEOUT ))
    local needle="policy=$policy"
    while [ "$(date +%s)" -lt "$deadline" ]; do
        if [ -e "$LSM_LOG" ]; then
            # tail -n +N is 1-indexed; start_pos is a line count so we
            # want the (count+1)-th line onward.
            local hit
            hit=$(tail -n "+$((start_pos + 1))" "$LSM_LOG" | grep -F "$needle" || true)
            if [ -n "$hit" ]; then
                if [ -n "$pid_hint" ]; then
                    if printf '%s\n' "$hit" | grep -q "pid=$pid_hint "; then
                        printf '%s\n' "$hit" | head -1
                        return 0
                    fi
                else
                    printf '%s\n' "$hit" | head -1
                    return 0
                fi
            fi
        fi
        sleep 0.25
    done
    return 1
}

# run_as_test_user CMD [ARG ...]
#
# Executes the command as $TEST_USER. Uses `runuser` for a clean
# session (no PAM stack noise that would itself trip CRED-002).
run_as_test_user() {
    runuser -u "$TEST_USER" -- "$@"
}

# Global cleanup hook installed by run-all.sh. Scenarios that need
# their own teardown should register via add_cleanup.
declare -a _CLEANUPS=()
add_cleanup() { _CLEANUPS+=("$*"); }
run_cleanups() {
    local i
    for ((i=${#_CLEANUPS[@]}-1; i>=0; i--)); do
        eval "${_CLEANUPS[i]}" || true
    done
    _CLEANUPS=()
}

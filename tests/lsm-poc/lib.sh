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
: "${SCRATCH_DIR:=/var/lib/cfmpoc}"   # exec+suid-capable scratch (not /tmp)
: "${HELPERS_DIR:=}"       # set by run-all.sh; scenarios resolve relative
: "${LISTENER_PORT:=4444}"
: "${EXPECT_TIMEOUT:=20}"
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
    # Each scenario runs in its own subshell (see run-all.sh), so
    # TEST_UID set by useradd-time discovery in the first scenario
    # is lost by the time the second scenario sources lib.sh. The
    # user itself persists (we created it on disk), but the variable
    # doesn't — repopulate from the live passwd db when the user
    # already exists so downstream helpers like test_user_is_watched
    # have a uid to look up.
    if id -u "$TEST_USER" >/dev/null 2>&1; then
        TEST_UID=$(id -u "$TEST_USER")
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

# test_user_is_watched — query the live cfm_watched_uids BPF map
# (via bpftool) and report whether TEST_UID is present. The map is
# pinned at /sys/fs/bpf/cfm/maps/cfm_watched_uids. Returns:
#   0 — uid IS watched (EXEC-004 / EXEC-006 / FS-005 will fire)
#   1 — uid is NOT watched (those scenarios will silently no-op)
#   2 — couldn't determine (bpftool missing or map unreadable)
#
# The cfm_watched_uids map is HASH<u32 uid, u8>; bpftool dumps it as
# {"key":[0x53,0x00,0x00,0x00], ...} format. We convert TEST_UID to
# the same little-endian hex pattern and grep.
test_user_is_watched() {
    if ! command -v bpftool >/dev/null 2>&1; then
        return 2
    fi
    local map_path="/sys/fs/bpf/cfm/maps/cfm_watched_uids"
    if [ ! -e "$map_path" ]; then
        return 2
    fi
    if [ -z "$TEST_UID" ]; then
        return 2
    fi
    # Use `bpftool map lookup` for the actual lookup semantic: returns
    # 0 on hit, non-zero on miss. No output-format dependency — the
    # earlier `bpftool map dump | grep "key.*HEX"` approach was fragile
    # across bpftool versions (EL10's bpftool prints map dumps without
    # the literal "key" prefix the regex expected, so the test always
    # returned "miss" even when the uid WAS in the map; observed live
    # on edge after watched_uid_fallback_min=1000 + cfm lsm restart).
    #
    # bpftool's `key` argument accepts decimal byte values; pass the
    # four LE bytes of TEST_UID as a u32.
    local b0 b1 b2 b3
    b0=$(( TEST_UID        & 0xff ))
    b1=$(( (TEST_UID >>  8) & 0xff ))
    b2=$(( (TEST_UID >> 16) & 0xff ))
    b3=$(( (TEST_UID >> 24) & 0xff ))
    if bpftool map lookup pinned "$map_path" key "$b0" "$b1" "$b2" "$b3" >/dev/null 2>&1; then
        return 0
    fi
    return 1
}

# require_policy_enabled — preflight that confirms a policy is at
# least in monitor mode before running its trigger. The shipped
# configs/lsm.conf template carries `mode = monitor` for every rule,
# but operators who edited /etc/cfm/lsm.conf before a new rule was
# added — or who installed the new cfm release without merging
# template additions into their conf — see the new policy default
# to ModeDisabled. Running the PoC trigger in that state would fail
# silently (BPF program isn't attached, no event possible).
#
# Parses `cfm lsm status` for a line of the form
#   CFML-XXX-NNN  mode=disabled  runtime=skip (...)
# and SKIPs the scenario cleanly with an actionable hint when the
# policy is disabled. Optimistic fall-through when the cfm CLI is
# unavailable or the status output shape changes.
require_policy_enabled() {
    local rule="$1"
    if ! command -v cfm >/dev/null 2>&1; then
        warn "$rule: cfm CLI not on PATH; cannot verify policy mode (proceeding optimistically)"
        return 0
    fi
    local mode
    # `cfm lsm status` mentions each policy twice:
    #   - In the [Pinned BPF state] section as a bare token:  CFML-FS-007
    #   - In the [Policies] section as:  CFML-FS-007  mode=monitor  runtime=...
    # Without the `$2 ~ /^mode=/` guard, awk matched the pinned-state
    # line first, returned an empty mode, and the SKIP message printed
    # `policy is mode=` with nothing after the `=`. Requiring the
    # `mode=` prefix makes us skip the bare-token line and reach the
    # actual policy table row.
    mode=$(cfm lsm status 2>/dev/null \
        | awk -v p="$rule" '$1==p && $2 ~ /^mode=/ {sub(/^mode=/, "", $2); print $2; exit}')
    case "$mode" in
        monitor|enforce)
            return 0
            ;;
        disabled|"")
            warn "$rule SKIP: policy is mode=$mode in /etc/cfm/lsm.conf (or missing entirely)"
            warn "  the BPF program for this rule isn't attached, so the trigger has nothing to catch."
            warn "  to enable it, add this stanza to /etc/cfm/lsm.conf:"
            warn "    [policy \"$rule\"]"
            warn "    mode = monitor"
            warn "  then run 'cfm lsm restart' and re-run this harness."
            exit 0
            ;;
        *)
            warn "$rule: unexpected mode=$mode in cfm lsm status; proceeding optimistically"
            return 0
            ;;
    esac
}

# require_test_user_watched — preflight for scenarios whose rule
# gates on cfm_uid_watched (EXEC-004, EXEC-006, FS-005). When the
# test user is NOT in the watched set, the rule is structurally
# unreachable from this user — no point running the trigger.
#
# Exits the scenario cleanly with a SKIP-equivalent return code 0
# (so the harness records "passed" without the rule actually firing)
# and an explanatory warn. This matches the existing
# EXEC-006-on-noexec-tmp pattern: clean skip with reason, not a hard
# failure.
#
# The operator can either:
#   - set watched_uid_fallback_min = 1000 in /etc/cfm/lsm.conf (the
#     login.defs UID_MIN convention; includes every regular account
#     including the test user at uid 1500) and run `cfm lsm restart`, OR
#   - move TEST_USER to a uid that the host's panel manifest already
#     includes (DA / cPanel / Plesk reseller account, etc.)
require_test_user_watched() {
    local rule="$1"
    case $(test_user_is_watched; echo $?) in
        0)
            return 0
            ;;
        1)
            warn "$rule SKIP: test user $TEST_USER (uid=$TEST_UID) is not in cfm_watched_uids"
            warn "  the host has a panel manifest (cPanel/DA/Plesk) that overrides the uid fallback"
            warn "  to include cfmpoc (and every other uid >= 1000, the login.defs UID_MIN"
            warn "  convention), edit /etc/cfm/lsm.conf:"
            warn "    watched_uid_fallback_min = 1000"
            warn "  then run 'cfm lsm restart' and re-run this harness"
            exit 0
            ;;
        2)
            warn "$rule: bpftool unavailable or map unreadable; proceeding optimistically"
            warn "  if the rule doesn't fire, install bpftool and re-run for diagnostics"
            return 0
            ;;
    esac
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

# ensure_scratch_dir — root-owned scratch under /var/lib/ that we can
# trust to be exec+suid-capable. /tmp is mounted noexec,nosuid on
# hardened EL10 / CL10 boxes (and increasingly on stock cPanel
# installs), which silently breaks every PoC that drops a binary and
# tries to exec it. /var/lib/ is normally on the root filesystem with
# default mount options, so binaries we drop there can actually run.
#
# The test user gets read+exec on this directory (so runuser can exec
# binaries we copy into it) but no write — the harness owns staging.
ensure_scratch_dir() {
    mkdir -p "$SCRATCH_DIR"
    chmod 0755 "$SCRATCH_DIR"
    chown root:root "$SCRATCH_DIR"
    # Sanity check: can we exec from here? If the operator put
    # /var/lib on a noexec mount (rare, but happens on extreme
    # hardening profiles), surface that loudly rather than have every
    # scenario fail mysteriously.
    local probe="$SCRATCH_DIR/.cfmpoc-execprobe"
    cp /bin/true "$probe"
    chmod 0755 "$probe"
    if ! "$probe" 2>/dev/null; then
        rm -f "$probe"
        fail "$SCRATCH_DIR is on a noexec mount; cannot run PoCs"
        fail "set SCRATCH_DIR=/some/other/exec-capable/path and re-run"
        exit 2
    fi
    rm -f "$probe"
    # Suid sanity check: drop a setuid binary, run as nobody, ensure
    # the kernel honoured the bit. Skipped silently when no `nobody`
    # account exists.
    if id -u nobody >/dev/null 2>&1; then
        local suid_probe="$SCRATCH_DIR/.cfmpoc-suidprobe"
        cp /usr/bin/id "$suid_probe"
        chmod 4755 "$suid_probe"
        local got
        got=$(runuser -u nobody -- "$suid_probe" -u 2>/dev/null || true)
        rm -f "$suid_probe"
        if [ "$got" != "0" ]; then
            warn "$SCRATCH_DIR appears to be on a nosuid mount; CRED-002 will skip"
            export SCRATCH_NOSUID=1
        fi
    fi
}

# stage_helper HELPER_NAME [PERMS] — copy a helper binary from
# HELPERS_DIR/bin into SCRATCH_DIR so it can be exec'd from a context
# (test user, sudo-dropped task) that has no access to the source
# tree. Prints the staged path on stdout.
#
# PERMS default is 0755 (root-owned, world-rx). Pass "4755" to set the
# setuid bit for CRED-002 scenarios.
stage_helper() {
    local name="$1"
    local perms="${2:-0755}"
    local src="$HELPERS_DIR/bin/$name"
    local dst="$SCRATCH_DIR/$name"
    if [ ! -x "$src" ]; then
        fail "helper $src not built; did 'make -C tests/lsm-poc/helpers' run?"
        return 1
    fi
    cp "$src" "$dst"
    chown root:root "$dst"
    chmod "$perms" "$dst"
    printf '%s\n' "$dst"
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
    # Timeout: dump the post-mark log tail to stderr so the operator
    # can see WHAT did land in the window (often a same-policy event
    # with a different pid, or a different policy entirely). Cheap and
    # makes "no CFML-X line within Ns" failures actually debuggable.
    {
        printf '%s\n' "---- lsm.log lines added during the wait ----"
        tail -n "+$((start_pos + 1))" "$LSM_LOG" 2>/dev/null | tail -20
        printf '%s\n' "---- end ----"
    } >&2
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

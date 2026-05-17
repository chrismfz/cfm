#!/usr/bin/env bash
# run-all.sh — drive every scenario under scenarios/, tail lsm.log,
# print a PASS/FAIL summary.
#
# See README.md for the safety contract — this harness is destructive
# by design and must never run on a production host.

set -uo pipefail

HARNESS_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
export HELPERS_DIR="$HARNESS_DIR/helpers"

# shellcheck source=lib.sh
. "$HARNESS_DIR/lib.sh"

usage() {
    cat <<EOF
Usage: $0 [options]

Options:
  -v, --verbose          echo every trigger command before running
  -k, --keep-going       continue on failure; report all results
      --allow-enforce    skip the monitor-mode preflight check
      --listener-port N  TCP port for revshell scenarios (default 4444)
      --timeout N        seconds to wait for each expected event (default 10)
      --only RULE        run only scenarios matching RULE (e.g. EXEC-001)
      --skip RULE        skip scenarios matching RULE; repeatable
  -h, --help             show this help

Environment overrides: LSM_LOG, TEST_USER, TEST_UID, POC_TMPDIR.
EOF
}

KEEP_GOING=0
ONLY=""
declare -a SKIPS=()

while [ $# -gt 0 ]; do
    case "$1" in
        -v|--verbose)       VERBOSE=1; shift ;;
        -k|--keep-going)    KEEP_GOING=1; shift ;;
        --allow-enforce)    export ALLOW_ENFORCE=1; shift ;;
        --listener-port)    LISTENER_PORT="$2"; shift 2 ;;
        --timeout)          EXPECT_TIMEOUT="$2"; shift 2 ;;
        --only)             ONLY="$2"; shift 2 ;;
        --skip)             SKIPS+=("$2"); shift 2 ;;
        -h|--help)          usage; exit 0 ;;
        *) fail "unknown option: $1"; usage; exit 2 ;;
    esac
done
export VERBOSE LISTENER_PORT EXPECT_TIMEOUT

require_root
require_cfm_lsm_monitor

# Global teardown — fires on normal exit, Ctrl-C, and uncaught errors.
trap 'run_cleanups; cleanup_test_user; cleanup_tmpdir' EXIT INT TERM

ensure_tmpdir

# Build C helpers up front so per-scenario failures aren't masked by a
# stale binary. Idempotent — make does the right thing if everything
# is already up to date.
if [ -f "$HELPERS_DIR/Makefile" ]; then
    note "[build] $HELPERS_DIR"
    make -s -C "$HELPERS_DIR" all || {
        fail "helper build failed; cannot proceed"
        exit 3
    }
fi

# Discover scenarios. Sort numerically by the leading rule id so the
# output reads top-to-bottom in policy order.
declare -a SCENARIOS=()
while IFS= read -r -d '' f; do
    SCENARIOS+=("$f")
done < <(find "$HARNESS_DIR/scenarios" -maxdepth 1 -name '*.sh' -print0 | sort -z)

if [ ${#SCENARIOS[@]} -eq 0 ]; then
    fail "no scenarios under $HARNESS_DIR/scenarios"
    exit 3
fi

declare -a RESULTS=()
overall_rc=0

for sc in "${SCENARIOS[@]}"; do
    base="$(basename "$sc" .sh)"
    if [ -n "$ONLY" ] && ! [[ "$base" == *"$ONLY"* ]]; then
        RESULTS+=("$base SKIP filtered-by-only")
        continue
    fi
    skipped=0
    for s in "${SKIPS[@]}"; do
        if [[ "$base" == *"$s"* ]]; then
            RESULTS+=("$base SKIP filtered-by-skip")
            skipped=1
            break
        fi
    done
    [ "$skipped" -eq 1 ] && continue

    note ""
    note "===== scenario: $base ====="
    # Run scenario in a subshell so cleanups don't leak between runs.
    if ( . "$sc" ); then
        RESULTS+=("$base PASS")
    else
        rc=$?
        RESULTS+=("$base FAIL rc=$rc")
        overall_rc=1
        if [ "$KEEP_GOING" -ne 1 ]; then
            fail "scenario $base failed (rc=$rc); pass --keep-going to continue"
            break
        fi
    fi
done

note ""
note "===== summary ====="
for r in "${RESULTS[@]}"; do
    case "$r" in
        *" PASS"*) pass "$r" ;;
        *" FAIL"*) fail "$r" ;;
        *" SKIP"*) warn "$r" ;;
    esac
done

exit "$overall_rc"

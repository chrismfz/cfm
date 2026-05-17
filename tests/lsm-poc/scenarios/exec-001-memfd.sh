#!/usr/bin/env bash
# CFML-EXEC-001 — fileless ELF loader via memfd_create.
#
# What this proves: an attacker who got code-exec in any process can
# stage a payload entirely in tmpfs/memfd (no path on disk for AV /
# forensics to recover) and exec it. The kernel's bprm_check_security
# sees a tmpfs superblock with a "memfd:" dentry name on the file
# being exec'd — EXEC-001 fires.

set -uo pipefail
. "$HARNESS_DIR/lib.sh"

note "[EXEC-001] fileless memfd-exec of /bin/echo via the loader helper"

start_pos=$(mark_log_position)
helper="$HELPERS_DIR/bin/memfd-exec"
trace "$helper /bin/echo cfm-poc-fileless-payload"

"$helper" /bin/echo cfm-poc-fileless-payload &
trigger_pid=$!
wait "$trigger_pid"
trigger_rc=$?

if [ "$trigger_rc" -ne 0 ]; then
    fail "memfd-exec helper exited $trigger_rc — cannot proceed"
    exit 1
fi

if hit=$(expect_event "$start_pos" "CFML-EXEC-001"); then
    pass "EXEC-001 fired: $hit"
    exit 0
fi
fail "no CFML-EXEC-001 line in $LSM_LOG within ${EXPECT_TIMEOUT}s of trigger"
exit 1

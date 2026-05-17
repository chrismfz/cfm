#!/usr/bin/env bash
# CFML-EXEC-004 — drop, unlink, exec by a web-class uid.
#
# What this proves: webshell anti-forensics pattern. The attacker drops
# a binary to /tmp, opens it for read, unlinks the path so no on-disk
# evidence remains, then fexecve's the still-open fd. The inode is kept
# alive by the open fd but i_nlink == 0 and the dentry is unhashed.
# CFML-EXEC-004 fires at bprm_check_security when the calling uid is a
# watched (web-class) uid.

set -uo pipefail
. "$HARNESS_DIR/lib.sh"

note "[EXEC-004] drop-unlink-exec as web-class uid $TEST_USER"
ensure_test_user
ensure_scratch_dir

# Stage the helper into SCRATCH_DIR so the test user (who has no
# access to the source tree under /root/) can exec it.
helper=$(stage_helper deleted-exec) || exit 1
trace "runuser -u $TEST_USER -- $helper $SCRATCH_DIR /bin/echo cfm-poc-deleted-payload"

# Give the test user write access to SCRATCH_DIR for this scenario
# only — the helper needs to create its mkstemp staging file there.
chmod 1777 "$SCRATCH_DIR"
add_cleanup "chmod 0755 '$SCRATCH_DIR'"

start_pos=$(mark_log_position)
run_as_test_user "$helper" "$SCRATCH_DIR" /bin/echo cfm-poc-deleted-payload &
trigger_pid=$!
wait "$trigger_pid"
trigger_rc=$?

if [ "$trigger_rc" -ne 0 ]; then
    fail "deleted-exec helper exited $trigger_rc"
    exit 1
fi

if hit=$(expect_event "$start_pos" "CFML-EXEC-004"); then
    pass "EXEC-004 fired: $hit"
    exit 0
fi
fail "no CFML-EXEC-004 line in $LSM_LOG within ${EXPECT_TIMEOUT}s"
exit 1

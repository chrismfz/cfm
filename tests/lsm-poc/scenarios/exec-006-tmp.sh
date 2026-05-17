#!/usr/bin/env bash
# CFML-EXEC-006 — web-class uid exec from /tmp.
#
# What this proves: the staged-payload-and-exec pattern at the kernel
# layer. Imunify Proactive Defense catches the WRITE at the PHP VM
# layer; EXEC-006 catches the EXEC at bprm_check_security when the
# Proactive Defense layer is absent or bypassed.
#
# Trigger: as a watched uid, copy a known binary into /tmp/.<obfuscated>
# (mode 0755) and execute it. The detector inspects the bprm->file's
# backing superblock (tmpfs) or path prefix (/tmp/, /var/tmp/) and
# fires when the calling uid is in cfm_watched_uids.

set -uo pipefail
. "$HARNESS_DIR/lib.sh"

note "[EXEC-006] watched-uid exec from /tmp"
ensure_test_user

stage="/tmp/.cfmpoc-staged-$$"
add_cleanup "rm -f '$stage'"

# Stage as the test user so the file is owned by them (and not deleted
# by tmpwatch / systemd-tmpfiles before exec).
run_as_test_user cp /bin/echo "$stage"
run_as_test_user chmod 0755 "$stage"

start_pos=$(mark_log_position)
trace "runuser -u $TEST_USER -- $stage cfm-poc-tmpexec-payload"
run_as_test_user "$stage" cfm-poc-tmpexec-payload &
trigger_pid=$!
wait "$trigger_pid"
trigger_rc=$?

if [ "$trigger_rc" -ne 0 ]; then
    fail "/tmp exec returned $trigger_rc — was EXEC-006 in enforce mode?"
    exit 1
fi

if hit=$(expect_event "$start_pos" "CFML-EXEC-006"); then
    pass "EXEC-006 fired: $hit"
    exit 0
fi
fail "no CFML-EXEC-006 line in $LSM_LOG within ${EXPECT_TIMEOUT}s"
exit 1

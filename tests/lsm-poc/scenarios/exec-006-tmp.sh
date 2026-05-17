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
require_test_user_watched CFML-EXEC-006

# The whole point of EXEC-006 is exec-from-/tmp, so we genuinely need
# /tmp (or /var/tmp) writeable AND executable. Detect noexec and pick
# the first usable candidate.
stage=""
for candidate_dir in /tmp /var/tmp; do
    probe="$candidate_dir/.cfmpoc-execprobe-$$"
    cp /bin/true "$probe" 2>/dev/null || continue
    chmod 0755 "$probe"
    if "$probe" 2>/dev/null; then
        rm -f "$probe"
        stage="$candidate_dir/.cfmpoc-staged-$$"
        break
    fi
    rm -f "$probe"
done

if [ -z "$stage" ]; then
    warn "neither /tmp nor /var/tmp is exec-capable; EXEC-006 cannot be exercised"
    warn "(this host has noexec on both — the rule still protects against tmpfs/dev/shm execs)"
    exit 0
fi
add_cleanup "rm -f '$stage'"

run_as_test_user cp /bin/echo "$stage"
run_as_test_user chmod 0755 "$stage"

start_pos=$(mark_log_position)
trace "runuser -u $TEST_USER -- $stage cfm-poc-tmpexec-payload"
run_as_test_user "$stage" cfm-poc-tmpexec-payload &
trigger_pid=$!
wait "$trigger_pid"
trigger_rc=$?

if [ "$trigger_rc" -ne 0 ]; then
    fail "exec from $stage returned $trigger_rc"
    exit 1
fi

if hit=$(expect_event "$start_pos" "CFML-EXEC-006"); then
    pass "EXEC-006 fired: $hit"
    exit 0
fi
fail "no CFML-EXEC-006 line in $LSM_LOG within ${EXPECT_TIMEOUT}s"
exit 1

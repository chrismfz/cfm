#!/usr/bin/env bash
# CFML-CRED-002 — non-root → root via a setuid binary outside the
# allowlist.
#
# What this proves: post-exploit persistence catches. After any
# transient root gain, attackers chmod 4755 a stash binary in /tmp
# (or /var/tmp, /dev/shm, /home/<user>/) so an unprivileged shell
# can re-acquire root later without re-exploiting. The disk-walked
# setuid_inodes map only covers /usr/{bin,sbin,local/{bin,sbin}},
# /bin, /sbin — anything outside that path tree, or any path the
# operator hasn't explicitly added via allow_exe, is NOT in the
# allowlist. When a non-root user execs such a binary and the kernel
# auto-sets euid=0 from the setuid bit, task_fix_setuid fires with
# the exe NOT matching setuid_inodes → CRED-002 emits.
#
# This scenario builds a tiny setuid-root binary, drops it under
# /tmp/.cfmpoc-bd, and runs it as the test user.

set -uo pipefail
. "$HARNESS_DIR/lib.sh"

note "[CRED-002] setuid-root binary dropped to scratch dir, run as $TEST_USER"
ensure_test_user
ensure_scratch_dir

if [ "${SCRATCH_NOSUID:-0}" = "1" ]; then
    warn "$SCRATCH_DIR is on a nosuid mount; CRED-002 cannot fire"
    warn "(remount /var/lib without nosuid, or set SCRATCH_DIR=/some/exec+suid/path)"
    exit 0
fi

# The threat model is: attacker dropped a setuid-root stash binary
# during a transient root window so they can re-acquire root later
# without re-exploiting. We mirror that exactly — root-owned, mode
# 4755, dropped in an exec+suid-capable directory, run as a low-uid
# user. The dropper's setuid(0) is what the LSM hook sees.
stash="$SCRATCH_DIR/.cfmpoc-bd-$$"
add_cleanup "rm -f '$stash'"
cp "$HELPERS_DIR/bin/suid-dropper" "$stash"
chown 0:0 "$stash"
chmod 4755 "$stash"

start_pos=$(mark_log_position)
trace "runuser -u $TEST_USER -- $stash"
# The dropper does setuid(0) then exec's /bin/id. The kernel hits
# task_fix_setuid on the non-root → root transition; the exe at
# that point is the stash binary (mm->exe_file is set before
# task_fix_setuid runs for setuid-bit exec entry).
run_as_test_user "$stash" >/dev/null 2>&1
trigger_rc=$?

if [ "$trigger_rc" -ne 0 ]; then
    fail "stash binary exited $trigger_rc — setuid bit lost? noexec mount?"
    exit 1
fi

if hit=$(expect_event "$start_pos" "CFML-CRED-002"); then
    pass "CRED-002 fired: $hit"
    exit 0
fi
fail "no CFML-CRED-002 line in $LSM_LOG within ${EXPECT_TIMEOUT}s"
exit 1

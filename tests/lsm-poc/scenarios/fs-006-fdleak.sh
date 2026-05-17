#!/usr/bin/env bash
# CFML-FS-006 — sensitive read via root-owned fd from unprivileged task.
#
# What this proves: the setuid-helper fd-leak class. A privileged
# process opens /etc/shadow as root (so struct file's f_cred captures
# euid=0), then drops privileges (setresuid to a non-root uid), then
# read()s through the still-open fd. The LSM file_permission hook sees
# cur_euid != 0 but file->f_cred->euid == 0 — exactly the fingerprint
# that catches:
#   - pidfd_getfd exit-window race against ssh-keysign / chage / unix_chkpwd
#   - older CLONE_FILES + setuid-exec variants
#   - /proc/<pid>/fd/<n> open races
#
# Our PoC bundles open+drop+read in one process for reliability — the
# kernel-side detection logic is identical to the race-based variant.

set -uo pipefail
. "$HARNESS_DIR/lib.sh"

note "[FS-006] root-opened fd to /etc/shadow, read after dropping to $TEST_USER"
ensure_test_user

helper="$HELPERS_DIR/bin/fdleak-attacker"
test_uid=$(id -u "$TEST_USER")

start_pos=$(mark_log_position)
trace "$helper /etc/shadow $test_uid"
"$helper" /etc/shadow "$test_uid"
trigger_rc=$?

if [ "$trigger_rc" -ne 0 ]; then
    fail "fdleak-attacker returned $trigger_rc"
    exit 1
fi

if hit=$(expect_event "$start_pos" "CFML-FS-006"); then
    pass "FS-006 fired: $hit"
    exit 0
fi
fail "no CFML-FS-006 line in $LSM_LOG within ${EXPECT_TIMEOUT}s"
exit 1

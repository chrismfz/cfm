#!/usr/bin/env bash
# CFML-CRED-002 — non-root → root via cap_setuid+ep file capability.
#
# What this proves: the canonical CRED-002 trigger. The realistic
# post-exploit pattern is `setcap cap_setuid+ep /tmp/.bd` — file
# capabilities, not the setuid bit, because:
#
#   1. setuid-bit elevation happens via execve's bprm_creds_for_exec,
#      NOT task_fix_setuid. By the time a suid-bit binary's main()
#      calls setuid(0), old_euid is already 0, so CRED-002 returns
#      early on the "already root" check.
#
#   2. cap_setuid+ep leaves euid at the calling user's value at
#      execve time but adds CAP_SETUID to the effective capability
#      set. When the binary calls setuid(0), the kernel's
#      task_fix_setuid hook fires with new_euid=0, old_euid=cfmpoc —
#      the exact CFML-CRED-002 fingerprint.
#
# This also matches the harder-to-spot real-world threat: `ls -l`
# shows mode 0755 with no leading `s` — only `getcap` reveals the
# privilege. Many ad-hoc audit scripts only look for setuid bits.

set -uo pipefail
. "$HARNESS_DIR/lib.sh"

note "[CRED-002] cap_setuid+ep binary, run as $TEST_USER"
ensure_test_user
ensure_scratch_dir

# setcap requires CAP_SETFCAP (we have it as root) and xattr support
# on the destination filesystem. /var/lib/ on ext4/xfs/btrfs has
# xattrs; some hardened mount options strip them. Probe early.
if ! command -v setcap >/dev/null 2>&1; then
    warn "setcap not on PATH (libcap-utils package missing); cannot exercise CRED-002"
    exit 0
fi

stash="$SCRATCH_DIR/.cfmpoc-bd-$$"
add_cleanup "rm -f '$stash'"
cp "$HELPERS_DIR/bin/suid-dropper" "$stash"
chown 0:0 "$stash"
chmod 0755 "$stash"        # no setuid bit — file caps do the work

if ! setcap cap_setuid+ep "$stash" 2>/dev/null; then
    warn "setcap failed on $stash (no xattr support? nouserxattr mount?)"
    warn "CRED-002 cannot be exercised on this filesystem layout"
    exit 0
fi
# Verify the capability actually applied.
if ! getcap "$stash" 2>/dev/null | grep -q cap_setuid; then
    warn "getcap shows no cap_setuid on $stash — capabilities silently stripped"
    exit 0
fi

start_pos=$(mark_log_position)
trace "runuser -u $TEST_USER -- $stash"
# Run synchronously, capture both rc and stderr.
out=$(run_as_test_user "$stash" 2>&1)
trigger_rc=$?

if [ "$trigger_rc" -ne 0 ]; then
    fail "stash binary exited $trigger_rc; output: $out"
    exit 1
fi

if hit=$(expect_event "$start_pos" "CFML-CRED-002"); then
    pass "CRED-002 fired: $hit"
    exit 0
fi
fail "no CFML-CRED-002 line in $LSM_LOG within ${EXPECT_TIMEOUT}s"
exit 1

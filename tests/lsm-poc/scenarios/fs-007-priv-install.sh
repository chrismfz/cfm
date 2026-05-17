#!/usr/bin/env bash
# CFML-FS-007 — privilege-primitive install by watched uid.
#
# Two legs, both threat-realistic:
#
#   leg 1 (suid bit):  watched-uid chmod 4755 on a binary it owns.
#                      The post-exploit dropper pattern paired with
#                      CRED-002 (which catches the *use*).
#   leg 2 (file cap):  watched-uid setxattr security.capability with
#                      cap_setuid+ep. Harder to spot than the suid
#                      bit (no `s` in ls -l, only `getcap` reveals).
#
# Both legs need cfmpoc to be in cfm_watched_uids. On panel hosts
# where the manifest skips the uid-fallback, the harness's
# require_test_user_watched helper SKIPs cleanly with an actionable
# hint instead of FAILing silently.
#
# Leg 2 needs CAP_SETFCAP to write security.capability. The helper
# (setcapper.c) gets cap_setfcap+ep via setcap during this scenario
# so it runs with the cap as cfmpoc — matching the realistic threat
# model where the attacker already obtained CAP_SETFCAP somehow.

set -uo pipefail
. "$HARNESS_DIR/lib.sh"

note "[FS-007] privilege-primitive install by watched uid $TEST_USER"
require_policy_enabled CFML-FS-007
ensure_test_user
ensure_scratch_dir
require_test_user_watched CFML-FS-007

# SCRATCH_DIR is root-owned 0755 — let cfmpoc create files in it for
# this scenario only. The cleanup restores tight perms.
chmod 1777 "$SCRATCH_DIR"
add_cleanup "chmod 0755 '$SCRATCH_DIR'"

# ─── Leg 1: chmod 4755 (suid bit install) ───────────────────────────
note "  leg 1: chmod 4755 (suid bit) as $TEST_USER"
target_suid="$SCRATCH_DIR/.cfmpoc-fs007-suid-$$"
add_cleanup "rm -f '$target_suid'"
run_as_test_user cp /bin/echo "$target_suid"

start_pos=$(mark_log_position)
trace "runuser -u $TEST_USER -- chmod 4755 $target_suid"
run_as_test_user chmod 4755 "$target_suid"
trigger_rc=$?
if [ "$trigger_rc" -ne 0 ]; then
    fail "chmod returned $trigger_rc"
    exit 1
fi

if hit=$(expect_event "$start_pos" "CFML-FS-007"); then
    pass "FS-007 suid leg: $hit"
else
    fail "no CFML-FS-007 line for suid leg within ${EXPECT_TIMEOUT}s"
    exit 1
fi

# ─── Leg 2: setcap cap_setuid+ep (file capability install) ──────────
note "  leg 2: setcap cap_setuid+ep (file capability) as $TEST_USER"

if ! command -v setcap >/dev/null 2>&1; then
    warn "  setcap not on PATH (libcap-utils package missing); skipping file-cap leg"
    exit 0
fi

helper=$(stage_helper setcapper) || exit 1
# Grant CAP_SETFCAP on the helper so it can write security.capability
# while running as the (non-root) test user.
if ! setcap cap_setfcap+ep "$helper" 2>/dev/null; then
    warn "  setcap cap_setfcap+ep $helper failed (no xattr support? nouserxattr mount?)"
    warn "  file-cap leg cannot be exercised on this filesystem layout"
    exit 0
fi
if ! getcap "$helper" 2>/dev/null | grep -q cap_setfcap; then
    warn "  getcap shows no cap_setfcap on $helper; skipping file-cap leg"
    exit 0
fi

target_cap="$SCRATCH_DIR/.cfmpoc-fs007-cap-$$"
add_cleanup "rm -f '$target_cap'"
run_as_test_user cp /bin/echo "$target_cap"

start_pos=$(mark_log_position)
trace "runuser -u $TEST_USER -- $helper $target_cap"
run_as_test_user "$helper" "$target_cap"
trigger_rc=$?
if [ "$trigger_rc" -ne 0 ]; then
    fail "setcapper returned $trigger_rc"
    exit 1
fi

if hit=$(expect_event "$start_pos" "CFML-FS-007"); then
    pass "FS-007 file-cap leg: $hit"
    exit 0
fi
fail "no CFML-FS-007 line for file-cap leg within ${EXPECT_TIMEOUT}s"
exit 1

#!/usr/bin/env bash
# CFML-FS-005 — sensitive-file modification by a web-class uid.
#
# What this proves: post-privesc cash-in. After any other bug gave the
# web user a route to write under /etc/sudoers.d/ (we simulate this
# by pre-staging a world-writable file there), the act of writing to
# the sensitive path is the moment we want to catch — kernel-side,
# regardless of how the write authority was obtained.
#
# Real-world equivalent: Dirty Pipe / Dirty COW completion. The
# kernel bug gives the unprivileged process a write capability; the
# attacker then installs a sudoers line / SSH key / cron job for
# persistence. CFML-FS-005 fires at inode_setattr / inode_create /
# inode_link / inode_rename / inode_unlink / inode_setxattr.

set -uo pipefail
. "$HARNESS_DIR/lib.sh"

note "[FS-005] watched-uid setattr on a sensitive path"
ensure_test_user

# Sentinel under /etc/cron.d/, which (a) is in
# DefaultPersistencePaths so its inode is in the FS-005 watched-inode
# set, and (b) is typically mode 0755 so the test user can traverse
# it. We use /etc/cron.d rather than /etc/sudoers.d (mode 0700 —
# test user can't even list it) so this scenario works on a stock EL
# host without the harness having to chmod the directory.
#
# The sentinel itself is created mode 0666 by the harness so the test
# user can rewrite it. CRITICAL: this temporarily lets any local user
# put a root-cron entry on the host; the trap removes it on every
# exit path but never run on production. README spells this out.
sentinel="/etc/cron.d/.cfmpoc-fs005-$$"
: > "$sentinel"
chmod 0666 "$sentinel"
add_cleanup "rm -f '$sentinel'"

start_pos=$(mark_log_position)
# touch -> utimensat -> inode_setattr. That's the cheapest "writeable"
# operation that hits one of FS-005's hooked methods. We don't actually
# need to append cron content — the LSM fires on the inode op
# regardless of the bytes written.
trace "runuser -u $TEST_USER -- touch $sentinel"
run_as_test_user touch "$sentinel"
trigger_rc=$?

if [ "$trigger_rc" -ne 0 ]; then
    fail "touch returned $trigger_rc — sentinel perms wrong?"
    exit 1
fi

if hit=$(expect_event "$start_pos" "CFML-FS-005"); then
    pass "FS-005 fired: $hit"
    exit 0
fi
fail "no CFML-FS-005 line in $LSM_LOG within ${EXPECT_TIMEOUT}s"
exit 1

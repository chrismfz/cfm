#!/usr/bin/env bash
# CFML-FS-006 — sensitive read via root-owned fd from unprivileged task.
#
# What this proves: the setuid-helper fd-leak class. A privileged
# process opens a sensitive file as root (so struct file's f_cred
# captures euid=0), then drops privileges (setresuid to a non-root
# uid), then read()s through the still-open fd. The LSM
# file_permission hook sees cur_euid != 0 but file->f_cred->euid == 0
# — exactly the fingerprint that catches:
#   - pidfd_getfd exit-window race against ssh-keysign / chage / unix_chkpwd
#   - older CLONE_FILES + setuid-exec variants
#   - /proc/<pid>/fd/<n> open races
#
# Our PoC bundles open+drop+read in one process for reliability — the
# kernel-side detection logic is identical to the race-based variant.
#
# Target file: /etc/sudoers (not /etc/shadow). Both are in the
# DefaultCoreSensitivePaths watched-inodes set, so the detection
# path is identical. We use sudoers because the harness's own
# ensure_test_user / cleanup_test_user invoke useradd / userdel,
# which atomically rewrite /etc/shadow (shadow.new → rename), and
# that rotates shadow's inode out of the cfm_watched_inodes map
# between harness runs — the BPF lookup misses and FS-006 stays
# silent. /etc/sudoers isn't touched by useradd/userdel and stays
# stable across the run.

set -uo pipefail
. "$HARNESS_DIR/lib.sh"

SENSITIVE_PATH="${SENSITIVE_PATH:-/etc/sudoers}"
note "[FS-006] root-opened fd to $SENSITIVE_PATH, read after dropping to $TEST_USER"
ensure_test_user

if [ ! -r "$SENSITIVE_PATH" ]; then
    fail "FS-006: $SENSITIVE_PATH not readable as root (unexpected); set SENSITIVE_PATH= to override"
    exit 1
fi

helper="$HELPERS_DIR/bin/fdleak-attacker"
test_uid=$(id -u "$TEST_USER")

start_pos=$(mark_log_position)
trace "$helper $SENSITIVE_PATH $test_uid"
"$helper" "$SENSITIVE_PATH" "$test_uid"
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

# Likely cause: the target file's inode has rotated since the cfm-lsm
# daemon last ran PopulateMaps. Background activity (passwd / chage
# / cron-managed shadow rotation, package updates that rewrite
# /etc/sudoers in place) occasionally rewrites these files (creates
# foo.new, renames over foo), which changes the inode. The
# watched_inodes map still has the old inode → BPF returns early on
# the lookup.
#
# Auto-diagnose: stat the live file and compare its inode to the
# values the BPF map currently holds. If they don't intersect, the
# map is stale and the operator should re-run `cfm lsm restart`.
live_ino=$(stat -c '%i' "$SENSITIVE_PATH" 2>/dev/null)
warn "  $SENSITIVE_PATH live inode: ${live_ino:-unreadable}"
if command -v bpftool >/dev/null 2>&1 && [ -e /sys/fs/bpf/cfm/maps/cfm_watched_inodes ]; then
    # bpftool dumps {"key":[byte0,byte1,...], "value":[...]}. The key
    # is cfm_inode_key { dev:u64, ino:u64 } in little-endian — bytes
    # 8-15 are the ino. We extract every ino in the map and grep
    # for the live one.
    cached_inos=$(bpftool map dump pinned /sys/fs/bpf/cfm/maps/cfm_watched_inodes 2>/dev/null \
        | awk '/key:/{found=1; bytes=""} found && /value:/{found=0; print bytes} found{bytes=bytes" "$0}')
    if [ -n "$live_ino" ] && [ -n "$cached_inos" ]; then
        # Format live_ino as the 8-byte little-endian hex pattern
        # bpftool prints. uint64; we only need to print as much as
        # the inode actually consumes (typically 4 bytes for ext4 +
        # 4 zero bytes).
        hexkey=$(printf '%02x %02x %02x %02x %02x %02x %02x %02x' \
            $(( live_ino        & 0xff )) \
            $(( (live_ino >>  8) & 0xff )) \
            $(( (live_ino >> 16) & 0xff )) \
            $(( (live_ino >> 24) & 0xff )) \
            $(( (live_ino >> 32) & 0xff )) \
            $(( (live_ino >> 40) & 0xff )) \
            $(( (live_ino >> 48) & 0xff )) \
            $(( (live_ino >> 56) & 0xff )))
        if printf '%s\n' "$cached_inos" | grep -qiF "$hexkey"; then
            warn "  cached map DOES contain $SENSITIVE_PATH's live inode — different root cause"
            warn "  (rate cap? hook unattached? check 'cfm lsm status')"
        else
            warn "  cached map does NOT contain $SENSITIVE_PATH's live inode — inode rotated under daemon"
            warn "  resolve with: cfm lsm restart"
        fi
    fi
else
    warn "  install bpftool to auto-compare live vs cached inode on next FAIL"
fi
exit 1

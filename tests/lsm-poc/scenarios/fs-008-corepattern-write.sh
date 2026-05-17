#!/usr/bin/env bash
# CFML-FS-008 — write to a sensitive kernel knob from a non-trusted
# comm.
#
# Threat model: kernel-exploit completion / persistence pivot.
# Every public Linux kernel exploit from the last five years pivots
# through one of /proc/sys/kernel/{core_pattern,modprobe_path,
# hotplug} / /proc/sysrq-trigger / /sys/kernel/uevent_helper /
# /proc/sys/fs/binfmt_misc/register once it has the write primitive.
#
# Trusted-writer allowlist: cfm / sysctl / systemd / systemd-sysctl.
# The harness renames the knob-writer helper to a non-trusted comm
# before running it so the BPF program emits.
#
# Targets core_pattern (always present on every supported kernel)
# and saves+restores the original value around the test. No watched-
# uid gate on FS-008 — the rule fires on the comm allowlist, not the
# calling uid. The harness runs as root because writing /proc/sys/*
# requires CAP_SYS_ADMIN; that matches the realistic threat shape
# (kernel exploit completion has root).

set -uo pipefail
. "$HARNESS_DIR/lib.sh"

KNOB="/proc/sys/kernel/core_pattern"
note "[FS-008] write to $KNOB from non-trusted comm"
ensure_scratch_dir

if [ ! -e "$KNOB" ]; then
    warn "$KNOB not present on this kernel; cannot test FS-008"
    exit 0
fi

# Save original. We MUST restore — leaving a hostile core_pattern
# means the next coredump executes the attacker pipe.
original=$(cat "$KNOB" 2>/dev/null || true)
if [ -z "$original" ]; then
    warn "could not read $KNOB to save original; refusing to clobber"
    exit 1
fi
add_cleanup "printf '%s\n' '$original' > '$KNOB' 2>/dev/null"

helper=$(stage_helper knob-writer) || exit 1

# Masquerade the writer's comm. The BPF program's trusted-writer
# allowlist matches comm exactly (cfm / sysctl / systemd /
# systemd-sysctl); anything else is the signal. We use a name that's
# also plausibly an attacker-installed component.
masquerade="$SCRATCH_DIR/.cfm-exploit-writer"
cp "$helper" "$masquerade"
chmod 0755 "$masquerade"
add_cleanup "rm -f '$masquerade'"

# A harmless sentinel value. /proc/sys/kernel/core_pattern accepts
# the pipe-handler syntax `|<command>` which is the kernel-exploit
# trigger; we write a harmless variant so the system stays usable
# even in the (tiny) window between write and cleanup restore.
sentinel="|/bin/true cfm-poc-fs008-sentinel"

start_pos=$(mark_log_position)
trace "$masquerade $KNOB '$sentinel'"
"$masquerade" "$KNOB" "$sentinel"
trigger_rc=$?
if [ "$trigger_rc" -ne 0 ]; then
    fail "knob-writer returned $trigger_rc"
    exit 1
fi

if hit=$(expect_event "$start_pos" "CFML-FS-008"); then
    pass "FS-008 fired: $hit"
    exit 0
fi
fail "no CFML-FS-008 line in $LSM_LOG within ${EXPECT_TIMEOUT}s"
exit 1

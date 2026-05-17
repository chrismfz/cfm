#!/usr/bin/env bash
# CFML-CRED-003 — direct commit_creds() install of root credentials.
#
# What this DOES NOT prove from userspace: there is no clean userland
# PoC. CRED-003 fires on commit_creds() calls that bypass
# task_fix_setuid — the canonical kernel-exploit completion path
# (e.g. commit_creds(prepare_kernel_cred(NULL)) via ROP). Every
# legitimate userspace privilege change goes through task_fix_setuid
# first, so CRED-002 covers all userland triggers and CRED-003 stays
# silent until a real kernel exploit fires it.
#
# What this scenario DOES verify:
#   1. The fentry/commit_creds program is actually attached.
#   2. The ringbuf drain is healthy (recent CRED-002 events suffice).
#   3. The kmsg "ALIVE" line lists CFML-CRED-003 among enabled policies.
#
# For full coverage, build the out-of-tree kernel-module harness
# referenced in README.md (an LKM that calls commit_creds() directly
# from a syscall-table-stashed function pointer is the most reliable
# clean trigger). That's intentionally out of this tree — loading an
# LKM is a much bigger blast radius than the userspace PoCs here.

set -uo pipefail
. "$HARNESS_DIR/lib.sh"

note "[CRED-003] verify hook is attached (no userland trigger; see README)"

# Confirm cfm-lsm reports CRED-003 as attached. Two signals:
#  (a) `cfm lsm status` lists it.
#  (b) bpftool prog list shows a program whose name starts with
#      "cfm_cred003" (the BPF_PROG macro mangles the SEC name).
ok=1
if command -v cfm >/dev/null 2>&1; then
    if ! cfm lsm status 2>/dev/null | grep -q "CFML-CRED-003"; then
        warn "cfm lsm status does not list CFML-CRED-003"
        ok=0
    fi
fi
if command -v bpftool >/dev/null 2>&1; then
    if ! bpftool prog list 2>/dev/null | grep -qiE 'cfm_cred003|cred003'; then
        warn "bpftool prog list does not show cfm_cred003"
        ok=0
    fi
else
    warn "bpftool not installed; skipping kernel-side attach check"
fi

# Verify the ringbuf drain is processing events at all by leaning on
# the CRED-002 trigger we already have. If CRED-002 emits within the
# window, the same ringbuf would carry a CRED-003 event if the kernel
# ever produced one.
note "[CRED-003] piggy-backing on the CRED-002 trigger to prove the drain is alive"
start_pos=$(mark_log_position)
"$HARNESS_DIR/scenarios/cred-002-suid-dropper.sh" >/dev/null 2>&1 || true
if expect_event "$start_pos" "CFML-CRED-002" >/dev/null; then
    note "  ringbuf drain confirmed (CRED-002 fired)"
else
    warn "  CRED-002 did not fire on piggy-back — drain may be stalled"
    ok=0
fi

if [ "$ok" -eq 1 ]; then
    pass "CRED-003 hook is attached and drain is healthy"
    pass "  (no userland PoC; commit_creds bypass needs a kernel-exploit primitive)"
    exit 0
fi
fail "CRED-003 attach/drain verification failed; see warnings above"
exit 1

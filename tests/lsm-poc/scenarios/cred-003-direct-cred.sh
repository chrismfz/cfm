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
# What this scenario DOES verify (each is necessary but not
# sufficient on its own):
#   1. The fentry/commit_creds program is attached, per `cfm lsm status`.
#   2. bpftool prog list shows a cfm_-prefixed program (any of them —
#      we don't depend on the exact name field, which depends on
#      kernel + libbpf version).
#   3. The ringbuf drain is healthy: a fresh memfd-exec trigger
#      (EXEC-001, the simplest one) appears in lsm.log within the
#      expect timeout.
#
# For full coverage, build the out-of-tree kernel-module harness
# referenced in README.md (an LKM that calls commit_creds() directly
# is the most reliable clean trigger). That's intentionally out of
# this tree — loading an LKM has a much bigger blast radius than the
# userspace PoCs here.

set -uo pipefail
. "$HARNESS_DIR/lib.sh"

note "[CRED-003] verify hook is attached (no userland trigger; see README)"

ok=1

# (1) cfm lsm status lists the policy as attached.
if command -v cfm >/dev/null 2>&1; then
    if cfm lsm status 2>/dev/null | grep -qE 'CFML-CRED-003.*attached'; then
        note "  cfm lsm status: CFML-CRED-003 attached"
    else
        warn "  cfm lsm status does not show CFML-CRED-003 as attached"
        ok=0
    fi
else
    warn "  cfm CLI not on PATH; skipping status check"
fi

# (2) bpftool sees at least one cfm_-prefixed program. The exact
# program name varies (cfm_cred003 / cfm_cred003.0 / etc depending on
# libbpf-tools version), so we just look for the prefix.
if command -v bpftool >/dev/null 2>&1; then
    if bpftool prog list 2>/dev/null | grep -qE 'cfm_[a-z0-9_]+'; then
        note "  bpftool prog list: at least one cfm_ program loaded"
    else
        warn "  bpftool prog list shows no cfm_ programs"
        ok=0
    fi
else
    warn "  bpftool not installed; skipping kernel-side attach check"
fi

# (3) drain is healthy — fire EXEC-001 (cheapest, no scratch dir
# needed, no test user needed) and confirm the event lands.
note "  drain check via EXEC-001 (memfd) trigger:"
start_pos=$(mark_log_position)
"$HELPERS_DIR/bin/memfd-exec" /bin/echo cfm-poc-cred003-drain-probe >/dev/null 2>&1 || true
if expect_event "$start_pos" "CFML-EXEC-001" >/dev/null; then
    note "  ringbuf drain confirmed (EXEC-001 fired on probe)"
else
    warn "  EXEC-001 probe did not land — drain may be stalled"
    ok=0
fi

if [ "$ok" -eq 1 ]; then
    pass "CRED-003 hook is attached and drain is healthy"
    pass "  (no userland PoC for the actual rule; commit_creds bypass needs a kernel-exploit primitive)"
    exit 0
fi
fail "CRED-003 attach/drain verification failed; see warnings above"
exit 1

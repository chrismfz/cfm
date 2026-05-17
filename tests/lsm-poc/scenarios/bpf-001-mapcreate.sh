#!/usr/bin/env bash
# CFML-BPF-001 — bpf() syscall from an untrusted comm.
#
# What this proves: BPF-rootkit installer pattern. Modern Linux malware
# (bvp47, boopkit, symbiote) bootstraps with bpf(BPF_MAP_CREATE) and
# bpf(BPF_PROG_LOAD) to install hidden tracing programs. The BPF-001
# rule fires on the syscall-entry tracepoint when the calling task's
# comm is NOT in the small trusted-agent allowlist (cfm / systemd /
# systemd-udevd / systemd-network / NetworkManager / bpftool / auditd).
#
# Trigger: rename our bpf-mapcreate helper to a non-trusted comm
# (".cfm-bd-installer") and invoke it. The kernel sees the bpf()
# call from an untrusted comm and emits.

set -uo pipefail
. "$HARNESS_DIR/lib.sh"

note "[BPF-001] bpf(BPF_MAP_CREATE) from non-trusted comm"

src="$HELPERS_DIR/bin/bpf-mapcreate"
masquerade="$POC_TMPDIR/.cfm-bd-installer"
cp "$src" "$masquerade"
chmod 0755 "$masquerade"
add_cleanup "rm -f '$masquerade'"

start_pos=$(mark_log_position)
trace "$masquerade"
"$masquerade" >/dev/null 2>&1
trigger_rc=$?

# rc != 0 is fine — the bpf() call may fail (EPERM on hosts with
# unprivileged_bpf_disabled=1, no CAP_BPF, etc). The LSM tracepoint
# fires on syscall entry, before the kernel even checks permissions,
# so the event lands either way.
if [ "$trigger_rc" -ne 0 ]; then
    note "  bpf() returned non-zero (rc=$trigger_rc) — expected on restricted kernels"
fi

if hit=$(expect_event "$start_pos" "CFML-BPF-001"); then
    pass "BPF-001 fired: $hit"
    exit 0
fi
fail "no CFML-BPF-001 line in $LSM_LOG within ${EXPECT_TIMEOUT}s"
exit 1

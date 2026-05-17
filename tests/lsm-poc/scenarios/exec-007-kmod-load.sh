#!/usr/bin/env bash
# CFML-EXEC-007 — kernel module load from non-trusted comm.
#
# Threat model: kernel-rootkit installer calling init_module(2) or
# finit_module(2). The CFML-EXEC-007 tracepoint fires on syscall
# entry regardless of whether the kernel ultimately accepts the
# module, so the PoC doesn't need a valid .ko — /dev/null on
# finit_module returns -ENOEXEC, but the tracepoint already emitted.
#
# Trusted-comm allowlist: modprobe / insmod / kmod / systemd /
# systemd-modules / systemd-udevd. The harness renames the kmod-
# loader helper to a non-trusted comm before executing so the BPF
# program doesn't suppress.
#
# No watched-uid gate on EXEC-007 — any non-trusted comm attempting
# init/finit_module is the signal. The harness runs as root; that
# matches the realistic threat-model shape (kernel-exploit completion
# has root) and exercises the rule's intended path.

set -uo pipefail
. "$HARNESS_DIR/lib.sh"

note "[EXEC-007] init_module / finit_module from non-trusted comm"
require_policy_enabled CFML-EXEC-007
ensure_scratch_dir

src="$HELPERS_DIR/bin/kmod-loader"
# A masquerade name that's plausibly an attacker-installed rootkit
# loader. Anything not in cfm_comm_is_trusted_modprobe() works;
# this one is also long enough that the leading-dot doesn't make
# it disappear from typical `ps` columns.
masquerade="$SCRATCH_DIR/.cfm-rootkit-loader"
cp "$src" "$masquerade"
chmod 0755 "$masquerade"
add_cleanup "rm -f '$masquerade'"

start_pos=$(mark_log_position)
trace "$masquerade"
# rc is irrelevant — finit_module / init_module on garbage args
# always return non-zero, but the tracepoints already fired.
"$masquerade" >/dev/null 2>&1 || true

if hit=$(expect_event "$start_pos" "CFML-EXEC-007"); then
    pass "EXEC-007 fired: $hit"
    exit 0
fi
fail "no CFML-EXEC-007 line in $LSM_LOG within ${EXPECT_TIMEOUT}s"
exit 1

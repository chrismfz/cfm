#!/usr/bin/env bash
# CFML-EXEC-008 — kexec_load / kexec_file_load from non-trusted comm.
#
# Threat model: rootkit-persistence installer calling kexec_load(2) or
# kexec_file_load(2) to stage a backdoored kernel image. The next
# kexec_reboot would boot that image without firmware involvement,
# surviving every "is the running kernel the one we shipped" audit.
#
# The CFML-EXEC-008 tracepoints fire on syscall entry regardless of
# whether the kernel ultimately accepts the args, so the PoC doesn't
# need a valid kernel image — bogus args still cause the tracepoint
# to emit before the syscall returns -EPERM / -EINVAL / -ENOEXEC.
#
# Architecture / kernel-config note: kexec_load(2) is present on every
# supported kernel + arch. kexec_file_load(2) on arm64 requires
# CONFIG_KEXEC_FILE=y in the kernel build (default-on for distro
# kernels but absent on some embedded arm64 boards); when missing,
# the syscall returns -ENOSYS but the entry tracepoint still fires
# and EXEC-008 still emits — exactly the desired behaviour. The
# helper uses arch-guarded syscall-number fallbacks so the PoC works
# on both x86_64 and arm64 even on libcs that don't ship the __NR_
# defines.
#
# Trusted-comm allowlist: kexec / systemctl. The harness renames the
# kexec-loader helper to a non-trusted comm before executing so the
# BPF program doesn't suppress.
#
# No watched-uid gate on EXEC-008 — any non-trusted comm attempting
# kexec_load / kexec_file_load is the signal. The harness runs as root;
# that matches the realistic threat-model shape (rootkit persistence
# requires CAP_SYS_BOOT, which only root holds) and exercises the
# rule's intended path. Note: on hosts where kernsec has applied
# kernel.kexec_load_disabled=1, the syscalls return -EPERM but the
# tracepoint still fires — that's the forensic-trail co-design.

set -uo pipefail
. "$HARNESS_DIR/lib.sh"

note "[EXEC-008] kexec_load / kexec_file_load from non-trusted comm"
require_policy_enabled CFML-EXEC-008
ensure_scratch_dir

src="$HELPERS_DIR/bin/kexec-loader"
# A masquerade name that's plausibly an attacker-installed kernel
# loader. Anything not in cfm_comm_is_trusted_kexec() works; this
# one is also long enough that the leading-dot doesn't make it
# disappear from typical `ps` columns.
masquerade="$SCRATCH_DIR/.cfm-kernel-stager"
cp "$src" "$masquerade"
chmod 0755 "$masquerade"
add_cleanup "rm -f '$masquerade'"

start_pos=$(mark_log_position)
trace "$masquerade"
# rc is irrelevant — kexec_load / kexec_file_load on bogus args
# always return non-zero, but the tracepoints already fired.
"$masquerade" >/dev/null 2>&1 || true

if hit=$(expect_event "$start_pos" "CFML-EXEC-008"); then
    pass "EXEC-008 fired: $hit"
    exit 0
fi
fail "no CFML-EXEC-008 line in $LSM_LOG within ${EXPECT_TIMEOUT}s"
exit 1

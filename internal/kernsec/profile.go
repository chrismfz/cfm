// Package kernsec implements the cfm kernel attack-surface reduction
// component. See docs/kernsec.md for the full design.
//
// This file defines the KSPP server-safe profile (sysctls + boot args)
// that kernsec inherits from scripts/kspp.sh and the Tier 1 extensions
// (modules + fstab) added in Phase 2. Stable rule IDs follow the
// `KSEC-<class>-<group>-<NNN>` scheme from docs/kernsec.md.
package kernsec

// Tier classifies a rule by safety / blast radius.
//
//	Tier1: safe-everywhere on hosting / KVM / cPanel / EL / Debian.
//	Tier2: server-aggressive — opt-in per host role, host-profile gated.
//	Tier3: aggressive — operator must explicitly opt in by raising
//	       conf.Tier to 3. Rules carry an audit-surfaced notice (stacked
//	       perf cost, legacy-binary risk, observability impact) that
//	       describes what the operator is signing up for. Host-profile
//	       probes still auto-skip individual entries on hosts where the
//	       break would be guaranteed (e.g. debugfs=off on a host with
//	       active bpftrace), exactly the same SkipReason mechanism Tier
//	       2 uses.
type Tier int

const (
	Tier1 Tier = 1
	Tier2 Tier = 2
	Tier3 Tier = 3
)

// SysctlRule is one expected sysctl key/value pair plus the human-readable
// blurbs the TUI surfaces and the registry metadata used by selectors.
type SysctlRule struct {
	ID          string // stable, e.g. KSEC-SCT-kspp.kernel-001
	Group       string // dotted tag, e.g. kspp.kernel
	Tier        Tier
	Key         string // dotted form, e.g. kernel.kptr_restrict
	Value       string // expected value as string
	Description string // one-line "what this does"
	Affects     string // one-line "what enabling this breaks"

	// AcceptValues lists additional live values that should be treated
	// as OK even though they don't match Value exactly. Used for
	// knobs where multiple settings deliver the same primary security
	// stance and the "ideal" value cannot be set at runtime (e.g.
	// kernel.unprivileged_bpf_disabled: 1 and 2 both block unprivileged
	// BPF; 2 additionally locks the knob; CONFIG_BPF_UNPRIV_DEFAULT_OFF
	// kernels boot at 1 and refuse runtime upgrade to 2). Empty for
	// the vast majority of rules where the desired value is the only
	// acceptable one.
	AcceptValues []string
}

// BootArg is one expected kernel boot argument.
//
// A bare token like "slab_nomerge" has Key=="slab_nomerge", Value=="".
// A "k=v" arg like "init_on_alloc=1" has Key=="init_on_alloc", Value=="1".
type BootArg struct {
	ID          string
	Group       string
	Tier        Tier
	Key         string
	Value       string
	Description string
	Affects     string
}

// ModuleRule is one kernel module that should be blacklisted.
// Phase 2 carries the data; the actual /etc/modprobe.d generator lives
// in Phase 3.
type ModuleRule struct {
	ID          string
	Group       string
	Tier        Tier
	Name        string // module name as used by lsmod / modprobe
	Description string
	Affects     string
}

// MountRule is one fstab audit entry. Most rules are report-only and
// kernsec NEVER auto-mutates /etc/fstab for them — the operator
// applies the recommendation by hand using the per-row tip. The
// narrow CanEnable=true exception lets `cfm kernsec apply` add the
// recommended options to /etc/fstab and remount for paths where
// auto-application is safe in every realistic context (currently
// only /dev/shm: tmpfs with no on-disk data to migrate, remount
// preserves contents, kernel noexec is a soft flag that does not
// kill running processes).
type MountRule struct {
	ID          string
	Group       string
	Tier        Tier
	MountPoint  string // e.g. "/tmp"
	Recommended string // e.g. "nodev,nosuid,noexec"
	Description string
	Affects     string

	// CanEnable means `cfm kernsec apply` is allowed to add this
	// rule's recommended options to /etc/fstab + remount the mount
	// point in-place. Defaults to false: every audit-only mount row
	// stays operator-managed. Set to true ONLY when:
	//   - the mount has no on-disk state to migrate;
	//   - remount with the recommended options is safe on a live
	//     production host (no risk of killing existing workloads);
	//   - the operator-recovery path is one short remount.
	// /dev/shm meets all three; /tmp and /var/tmp do not (live
	// MySQL temp tables, session files, the /var/tmp-survives-reboot
	// contract, etc.) and stay tip-only.
	CanEnable bool

	// DefaultLiveOptions lists the subset of Recommended that the
	// kernel / systemd / distro already applies at boot without
	// kernsec doing anything. /dev/shm is the canonical case: every
	// modern distro mounts it via systemd PID 1's mount-setup table
	// with nosuid,nodev already on, so the only option kernsec
	// effectively adds is noexec. Disable consults this field to
	// avoid the obvious foot-gun of remounting /dev/shm with
	// `dev,suid,exec` — that would leave the host *less* hardened
	// than a fresh distro install. With DefaultLiveOptions set,
	// disable reverts only the options kernsec actually added on
	// top of the distro baseline, never the baseline itself.
	DefaultLiveOptions string
}

// KSPPSysctls is the server-safe sysctl profile from kspp.sh.
// Keep in sync with scripts/kspp.sh KSPP_SYSCTL until kspp.sh is removed.
var KSPPSysctls = []SysctlRule{
	{
		ID: "KSEC-SCT-kspp.kernel-001", Group: "kspp.kernel", Tier: Tier1,
		Key: "kernel.kptr_restrict", Value: "2",
		Description: "Hide kernel pointers from userspace (/proc/kallsyms, dmesg, /proc/<pid>/stack).",
		Affects:     "Nothing on production. Symbol resolution still works for root.",
	},
	{
		ID: "KSEC-SCT-kspp.kernel-002", Group: "kspp.kernel", Tier: Tier1,
		Key: "kernel.dmesg_restrict", Value: "1",
		Description: "Restrict dmesg / kernel log reads to root.",
		Affects:     "Regular users can no longer read the kernel log.",
	},
	{
		ID: "KSEC-SCT-kspp.kernel-003", Group: "kspp.kernel", Tier: Tier1,
		Key: "kernel.unprivileged_bpf_disabled", Value: "2",
		// Live=1 already blocks unprivileged BPF; the only thing
		// Value=2 adds is "knob can no longer be changed", which
		// matters for defence-in-depth against root-equivalent
		// processes flipping it back. For the audit's green/OK
		// signal both are acceptable — flagging =1 as WARN would
		// be noise on CONFIG_BPF_UNPRIV_DEFAULT_OFF=y kernels where
		// =1 is the boot-time default and runtime upgrade is locked.
		AcceptValues: []string{"1"},
		Description:  "Block unprivileged BPF program loading and lock the setting until reboot. Value 2 differs from 1 in that it cannot be lowered back to 0 at runtime — closes the window where a kernel CVE or root-equivalent process re-enables unprivileged BPF without a reboot.",
		Affects:      "Kills a major LPE primitive class (eBPF-assisted privesc chains). Root BPF (cilium, imunify360 syscall tracing, bcc/bpftrace as root) unchanged. NOTE: kernels built with CONFIG_BPF_UNPRIV_DEFAULT_OFF=y (RHEL/Alma 9/10, recent stable kernels) boot with this knob already set to 1; once non-zero the kernel locks it and refuses every further sysctl write with EPERM. =1 is treated as an acceptable runtime value (still blocks unprivileged BPF); landing on the stricter =2 requires the paired boot arg KSEC-BOOT-bpf-001 (`unprivileged_bpf_disabled=2`) plus reboot. On kernels older than ~5.13 that don't recognise =2, the runtime apply may report 'not exposed' and the value falls back to whatever the kernel accepts.",
	},
	{
		ID: "KSEC-SCT-kspp.kernel-004", Group: "kspp.kernel", Tier: Tier1,
		Key: "kernel.randomize_va_space", Value: "2",
		Description: "Full ASLR for stack, heap, mmap, VDSO.",
		Affects:     "Nothing. Distro default already.",
	},
	{
		ID: "KSEC-SCT-kspp.fs-001", Group: "kspp.fs", Tier: Tier1,
		Key: "fs.protected_hardlinks", Value: "1",
		Description: "Prevent hardlink-based privilege escalation in shared directories.",
		Affects:     "Nothing in normal use.",
	},
	{
		ID: "KSEC-SCT-kspp.fs-002", Group: "kspp.fs", Tier: Tier1,
		Key: "fs.protected_symlinks", Value: "1",
		Description: "Restrict symlink-following in sticky-bit directories like /tmp.",
		Affects:     "Nothing in normal use.",
	},
	{
		ID: "KSEC-SCT-kspp.fs-003", Group: "kspp.fs", Tier: Tier1,
		Key: "fs.protected_fifos", Value: "2",
		Description: "Block unsafe FIFO usage in world-writable directories.",
		Affects:     "Nothing in normal use.",
	},
	{
		ID: "KSEC-SCT-kspp.fs-004", Group: "kspp.fs", Tier: Tier1,
		Key: "fs.protected_regular", Value: "2",
		Description: "Same protection family applied to regular files.",
		Affects:     "Nothing in normal use.",
	},
	{
		ID: "KSEC-SCT-kspp.net-001", Group: "kspp.net", Tier: Tier1,
		Key: "net.core.bpf_jit_harden", Value: "2",
		Description: "Constant blinding in the BPF JIT to defeat JIT-spray exploits.",
		Affects:     "Minor JIT performance cost. Negligible in practice.",
	},
	{
		ID: "KSEC-SCT-kspp.kernel-005", Group: "kspp.kernel", Tier: Tier1,
		Key: "kernel.perf_event_paranoid", Value: "3",
		// Upstream Documentation/admin-guide/sysctl/kernel.rst only
		// defines -1, 0, 1, 2. Value 3 is the Debian/Ubuntu/RHEL
		// downstream patch (Kees Cook, ~2014, never upstreamed) that
		// adds "disallow perf_event_open() entirely for users without
		// CAP_SYS_ADMIN / CAP_PERFMON" — the right default for a
		// multi-tenant hosting box and what kernsec ships. Some
		// hardened forks (Ubuntu hardened streams, grsec derivatives)
		// extend the patch further with value 4. Treat both ends as
		// also-green:
		//   "2" → mainline-vanilla kernels physically cannot reach 3;
		//         the sysctl handler clamps any write > the highest
		//         known constant. Audit would crywolf on those hosts.
		//   "4" → operators on a fork that defines 4 are STRICTER than
		//         the recommendation; equality-check would fail them.
		AcceptValues: []string{"2", "4"},
		Description:  "Restrict perf_event_open() to root. Debian/Ubuntu/EL downstream patch defines =3; some hardened forks define =4. Stricter values are also-green; =2 (upstream max) is also-green on mainline-vanilla kernels that don't carry the Debian patch.",
		Affects:      "Developer profiling tools (perf, flamegraph) need sudo.",
	},
	{
		ID: "KSEC-SCT-kspp.kernel-006", Group: "kspp.kernel", Tier: Tier1,
		Key: "kernel.yama.ptrace_scope", Value: "2",
		// Mode 1 still blocks the classic same-uid ptrace_attach
		// against non-children, but it does NOT block the
		// pidfd_getfd() exit-window race against setuid helpers
		// (the attacker fork+exec's the helper so it IS the
		// parent, which mode 1 allows through — confirmed live on
		// the ssh-keysign-pwn / chage_pwn reproducer chain). Mode 2
		// routes the check via security_ptrace_access_check() and
		// requires CAP_SYS_PTRACE, closing that primitive. Mode 1
		// used to be accepted as also-green here for hosts that
		// preferred same-uid debuggability (gdb/strace/py-spy
		// without sudo); we now require =2 because the residual
		// exit-window race is a working /etc/shadow disclosure
		// primitive against any setuid helper that opens a
		// sensitive file (chage, ssh-keysign, unix_chkpwd, ...).
		// Operators who genuinely need same-uid debuggability must
		// opt out explicitly via `[rule "KSEC-SCT-kspp.kernel-006"]
		// state = skip` in kernsec.conf. See Linus commit
		// 31e62c2ebbfd (ptrace: slightly saner get_dumpable() logic).
		Description: "Require CAP_SYS_PTRACE for any ptrace attach. Mode 2 also blocks the same-uid pidfd_getfd() exit-window race against setuid helpers — the ssh-keysign / chage fd-leak chain reported by Qualys (kernel fix: Linus commit 31e62c2ebbfd) — which mode 1 leaves wide open.",
		Affects:     "gdb --attach, strace -p, py-spy, bpftrace -p, rr record -p and similar attach-style debuggers/profilers need sudo even on the user's own processes. Crash reporters that opt in via PR_SET_PTRACER (Chrome crashpad, Firefox, drkonqi, abrt) can no longer produce minidumps — irrelevant on headless servers. Hosts that need same-uid debuggability without sudo must `state = skip` this rule; they keep the residual setuid-helper fd-leak race in exchange.",
	},
	{
		ID: "KSEC-SCT-kspp.kernel-007", Group: "kspp.kernel", Tier: Tier1,
		Key: "vm.mmap_min_addr", Value: "65536",
		// Modern x86_64 distros (Debian, Ubuntu, RHEL >= 7, Arch)
		// already default to 65536. Some EL configs ship 128K/256K;
		// stricter is also-green. The afflicted.sh "Resolute mitigation
		// map" article calls this out by name as the knob that blocks
		// NULL-deref-to-userspace exploitation primitives.
		AcceptValues: []string{"131072", "262144"},
		Description:  "Block userspace mmap() below 64 KiB. Defeats NULL-deref-to-userspace exploit primitives by ensuring no controllable userspace mapping can sit at low addresses where a kernel NULL pointer dereference would land.",
		Affects:      "Negligible on modern distros — this is already the default. Pre-2015 wine for 16-bit Windows, dosbox in raw mode, very old QEMU configs, and a handful of legacy emulators may need a per-binary override via prctl(PR_SET_MM_MAP_MIN_ADDR).",
	},
}

// KSPPBootArgs is the server-safe boot-arg profile from kspp.sh.
// Keep in sync with scripts/kspp.sh KSPP_ARGS until kspp.sh is removed.
//
// initcall_blacklist=algif_aead_init is the temporary mitigation for
// CVE-2026-31431 (Copy Fail). Remove later once all relevant kernels
// are patched.
var KSPPBootArgs = []BootArg{
	{
		ID: "KSEC-BOOT-kspp-001", Group: "kspp.boot", Tier: Tier1,
		Key:         "slab_nomerge",
		Description: "Don't merge slab caches that have similar size. Hardens against type-confusion UAF exploits.",
		Affects:     "Small RAM overhead.",
	},
	{
		ID: "KSEC-BOOT-kspp-002", Group: "kspp.boot", Tier: Tier1,
		Key: "init_on_alloc", Value: "1",
		Description: "Zero pages on allocation. Kills uninitialized-memory leaks across the whole kernel.",
		Affects:     "~0-5% performance cost on alloc-heavy workloads.",
	},
	{
		ID: "KSEC-BOOT-kspp-003", Group: "kspp.boot", Tier: Tier1,
		Key: "page_alloc.shuffle", Value: "1",
		Description: "Randomize buddy-allocator freelists. Mild ASLR boost for kernel allocations.",
		Affects:     "Nothing measurable.",
	},
	{
		ID: "KSEC-BOOT-kspp-004", Group: "kspp.boot", Tier: Tier1,
		Key: "randomize_kstack_offset", Value: "on",
		Description: "Per-syscall kernel-stack randomization. Makes ROP / stack-spray exploits harder.",
		Affects:     "Nothing.",
	},
	{
		ID: "KSEC-BOOT-kspp-005", Group: "kspp.boot", Tier: Tier1,
		Key: "initcall_blacklist", Value: "algif_aead_init",
		Description: "TEMPORARY: blocks algif_aead init at boot — mitigation for Copy Fail / CVE-2026-31431.",
		Affects:     "AEAD operations via AF_ALG userspace API. Remove once kernels are patched.",
	},
}

// Tier2Sysctls is the server-aggressive sysctl profile (Phase 4).
// Each rule is opt-in — operator must set tier=2 in kernsec.conf — and
// host-profile gated where it would break common workloads.
//
// kernel.modules_disabled=1 is intentionally NOT here. It needs a late
// systemd unit (post multi-user.target) so cfm itself can finish
// loading kernel modules before the lockout fires; that's a follow-up
// PR, not Phase 4.
var Tier2Sysctls = []SysctlRule{
	{
		ID: "KSEC-SCT-tier2.namespace-001", Group: "tier2.namespace", Tier: Tier2,
		Key: "user.max_user_namespaces", Value: "0",
		Description: "Disable unprivileged user namespace creation — kills a major LPE primitive class.",
		Affects:     "Breaks rootless podman, bwrap, Chromium sandbox, cPanel jails, CloudLinux/CageFS isolation. Skipped if containers or hosting panels detected.",
	},
	{
		ID: "KSEC-SCT-tier2.namespace-002", Group: "tier2.namespace", Tier: Tier2,
		Key: "kernel.unprivileged_userns_clone", Value: "0",
		Description: "Debian-flavoured alternative for blocking unprivileged userns. Reversible without breaking root use.",
		Affects:     "Same surface as user.max_user_namespaces=0. Skipped if containers or hosting panels detected. Skipped if kernel doesn't expose the key (non-Debian).",
	},
}

// Tier2BootArgs is the server-aggressive boot-arg profile (Phase 4).
//
// Each adds an entry to ManagedBootArgKeys so disable / apply --remove
// strip it cleanly.
var Tier2BootArgs = []BootArg{
	{
		ID: "KSEC-BOOT-tier2.oops-001", Group: "tier2.oops", Tier: Tier2,
		Key: "oops", Value: "panic",
		Description: "Pair with kernel.panic_on_oops=1 to stop oops-spray exploit techniques cold.",
		Affects:     "Aggressive: any kernel oops becomes a reboot. On a multi-tenant host (KVM hypervisor, libvirt, Proxmox, container engine) one oops reboots every guest/container at once. Auto-skipped on multi-tenant hosts; defensible on single-tenant boxes.",
	},
}

// Tier3BootArgs is the aggressive opt-in boot-arg profile.
//
// Tier 3 entries are not applied unless the operator raises conf.Tier
// to 3 explicitly. Each entry pairs with either a host-profile probe
// that auto-skips it on hosts where the break would be guaranteed,
// or a preflight notice that surfaces the cost the operator is
// signing up for (init_on_free + stacked perf cost on top of the
// Tier 1 init_on_alloc=1).
//
// Each also adds an entry to ManagedBootArgKeys so disable / apply
// --remove strip it cleanly.
//
// Held-back candidates documented in docs/kernsec.md
// ("Considered but not shipped"): kernel.io_uring_disabled=2,
// vsyscall=none, debugfs=off. Bring them back once the probes /
// audit-only path identified in that section are reliable.
var Tier3BootArgs = []BootArg{
	{
		ID: "KSEC-BOOT-tier3.mempaint-001", Group: "tier3.mempaint", Tier: Tier3,
		Key: "init_on_free", Value: "1",
		Description: "Zero pages at free time. Pairs with the Tier 1 init_on_alloc=1 (KSEC-BOOT-kspp-002) to fully eliminate use-after-free read primitives: init_on_alloc defeats UAF-read-of-stale-data, init_on_free defeats UAF-read-of-just-freed. The afflicted.sh \"Resolute mitigation map\" writeup specifically names INIT_ON_FREE=off as the kernel-side gap that keeps UAF-read viable on otherwise fully-hardened distros.",
		Affects:     "Additional ~1-3% memory-allocation perf cost on free paths, stacked on top of init_on_alloc=1's ~0-5%. Brick-safe — no compatibility breakages, only measurable throughput cost. Apply only on hosts where the combined ceiling (~3-8% worst-case) is acceptable.",
	},
}

// Tier1BootArgsExt are Tier 1 boot args beyond the KSPP baseline.
var Tier1BootArgsExt = []BootArg{
	// --- boot.bug-detection ------------------------------------------
	{
		ID: "KSEC-BOOT-bug-detection-001", Group: "boot.bug-detection", Tier: Tier1,
		Key: "kfence.sample_interval", Value: "100",
		Description: "Enable KFENCE heap safety net: one in 100 allocations gets a guarded page, catching use-after-free and out-of-bounds bugs in production at effectively zero overhead.",
		Affects:     "None measurable. The guarded fraction adds <0.1% allocation latency on benchmarks; field experience shows negligible impact on hosting workloads.",
	},
	// --- boot.dma: pre-IOMMU DMA window hardening (EFI only) ---------
	{
		ID: "KSEC-BOOT-dma-001", Group: "boot.dma", Tier: Tier1,
		Key: "efi", Value: "disable_early_pci_dma",
		Description: "Disable DMA from PCI devices before the IOMMU is initialised — closes the pre-IOMMU window that a malicious peripheral (e.g. a Thunderbolt device) could use to read/write kernel memory before protections are active.",
		Affects:     "None on well-behaved hardware. Skipped on non-EFI systems (parameter is EFI-specific and a no-op on BIOS/legacy-boot).",
	},
	// --- boot.sidechannel: TSX side-channel mitigation ---------------
	{
		ID: "KSEC-BOOT-sidechannel-001", Group: "boot.sidechannel", Tier: Tier1,
		Key: "tsx", Value: "off",
		Description: "Disable Intel Transactional Synchronization Extensions — removes the hardware primitives exploited by TAA (CVE-2019-11135) and related MDS variants. TSX is unused by any standard hosting or KVM workload.",
		Affects:     "None on hosting / KVM servers; TSX is not used by MySQL, nginx, PHP, Python, etc. Non-Intel CPUs and Intel CPUs with the TSX deprecation microcode already applied ignore the parameter.",
	},
	// --- boot.bpf: pair the sticky kernel.unprivileged_bpf_disabled sysctl
	// with the only path that actually lands on value 2 on locked kernels.
	// CONFIG_BPF_UNPRIV_DEFAULT_OFF=y kernels (RHEL/Alma 9/10) boot the
	// sysctl at 1 and refuse every later runtime write with EPERM, so the
	// matching sysctl rule (KSEC-SCT-kspp.kernel-003) cannot reach 2
	// without this cmdline arg + reboot.
	{
		ID: "KSEC-BOOT-bpf-001", Group: "boot.bpf", Tier: Tier1,
		Key: "unprivileged_bpf_disabled", Value: "2",
		Description: "Boot the kernel with kernel.unprivileged_bpf_disabled already set to 2 — the only way to land on value 2 on kernels built with CONFIG_BPF_UNPRIV_DEFAULT_OFF=y, which boot the knob at 1 and lock it against further sysctl writes.",
		Affects:     "Same surface as the paired sysctl rule. Older kernels that don't recognise =2 ignore the arg silently.",
	},
}

// MemExploitSysctls is the memory/exploit-mitigation sysctl group.
// The safe-everywhere entries reduce common LPE primitives without
// changing normal server behaviour. The oops/panic pair intentionally
// lives in Tier 2 because it trades availability for fail-closed exploit
// mitigation: any kernel oops can reboot the host.
var MemExploitSysctls = []SysctlRule{
	{
		ID: "KSEC-SCT-mem.exploit-001", Group: "sysctl.mem.exploit", Tier: Tier1,
		Key: "vm.unprivileged_userfaultfd", Value: "0",
		Description: "Disable unprivileged userfaultfd — removes a frequently-abused heap-spray / race primitive from unprivileged attackers.",
		Affects:     "Rare userspace checkpointing / post-copy migration tools need privileges or a per-host override.",
	},
	{
		ID: "KSEC-SCT-mem.exploit-002", Group: "sysctl.mem.exploit", Tier: Tier1,
		Key: "vm.mmap_rnd_bits", Value: "32",
		Description: "Maximise mmap ASLR entropy on 64-bit kernels that expose this knob.",
		Affects:     "None on normal hosting workloads; skipped automatically on kernels that do not expose the key.",
	},
	{
		ID: "KSEC-SCT-mem.exploit-003", Group: "sysctl.mem.exploit", Tier: Tier1,
		Key: "vm.mmap_rnd_compat_bits", Value: "16",
		Description: "Maximise mmap ASLR entropy for 32-bit compatibility processes where supported.",
		Affects:     "None; skipped automatically on kernels without 32-bit compat ASLR support.",
	},
	{
		ID: "KSEC-SCT-mem.exploit-004", Group: "sysctl.mem.exploit", Tier: Tier1,
		Key: "kernel.warn_limit", Value: "10",
		Description: "Rate-limit WARN splats so warning-spray exploit techniques cannot loop indefinitely.",
		Affects:     "None for production use; very noisy kernel debugging sessions may need an override.",
	},
	{
		ID: "KSEC-SCT-mem.exploit-005", Group: "sysctl.mem.exploit", Tier: Tier1,
		Key: "kernel.oops_limit", Value: "10",
		Description: "Rate-limit kernel oops handling to blunt oops-spray exploit techniques.",
		Affects:     "None in normal operation; repeated kernel bugs stop producing unlimited oops reports.",
	},
	{
		ID: "KSEC-SCT-mem.exploit-006", Group: "tier2.oops", Tier: Tier2,
		Key: "kernel.panic_on_oops", Value: "1",
		Description: "Fail closed on a kernel oops instead of continuing after possible kernel memory corruption.",
		Affects:     "Aggressive: any kernel oops can reboot the host. On a multi-tenant host (KVM hypervisor, libvirt, Proxmox, container engine) the reboot takes down every guest/container at once. Tier 2 only; auto-skipped on multi-tenant hosts; pair with oops=panic and kernel.panic=10 on single-tenant boxes.",
	},
	{
		ID: "KSEC-SCT-mem.exploit-007", Group: "sysctl.mem.exploit", Tier: Tier1,
		Key: "fs.suid_dumpable", Value: "0",
		Description: "Disable core dumps from setuid/setgid binaries so privileged memory is not written to attacker-readable paths.",
		Affects:     "Crash diagnostics for setuid helpers require a deliberate per-host override.",
	},
	{
		ID: "KSEC-SCT-mem.exploit-008", Group: "tier2.oops", Tier: Tier2,
		Key: "kernel.panic", Value: "10",
		Description: "Reboot ten seconds after a panic so Tier 2 oops=panic hosts recover automatically after fail-closed crashes.",
		Affects:     "Aggressive: panic reboots may reduce forensic time on the console. On a multi-tenant host the reboot takes down every guest/container at once. Tier 2 only; auto-skipped on multi-tenant hosts.",
	},
}

// KernelSurface is the kernel attack-surface hardening sysctl group.
var KernelSurface = []SysctlRule{
	// --- sysctl.kernel.surface: generic kernel surface reductions -----
	{
		ID: "KSEC-SCT-kernel.surface-001", Group: "sysctl.kernel.surface", Tier: Tier1,
		Key: "dev.tty.ldisc_autoload", Value: "0",
		Description: "Disable automatic TTY line-discipline module loading — closes n_hdlc-style autoload attack paths from unprivileged TTY users.",
		Affects:     "None on servers; unusual TTY line disciplines must be loaded explicitly by root before use.",
	},
	{
		ID: "KSEC-SCT-kernel.surface-003", Group: "sysctl.kernel.surface", Tier: Tier1,
		Key: "kernel.sysrq", Value: "0",
		Description: "Disable Magic SysRq actions from keyboard/proc triggers to reduce emergency-control primitives exposed to compromised privileged processes.",
		Affects:     "Loses Magic SysRq emergency debugging shortcuts unless overridden (for example to SAK-only mode).",
	},

	// --- sysctl.kernel.coredump: core_pattern (Tier 2, gated) -----
	{
		ID: "KSEC-SCT-kernel.coredump-001", Group: "sysctl.kernel.coredump", Tier: Tier2,
		Key: "kernel.core_pattern", Value: "|/bin/false",
		Description: "Redirect coredumps to /bin/false — prevents exploit-writable core-dump paths used by OverlayFS-class privilege escalations (CVE-2023-0386 and similar). On a shared hosting server where tenants can trigger process crashes you do not want coredumps landing anywhere.",
		Affects:     "Tier 2: coredumps are suppressed for all processes, which can break support diagnostics, backup/monitoring crash capture, and hosting-panel/vendor troubleshooting. Skipped when those risks are detected.",
	},

	// --- sysctl.kernel.kexec: lock out kexec_load (Tier 1, gated) -----
	{
		ID: "KSEC-SCT-kspp.kexec-001", Group: "sysctl.kernel.kexec", Tier: Tier1,
		Key: "kernel.kexec_load_disabled", Value: "1",
		Description: "Disable kexec_load(2) and kexec_file_load(2) — closes a rootkit-persistence vector that loads a replacement kernel post-boot. KernelCare / Ksplice live-patch through kernel modules, not kexec, so this knob does NOT conflict with them. Standard package-manager kernel updates use the bootloader, not kexec. The one real conflict — kdump's crash-kernel preloading — is gated by the host-profile probe HasKdump (skipped when /proc/cmdline carries crashkernel= or kdump.service is installed).",
		Affects:     "On hosts without kdump configured: zero user-visible change. On hosts WITH kdump: rule is auto-skipped with an audit line so crash-dump capability stays intact. Once set, the knob is sticky — kexec_load cannot be re-enabled until reboot.",
	},
}

// NetHardenSysctls is the network hardening sysctl group owned
// directly by kernsec. These keys are NOT owned by cfm-sysctl-tweaks
// (compare NetSysctls which is audit-only / EXT for sys_tweaks keys).
// kernsec writes these values itself via the normal apply pipeline.
var NetHardenSysctls = []SysctlRule{
	{
		ID: "KSEC-SCT-net.harden-001", Group: "sysctl.net.harden", Tier: Tier1,
		Key: "net.ipv4.icmp_echo_ignore_broadcasts", Value: "1",
		Description: "Ignore ICMP echo requests sent to broadcast addresses — prevents Smurf amplification attacks that can overwhelm bandwidth.",
		Affects:     "None. Broadcast ping is unused in any legitimate hosting workflow.",
	},
	{
		ID: "KSEC-SCT-net.harden-002", Group: "sysctl.net.harden", Tier: Tier1,
		Key: "net.ipv4.conf.all.accept_source_route", Value: "0",
		Description: "Reject IPv4 source-routed packets — source routing can bypass firewall rules and enable traffic redirection attacks.",
		Affects:     "None. Source routing is deprecated and unused on modern networks.",
	},
	{
		ID: "KSEC-SCT-net.harden-003", Group: "sysctl.net.harden", Tier: Tier1,
		Key: "net.ipv4.conf.default.accept_source_route", Value: "0",
		Description: "Same source-route rejection policy for newly-created interfaces (ensures the secure default propagates).",
		Affects:     "None.",
	},
	{
		ID: "KSEC-SCT-net.harden-004", Group: "sysctl.net.harden", Tier: Tier1,
		Key: "net.ipv4.conf.all.log_martians", Value: "1",
		Description: "Log packets with impossible (martian) source addresses — surfaces IP spoofing, route injection, and misconfigured upstream routers.",
		Affects:     "Minor log volume on misconfigured network segments. Expected to produce no log lines on a well-configured host.",
	},
	{
		ID: "KSEC-SCT-net.harden-005", Group: "sysctl.net.harden", Tier: Tier1,
		Key: "net.ipv4.tcp_rfc1337", Value: "1",
		Description: "RFC 1337 TIME_WAIT assassination fix — prevents RST packets from prematurely killing connections in TIME_WAIT, closing a timing-based connection-hijack vector.",
		Affects:     "None.",
	},
}

// ManagedBootArgKeys is the set of cmdline keys kernsec owns.
// Mirrors kspp.sh MANAGED_ARG_KEYS. enable removes any stale instance
// of these keys before adding the desired set; disable removes them
// entirely. Operator-set args on the cmdline outside this set are
// preserved untouched.
var ManagedBootArgKeys = []string{
	// Tier 1 (KSPP)
	"slab_nomerge",
	"init_on_alloc",
	"page_alloc.shuffle",
	"randomize_kstack_offset",
	"initcall_blacklist",
	// Tier 1 extensions
	"kfence.sample_interval",
	"efi",
	"tsx",
	"unprivileged_bpf_disabled",
	// Tier 2
	"oops",
	// Tier 3
	"init_on_free",
}

// String returns the cmdline form of a boot arg ("key" or "key=value").
func (a BootArg) String() string {
	if a.Value == "" {
		return a.Key
	}
	return a.Key + "=" + a.Value
}

// AllSysctls returns the full sysctl rule set across tiers (Tier 1 KSPP +
// Tier 1 surface/net extensions + Tier 2 server-aggressive + EXT audit).
// Order: Tier 1 first, then Tier 2, EXT last — keeps the rendered file
// deterministic and Tier-1-first-readable.
func AllSysctls() []SysctlRule {
	out := make([]SysctlRule, 0,
		len(KSPPSysctls)+len(MemExploitSysctls)+len(KernelSurface)+len(NetHardenSysctls)+
			len(Tier2Sysctls)+len(NetSysctls))
	out = append(out, KSPPSysctls...)
	out = append(out, MemExploitSysctls...)
	out = append(out, KernelSurface...)
	out = append(out, NetHardenSysctls...)
	out = append(out, Tier2Sysctls...)
	out = append(out, NetSysctls...)
	return out
}

// NetSysctls is the network-hardening sysctl audit set. Every key
// here is owned by `internal/sysctl/sys_tweaks.go` (the cfm daemon's
// imperative TCP/conntrack/spoof-guard tuning) per the
// managedsysctl cross-component registry. kernsec ships these as
// Tier 1 audit-only rules: the resolver consults
// managedsysctl.Default().OwnerOf(), sees sys_tweaks owns the key,
// and resolves every rule in this group to ManagedExternally —
// kernsec NEVER writes these values, only audits whether the live
// state matches what sys_tweaks intended.
//
// This realises the "single source of truth per setting" goal of
// Phase 6 without merging the imperative sys_tweaks logic into
// kernsec rule data: sys_tweaks keeps owning runtime computation
// (RAM-derived nf_conntrack_max, config-driven rp_filter strict-
// vs-loose, etc.), kernsec keeps owning the audit / status / TUI
// surface, and the managedsysctl registry mediates.
//
// Scope intentionally limited to keys sys_tweaks's ManagedKeys()
// actually claims. Additional network-hardening rules (icmp_echo
// broadcast drop, accept_source_route=0, log_martians, etc.) are
// design-table candidates but not shipped here — they'd require
// either expanding sys_tweaks's surface or having kernsec own them
// directly. Future PR.
//
// Operators who disagree with sys_tweaks's chosen values edit
// cfm.conf's SystemTweaks fields rather than via kernsec overrides;
// kernsec.Resolve respects `state = force` though, in which case
// kernsec WILL write its recommended value and the conflict surfaces
// in the daemon log.
var NetSysctls = []SysctlRule{
	{
		ID: "KSEC-SCT-net.spoof-001", Group: "sysctl.net", Tier: Tier1,
		Key: "net.ipv4.conf.all.rp_filter", Value: "1",
		Description: "Reverse-path filter — drops packets whose source can't route back the same way.",
		Affects:     "Asymmetric-routing setups (rare on hosting). Owned by cfm-sysctl-tweaks; tunable via SystemTweaks.RPFilter.",
	},
	{
		ID: "KSEC-SCT-net.redirect-001", Group: "sysctl.net", Tier: Tier1,
		Key: "net.ipv4.conf.all.accept_redirects", Value: "0",
		Description: "Refuse ICMP redirects — closes the routing-table-MitM primitive.",
		Affects:     "None — modern routing tables don't depend on ICMP redirects. Owned by cfm-sysctl-tweaks; tunable via SystemTweaks.AcceptRedirects.",
	},
	{
		ID: "KSEC-SCT-net.redirect-002", Group: "sysctl.net", Tier: Tier1,
		Key: "net.ipv4.conf.all.send_redirects", Value: "0",
		Description: "Don't emit ICMP redirects — host isn't a router.",
		Affects:     "None on hosting. Owned by cfm-sysctl-tweaks; tunable via SystemTweaks.SendRedirects.",
	},
	{
		ID: "KSEC-SCT-net.tcp-001", Group: "sysctl.net", Tier: Tier1,
		Key: "net.ipv4.tcp_syncookies", Value: "1",
		Description: "TCP SYN cookies — survive SYN floods without resource exhaustion.",
		Affects:     "None. Owned by cfm-sysctl-tweaks (hard-coded =1 when SystemTweaks.Enable).",
	},
	{
		ID: "KSEC-SCT-net.ipv6-001", Group: "sysctl.net", Tier: Tier1,
		Key: "net.ipv6.conf.all.accept_redirects", Value: "0",
		Description: "v6 ICMP-redirect refusal — same MitM closure for IPv6.",
		Affects:     "None. Owned by cfm-sysctl-tweaks (hard-coded =0 when SystemTweaks.Enable).",
	},
}

// AllBootArgs returns the full boot-arg rule set across tiers.
// Order: Tier 1 KSPP baseline, Tier 1 extensions, Tier 2 opt-in,
// Tier 3 explicit opt-in.
func AllBootArgs() []BootArg {
	out := make([]BootArg, 0, len(KSPPBootArgs)+len(Tier1BootArgsExt)+len(Tier2BootArgs)+len(Tier3BootArgs))
	out = append(out, KSPPBootArgs...)
	out = append(out, Tier1BootArgsExt...)
	out = append(out, Tier2BootArgs...)
	out = append(out, Tier3BootArgs...)
	return out
}

// AllModules returns the full module-blacklist rule set.
// Phase 2 carries the data; apply lands in Phase 3.
func AllModules() []ModuleRule {
	out := make([]ModuleRule, 0, len(Tier1Modules)+len(Tier2Modules))
	out = append(out, Tier1Modules...)
	out = append(out, Tier2Modules...)
	return out
}

// AllMounts returns the full fstab audit rule set.
func AllMounts() []MountRule {
	return append([]MountRule(nil), Tier1Mounts...)
}

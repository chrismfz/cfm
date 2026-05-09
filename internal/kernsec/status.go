package kernsec

import (
	"fmt"
	"io"
)

// StatusOptions controls what RunStatus emits.
type StatusOptions struct {
	// SkipAFAlg skips AF_ALG bind probes (they require AF_ALG support
	// in the kernel and will produce noise on systems where the family
	// is entirely absent). Defaults false.
	SkipAFAlg bool
}

// StatusResult is the machine-readable summary returned by RunStatus.
// Phase 1 keeps it minimal; Phase 2 expands it once rule IDs land.
type StatusResult struct {
	OK       bool // false if any check produced WARN
	Warnings int
}

// RunStatus prints the kernsec audit-only status to w. Mirrors
// kspp.sh status output and adds AF_ALG probes for the broader
// algif_* set. No mutations.
func RunStatus(w io.Writer, opts StatusOptions) StatusResult {
	res := StatusResult{OK: true}

	fs := RealFS{}
	be := DetectBackend(fs)
	currentCmdline := ReadProcCmdline()
	nextCmdline, _ := be.NextBootCmdline()

	fmt.Fprintln(w, "===== CFM kernsec STATUS =====")
	fmt.Fprintln(w)

	fmt.Fprintln(w, "[Boot mode]")
	fmt.Fprintln(w, be.Label())
	fmt.Fprintln(w)

	fmt.Fprintln(w, "[Current running kernel cmdline]")
	fmt.Fprintln(w, currentCmdline)
	fmt.Fprintln(w)

	fmt.Fprintln(w, "[Configured default kernel cmdline — next boot]")
	fmt.Fprintln(w, nextCmdline)
	fmt.Fprintln(w)

	fmt.Fprintln(w, "[Expected runtime sysctl verification]")
	for _, rule := range KSPPSysctls {
		state, found := CheckSysctl(rule)
		switch state {
		case SysctlOK:
			fmt.Fprintf(w, "OK    %s=%s\n", rule.Key, found)
		case SysctlMismatch:
			fmt.Fprintf(w, "WARN  %s expected %s, found %s\n", rule.Key, rule.Value, found)
			res.warn()
		case SysctlMissing:
			fmt.Fprintf(w, "SKIP  %s missing on this kernel\n", rule.Key)
		}
	}
	fmt.Fprintln(w)

	currentTokens := ParseCmdline(currentCmdline)
	nextTokens := ParseCmdline(nextCmdline)

	res.printArgState(w, "KSPP boot args in current running kernel", currentTokens)
	res.printArgState(w, "KSPP boot args configured for next boot", nextTokens)

	klog := ReadKernelLog()
	fmt.Fprintln(w, "[Kernel boot warnings about managed args]")
	if matched := UnknownArgWarnings(klog, ManagedBootArgKeys); len(matched) > 0 {
		for _, line := range matched {
			fmt.Fprintln(w, line)
		}
		res.warn()
	} else {
		fmt.Fprintln(w, "OK    no unknown/invalid warning found for managed kernsec args")
	}
	fmt.Fprintln(w)

	fmt.Fprintln(w, "[Copy Fail / algif_aead mitigation]")
	mitigation := BootArg{Key: "initcall_blacklist", Value: "algif_aead_init"}
	if state, _ := CheckBootArg(currentTokens, mitigation); state == ArgOK {
		fmt.Fprintln(w, "OK    initcall_blacklist=algif_aead_init present in current cmdline")
	} else {
		fmt.Fprintln(w, "WARN  initcall_blacklist=algif_aead_init not active in current cmdline")
		fmt.Fprintln(w, "      Reboot is required after enable.")
		res.warn()
	}

	if !opts.SkipAFAlg {
		fmt.Fprintln(w)
		fmt.Fprintln(w, "[AF_ALG bind probes]")
		for _, r := range ProbeAllAFAlg() {
			fmt.Fprintln(w, FormatAFAlg(r))
			if r.Bound && r.Type == "aead" {
				res.warn()
			}
		}
	}
	fmt.Fprintln(w)

	fmt.Fprintln(w, "[page_alloc.shuffle runtime state]")
	if raw, ok := PageAllocShuffleState(); ok {
		if IsPageAllocShuffleOn(raw) {
			fmt.Fprintf(w, "OK    /sys/module/page_alloc/parameters/shuffle = %s\n", raw)
		} else {
			fmt.Fprintf(w, "WARN  /sys/module/page_alloc/parameters/shuffle = %s\n", raw)
			res.warn()
		}
	} else {
		fmt.Fprintln(w, "WARN  /sys/module/page_alloc/parameters/shuffle not found")
		fmt.Fprintln(w, "      Kernel may lack CONFIG_SHUFFLE_PAGE_ALLOCATOR=y")
		res.warn()
	}
	fmt.Fprintln(w)

	fmt.Fprintln(w, "[mem auto-init state]")
	if line := MemAutoInitLine(klog); line != "" {
		fmt.Fprintln(w, line)
		if IsInitOnAllocActive(line) {
			fmt.Fprintln(w, "OK    init_on_alloc appears active")
		} else {
			fmt.Fprintln(w, "WARN  init_on_alloc does not appear active")
			res.warn()
		}
	} else {
		fmt.Fprintln(w, "WARN  no mem auto-init line found in kernel log")
		fmt.Fprintln(w, "      Try: journalctl -k -b -o cat | grep -i 'mem auto-init'")
		res.warn()
	}
	fmt.Fprintln(w)

	fmt.Fprintln(w, "[randomize_kstack_offset support]")
	cfg, ok := ReadKernelConfig()
	if ok {
		if HasKernelConfigIn(cfg, "HAVE_ARCH_RANDOMIZE_KSTACK_OFFSET") &&
			HasKernelConfigIn(cfg, "RANDOMIZE_KSTACK_OFFSET") {
			fmt.Fprintln(w, "OK    kernel config supports randomize_kstack_offset")
		} else {
			fmt.Fprintln(w, "WARN  kernel config may not support randomize_kstack_offset")
			res.warn()
		}
		fmt.Fprintln(w)
		fmt.Fprintln(w, "[Kernel config hints]")
		for _, name := range []string{
			"SHUFFLE_PAGE_ALLOCATOR",
			"INIT_ON_ALLOC_DEFAULT_ON",
			"HAVE_ARCH_RANDOMIZE_KSTACK_OFFSET",
			"RANDOMIZE_KSTACK_OFFSET",
			"SLUB",
			"BPF_JIT",
			"CRYPTO_USER_API",
			"CRYPTO_USER_API_AEAD",
		} {
			if HasKernelConfigIn(cfg, name) {
				fmt.Fprintf(w, "CONFIG_%s=y\n", name)
			}
		}
	} else {
		fmt.Fprintln(w, "WARN  kernel config not readable from /boot/config-<release> or /proc/config.gz")
		res.warn()
	}
	fmt.Fprintln(w)

	if res.Warnings == 0 {
		fmt.Fprintln(w, "[+] Status verification looks good.")
	} else {
		fmt.Fprintf(w, "[!] Status verification found %d warning(s). Review output above.\n", res.Warnings)
	}
	fmt.Fprintln(w, "==============================")
	return res
}

// printArgState renders one section of expected boot args against a
// concrete cmdline. Mirrors kspp.sh show_arg_state.
func (res *StatusResult) printArgState(w io.Writer, label string, tokens []string) {
	fmt.Fprintf(w, "[%s]\n", label)
	for _, want := range KSPPBootArgs {
		state, found := CheckBootArg(tokens, want)
		switch state {
		case ArgOK:
			fmt.Fprintf(w, "OK         %s\n", want)
		case ArgDiff:
			fmt.Fprintf(w, "DIFF       wanted: %s    found: %s=%s\n", want, want.Key, found)
			res.warn()
		case ArgMissing:
			fmt.Fprintf(w, "MISSING    %s\n", want)
			res.warn()
		}
	}
	fmt.Fprintln(w)
}

func (res *StatusResult) warn() {
	res.Warnings++
	res.OK = false
}

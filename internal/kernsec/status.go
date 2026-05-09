package kernsec

import (
	"errors"
	"fmt"
	"io"
	"os"
)

// StatusOptions controls what RunStatus emits.
type StatusOptions struct {
	// SkipAFAlg skips AF_ALG bind probes (they require AF_ALG support
	// in the kernel and will produce noise on systems where the family
	// is entirely absent). Defaults false.
	SkipAFAlg bool
}

// StatusResult is the machine-readable summary returned by RunStatus.
type StatusResult struct {
	OK       bool // false if any check produced WARN
	Warnings int
	Tier     Tier // tier in effect when the audit ran (0/1/2)
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

	// Best-effort conf load. If absent or unreadable, default to
	// tier=1 — matches first-run UX and produces sensible audit on
	// hosts that haven't run init yet.
	conf, err := LoadConf(false)
	if err != nil {
		conf = &Conf{Tier: Tier1, Overrides: map[string]RuleOverride{}}
	}
	res.Tier = conf.Tier

	fmt.Fprintln(w, "===== CFM kernsec STATUS =====")
	fmt.Fprintln(w)

	fmt.Fprintln(w, "[Boot mode]")
	fmt.Fprintln(w, be.Label())
	fmt.Fprintln(w)

	fmt.Fprintf(w, "[Conf tier]  %d\n", conf.Tier)
	fmt.Fprintln(w)

	fmt.Fprintln(w, "[Current running kernel cmdline]")
	fmt.Fprintln(w, currentCmdline)
	fmt.Fprintln(w)

	fmt.Fprintln(w, "[Configured default kernel cmdline — next boot]")
	fmt.Fprintln(w, nextCmdline)
	fmt.Fprintln(w)

	fmt.Fprintln(w, "[Expected runtime sysctl verification]")
	for _, rule := range AllSysctls() {
		if rule.Tier > conf.Tier {
			continue
		}
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

	res.printArgState(w, "Managed boot args in current running kernel", currentTokens, conf.Tier)
	res.printArgState(w, "Managed boot args configured for next boot", nextTokens, conf.Tier)

	res.printModuleState(w)

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
// concrete cmdline. Mirrors kspp.sh show_arg_state. Filters to rules
// whose tier <= confTier so a tier=1 host doesn't see Tier 2 rules
// reported as MISSING (they're not expected to apply at tier=1).
func (res *StatusResult) printArgState(w io.Writer, label string, tokens []string, confTier Tier) {
	fmt.Fprintf(w, "[%s]\n", label)
	for _, want := range AllBootArgs() {
		if want.Tier > confTier {
			continue
		}
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

// printModuleState surfaces the module-blacklist audit in the same
// label-prefixed style as the rest of status output: managed file's
// presence and per-module state. Phase 3 keeps this concise — the TUI
// is the rich surface; text mode is for piping / monitoring.
func (res *StatusResult) printModuleState(w io.Writer) {
	fmt.Fprintln(w, "[Module blacklist]")

	managedExists := true
	if _, err := os.Stat(ModprobePath); err != nil {
		if errors.Is(err, os.ErrNotExist) {
			fmt.Fprintf(w, "MISSING    %s not present — `cfm kernsec apply` to create it\n", ModprobePath)
			res.warn()
			managedExists = false
		} else {
			fmt.Fprintf(w, "ERROR      cannot stat %s: %v\n", ModprobePath, err)
			res.warn()
			managedExists = false
		}
	}

	loaded := LoadedModules()
	managed := ParseManagedBlacklist()
	var loadedCount, missingCount, okCount, skipCount int

	for _, m := range Tier1Modules {
		_, isBlacklisted := managed[m.Name]
		_, isLoaded := loaded[m.Name]
		switch {
		case isBlacklisted && isLoaded:
			loadedCount++
		case isBlacklisted:
			okCount++
		case !ModulePresentOnKernel(m.Name):
			skipCount++
		default:
			missingCount++
		}
	}

	if managedExists {
		fmt.Fprintf(w, "OK         %s present (%d managed entries audited)\n",
			ModprobePath, len(Tier1Modules))
	}
	fmt.Fprintf(w, "OK         %d modules blacklisted and not loaded\n", okCount)
	if loadedCount > 0 {
		fmt.Fprintf(w, "WARN       %d modules blacklisted but still loaded — reboot or rmmod for effect\n",
			loadedCount)
		res.warn()
	}
	if missingCount > 0 {
		fmt.Fprintf(w, "MISSING    %d modules expected to be blacklisted but absent from %s\n",
			missingCount, ModprobePath)
		res.warn()
	}
	if skipCount > 0 {
		fmt.Fprintf(w, "SKIP       %d modules not present on this kernel\n", skipCount)
	}
	fmt.Fprintln(w)
}

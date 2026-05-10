package kernsec

import (
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"os"
	"strings"
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
	OK            bool // false if any check produced WARN or an indeterminate read error
	Warnings      int
	Tier          Tier // tier in effect when the audit ran (0/1/2)
	Indeterminate bool // true if a source of truth could not be read
	Errors        []string
}

// RunStatusJSON emits the kernsec audit as a JSON document. It is the
// machine-readable counterpart to RunStatus, designed for fleet
// aggregation (e.g. `for h in fleet; do ssh $h cfm kernsec status --json; done`).
// The returned StatusResult mirrors RunStatus semantics (OK, Warnings, Tier).
func RunStatusJSON(w io.Writer) StatusResult {
	conf, confErr := loadStatusConf()
	profile := DetectHostProfile()
	rows := BuildAuditRows(conf, profile)

	fs := RealFS{}
	be := DetectBackend(fs)

	var warnings int
	for _, r := range rows {
		switch r.State {
		case StateWARN, StateDIFF, StateMISSING, StateDRIFT:
			warnings++
		}
	}
	errs := appendStatusErrors(nil, statusConfError(confErr))
	errs = appendStatusErrors(errs, auditRowErrors(rows)...)

	out := StatusJSON{
		OK:       warnings == 0 && len(errs) == 0,
		Warnings: warnings,
		Tier:     conf.Tier,
		Backend:  be.Label(),
		Profile:  profile,
		Errors:   errs,
		Rules:    rows,
	}
	enc := json.NewEncoder(w)
	enc.SetIndent("", "  ")
	_ = enc.Encode(out)
	return StatusResult{OK: out.OK, Warnings: warnings, Tier: conf.Tier, Indeterminate: len(errs) > 0, Errors: errs}
}

func loadStatusConf() (*Conf, error) {
	conf, err := LoadConf(false)
	if err == nil {
		return conf, nil
	}
	if errors.Is(err, os.ErrNotExist) {
		return DefaultConf(), nil
	}
	return DefaultConf(), err
}

func statusConfError(err error) string {
	if err == nil {
		return ""
	}
	return fmt.Sprintf("kernsec config read failed: %v", err)
}

func appendStatusErrors(errs []string, msgs ...string) []string {
	for _, msg := range msgs {
		if msg == "" {
			continue
		}
		seen := false
		for _, existing := range errs {
			if existing == msg {
				seen = true
				break
			}
		}
		if !seen {
			errs = append(errs, msg)
		}
	}
	return errs
}

// RunStatus prints the kernsec audit-only status to w. Mirrors
// kspp.sh status output and adds AF_ALG probes for the broader
// algif_* set. No mutations.
func RunStatus(w io.Writer, opts StatusOptions) StatusResult {
	res := StatusResult{OK: true}

	fs := RealFS{}
	be := DetectBackend(fs)
	currentCmdline := ReadProcCmdline()
	nextCmdline, nextErr := be.NextBootCmdline()

	// Best-effort conf load. If absent, default to tier=1 — matches
	// first-run UX and produces sensible audit on hosts that have not
	// run init yet. Existing malformed or unreadable configs are also
	// defaulted for rendering, but the original LoadConf(false) error is
	// surfaced as an indeterminate status instead of being swallowed.
	conf, confErr := loadStatusConf()
	res.Tier = conf.Tier

	fmt.Fprintln(w, "===== CFM kernsec STATUS =====")
	fmt.Fprintln(w)

	fmt.Fprintln(w, "[Boot mode]")
	fmt.Fprintln(w, be.Label())
	fmt.Fprintln(w)

	fmt.Fprintf(w, "[Conf tier]  %d\n", conf.Tier)
	if confErr != nil {
		msg := statusConfError(confErr)
		fmt.Fprintf(w, "ERROR unable to read kernsec config from %s: %v\n", ConfPath, confErr)
		res.indeterminate(msg)
	}
	if warnings := ValidateConfOverrideIDs(conf); len(warnings) > 0 {
		for _, msg := range warnings {
			fmt.Fprintf(w, "[!] %s\n", msg)
			res.warn()
		}
	}
	fmt.Fprintln(w)

	fmt.Fprintln(w, "[Current running kernel cmdline]")
	fmt.Fprintln(w, currentCmdline)
	fmt.Fprintln(w)

	fmt.Fprintln(w, "[Configured default kernel cmdline — next boot]")
	if nextErr != nil {
		fmt.Fprintf(w, "ERROR unable to read next-boot cmdline from %s: %v\n", be.Label(), nextErr)
		res.indeterminate(fmt.Sprintf("next-boot cmdline read failed: %v", nextErr))
	} else {
		fmt.Fprintln(w, nextCmdline)
	}
	fmt.Fprintln(w)

	// Resolve every rule against conf + host profile so OFF (operator-
	// disabled) and SKIP (host-profile blocked) decisions render
	// honestly instead of being silently dropped or mis-classified
	// as MISSING.
	profile := DetectHostProfile()
	resolved := Resolve(conf, profile)

	fmt.Fprintln(w, "[Expected runtime sysctl verification]")
	for i, rule := range AllSysctls() {
		rr := resolved.Sysctls[i]
		state, found := CheckSysctl(rule)
		switch rr.Decision {
		case SkipByConf, SkipByTier:
			fmt.Fprintf(w, "OFF   %s  (%s)\n", rule.Key, rr.Reason)
			continue
		case SkipByHostProfile:
			fmt.Fprintf(w, "SKIP  %s  (host profile: %s)\n", rule.Key, rr.Reason)
			continue
		case ManagedExternally:
			// Audit-only: render the live value alongside the EXT
			// label so the operator can see at a glance whether the
			// other component's intent is actually live. No
			// res.warn() — kernsec doesn't own the value, so
			// drift here isn't a kernsec problem.
			switch state {
			case SysctlOK:
				fmt.Fprintf(w, "EXT   %s=%s  (%s; live matches kernsec recommendation)\n",
					rule.Key, found, rr.Reason)
			case SysctlMismatch:
				fmt.Fprintf(w, "EXT   %s=%s  (%s; live differs from kernsec recommendation %s)\n",
					rule.Key, found, rr.Reason, rule.Value)
			case SysctlMissing:
				fmt.Fprintf(w, "EXT   %s  (%s; not exposed by this kernel)\n",
					rule.Key, rr.Reason)
			}
			continue
		}
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

	res.printArgState(w, "Managed boot args in current running kernel", currentTokens, resolved, nil)
	res.printArgState(w, "Managed boot args configured for next boot", nextTokens, resolved, nextErr)

	res.printModuleState(w, resolved)

	res.printMountState(w, resolved)

	klog := ReadKernelLog()
	fmt.Fprintln(w, "[Kernel boot warnings about managed args]")
	// Scan only for managed keys whose rule is currently in Apply
	// state. Keys that are OFF / SKIP shouldn't be on the cmdline at
	// all, so kernel warnings about them aren't kernsec-actionable —
	// they reflect operator-managed args, not our drift.
	applyBootKeys := applyBootKeysFromResolved(resolved)
	if matched := UnknownArgWarnings(klog, applyBootKeys); len(matched) > 0 {
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
	// This is the kernsec-managed boot-arg rule KSEC-BOOT-kspp-005, so
	// the WARN must respect the operator's conf: a tier=0 host or one
	// that explicitly skipped this rule should see OFF, not WARN.
	// Previously the check fired unconditionally and made
	// `cfm kernsec status --check` a false-positive on legitimately
	// disabled hosts.
	mitigationDecision := decisionForBootArg(resolved, mitigation.Key, mitigation.Value)
	switch mitigationDecision {
	case SkipByConf, SkipByTier:
		fmt.Fprintln(w, "OFF   initcall_blacklist=algif_aead_init disabled by conf (tier or per-rule skip)")
	case SkipByHostProfile:
		fmt.Fprintln(w, "SKIP  initcall_blacklist=algif_aead_init skipped by host profile")
	default:
		if state, _ := CheckBootArg(currentTokens, mitigation); state == ArgOK {
			fmt.Fprintln(w, "OK    initcall_blacklist=algif_aead_init present in current cmdline")
		} else {
			fmt.Fprintln(w, "WARN  initcall_blacklist=algif_aead_init not active in current cmdline")
			fmt.Fprintln(w, "      Reboot is required after enable.")
			res.warn()
		}
	}

	// Each kernel-feature health probe below is paired with a
	// kernsec-managed boot-arg rule. When that rule is OFF / SKIP the
	// probe still runs (operator may want to know the kernel state)
	// but we don't escalate to res.warn() — the operator chose to
	// disable the rule, so a "missing" runtime state isn't drift
	// against their intent. Previously every probe warned
	// unconditionally, making `cfm kernsec status --check` exit
	// non-zero on legitimately-disabled (tier=0 / per-rule skip) hosts.
	algifApply := decisionForBootArg(resolved, "initcall_blacklist", "algif_aead_init") == Apply
	shuffleApply := decisionForBootArg(resolved, "page_alloc.shuffle", "1") == Apply
	initApply := decisionForBootArg(resolved, "init_on_alloc", "1") == Apply
	kstackApply := decisionForBootArg(resolved, "randomize_kstack_offset", "on") == Apply

	if !opts.SkipAFAlg {
		fmt.Fprintln(w)
		fmt.Fprintln(w, "[AF_ALG bind probes]")
		for _, r := range ProbeAllAFAlg() {
			fmt.Fprintln(w, FormatAFAlg(r))
			if r.Bound && r.Type == "aead" && algifApply {
				res.warn()
			}
		}
	}
	fmt.Fprintln(w)

	fmt.Fprintln(w, "[page_alloc.shuffle runtime state]")
	if !shuffleApply {
		fmt.Fprintln(w, "OFF   page_alloc.shuffle rule is disabled by conf — runtime state not checked")
	} else if raw, ok := PageAllocShuffleState(); ok {
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
	if !initApply {
		fmt.Fprintln(w, "OFF   init_on_alloc rule is disabled by conf — runtime state not checked")
	} else if line := MemAutoInitLine(klog); line != "" {
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
	cfg, cfgOK := ReadKernelConfig()
	switch {
	case !kstackApply:
		fmt.Fprintln(w, "OFF   randomize_kstack_offset rule is disabled by conf — kernel-config support not checked")
	case !cfgOK:
		fmt.Fprintln(w, "WARN  kernel config not readable from /boot/config-<release> or /proc/config.gz")
		res.warn()
	case HasKernelConfigIn(cfg, "HAVE_ARCH_RANDOMIZE_KSTACK_OFFSET") &&
		HasKernelConfigIn(cfg, "RANDOMIZE_KSTACK_OFFSET"):
		fmt.Fprintln(w, "OK    kernel config supports randomize_kstack_offset")
	default:
		fmt.Fprintln(w, "WARN  kernel config may not support randomize_kstack_offset")
		res.warn()
	}
	// Kernel config hints are info-only; they print regardless of any
	// rule decision so an operator inspecting `status` always sees
	// what the kernel was built with.
	if cfgOK {
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
	}
	fmt.Fprintln(w)

	if res.Indeterminate {
		fmt.Fprintf(w, "[!] Status verification indeterminate due to %d read error(s). Review ERROR lines above.\n", len(res.Errors))
	} else if res.Warnings == 0 {
		fmt.Fprintln(w, "[+] Status verification looks good.")
	} else {
		fmt.Fprintf(w, "[!] Status verification found %d warning(s). Review output above.\n", res.Warnings)
	}
	fmt.Fprintln(w, "==============================")
	return res
}

// printArgState renders one section of expected boot args against a
// concrete cmdline. Mirrors kspp.sh show_arg_state. Iterates the
// resolved set so OFF (operator-disabled / tier-gated) and SKIP
// (host-profile blocked) rules render explicitly instead of being
// silently dropped.
func (res *StatusResult) printArgState(w io.Writer, label string, tokens []string, resolved ResolvedSet, readErr error) {
	fmt.Fprintf(w, "[%s]\n", label)
	if readErr != nil {
		fmt.Fprintf(w, "ERROR      unable to read cmdline: %v\n", readErr)
		fmt.Fprintln(w)
		return
	}
	for i, want := range AllBootArgs() {
		rr := resolved.BootArgs[i]
		switch rr.Decision {
		case SkipByConf, SkipByTier:
			fmt.Fprintf(w, "OFF        %s  (%s)\n", want, rr.Reason)
			continue
		case SkipByHostProfile:
			fmt.Fprintf(w, "SKIP       %s  (host profile: %s)\n", want, rr.Reason)
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

func (res *StatusResult) indeterminate(msg string) {
	res.Indeterminate = true
	res.OK = false
	for _, existing := range res.Errors {
		if existing == msg {
			return
		}
	}
	res.Errors = append(res.Errors, msg)
}

func auditRowErrors(rows []AuditRow) []string {
	seen := map[string]bool{}
	var errs []string
	for _, r := range rows {
		if r.Error == "" || seen[r.Error] {
			continue
		}
		seen[r.Error] = true
		errs = append(errs, r.Error)
	}
	return errs
}

// printMountState surfaces the fstab audit rules. kernsec never
// auto-mutates fstab — every MISSING line is operator-actionable
// advice, not a kernsec bug. Counts as a warning so that
// `cfm kernsec status --check` exits non-zero when an operator-
// reviewable item exists, matching the boot-arg / module sections.
// Each row also passes through the resolver so OFF / SKIP rows
// surface honestly instead of being lumped into MISSING.
func (res *StatusResult) printMountState(w io.Writer, resolved ResolvedSet) {
	fmt.Fprintln(w, "[Mount audit (read-only — fstab is operator-managed)]")
	for i, m := range Tier1Mounts {
		rr := resolved.Mounts[i]
		switch rr.Decision {
		case SkipByConf, SkipByTier:
			fmt.Fprintf(w, "OFF        %s  recommend %s  (%s)\n",
				m.MountPoint, m.Recommended, rr.Reason)
			continue
		case SkipByHostProfile:
			fmt.Fprintf(w, "SKIP       %s  (host profile: %s)\n",
				m.MountPoint, rr.Reason)
			continue
		}
		state, current := CheckMount(m)
		switch state {
		case MountOK:
			fmt.Fprintf(w, "OK         %s  has %s\n", m.MountPoint, m.Recommended)
		case MountMissingOptions:
			fmt.Fprintf(w, "MISSING    %s  recommend %s  (current: %s)\n",
				m.MountPoint, m.Recommended, current)
			res.warn()
		case MountNotSeparate:
			fmt.Fprintf(w, "SKIP       %s  not a separate mount (recommendations N/A)\n", m.MountPoint)
		}
	}
	fmt.Fprintln(w)
}

// applyBootKeysFromResolved returns the bare keys (without value) of
// boot-arg rules whose resolver decision is Apply. Used by the
// kernel-log "unknown args" scan so warnings about kernsec-disabled
// keys (which legitimately don't appear on the cmdline) don't get
// surfaced as kernsec drift.
func applyBootKeysFromResolved(resolved ResolvedSet) []string {
	out := make([]string, 0, len(resolved.BootArgs))
	for _, rr := range resolved.BootArgs {
		if rr.Decision != Apply {
			continue
		}
		if i := strings.IndexByte(rr.Display, '='); i >= 0 {
			out = append(out, rr.Display[:i])
		} else {
			out = append(out, rr.Display)
		}
	}
	return out
}

// decisionForBootArg returns the resolver decision for the boot-arg
// rule matching the given key+value. Falls back to Apply if no rule is
// registered for that pair — keeps the hard-coded follow-up checks in
// RunStatus (algif_aead_init etc.) functioning even if the rule
// registry doesn't include the exact arg.
func decisionForBootArg(resolved ResolvedSet, key, value string) Decision {
	display := key
	if value != "" {
		display = key + "=" + value
	}
	for _, rr := range resolved.BootArgs {
		if rr.Display == display {
			return rr.Decision
		}
	}
	return Apply
}

// printModuleState surfaces the module-blacklist audit in the same
// label-prefixed style as the rest of status output: managed file's
// presence and per-module state. Buckets the rules by resolver
// decision (OFF / SKIP / Apply) so operator-disabled and host-profile
// gated rules don't get lumped into MISSING.
//
// The managed-file MISSING warning is suppressed when every module
// rule is OFF / host-skipped / not-on-kernel — the file legitimately
// shouldn't exist in that case. Previously the file-MISSING warn
// fired even on tier=0 hosts, making `status --check` exit non-zero
// on legitimately-disabled hosts.
func (res *StatusResult) printModuleState(w io.Writer, resolved ResolvedSet) {
	fmt.Fprintln(w, "[Module blacklist]")

	loaded := LoadedModules()
	managed := ParseManagedBlacklist()
	var loadedCount, missingCount, okCount, kernelSkipCount, offCount, hostSkipCount int

	// Count first so we know whether any rule is in Apply state. If
	// all rules are OFF / SKIP / not-on-kernel, the managed file
	// genuinely doesn't need to exist — so a missing file isn't drift.
	for i, m := range Tier1Modules {
		rr := resolved.Modules[i]
		switch rr.Decision {
		case SkipByConf, SkipByTier:
			offCount++
			continue
		case SkipByHostProfile:
			hostSkipCount++
			continue
		}
		_, isBlacklisted := managed[m.Name]
		_, isLoaded := loaded[m.Name]
		switch {
		case isBlacklisted && isLoaded:
			loadedCount++
		case isBlacklisted:
			okCount++
		case !ModulePresentOnKernel(m.Name):
			kernelSkipCount++
		default:
			missingCount++
		}
	}
	activeRules := okCount + missingCount + loadedCount

	managedExists := true
	if _, err := os.Stat(ModprobePath); err != nil {
		if errors.Is(err, os.ErrNotExist) {
			if activeRules == 0 {
				fmt.Fprintf(w, "OFF        %s not present (no module rules active under current conf)\n", ModprobePath)
			} else {
				fmt.Fprintf(w, "MISSING    %s not present — `cfm kernsec apply` to create it\n", ModprobePath)
				res.warn()
			}
			managedExists = false
		} else {
			fmt.Fprintf(w, "ERROR      cannot stat %s: %v\n", ModprobePath, err)
			res.warn()
			managedExists = false
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
	if kernelSkipCount > 0 {
		fmt.Fprintf(w, "SKIP       %d modules not present on this kernel\n", kernelSkipCount)
	}
	if hostSkipCount > 0 {
		fmt.Fprintf(w, "SKIP       %d modules skipped by host profile (would break host workloads)\n", hostSkipCount)
	}
	if offCount > 0 {
		fmt.Fprintf(w, "OFF        %d modules disabled by conf (tier or per-rule skip)\n", offCount)
	}
	fmt.Fprintln(w)
}

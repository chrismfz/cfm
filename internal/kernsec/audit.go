package kernsec

// RuleKind classifies an audit row by where it lives.
type RuleKind string

const (
	KindSysctl RuleKind = "sysctl"
	KindBoot   RuleKind = "boot"
	KindModule RuleKind = "module"
)

// RuleState is the per-row tri-state surfaced in status / TUI output.
type RuleState string

const (
	StateOK      RuleState = "OK"
	StateWARN    RuleState = "WARN"    // configured for next boot, not yet active in current cmdline
	StateDIFF    RuleState = "DIFF"    // sysctl present with wrong value
	StateMISSING RuleState = "MISSING" // expected entry absent from managed file
	StateSKIP    RuleState = "SKIP"    // sysctl key / module not present on this kernel
	StateDRIFT   RuleState = "DRIFT"   // active in current but missing from next-boot config
	StateLOADED  RuleState = "LOADED"  // module blacklisted but still loaded — needs reboot or rmmod
)

// AuditRow is one rule's audit summary for the TUI / future structured output.
// One source of truth for per-rule state; the text RunStatus and the TUI both
// derive from BuildAuditRows.
type AuditRow struct {
	ID          string
	Kind        RuleKind
	Group       string
	Tier        Tier
	Display     string // "kernel.kptr_restrict=2" or "slab_nomerge"
	State       RuleState
	Description string
	Affects     string

	// Sysctl-only.
	LiveValue     string // /proc/sys reading; "" if missing
	ExpectedValue string // expected value as configured

	// Boot-arg-only.
	InCurrent     bool // expected arg present in /proc/cmdline
	InNextBoot    bool // expected arg present in next-boot cmdline
	NextBootKnown bool // bootloader cmdline read succeeded

	// Module-only.
	ModuleName        string // module name (matches `lsmod` first column)
	BlacklistedInFile bool   // module is in /etc/modprobe.d/cfm-kernsec.conf
	Loaded            bool   // module is currently in /proc/modules
	PresentOnKernel   bool   // module file exists under /lib/modules/$(uname -r)
}

// BuildAuditRows runs the same probes as RunStatus and returns one row per
// rule across sysctls, boot args, and modules. Pure data: no formatting, no
// terminal output.
//
// Resolved against the on-disk conf and host profile. Rules whose Decision
// is not Apply are still surfaced as audit rows but with reasonable states
// (modules not blacklisted in our file → MISSING; sysctls / boot args
// behave as before).
func BuildAuditRows() []AuditRow {
	fs := RealFS{}
	be := DetectBackend(fs)
	current := ReadProcCmdline()
	next, nextErr := be.NextBootCmdline()

	curTokens := ParseCmdline(current)
	nxtTokens := ParseCmdline(next)

	loaded := LoadedModules()
	managedBlacklist := ParseManagedBlacklist()

	rows := make([]AuditRow, 0, len(KSPPSysctls)+len(KSPPBootArgs)+len(Tier1Modules))

	for _, r := range KSPPSysctls {
		state, found := CheckSysctl(r)
		row := AuditRow{
			ID:            r.ID,
			Kind:          KindSysctl,
			Group:         r.Group,
			Tier:          r.Tier,
			Display:       r.Key + "=" + r.Value,
			Description:   r.Description,
			Affects:       r.Affects,
			LiveValue:     found,
			ExpectedValue: r.Value,
		}
		switch state {
		case SysctlOK:
			row.State = StateOK
		case SysctlMismatch:
			row.State = StateDIFF
		case SysctlMissing:
			row.State = StateSKIP
		}
		rows = append(rows, row)
	}

	for _, a := range KSPPBootArgs {
		curState, _ := CheckBootArg(curTokens, a)
		nxtState, _ := CheckBootArg(nxtTokens, a)
		row := AuditRow{
			ID:            a.ID,
			Kind:          KindBoot,
			Group:         a.Group,
			Tier:          a.Tier,
			Display:       a.String(),
			Description:   a.Description,
			Affects:       a.Affects,
			InCurrent:     curState == ArgOK,
			InNextBoot:    nxtState == ArgOK,
			NextBootKnown: nextErr == nil,
		}
		row.State = bootRowState(curState, nxtState, nextErr == nil)
		rows = append(rows, row)
	}

	for _, m := range Tier1Modules {
		row := AuditRow{
			ID:                m.ID,
			Kind:              KindModule,
			Group:             m.Group,
			Tier:              m.Tier,
			Display:           m.Name,
			Description:       m.Description,
			Affects:           m.Affects,
			ModuleName:        m.Name,
			PresentOnKernel:   ModulePresentOnKernel(m.Name),
		}
		_, row.BlacklistedInFile = managedBlacklist[m.Name]
		_, row.Loaded = loaded[m.Name]
		row.State = moduleRowState(row.BlacklistedInFile, row.Loaded, row.PresentOnKernel)
		rows = append(rows, row)
	}

	return rows
}

// moduleRowState collapses the (blacklisted, loaded, present-on-kernel)
// triple into a single state for the TUI / status output.
//
//   - blacklisted + not loaded                  → OK
//   - blacklisted + still loaded                → LOADED (need rmmod / reboot)
//   - not blacklisted + present on this kernel  → MISSING (apply will fix)
//   - not present on this kernel                → SKIP (irrelevant on this host)
//
// Pure for testability.
func moduleRowState(blacklisted, loaded, presentOnKernel bool) RuleState {
	switch {
	case blacklisted && loaded:
		return StateLOADED
	case blacklisted:
		return StateOK
	case !presentOnKernel:
		return StateSKIP
	default:
		return StateMISSING
	}
}

// bootRowState collapses the four-way (current present?, next-boot present?)
// into a single state for the TUI. Pure for testability.
func bootRowState(cur, nxt CmdlineArgState, nextKnown bool) RuleState {
	curOK := cur == ArgOK
	nxtOK := nxt == ArgOK
	switch {
	case curOK && nxtOK:
		return StateOK
	case !curOK && nxtOK:
		// Configured for next boot but not yet active.
		return StateWARN
	case curOK && nextKnown && !nxtOK:
		// Currently active but config will not preserve it across reboot.
		return StateDRIFT
	case cur == ArgMissing && (nxt == ArgMissing || !nextKnown):
		return StateMISSING
	}
	return StateDIFF
}

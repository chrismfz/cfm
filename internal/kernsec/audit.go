package kernsec

// RuleKind classifies an audit row by where it lives.
type RuleKind string

const (
	KindSysctl RuleKind = "sysctl"
	KindBoot   RuleKind = "boot"
)

// RuleState is the per-row tri-state surfaced in status / TUI output.
type RuleState string

const (
	StateOK      RuleState = "OK"
	StateWARN    RuleState = "WARN"    // configured for next boot, not yet active in current cmdline
	StateDIFF    RuleState = "DIFF"    // sysctl present with wrong value
	StateMISSING RuleState = "MISSING" // expected boot arg absent in both current and next-boot
	StateSKIP    RuleState = "SKIP"    // sysctl key not exposed by this kernel
	StateDRIFT   RuleState = "DRIFT"   // active in current but missing from next-boot config
)

// AuditRow is one rule's audit summary for the TUI / future structured output.
// One source of truth for per-rule state; the text RunStatus and the TUI both
// derive from BuildAuditRows.
type AuditRow struct {
	Kind        RuleKind
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
}

// BuildAuditRows runs the same probes as RunStatus and returns one row per
// KSPP rule. Pure data: no formatting, no terminal output.
func BuildAuditRows() []AuditRow {
	fs := RealFS{}
	be := DetectBackend(fs)
	current := ReadProcCmdline()
	next, nextErr := be.NextBootCmdline()

	curTokens := ParseCmdline(current)
	nxtTokens := ParseCmdline(next)

	rows := make([]AuditRow, 0, len(KSPPSysctls)+len(KSPPBootArgs))

	for _, r := range KSPPSysctls {
		state, found := CheckSysctl(r)
		row := AuditRow{
			Kind:          KindSysctl,
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
			Kind:          KindBoot,
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

	return rows
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

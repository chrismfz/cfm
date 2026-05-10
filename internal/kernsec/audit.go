package kernsec

// RuleKind classifies an audit row by where it lives.
type RuleKind string

const (
	KindSysctl RuleKind = "sysctl"
	KindBoot   RuleKind = "boot"
	KindModule RuleKind = "module"
	KindMount  RuleKind = "mount"
)

// RuleState is the per-row tri-state surfaced in status / TUI output.
type RuleState string

const (
	StateOK      RuleState = "OK"
	StateWARN    RuleState = "WARN"    // configured for next boot, not yet active in current cmdline
	StateDIFF    RuleState = "DIFF"    // sysctl present with wrong value
	StateMISSING RuleState = "MISSING" // expected entry absent from managed file
	StateSKIP    RuleState = "SKIP"    // host profile blocks the rule, OR the sysctl key / module isn't exposed by this kernel
	StateDRIFT   RuleState = "DRIFT"   // active in current but missing from next-boot config
	StateLOADED  RuleState = "LOADED"  // module blacklisted but still loaded — needs reboot or rmmod
	// StateOFF means the operator chose to leave the rule disabled
	// (tier=0, rule tier above conf tier, or per-rule `state = skip`
	// in kernsec.conf). Unlike SKIP, OFF reflects operator intent
	// rather than a host-profile or kernel-feature constraint.
	// Operators can flip OFF rules on with `state = force`; SKIP rules
	// are gated by something the operator should investigate first.
	StateOFF RuleState = "OFF"
	// StateEXT means another cfm component (per the managedsysctl
	// cross-component registry) owns the underlying setting, so
	// kernsec audits the runtime state but never writes the key.
	// Currently used only by KSEC-SCT-net.* rules whose keys are
	// owned by internal/sysctl/sys_tweaks.go. The audit row also
	// tracks live runtime state — the operator sees whether the
	// other component's intent is actually live.
	StateEXT RuleState = "EXT"
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

	// Decision is the resolver's per-rule outcome (Apply / SkipByConf /
	// SkipByTier / SkipByHostProfile). State maps from Decision plus the
	// live probe result.
	Decision Decision
	// Reason is a free-text explanation of the Decision, e.g. "rule tier 2
	// > conf tier 1" or "host has containers running". Empty for Apply
	// rows that are in compliance (the State alone is enough).
	Reason string

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

	// Mount-only. kernsec audits but never auto-mutates /etc/fstab —
	// these fields surface what the operator would need to add.
	MountPoint         string // e.g. "/tmp"
	RecommendedOptions string // e.g. "nodev,nosuid,noexec"
	CurrentOptions     string // active mount options or "" if not separately mounted
}

// BuildAuditRows resolves every kernsec rule against the supplied conf and
// host profile, then attaches per-rule live-state probes (sysctl read,
// cmdline tokens, modprobe contents, /proc/modules). Returns one row per
// rule across sysctls, boot args, and modules. Pure data: no formatting,
// no terminal output.
//
// Decision-to-state mapping:
//
//	Apply              → existing OK/DIFF/MISSING/WARN/DRIFT/LOADED logic
//	SkipByConf         → OFF (operator chose to disable this rule)
//	SkipByTier         → OFF (rule's tier is above the configured tier)
//	SkipByHostProfile  → SKIP (host probe says the rule would break workloads)
//
// Live probes still run for OFF/SKIP rows so the TUI can show whether a
// disabled rule's underlying setting happens to already be in compliance.
func BuildAuditRows(conf *Conf, profile HostProfile) []AuditRow {
	rs := Resolve(conf, profile)

	fs := RealFS{}
	be := DetectBackend(fs)
	current := ReadProcCmdline()
	next, nextErr := be.NextBootCmdline()

	curTokens := ParseCmdline(current)
	nxtTokens := ParseCmdline(next)

	loaded := LoadedModules()
	managedBlacklist := ParseManagedBlacklist()

	allSysctls := AllSysctls()
	allBootArgs := AllBootArgs()
	rows := make([]AuditRow, 0, len(allSysctls)+len(allBootArgs)+len(Tier1Modules))

	// rs.Sysctls / rs.BootArgs / rs.Modules are populated in the same
	// stable order as AllSysctls / AllBootArgs / Tier1Modules (see
	// Resolve in resolve.go), so index-zip is safe.
	for i, r := range allSysctls {
		rr := rs.Sysctls[i]
		state, found := CheckSysctl(r)
		row := AuditRow{
			ID:            r.ID,
			Kind:          KindSysctl,
			Group:         r.Group,
			Tier:          r.Tier,
			Display:       r.Key + "=" + r.Value,
			Description:   r.Description,
			Affects:       r.Affects,
			Decision:      rr.Decision,
			Reason:        rr.Reason,
			LiveValue:     found,
			ExpectedValue: r.Value,
		}
		row.State = sysctlRowState(rr.Decision, state)
		rows = append(rows, row)
	}

	for i, a := range allBootArgs {
		rr := rs.BootArgs[i]
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
			Decision:      rr.Decision,
			Reason:        rr.Reason,
			InCurrent:     curState == ArgOK,
			InNextBoot:    nxtState == ArgOK,
			NextBootKnown: nextErr == nil,
		}
		row.State = bootRowStateForDecision(rr.Decision, curState, nxtState, nextErr == nil)
		rows = append(rows, row)
	}

	for i, m := range Tier1Modules {
		rr := rs.Modules[i]
		row := AuditRow{
			ID:              m.ID,
			Kind:            KindModule,
			Group:           m.Group,
			Tier:            m.Tier,
			Display:         m.Name,
			Description:     m.Description,
			Affects:         m.Affects,
			Decision:        rr.Decision,
			Reason:          rr.Reason,
			ModuleName:      m.Name,
			PresentOnKernel: ModulePresentOnKernel(m.Name),
		}
		_, row.BlacklistedInFile = managedBlacklist[m.Name]
		_, row.Loaded = loaded[m.Name]
		row.State = moduleRowStateForDecision(rr.Decision, row.BlacklistedInFile, row.Loaded, row.PresentOnKernel)
		rows = append(rows, row)
	}

	for i, m := range Tier1Mounts {
		rr := rs.Mounts[i]
		mountState, current := CheckMount(m)
		row := AuditRow{
			ID:                 m.ID,
			Kind:               KindMount,
			Group:              m.Group,
			Tier:               m.Tier,
			Display:            m.MountPoint,
			Description:        m.Description,
			Affects:            m.Affects,
			Decision:           rr.Decision,
			Reason:             rr.Reason,
			MountPoint:         m.MountPoint,
			RecommendedOptions: m.Recommended,
			CurrentOptions:     current,
		}
		row.State = mountRowStateForDecision(rr.Decision, mountState)
		rows = append(rows, row)
	}

	return rows
}

// sysctlRowState maps (decision, live probe) to a row state.
func sysctlRowState(d Decision, live SysctlState) RuleState {
	switch d {
	case Apply:
		switch live {
		case SysctlOK:
			return StateOK
		case SysctlMismatch:
			return StateDIFF
		case SysctlMissing:
			return StateSKIP
		}
	case ManagedExternally:
		// Audit-only: render EXT regardless of live state. Live
		// value still surfaces in the AuditRow for the operator to
		// see whether the other component's intent is live.
		return StateEXT
	case SkipByConf, SkipByTier:
		return StateOFF
	case SkipByHostProfile:
		return StateSKIP
	}
	return StateMISSING
}

// bootRowStateForDecision wraps bootRowState with the resolver decision.
// OFF / SKIP short-circuit the (cur, nxt) interpretation.
func bootRowStateForDecision(d Decision, cur, nxt CmdlineArgState, nextKnown bool) RuleState {
	switch d {
	case SkipByConf, SkipByTier:
		return StateOFF
	case SkipByHostProfile:
		return StateSKIP
	}
	return bootRowState(cur, nxt, nextKnown)
}

// moduleRowStateForDecision wraps moduleRowState with the resolver
// decision.
func moduleRowStateForDecision(d Decision, blacklisted, loaded, presentOnKernel bool) RuleState {
	switch d {
	case SkipByConf, SkipByTier:
		return StateOFF
	case SkipByHostProfile:
		return StateSKIP
	}
	return moduleRowState(blacklisted, loaded, presentOnKernel)
}

// mountRowState maps a mount probe result to a row state for an
// Apply-decision mount row. kernsec never auto-mutates fstab so even
// MountMissingOptions is information, not a failure to act on — the
// operator decides whether `nodev,nosuid,noexec` is compatible with
// their workload.
//
//   - MountOK              → OK
//   - MountMissingOptions  → DIFF (mount exists but options missing)
//   - MountNotSeparate     → SKIP (not a distinct mount; recs N/A)
func mountRowState(s MountState) RuleState {
	switch s {
	case MountOK:
		return StateOK
	case MountMissingOptions:
		return StateDIFF
	}
	return StateSKIP
}

// mountRowStateForDecision wraps mountRowState with the resolver
// decision.
func mountRowStateForDecision(d Decision, s MountState) RuleState {
	switch d {
	case SkipByConf, SkipByTier:
		return StateOFF
	case SkipByHostProfile:
		return StateSKIP
	}
	return mountRowState(s)
}

// moduleRowState collapses the (blacklisted, loaded, present-on-kernel)
// triple into a single state for an Apply-decision module row.
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
// into a single state for an Apply-decision boot row. Pure for testability.
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

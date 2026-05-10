package kernsec

import "cfm/internal/managedsysctl"

// Decision is the per-rule outcome of combining the conf (tier +
// overrides) with the host-profile probe and cross-component
// ownership (managedsysctl registry).
type Decision int

const (
	// Apply means the rule is selected for `cfm kernsec apply`.
	Apply Decision = iota
	// SkipByConf means the operator wrote `state = skip` for this rule.
	SkipByConf
	// SkipByTier means the rule's tier is higher than the configured
	// tier and no `state = force` override is present.
	SkipByTier
	// SkipByHostProfile means the host-profile probe blocked the rule
	// (e.g. IPsec policies present, so the ipsec module group skips).
	SkipByHostProfile
	// ManagedExternally means another cfm component owns the
	// underlying setting (per the managedsysctl registry). kernsec
	// AUDITS the runtime state but never writes — that's the other
	// component's job. Currently only KSEC-SCT-net.* rules hit this
	// path (their keys are owned by internal/sysctl/sys_tweaks.go).
	ManagedExternally
)

// String renders a Decision for status output.
func (d Decision) String() string {
	switch d {
	case Apply:
		return "APPLY"
	case SkipByConf:
		return "SKIP-CONF"
	case SkipByTier:
		return "SKIP-TIER"
	case SkipByHostProfile:
		return "SKIP-HOST"
	case ManagedExternally:
		return "EXT"
	}
	return "?"
}

// ResolvedRule pairs a rule's metadata (kind/id/tier/group/display)
// with the decision the conf+profile produced and the optional reason.
type ResolvedRule struct {
	ID       string
	Kind     RuleKind
	Group    string
	Tier     Tier
	Display  string
	Decision Decision
	Reason   string
}

// ResolvedSet is the full set of resolved rules in stable order
// (sysctls, boot args, modules, mounts).
type ResolvedSet struct {
	Sysctls  []ResolvedRule
	BootArgs []ResolvedRule
	Modules  []ResolvedRule
	Mounts   []ResolvedRule
	Profile  HostProfile
}

// ApplySysctls returns just the sysctl rules whose decision is Apply.
func (s ResolvedSet) ApplySysctls() []SysctlRule {
	want := decisionIDSet(s.Sysctls, Apply)
	out := make([]SysctlRule, 0, len(want))
	for _, r := range AllSysctls() {
		if _, ok := want[r.ID]; ok {
			out = append(out, r)
		}
	}
	return out
}

// ApplyBootArgs returns just the boot-arg rules whose decision is Apply.
func (s ResolvedSet) ApplyBootArgs() []BootArg {
	want := decisionIDSet(s.BootArgs, Apply)
	out := make([]BootArg, 0, len(want))
	for _, r := range AllBootArgs() {
		if _, ok := want[r.ID]; ok {
			out = append(out, r)
		}
	}
	return out
}

// ApplyModules returns just the module rules whose decision is Apply.
// Order matches Tier1Modules so the rendered modprobe file is
// deterministic — required for byte-equal drift detection.
func (s ResolvedSet) ApplyModules() []ModuleRule {
	want := decisionIDSet(s.Modules, Apply)
	out := make([]ModuleRule, 0, len(want))
	for _, r := range Tier1Modules {
		if _, ok := want[r.ID]; ok {
			out = append(out, r)
		}
	}
	return out
}

func decisionIDSet(rs []ResolvedRule, want Decision) map[string]struct{} {
	m := make(map[string]struct{}, len(rs))
	for _, r := range rs {
		if r.Decision == want {
			m[r.ID] = struct{}{}
		}
	}
	return m
}

// Resolve combines the conf with a host profile to produce a per-rule
// decision for every rule in every kind. Pure: no probes, no I/O.
// Callers pass HostProfile from DetectHostProfile() (or a synthesised
// one in tests).
func Resolve(conf *Conf, profile HostProfile) ResolvedSet {
	out := ResolvedSet{Profile: profile}

	for _, r := range AllSysctls() {
		out.Sysctls = append(out.Sysctls, decideSysctl(r, conf, profile))
	}
	for _, r := range AllBootArgs() {
		out.BootArgs = append(out.BootArgs, decideBootArg(r, conf, profile))
	}
	for _, r := range Tier1Modules {
		out.Modules = append(out.Modules, decideModule(r, conf, profile))
	}
	for _, r := range Tier1Mounts {
		out.Mounts = append(out.Mounts, decideMount(r, conf, profile))
	}
	return out
}

func decideSysctl(r SysctlRule, conf *Conf, profile HostProfile) ResolvedRule {
	rr := ResolvedRule{
		ID: r.ID, Kind: KindSysctl, Group: r.Group, Tier: r.Tier,
		Display: r.Key + "=" + r.Value,
	}
	rr.Decision, rr.Reason = decide(r.ID, r.Tier, r.Group, conf, profile)
	// Cross-component check: if another cfm component (sys_tweaks /
	// firewall / etc.) owns this key per the managedsysctl registry,
	// flip the decision to ManagedExternally — kernsec audits but
	// never writes externally-owned keys.
	//
	// Exception: `state = force` in conf is the operator escape hatch
	// to take ownership back. decide() already returned Apply for
	// force; we honour that explicit operator intent over the registry
	// (operators who force a key into kernsec's hands accept the
	// resulting cross-component conflict — surfaced separately by
	// managedsysctl.Default().Conflicts() in apply output).
	if rr.Decision == Apply && conf != nil && conf.Overrides[r.ID] != OverrideForce {
		if owner := managedsysctl.Default().OwnerOf(r.Key); owner != "" && owner != managedsysctl.OwnerKernsec {
			rr.Decision = ManagedExternally
			rr.Reason = "managed by " + string(owner)
		}
	}
	return rr
}

func decideBootArg(r BootArg, conf *Conf, profile HostProfile) ResolvedRule {
	rr := ResolvedRule{
		ID: r.ID, Kind: KindBoot, Group: r.Group, Tier: r.Tier,
		Display: r.String(),
	}
	rr.Decision, rr.Reason = decide(r.ID, r.Tier, r.Group, conf, profile)
	return rr
}

func decideModule(r ModuleRule, conf *Conf, profile HostProfile) ResolvedRule {
	rr := ResolvedRule{
		ID: r.ID, Kind: "module", Group: r.Group, Tier: r.Tier,
		Display: r.Name,
	}
	rr.Decision, rr.Reason = decide(r.ID, r.Tier, r.Group, conf, profile)
	return rr
}

func decideMount(r MountRule, conf *Conf, profile HostProfile) ResolvedRule {
	rr := ResolvedRule{
		ID: r.ID, Kind: "mount", Group: r.Group, Tier: r.Tier,
		Display: r.MountPoint,
	}
	rr.Decision, rr.Reason = decide(r.ID, r.Tier, r.Group, conf, profile)
	return rr
}

// decide is the shared decision tree. Order:
//
//  1. Per-rule override `state = force` → Apply unconditionally.
//  2. Per-rule override `state = skip`  → SkipByConf.
//  3. Rule tier > conf tier             → SkipByTier.
//  4. Host-profile blocks the group     → SkipByHostProfile.
//  5. Otherwise                         → Apply.
//
// Step 1 is intentionally first: `force` exists exactly so operators
// can override host-profile blocks.
func decide(id string, tier Tier, group string, conf *Conf, profile HostProfile) (Decision, string) {
	if conf != nil {
		switch conf.Overrides[id] {
		case OverrideForce:
			return Apply, "forced by conf"
		case OverrideSkip:
			return SkipByConf, "skip = state in conf"
		}
	}
	if conf == nil || int(tier) > int(conf.Tier) {
		var t Tier
		if conf != nil {
			t = conf.Tier
		}
		return SkipByTier, "rule tier " + tier.label() + " > conf tier " + t.label()
	}
	if reason := profile.SkipReason(group); reason != "" {
		return SkipByHostProfile, reason
	}
	return Apply, ""
}

func (t Tier) label() string {
	switch t {
	case 0:
		return "0"
	case Tier1:
		return "1"
	case Tier2:
		return "2"
	}
	return "?"
}

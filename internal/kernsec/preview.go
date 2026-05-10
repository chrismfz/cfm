package kernsec

import (
	"fmt"
	"io"
	"strings"
)

// PreviewOptions selects which rules / decisions are shown.
type PreviewOptions struct {
	OnlyApply bool   // hide SKIP-* rows (only show what would be applied)
	Group     string // filter by group prefix; "" = all
	// Tier overrides conf.Tier for this preview iff TierOverride is true.
	// Setting Tier alone is not enough — the zero value of Tier is the
	// legitimate value 0 ("resolve as if every rule were tier-gated
	// off"), so we need an explicit flag to distinguish "operator did
	// not pass --tier" from "operator passed --tier 0".
	Tier         Tier
	TierOverride bool
	IDs          []string
	Skips        []string // additional ad-hoc skips (not persisted)
	Forces       []string // additional ad-hoc forces (not persisted)
}

// RunPreview renders a read-only diff of what `cfm kernsec apply` would
// do given the current conf + host profile + ad-hoc selectors.
//
// Phase 2a: groups rules by kind, prints decision + reason for each.
// The actual file/cmdline rendering for sysctls / boot args lands in
// Pass 2 (Phase 2b apply); for now the table answers "if I ran apply
// right now, which rules would be selected and why".
func RunPreview(w io.Writer, opts PreviewOptions) int {
	conf, err := LoadConf(true /* createDefault in memory */)
	if err != nil {
		fmt.Fprintln(w, "kernsec: load conf:", err)
		return 1
	}
	conf = applyAdHocOverrides(conf, opts)

	profile := DetectHostProfile()
	rs := Resolve(conf, profile)

	fmt.Fprintln(w, "===== CFM kernsec PREVIEW =====")
	fmt.Fprintln(w)
	fmt.Fprintf(w, "Conf:     %s\n", confSource(conf))
	fmt.Fprintf(w, "Tier:     %d\n", conf.Tier)
	fmt.Fprintf(w, "Profile:  %s\n", describeProfile(profile))
	if warnings := ValidateConfOverrideIDs(conf); len(warnings) > 0 {
		fmt.Fprintln(w)
		for _, msg := range warnings {
			fmt.Fprintf(w, "[!] %s\n", msg)
		}
	}
	fmt.Fprintln(w)

	printResolvedSection(w, "Sysctls", rs.Sysctls, opts)
	printResolvedSection(w, "Boot args", rs.BootArgs, opts)
	printResolvedSection(w, "Modules", rs.Modules, opts)
	printResolvedSection(w, "Mounts (audit-only)", rs.Mounts, opts)

	fmt.Fprintln(w)
	fmt.Fprintln(w, "[Summary]")
	fmt.Fprintf(w, "  apply: sysctls=%d  boot=%d  modules=%d  mounts=%d\n",
		count(rs.Sysctls, Apply),
		count(rs.BootArgs, Apply),
		count(rs.Modules, Apply),
		count(rs.Mounts, Apply),
	)
	fmt.Fprintf(w, "  skip:  conf=%d  tier=%d  host=%d\n",
		countAll(rs, SkipByConf),
		countAll(rs, SkipByTier),
		countAll(rs, SkipByHostProfile),
	)
	fmt.Fprintln(w, "===============================")
	return 0
}

func printResolvedSection(w io.Writer, label string, rs []ResolvedRule, opts PreviewOptions) {
	rs = filterRules(rs, opts)
	if len(rs) == 0 {
		return
	}
	fmt.Fprintf(w, "[%s]\n", label)
	for _, r := range rs {
		line := fmt.Sprintf("  %-9s  %-7s  %-26s  %s",
			r.Decision, "T"+r.Tier.label(), r.Group, r.Display)
		if r.Reason != "" {
			line += "    (" + r.Reason + ")"
		}
		fmt.Fprintln(w, line)
	}
	fmt.Fprintln(w)
}

func filterRules(rs []ResolvedRule, opts PreviewOptions) []ResolvedRule {
	out := make([]ResolvedRule, 0, len(rs))
	idSet := stringSet(opts.IDs)
	for _, r := range rs {
		if opts.OnlyApply && r.Decision != Apply {
			continue
		}
		if opts.Group != "" && !strings.HasPrefix(r.Group, opts.Group) {
			continue
		}
		// Display filter: clip rules above an explicit tier ceiling.
		// When opts.Tier == 0 (either default or explicit `--tier 0`)
		// no clip is needed — the resolver itself classifies every
		// rule as SkipByTier under tier=0 conf, and the operator
		// wants to see those OFF rows.
		if opts.Tier > 0 && r.Tier > opts.Tier {
			continue
		}
		if len(idSet) > 0 {
			if _, ok := idSet[r.ID]; !ok {
				continue
			}
		}
		out = append(out, r)
	}
	return out
}

func stringSet(s []string) map[string]struct{} {
	m := make(map[string]struct{}, len(s))
	for _, v := range s {
		m[v] = struct{}{}
	}
	return m
}

func count(rs []ResolvedRule, d Decision) int {
	n := 0
	for _, r := range rs {
		if r.Decision == d {
			n++
		}
	}
	return n
}

func countAll(rs ResolvedSet, d Decision) int {
	return count(rs.Sysctls, d) + count(rs.BootArgs, d) + count(rs.Modules, d) + count(rs.Mounts, d)
}

func confSource(c *Conf) string {
	if c == nil || c.Source == "" {
		return "(no conf loaded)"
	}
	return c.Source
}

func describeProfile(p HostProfile) string {
	var parts []string
	if p.IsKVMHost {
		parts = append(parts, "kvm-host")
	}
	if p.HasContainers {
		parts = append(parts, "containers")
	}
	if p.HasIPsec {
		parts = append(parts, "ipsec")
	}
	if p.HasWifi {
		parts = append(parts, "wifi")
	}
	if p.HasDKMS {
		parts = append(parts, "dkms")
	}
	if p.HasKdump {
		parts = append(parts, "kdump")
	}
	if p.HasBluetoothHardware {
		parts = append(parts, "bluetooth-hw")
	}
	if p.HasThunderbolt {
		parts = append(parts, "thunderbolt-hw")
	}
	if p.HasNFS {
		parts = append(parts, "nfs")
	}
	if len(parts) == 0 {
		return "no host-profile flags"
	}
	return strings.Join(parts, ", ")
}

func applyAdHocOverrides(conf *Conf, opts PreviewOptions) *Conf {
	if conf == nil {
		conf = DefaultConf()
	}
	if conf.Overrides == nil {
		conf.Overrides = map[string]RuleOverride{}
	}
	for _, id := range opts.Skips {
		conf.Overrides[id] = OverrideSkip
	}
	for _, id := range opts.Forces {
		conf.Overrides[id] = OverrideForce
	}
	if opts.TierOverride {
		// `--tier N` overrides whatever's in the conf for this preview
		// invocation. Operators use it both to clamp down (preview as
		// if I dropped to tier=1, or even tier=0 to see what disable
		// would render) and to bump up (preview as if I raised to
		// tier=2). Not persisted.
		conf.Tier = opts.Tier
	}
	return conf
}

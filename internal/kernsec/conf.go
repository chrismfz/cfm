package kernsec

import (
	"bufio"
	"errors"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"strconv"
	"strings"
)

// ConfPath is the canonical location of the kernsec config file. cfm
// daemon's flat KEY=VALUE cfm.conf (internal/config/config.go) stays
// separate — kernsec's per-rule overrides need a sectioned format that
// flat conf can't express cleanly.
//
// Declared as var (not const) so tests can redirect it to t.TempDir().
var ConfPath = "/etc/cfm/kernsec.conf"

// ConfFileMode is intentionally root-only. kernsec.conf does not contain
// credentials, but it can disclose which kernel mitigations an operator
// disabled or forced on a host; package upgrades and CLI writes should never
// make that security posture world-readable.
const ConfFileMode os.FileMode = 0o600

// RuleState declares operator intent for one rule, overriding the tier
// default.
type RuleOverride int

const (
	// OverrideDefault means the rule follows the tier-default decision.
	OverrideDefault RuleOverride = iota
	// OverrideSkip means do not apply the rule even if its tier is
	// selected and host profile would otherwise allow it.
	OverrideSkip
	// OverrideForce means apply the rule even if host profile says skip.
	OverrideForce
)

// String renders the override as it appears in kernsec.conf.
func (o RuleOverride) String() string {
	switch o {
	case OverrideSkip:
		return "skip"
	case OverrideForce:
		return "force"
	}
	return "default"
}

// Conf is the parsed contents of /etc/cfm/kernsec.conf.
type Conf struct {
	// Tier is the highest tier whose rules apply by default.
	// Tier 1 ships safe-everywhere rules; Tier 2 layers on top.
	// Tier 0 means kernsec is configured but no tier is enabled — the
	// rules are still audited but apply is a no-op.
	Tier Tier

	// Overrides maps a rule ID to an explicit per-rule override.
	Overrides map[string]RuleOverride

	// Source is the path the conf was loaded from, "" if synthesised
	// from defaults.
	Source string
}

// DefaultConf returns the default tier=1 configuration that
// `cfm kernsec init` writes on a fresh host.
func DefaultConf() *Conf {
	return &Conf{
		Tier:      Tier1,
		Overrides: map[string]RuleOverride{},
	}
}

// LoadConf reads ConfPath and returns the parsed configuration. If the
// file is absent and createDefault is true, a default tier=1 conf is
// synthesised in memory (not written to disk; use WriteDefaultConf for
// that).
func LoadConf(createDefault bool) (*Conf, error) {
	b, err := os.ReadFile(ConfPath)
	if err != nil {
		if os.IsNotExist(err) && createDefault {
			c := DefaultConf()
			c.Source = "(default — no " + ConfPath + ")"
			return c, nil
		}
		return nil, err
	}
	c, err := ParseConf(strings.NewReader(string(b)))
	if err != nil {
		return nil, fmt.Errorf("%s: %w", ConfPath, err)
	}
	c.Source = ConfPath
	return c, nil
}

// ParseConf parses kernsec.conf format from r. Format:
//
//	# comments and blank lines OK
//	tier = 1
//
//	[rule "KSEC-MOD-net.legacy-014"]
//	state = skip
//
//	[rule "KSEC-SCT-namespace-001"]
//	state = force
//
// Top-level keys: `tier` (1 or 2; 0 also accepted to mean "audit only").
// Stanzas: `[rule "<ID>"]` followed by `state = skip|force|default`.
// Quoted IDs match git-config's subsection style.
func ParseConf(r io.Reader) (*Conf, error) {
	c := &Conf{Overrides: map[string]RuleOverride{}}
	scanner := bufio.NewScanner(r)
	scanner.Buffer(make([]byte, 0, 4*1024), 1<<20)

	var (
		currentRule  string // non-empty when inside a [rule "..."] stanza
		lineno       int
		seenRules    = map[string]int{} // rule ID -> line number of first occurrence
		seenTopLevel = map[string]int{} // top-level key (e.g. "tier") -> first line
	)

	for scanner.Scan() {
		lineno++
		raw := scanner.Text()
		line := strings.TrimSpace(stripComment(raw))
		if line == "" {
			continue
		}

		if strings.HasPrefix(line, "[") && strings.HasSuffix(line, "]") {
			id, err := parseSectionHeader(line)
			if err != nil {
				return nil, fmt.Errorf("line %d: %w", lineno, err)
			}
			// Reject duplicate stanzas explicitly. Previously the
			// second definition silently overwrote the first;
			// operators with conflict-merge artifacts in their conf
			// got the LAST stanza's behaviour with no warning.
			if firstLine, ok := seenRules[id]; ok {
				return nil, fmt.Errorf("line %d: duplicate rule section %q (first at line %d)",
					lineno, id, firstLine)
			}
			seenRules[id] = lineno
			currentRule = id
			continue
		}

		// key = value (within a section or at top level)
		key, val, ok := splitKV(line)
		if !ok {
			return nil, fmt.Errorf("line %d: malformed (expected `key = value`): %q", lineno, line)
		}

		if currentRule == "" {
			// Top-level key. Reject duplicate keys explicitly so a
			// merge artifact like
			//   tier = 1
			//   tier = 2
			// surfaces with both line numbers instead of silently
			// last-wins. The duplicate-rule-section check below
			// already does this for [rule "X"] stanzas.
			lk := strings.ToLower(key)
			if firstLine, ok := seenTopLevel[lk]; ok {
				return nil, fmt.Errorf("line %d: duplicate top-level key %q (first at line %d)",
					lineno, lk, firstLine)
			}
			seenTopLevel[lk] = lineno
			switch lk {
			case "tier":
				n, err := strconv.Atoi(val)
				if err != nil || n < 0 || n > 2 {
					return nil, fmt.Errorf("line %d: tier must be 0, 1, or 2 (got %q)", lineno, val)
				}
				c.Tier = Tier(n)
			default:
				return nil, fmt.Errorf("line %d: unknown top-level key %q", lineno, key)
			}
			continue
		}

		// Stanza key.
		switch strings.ToLower(key) {
		case "state":
			ov, err := parseOverride(val)
			if err != nil {
				return nil, fmt.Errorf("line %d: %w", lineno, err)
			}
			c.Overrides[currentRule] = ov
		default:
			return nil, fmt.Errorf("line %d: unknown rule key %q (only `state` is supported)", lineno, key)
		}
	}
	if err := scanner.Err(); err != nil {
		return nil, err
	}
	return c, nil
}

// parseSectionHeader extracts the rule ID from `[rule "<ID>"]`.
func parseSectionHeader(line string) (string, error) {
	inner := strings.TrimSuffix(strings.TrimPrefix(line, "["), "]")
	inner = strings.TrimSpace(inner)
	// Expect: rule "<ID>"
	if !strings.HasPrefix(inner, "rule") {
		return "", fmt.Errorf("unknown section header: %q (expected `[rule \"...\"]`)", line)
	}
	rest := strings.TrimSpace(strings.TrimPrefix(inner, "rule"))
	if !strings.HasPrefix(rest, `"`) || !strings.HasSuffix(rest, `"`) || len(rest) < 2 {
		return "", fmt.Errorf("malformed rule section header: %q", line)
	}
	return rest[1 : len(rest)-1], nil
}

func parseOverride(s string) (RuleOverride, error) {
	switch strings.ToLower(strings.TrimSpace(s)) {
	case "skip":
		return OverrideSkip, nil
	case "force":
		return OverrideForce, nil
	case "default", "":
		return OverrideDefault, nil
	}
	return OverrideDefault, fmt.Errorf("state must be `skip`, `force`, or `default` (got %q)", s)
}

func stripComment(line string) string {
	for i, r := range line {
		if r == '#' {
			return line[:i]
		}
	}
	return line
}

func splitKV(line string) (key, value string, ok bool) {
	i := strings.IndexByte(line, '=')
	if i < 0 {
		return "", "", false
	}
	key = strings.TrimSpace(line[:i])
	value = strings.TrimSpace(line[i+1:])
	if key == "" {
		return "", "", false
	}
	return key, value, true
}

// AllRuleIDs returns the union of every rule ID kernsec knows about
// across sysctls, boot args, modules, and mount rules. Used to
// cross-check operator-authored conf overrides against the registry.
func AllRuleIDs() map[string]struct{} {
	out := make(map[string]struct{},
		len(AllSysctls())+len(AllBootArgs())+len(AllModules())+len(Tier1Mounts))
	for _, r := range AllSysctls() {
		out[r.ID] = struct{}{}
	}
	for _, r := range AllBootArgs() {
		out[r.ID] = struct{}{}
	}
	for _, r := range AllModules() {
		out[r.ID] = struct{}{}
	}
	for _, r := range Tier1Mounts {
		out[r.ID] = struct{}{}
	}
	return out
}

// ValidateConfOverrideIDs returns one warning per override key in the
// conf that doesn't match a known rule ID. A typo like
// `KSEC-MOD-net.legacy-024` (no such rule) silently never matches and
// the operator's intended `state = skip` is inert — previously the
// override sat there, undetected, until the operator ran preview
// expecting the rule to be skipped.
//
// Warnings, not errors: an operator may legitimately leave a
// placeholder override for a future rule, or run a forked tree with
// extra rules. Failing loud would block those workflows; warning loud
// catches the typos without breaking anything.
//
// Returns nil for nil conf or empty overrides.
func ValidateConfOverrideIDs(c *Conf) []string {
	if c == nil || len(c.Overrides) == 0 {
		return nil
	}
	known := AllRuleIDs()
	var unknown []string
	for id := range c.Overrides {
		if _, ok := known[id]; !ok {
			unknown = append(unknown, id)
		}
	}
	if len(unknown) == 0 {
		return nil
	}
	sortStrings(unknown)
	out := make([]string, 0, len(unknown))
	for _, id := range unknown {
		out = append(out, fmt.Sprintf(
			"unknown rule ID in conf override: %q (typo? renamed? — check docs/kernsec.md for current IDs)",
			id))
	}
	return out
}

// Render emits the conf back to a string in canonical form. Stable
// ordering: top-level keys first, then rule stanzas alphabetised by ID.
func (c *Conf) Render() string {
	var b strings.Builder
	b.WriteString("# /etc/cfm/kernsec.conf — managed by `cfm kernsec init` / cfm kernsec apply\n")
	b.WriteString("# See docs/kernsec.md for the full design.\n\n")
	fmt.Fprintf(&b, "tier = %d\n", int(c.Tier))

	if len(c.Overrides) > 0 {
		b.WriteString("\n# Per-rule overrides — state = skip | force | default\n")
		ids := make([]string, 0, len(c.Overrides))
		for id := range c.Overrides {
			ids = append(ids, id)
		}
		sortStrings(ids)
		for _, id := range ids {
			fmt.Fprintf(&b, "\n[rule %q]\n", id)
			fmt.Fprintf(&b, "state = %s\n", c.Overrides[id].String())
		}
	}
	return b.String()
}

// WriteDefaultConf writes the default tier=1 conf to ConfPath if and
// only if the file does not exist. Returns (true, nil) if a fresh
// conf was written; (false, nil) if one already existed.
func WriteDefaultConf() (created bool, err error) {
	if _, err := os.Stat(ConfPath); err == nil {
		return false, nil
	} else if !os.IsNotExist(err) {
		return false, err
	}
	if err := os.MkdirAll(filepath.Dir(ConfPath), 0o755); err != nil {
		return false, err
	}
	c := DefaultConf()
	if err := os.WriteFile(ConfPath, []byte(c.Render()), ConfFileMode); err != nil {
		return false, err
	}
	return true, nil
}

// WriteConf atomically writes c to ConfPath. Used by `cfm kernsec
// disable` to persist tier=0 without going through the
// "absent → write default tier=1" path WriteDefaultConf takes.
func WriteConf(c *Conf) error {
	if c == nil {
		return errors.New("WriteConf: nil conf")
	}
	if err := os.MkdirAll(filepath.Dir(ConfPath), 0o755); err != nil {
		return err
	}
	return AtomicWriteFile(ConfPath, []byte(c.Render()), ConfFileMode)
}

// sortStrings is a minimal in-place sort to avoid pulling sort just for
// this one site. Tiny lists; insertion sort is fine.
func sortStrings(s []string) {
	for i := 1; i < len(s); i++ {
		for j := i; j > 0 && s[j-1] > s[j]; j-- {
			s[j-1], s[j] = s[j], s[j-1]
		}
	}
}

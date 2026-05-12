package lsm

import (
	"bufio"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"strconv"
	"strings"
)

// ConfPath is the canonical location of the cfm-lsm config file.
// Declared as var (not const) so tests can redirect it to t.TempDir().
var ConfPath = "/etc/cfm/lsm.conf"

// ConfFileMode mirrors kernsec.conf — root-only. The file does not
// contain credentials, but it discloses which LSM hooks are active
// on the host and which policies the operator has enabled, which is
// information an attacker on the box can use to plan around them.
const ConfFileMode os.FileMode = 0o600

// Conf is the parsed contents of /etc/cfm/lsm.conf.
type Conf struct {
	// Enabled is the global on/off switch. When false (the default),
	// cfm-lsm does not run preflight at startup and does not attach
	// any BPF programs even if individual policies have non-disabled
	// modes set. Operators opt in by setting `enabled = true`.
	Enabled bool

	// Modes maps a policy ID to its configured mode. Policies absent
	// from this map fall back to the policy's DefaultMode (currently
	// always ModeDisabled).
	Modes map[PolicyID]Mode

	// Source is the path the conf was loaded from, or a synthesised
	// description ("(default — no <path>)") when no file was present.
	Source string
}

// DefaultConf returns the default configuration that `cfm lsm init`
// writes on a fresh host: cfm-lsm globally disabled, every policy at
// its DefaultMode.
func DefaultConf() *Conf {
	modes := map[PolicyID]Mode{}
	for _, p := range AllPolicies() {
		modes[p.ID] = p.DefaultMode
	}
	return &Conf{
		Enabled: false,
		Modes:   modes,
	}
}

// ModeFor returns the configured mode for id, falling back to the
// policy's DefaultMode when the conf is silent on it. Unknown IDs
// return ModeDisabled.
func (c *Conf) ModeFor(id PolicyID) Mode {
	if c == nil {
		return ModeDisabled
	}
	if m, ok := c.Modes[id]; ok {
		return m
	}
	if p, ok := PolicyByID(id); ok {
		return p.DefaultMode
	}
	return ModeDisabled
}

// LoadConf reads ConfPath and returns the parsed configuration. If the
// file is absent and createDefault is true, a default conf is
// synthesised in memory; otherwise os.ErrNotExist is returned for the
// caller to handle.
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

// ParseConf parses lsm.conf from r. Format mirrors kernsec.conf:
//
//	# comments and blank lines OK
//	enabled = false
//
//	[policy "CFML-EXEC-001"]
//	mode = monitor
//
//	[policy "CFML-EXEC-003"]
//	mode = disabled
//
// Unknown policy IDs and unknown keys are rejected with a line number
// so merge artifacts and typos surface immediately instead of
// silently dropping rules at runtime.
func ParseConf(r io.Reader) (*Conf, error) {
	c := &Conf{
		Enabled: false,
		Modes:   map[PolicyID]Mode{},
	}
	// Seed defaults for every known policy so the result is complete
	// even if the file declared a subset. Per-policy stanzas override.
	for _, p := range AllPolicies() {
		c.Modes[p.ID] = p.DefaultMode
	}

	scanner := bufio.NewScanner(r)
	scanner.Buffer(make([]byte, 0, 4*1024), 1<<20)

	var (
		currentPolicy  PolicyID // non-empty when inside a [policy "..."] stanza
		lineno         int
		seenPolicies   = map[PolicyID]int{}
		seenTopLevel   = map[string]int{}
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
			if _, ok := PolicyByID(id); !ok {
				return nil, fmt.Errorf("line %d: unknown policy ID %q (known IDs: %s)",
					lineno, id, knownPolicyIDsList())
			}
			if firstLine, dup := seenPolicies[id]; dup {
				return nil, fmt.Errorf("line %d: duplicate policy section %q (first at line %d)",
					lineno, id, firstLine)
			}
			seenPolicies[id] = lineno
			currentPolicy = id
			continue
		}

		key, val, ok := splitKV(line)
		if !ok {
			return nil, fmt.Errorf("line %d: malformed (expected `key = value`): %q", lineno, line)
		}

		if currentPolicy == "" {
			lk := strings.ToLower(key)
			if firstLine, dup := seenTopLevel[lk]; dup {
				return nil, fmt.Errorf("line %d: duplicate top-level key %q (first at line %d)",
					lineno, lk, firstLine)
			}
			seenTopLevel[lk] = lineno
			switch lk {
			case "enabled":
				b, err := parseBool(val)
				if err != nil {
					return nil, fmt.Errorf("line %d: enabled must be true|false|1|0|on|off (got %q)", lineno, val)
				}
				c.Enabled = b
			default:
				return nil, fmt.Errorf("line %d: unknown top-level key %q", lineno, key)
			}
			continue
		}

		switch strings.ToLower(key) {
		case "mode":
			m, err := parseMode(val)
			if err != nil {
				return nil, fmt.Errorf("line %d: %w", lineno, err)
			}
			c.Modes[currentPolicy] = m
		default:
			return nil, fmt.Errorf("line %d: unknown policy key %q (only `mode` is supported)", lineno, key)
		}
	}
	if err := scanner.Err(); err != nil {
		return nil, err
	}
	return c, nil
}

// FormatConf renders c in lsm.conf format. The output is deterministic
// (policies appear in AllPolicies order) so write-modify-write round
// trips do not churn the file.
func FormatConf(c *Conf) string {
	var b strings.Builder
	b.WriteString("# /etc/cfm/lsm.conf — cfm-lsm runtime configuration.\n")
	b.WriteString("# See docs/cfm-lsm.md for the design.\n")
	b.WriteString("\n")
	b.WriteString("# Global on/off. cfm-lsm runs kernel preflight and attaches BPF\n")
	b.WriteString("# programs only when this is true AND preflight passes.\n")
	fmt.Fprintf(&b, "enabled = %t\n", c.Enabled)
	for _, p := range AllPolicies() {
		mode := c.ModeFor(p.ID)
		b.WriteString("\n")
		fmt.Fprintf(&b, "# %s — %s\n", p.ID, p.Title)
		fmt.Fprintf(&b, "# Hook: %s\n", p.Hook)
		fmt.Fprintf(&b, "[policy %q]\n", string(p.ID))
		fmt.Fprintf(&b, "mode = %s  # disabled | monitor | enforce\n", mode)
	}
	return b.String()
}

// WriteDefaultConf writes the default configuration to ConfPath if it
// does not already exist. Returns (true, nil) when a new file was
// created, (false, nil) when the file already existed, or (false, err)
// on a write failure.
func WriteDefaultConf() (created bool, err error) {
	if _, err := os.Stat(ConfPath); err == nil {
		return false, nil
	} else if !os.IsNotExist(err) {
		return false, err
	}
	if err := os.MkdirAll(filepath.Dir(ConfPath), 0o755); err != nil {
		return false, err
	}
	body := FormatConf(DefaultConf())
	if err := os.WriteFile(ConfPath, []byte(body), ConfFileMode); err != nil {
		return false, err
	}
	return true, nil
}

func parseSectionHeader(line string) (PolicyID, error) {
	inner := strings.TrimSuffix(strings.TrimPrefix(line, "["), "]")
	inner = strings.TrimSpace(inner)
	if !strings.HasPrefix(inner, "policy") {
		return "", fmt.Errorf("unknown section header: %q (expected `[policy \"...\"]`)", line)
	}
	rest := strings.TrimSpace(strings.TrimPrefix(inner, "policy"))
	if !strings.HasPrefix(rest, `"`) || !strings.HasSuffix(rest, `"`) || len(rest) < 2 {
		return "", fmt.Errorf("malformed policy section header: %q", line)
	}
	return PolicyID(rest[1 : len(rest)-1]), nil
}

func parseMode(s string) (Mode, error) {
	switch strings.ToLower(strings.TrimSpace(s)) {
	case "disabled", "off", "0", "false":
		return ModeDisabled, nil
	case "monitor", "observe":
		return ModeMonitor, nil
	case "enforce", "block":
		return ModeEnforce, nil
	}
	return ModeDisabled, fmt.Errorf("invalid mode %q (want disabled | monitor | enforce)", s)
}

func parseBool(s string) (bool, error) {
	switch strings.ToLower(strings.TrimSpace(s)) {
	case "true", "1", "on", "yes":
		return true, nil
	case "false", "0", "off", "no":
		return false, nil
	}
	if b, err := strconv.ParseBool(s); err == nil {
		return b, nil
	}
	return false, fmt.Errorf("not a boolean: %q", s)
}

func splitKV(line string) (string, string, bool) {
	eq := strings.IndexByte(line, '=')
	if eq < 0 {
		return "", "", false
	}
	key := strings.TrimSpace(line[:eq])
	val := strings.TrimSpace(line[eq+1:])
	if key == "" {
		return "", "", false
	}
	// Strip surrounding quotes so `mode = "monitor"` works.
	if len(val) >= 2 && val[0] == '"' && val[len(val)-1] == '"' {
		val = val[1 : len(val)-1]
	}
	return key, val, true
}

func stripComment(line string) string {
	if i := strings.IndexByte(line, '#'); i >= 0 {
		return line[:i]
	}
	return line
}

func knownPolicyIDsList() string {
	ids := make([]string, 0, len(AllPolicies()))
	for _, p := range AllPolicies() {
		ids = append(ids, string(p.ID))
	}
	return strings.Join(ids, ", ")
}

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

	// FS005WebOriginMonitor enables CFML-FS-005 origin tracking in
	// monitor-only mode. When true, the BPF program records tasks whose
	// real/effective/fs uid matches cfm_watched_uids and reports later
	// sensitive writes by those tasks even after their current uid changes.
	FS005WebOriginMonitor bool

	// AllowExe is the operator-supplied per-policy executable allowlist.
	// Each entry is an absolute path to a binary whose (dev, inode)
	// key should be treated as legitimate for the policy. Today only
	// CFML-CRED-002 consumes it (merged into cfm_setuid_inodes alongside
	// the disk-walked suid-bit binaries) so that panel daemons like
	// directadmin / cpanel that legitimately call setresuid(0,…) without
	// the suid bit on disk stop firing CRED-002 false positives.
	//
	// Stored generically so future policies (FS-005, EXEC-003) can
	// adopt the same `allow_exe = …` syntax without re-parsing.
	AllowExe map[PolicyID][]string

	// Kmsg controls dmesg emission. Populated from the `[kmsg]`
	// section of lsm.conf; defaults from DefaultKmsgConf() if the
	// section is absent.
	Kmsg KmsgConf

	// Source is the path the conf was loaded from, or a synthesised
	// description ("(default — no <path>)") when no file was present.
	Source string
}

// DefaultConf returns the default configuration that `cfm lsm init`
// writes on a fresh host: cfm-lsm globally disabled, every policy at
// its DefaultMode, kmsg emission on with the documented defaults.
func DefaultConf() *Conf {
	modes := map[PolicyID]Mode{}
	for _, p := range AllPolicies() {
		modes[p.ID] = p.DefaultMode
	}
	return &Conf{
		Enabled:               false,
		Modes:                 modes,
		FS005WebOriginMonitor: true,
		AllowExe:              map[PolicyID][]string{},
		Kmsg:                  DefaultKmsgConf(),
	}
}

// AllowExeFor returns the configured allow_exe paths for id, or nil
// when none are set. Safe on a nil receiver.
func (c *Conf) AllowExeFor(id PolicyID) []string {
	if c == nil || c.AllowExe == nil {
		return nil
	}
	return c.AllowExe[id]
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
// sectionKind classifies what kind of section the parser is currently
// in. Empty means top-level (before any section header).
type sectionKind int

const (
	sectionTopLevel sectionKind = iota
	sectionPolicy
	sectionKmsg
)

func ParseConf(r io.Reader) (*Conf, error) {
	c := &Conf{
		Enabled:               false,
		Modes:                 map[PolicyID]Mode{},
		FS005WebOriginMonitor: false,
		AllowExe:              map[PolicyID][]string{},
		Kmsg:                  DefaultKmsgConf(),
	}
	// Seed defaults for every known policy so the result is complete
	// even if the file declared a subset. Per-policy stanzas override.
	for _, p := range AllPolicies() {
		c.Modes[p.ID] = p.DefaultMode
	}

	scanner := bufio.NewScanner(r)
	scanner.Buffer(make([]byte, 0, 4*1024), 1<<20)

	var (
		current       sectionKind // which section we are inside
		currentPolicy PolicyID    // valid when current == sectionPolicy
		lineno        int
		seenPolicies  = map[PolicyID]int{}
		seenTopLevel  = map[string]int{}
		seenKmsgKeys  = map[string]int{}
		kmsgSeen      int
	)

	for scanner.Scan() {
		lineno++
		raw := scanner.Text()
		line := strings.TrimSpace(stripComment(raw))
		if line == "" {
			continue
		}

		if strings.HasPrefix(line, "[") && strings.HasSuffix(line, "]") {
			kind, id, err := parseSectionHeader(line)
			if err != nil {
				return nil, fmt.Errorf("line %d: %w", lineno, err)
			}
			switch kind {
			case sectionPolicy:
				if _, ok := PolicyByID(id); !ok {
					return nil, fmt.Errorf("line %d: unknown policy ID %q (known IDs: %s)",
						lineno, id, knownPolicyIDsList())
				}
				if firstLine, dup := seenPolicies[id]; dup {
					return nil, fmt.Errorf("line %d: duplicate policy section %q (first at line %d)",
						lineno, id, firstLine)
				}
				seenPolicies[id] = lineno
				current = sectionPolicy
				currentPolicy = id
			case sectionKmsg:
				if kmsgSeen > 0 {
					return nil, fmt.Errorf("line %d: duplicate [kmsg] section (first at line %d)",
						lineno, kmsgSeen)
				}
				kmsgSeen = lineno
				current = sectionKmsg
				currentPolicy = ""
			}
			continue
		}

		key, val, ok := splitKV(line)
		if !ok {
			return nil, fmt.Errorf("line %d: malformed (expected `key = value`): %q", lineno, line)
		}

		switch current {
		case sectionTopLevel:
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
		case sectionPolicy:
			switch strings.ToLower(key) {
			case "mode":
				m, err := parseMode(val)
				if err != nil {
					return nil, fmt.Errorf("line %d: %w", lineno, err)
				}
				c.Modes[currentPolicy] = m
			case "origin_tracking":
				if currentPolicy != PolicySensitiveWrite {
					return nil, fmt.Errorf("line %d: origin_tracking is only valid for %s", lineno, PolicySensitiveWrite)
				}
				monitor, err := parseOriginTracking(val)
				if err != nil {
					return nil, fmt.Errorf("line %d: %w", lineno, err)
				}
				c.FS005WebOriginMonitor = monitor
			case "allow_exe":
				if currentPolicy != PolicyCredEscal {
					return nil, fmt.Errorf("line %d: allow_exe is only valid for %s", lineno, PolicyCredEscal)
				}
				p, err := parseAllowExe(val)
				if err != nil {
					return nil, fmt.Errorf("line %d: %w", lineno, err)
				}
				c.AllowExe[currentPolicy] = append(c.AllowExe[currentPolicy], p)
			default:
				return nil, fmt.Errorf("line %d: unknown policy key %q (supported: `mode`; %s also supports `origin_tracking`; %s also supports `allow_exe`)", lineno, key, PolicySensitiveWrite, PolicyCredEscal)
			}
		case sectionKmsg:
			lk := strings.ToLower(key)
			if firstLine, dup := seenKmsgKeys[lk]; dup {
				return nil, fmt.Errorf("line %d: duplicate kmsg key %q (first at line %d)",
					lineno, lk, firstLine)
			}
			seenKmsgKeys[lk] = lineno
			switch lk {
			case "state_transitions":
				b, err := parseBool(val)
				if err != nil {
					return nil, fmt.Errorf("line %d: state_transitions must be true|false (got %q)", lineno, val)
				}
				c.Kmsg.StateTransitions = b
			case "detect_events":
				b, err := parseBool(val)
				if err != nil {
					return nil, fmt.Errorf("line %d: detect_events must be true|false (got %q)", lineno, val)
				}
				c.Kmsg.DetectEvents = b
			case "detect_rate_per_min":
				n, err := strconv.Atoi(strings.TrimSpace(val))
				if err != nil || n < 0 {
					return nil, fmt.Errorf("line %d: detect_rate_per_min must be a non-negative integer (got %q)", lineno, val)
				}
				c.Kmsg.DetectRatePerMin = n
			default:
				return nil, fmt.Errorf("line %d: unknown kmsg key %q (state_transitions | detect_events | detect_rate_per_min)", lineno, key)
			}
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
		if p.ID == PolicySensitiveWrite {
			state := "disabled"
			if c.FS005WebOriginMonitor {
				state = "monitor"
			}
			fmt.Fprintf(&b, "origin_tracking = %s  # disabled | monitor (origin-only matches never enforce yet)\n", state)
		}
		if p.ID == PolicyCredEscal {
			paths := c.AllowExeFor(p.ID)
			if len(paths) == 0 {
				b.WriteString("# Allowlist binaries that legitimately call setresuid(0,…) without\n")
				b.WriteString("# the suid bit on disk (panel daemons, custom helpers). Repeat the\n")
				b.WriteString("# key per entry; absolute paths only. Resolved at daemon start.\n")
				b.WriteString("# allow_exe = /usr/local/directadmin/directadmin\n")
				b.WriteString("# allow_exe = /usr/local/cpanel/cpanel\n")
			} else {
				for _, ap := range paths {
					fmt.Fprintf(&b, "allow_exe = %s\n", ap)
				}
			}
		}
	}
	b.WriteString("\n")
	b.WriteString("# dmesg / /dev/kmsg emission. Lines tagged `CFM-LSM:` show up\n")
	b.WriteString("# in `dmesg`, `journalctl -k`, and (on most distros) /var/log/messages.\n")
	b.WriteString("# Route to a dedicated file via /etc/rsyslog.d/99-cfm-lsm.conf — see\n")
	b.WriteString("# configs/rsyslog/cfm-lsm.conf for a ready-to-drop-in example.\n")
	b.WriteString("[kmsg]\n")
	fmt.Fprintf(&b, "state_transitions   = %t   # ALIVE / ADOPT / STATE / ISSUE on enable/disable/adopt/stop\n", c.Kmsg.StateTransitions)
	fmt.Fprintf(&b, "detect_events       = %t   # one DETECT line per detection (rate-limited below)\n", c.Kmsg.DetectEvents)
	fmt.Fprintf(&b, "detect_rate_per_min = %d   # cap DETECT lines per policy per minute; 0 disables cap (not recommended)\n", c.Kmsg.DetectRatePerMin)
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

// parseSectionHeader recognises two header shapes:
//
//	[kmsg]                 -> sectionKmsg
//	[policy "CFML-EXEC-001"] -> sectionPolicy with the quoted ID
//
// Anything else is a parse error. The PolicyID return is valid only
// when kind == sectionPolicy; it is the empty string otherwise.
// parseAllowExe validates one `allow_exe = …` value. The path must be
// non-empty, absolute, and free of NUL bytes — anything fancier (glob,
// resolution against $PATH, …) belongs in userspace before reaching
// here. Existence is NOT checked at parse time: the daemon does a stat
// at map-population time so a missing path is a runtime warning, not
// a fatal config error.
func parseAllowExe(s string) (string, error) {
	p := strings.TrimSpace(s)
	if p == "" {
		return "", fmt.Errorf("allow_exe must be a non-empty path")
	}
	if !strings.HasPrefix(p, "/") {
		return "", fmt.Errorf("allow_exe must be an absolute path (got %q)", p)
	}
	if strings.ContainsRune(p, 0) {
		return "", fmt.Errorf("allow_exe must not contain NUL bytes")
	}
	return p, nil
}

func parseOriginTracking(s string) (bool, error) {
	switch strings.ToLower(strings.TrimSpace(s)) {
	case "disabled", "off", "false", "0":
		return false, nil
	case "monitor", "observe", "on", "true", "1":
		return true, nil
	}
	return false, fmt.Errorf("invalid origin_tracking %q (want disabled|monitor)", s)
}

func parseSectionHeader(line string) (sectionKind, PolicyID, error) {
	inner := strings.TrimSuffix(strings.TrimPrefix(line, "["), "]")
	inner = strings.TrimSpace(inner)

	// Bare-word section: currently only "kmsg".
	if inner == "kmsg" {
		return sectionKmsg, "", nil
	}

	if !strings.HasPrefix(inner, "policy") {
		return sectionTopLevel, "", fmt.Errorf("unknown section header: %q (expected `[kmsg]` or `[policy \"...\"]`)", line)
	}
	rest := strings.TrimSpace(strings.TrimPrefix(inner, "policy"))
	if !strings.HasPrefix(rest, `"`) || !strings.HasSuffix(rest, `"`) || len(rest) < 2 {
		return sectionTopLevel, "", fmt.Errorf("malformed policy section header: %q", line)
	}
	return sectionPolicy, PolicyID(rest[1 : len(rest)-1]), nil
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

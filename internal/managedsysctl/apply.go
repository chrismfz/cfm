package managedsysctl

import (
	"fmt"
	"os/exec"
	"strings"
)

// ApplyResult is the outcome of ApplyKeys: how many keys succeeded,
// per-key failures with kernel response, and the keys that were
// silently skipped (malformed lines etc).
type ApplyResult struct {
	Applied  int
	Failures []KeyFailure
	Skipped  []string // human-readable reasons
}

// KeyFailure describes a single rejected key.
type KeyFailure struct {
	Key      string
	Value    string
	Err      error
	Response string // trimmed sysctl(8) output
}

// Err returns a single error summarising every per-key failure, or
// nil if there were none. The error names every rejected key with
// kernel response so an operator can see exactly which sysctls were
// rejected and why.
func (r ApplyResult) Err() error {
	if len(r.Failures) == 0 {
		return nil
	}
	lines := make([]string, 0, len(r.Failures))
	for _, f := range r.Failures {
		lines = append(lines, fmt.Sprintf("  %s=%s: %v: %s",
			f.Key, f.Value, f.Err, f.Response))
	}
	return fmt.Errorf("sysctl: %d key(s) rejected by kernel:\n%s",
		len(r.Failures), strings.Join(lines, "\n"))
}

// SetCommand applies one sysctl key=value via `sysctl -w`. var, not
// function, so tests can substitute a deterministic stub. Both
// kernsec.LoadSysctl and any future component's apply path call
// through this so the stub set in one place is honoured everywhere.
var SetCommand = func(key, value string) ([]byte, error) {
	return exec.Command("sysctl", "-w", key+"="+value).CombinedOutput()
}

// KeyValuePair is one (key, value) tuple to apply. Used by
// ApplyKeys; lifted from kernsec/sys_tweaks's local maps so both
// callers share one struct.
type KeyValuePair struct {
	Key   string
	Value string
}

// ApplyKeys writes each (key, value) via `sysctl -w`. Continue-on-
// error: a single bad rule (kernel rejects the value, key was
// removed by module unload, lockdown blocks the write) does not stop
// subsequent rules from being applied. All per-key failures are
// accumulated in the returned ApplyResult.
//
// This is the canonical implementation; kernsec.LoadSysctl wraps it
// (after parsing the on-disk file into pairs), and sys_tweaks can
// migrate to it instead of looping over its own map and silently
// stderr-printing failures.
func ApplyKeys(pairs []KeyValuePair) ApplyResult {
	var res ApplyResult
	for _, p := range pairs {
		if p.Key == "" {
			res.Skipped = append(res.Skipped, "empty key")
			continue
		}
		out, err := SetCommand(p.Key, p.Value)
		if err != nil {
			res.Failures = append(res.Failures, KeyFailure{
				Key:      p.Key,
				Value:    p.Value,
				Err:      err,
				Response: strings.TrimSpace(string(out)),
			})
			continue
		}
		res.Applied++
	}
	return res
}

// ParseFileToPairs parses the contents of a managed sysctl file
// (`# header\nkey = value\n...` form) into a list of KeyValuePair.
// Comment lines and blank lines are skipped. Malformed lines (no
// `=` sign) are returned as Skipped reasons rather than silently
// dropped — kernsec writes the file itself, so a malformed line is
// a render bug worth surfacing.
func ParseFileToPairs(content []byte) (pairs []KeyValuePair, skipped []string) {
	for lineno, raw := range strings.Split(string(content), "\n") {
		line := strings.TrimSpace(raw)
		if line == "" || strings.HasPrefix(line, "#") {
			continue
		}
		eq := strings.IndexByte(line, '=')
		if eq < 0 {
			skipped = append(skipped,
				fmt.Sprintf("line %d: malformed (no `=`): %q", lineno+1, line))
			continue
		}
		key := strings.TrimSpace(line[:eq])
		val := strings.TrimSpace(line[eq+1:])
		if key == "" {
			skipped = append(skipped,
				fmt.Sprintf("line %d: empty key: %q", lineno+1, line))
			continue
		}
		pairs = append(pairs, KeyValuePair{Key: key, Value: val})
	}
	return pairs, skipped
}

package kernsec

import (
	"os"
	"strings"
)

// ParseCmdline splits a kernel cmdline string into tokens, ignoring
// empty fields. Whitespace-separated; values containing whitespace
// (rare in real kernel cmdlines) are not handled specially.
func ParseCmdline(line string) []string {
	out := make([]string, 0, 16)
	for _, f := range strings.Fields(line) {
		if f != "" {
			out = append(out, f)
		}
	}
	return out
}

// ReadProcCmdline reads /proc/cmdline. Returns "" on error.
func ReadProcCmdline() string {
	b, err := os.ReadFile("/proc/cmdline")
	if err != nil {
		return ""
	}
	return strings.TrimSpace(string(b))
}

// CmdlineArgState describes the state of one expected boot arg
// in a given cmdline.
type CmdlineArgState int

const (
	// ArgOK means the exact "key=value" (or bare key) is present.
	ArgOK CmdlineArgState = iota
	// ArgDiff means the key is present but with a different value.
	ArgDiff
	// ArgMissing means the key is not present at all.
	ArgMissing
)

// CheckBootArg reports the state of a single expected arg in a cmdline.
// foundValue is the actual value seen for the key, or "" if missing.
func CheckBootArg(tokens []string, want BootArg) (state CmdlineArgState, foundValue string) {
	wantKey := want.Key
	wantStr := want.String()
	state = ArgMissing
	for _, tok := range tokens {
		if tok == wantStr {
			return ArgOK, want.Value
		}
		key, val := splitArg(tok)
		if key == wantKey {
			state = ArgDiff
			foundValue = val
		}
	}
	return state, foundValue
}

// splitArg splits a "key=value" token. A bare "key" returns key, "".
func splitArg(tok string) (key, value string) {
	if i := strings.IndexByte(tok, '='); i >= 0 {
		return tok[:i], tok[i+1:]
	}
	return tok, ""
}

// IsManagedKey reports whether key is in ManagedBootArgKeys.
func IsManagedKey(key string) bool {
	for _, k := range ManagedBootArgKeys {
		if k == key {
			return true
		}
	}
	return false
}

// RemoveManagedArgs returns a copy of tokens with all managed-key
// tokens stripped. Used by enable to clear stale values before adding
// the desired set, and by disable to clear them entirely. Mirrors
// kspp.sh remove_managed_args_from_line.
func RemoveManagedArgs(tokens []string) []string {
	out := make([]string, 0, len(tokens))
	for _, tok := range tokens {
		key, _ := splitArg(tok)
		if IsManagedKey(key) {
			continue
		}
		out = append(out, tok)
	}
	return out
}

// KeepManagedArgs is the dual of RemoveManagedArgs: returns a copy of
// tokens containing ONLY managed-key tokens. Used by the BLS drift
// check to compare the managed subset across kernels — distro-specific
// unmanaged args (crashkernel=, transparent_hugepage=, …) legitimately
// differ between installed kernels and must not be flagged as drift.
func KeepManagedArgs(tokens []string) []string {
	out := make([]string, 0, len(tokens))
	for _, tok := range tokens {
		key, _ := splitArg(tok)
		if IsManagedKey(key) {
			out = append(out, tok)
		}
	}
	return out
}

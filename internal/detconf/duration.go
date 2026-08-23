package detconf

import (
	"fmt"
	"strconv"
	"strings"
	"time"
)

// ParseCfgDuration parses a detectors.conf duration value. It extends Go's
// time.ParseDuration with a "d" (days) unit — the stdlib parser stops at "h",
// so "7d"/"1d12h" would otherwise fail and silently fall back to the default.
//
// Every "<number>d" segment is expanded to its hour-equivalent (N days -> N*24
// h) and the fully-normalized string is handed to time.ParseDuration once.
// This keeps day support composable with the standard units (composites like
// "1d12h", fractional days like "1.5d") and reuses the stdlib's exact
// nanosecond arithmetic for everything else. Only lowercase "d" is recognised,
// matching Go's lowercase unit convention.
//
// This is the single duration parser for detectors.conf scalars: kvDur (EVERY/
// WINDOW/COOLDOWN/TIMEOUT/...), parseBlockPolicy (BLOCK) and the mysql
// QUERY_RULES MAX_TIME all route through it, so "d" means the same thing in
// every operator-writable duration field. It lives here — not in
// internal/detectors — so the API-server save-time validation can enforce the
// SAME grammar the runtime accepts; two parsers that disagree turn a valid
// operator value into a false "invalid block mode" error.
func ParseCfgDuration(s string) (time.Duration, error) {
	s = strings.TrimSpace(s)
	if s == "" {
		return 0, fmt.Errorf("empty duration")
	}
	// Fast path: no day unit -> stdlib handles the whole value unchanged.
	if !strings.Contains(s, "d") {
		return time.ParseDuration(s)
	}

	var b strings.Builder
	i := 0
	if s[0] == '+' || s[0] == '-' {
		b.WriteByte(s[0])
		i = 1
	}
	for i < len(s) {
		// number: digits and at most a decimal point
		numStart := i
		for i < len(s) && ((s[i] >= '0' && s[i] <= '9') || s[i] == '.') {
			i++
		}
		num := s[numStart:i]
		// unit: everything up to the next number/sign (covers multi-byte "µs")
		unitStart := i
		for i < len(s) && !((s[i] >= '0' && s[i] <= '9') || s[i] == '.' || s[i] == '+' || s[i] == '-') {
			i++
		}
		unit := s[unitStart:i]

		if unit != "d" {
			b.WriteString(num)
			b.WriteString(unit)
			continue
		}
		if num == "" {
			return 0, fmt.Errorf("invalid duration %q", s)
		}
		// N days -> N*24 h. Keep integer days exact; fall back to float only
		// for the rare fractional case (e.g. "1.5d").
		if !strings.Contains(num, ".") {
			n, err := strconv.ParseInt(num, 10, 64)
			if err != nil {
				return 0, fmt.Errorf("invalid duration %q", s)
			}
			b.WriteString(strconv.FormatInt(n*24, 10))
		} else {
			f, err := strconv.ParseFloat(num, 64)
			if err != nil {
				return 0, fmt.Errorf("invalid duration %q", s)
			}
			b.WriteString(strconv.FormatFloat(f*24, 'f', -1, 64))
		}
		b.WriteString("h")
	}
	return time.ParseDuration(b.String())
}

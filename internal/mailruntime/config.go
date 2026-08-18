package mailruntime

import (
	"regexp"
	"strconv"
	"strings"
)

// EximMaxima holds the SMTP-connection caps read from an Exim main-config. Each
// value carries a Found flag so an absent option is "unknown" (fall back to the
// documented default at the call site) rather than a silent zero.
//
// Exim semantics (stable, long-documented main-config options):
//   - smtp_accept_max          — max simultaneous incoming SMTP connections.
//     Default 20. A value of 0 means NO limit.
//   - smtp_accept_max_per_host — per-source cap; often a string expansion
//     (e.g. "${if …}"), which has no single integer
//     value, so PerHostFound stays false for those.
type EximMaxima struct {
	SMTPAcceptMax      int
	SMTPAcceptMaxFound bool
	Unlimited          bool // smtp_accept_max = 0 → no connection cap at all
	PerHost            int
	PerHostFound       bool
}

// eximOptRe matches one `name = value` main-config assignment, tolerating
// leading whitespace and spaces around `=`. It captures the raw value token
// (first whitespace-delimited chunk) so a trailing inline comment or expansion
// is handled by the caller. Comment lines (`#…`) are skipped before matching.
var eximOptRe = regexp.MustCompile(`^\s*([a-z0-9_]+)\s*=\s*(\S+)`)

// ParseEximMaxima extracts the SMTP-connection caps from Exim main-config text.
// It is line-oriented and mechanical: it reads the configured integers only and
// does not evaluate Exim string expansions (an expansion value leaves the
// corresponding Found flag false). The last assignment of an option wins, which
// mirrors how Exim itself treats a later reassignment in the same config.
func ParseEximMaxima(configText string) EximMaxima {
	var m EximMaxima
	for _, line := range strings.Split(configText, "\n") {
		trimmed := strings.TrimSpace(line)
		if trimmed == "" || strings.HasPrefix(trimmed, "#") {
			continue
		}
		sub := eximOptRe.FindStringSubmatch(line)
		if sub == nil {
			continue
		}
		name, rawVal := sub[1], sub[2]
		switch name {
		case "smtp_accept_max":
			if n, err := strconv.Atoi(rawVal); err == nil {
				m.SMTPAcceptMax = n
				m.SMTPAcceptMaxFound = true
				m.Unlimited = (n == 0) // Exim: 0 = no limit
			}
		case "smtp_accept_max_per_host":
			// Frequently a "${if …}" expansion — only record a plain integer.
			if n, err := strconv.Atoi(rawVal); err == nil {
				m.PerHost = n
				m.PerHostFound = true
			}
		}
	}
	return m
}

// spamdMaxChildrenRe matches the spamd max-children flag in a command line, in
// its documented forms: `--max-children=N`, `--max-children N`, `-m N`, `-mN`.
// Anchored on a word boundary so it does not match inside another token.
var spamdMaxChildrenRe = regexp.MustCompile(`(?:--max-children[=\s]+|(?:^|\s)-m\s*)(\d+)`)

// ParseSpamdMaxChildren extracts spamd's --max-children / -m value from its
// command line (or startup args). Returns (n, true) on a match; (0, false) when
// the flag is absent, so the caller treats it as unknown rather than a zero cap.
// spamd's own default when the flag is omitted is 5, but that default is applied
// by the caller (documented), not fabricated here.
func ParseSpamdMaxChildren(cmdline string) (int, bool) {
	sub := spamdMaxChildrenRe.FindStringSubmatch(cmdline)
	if sub == nil {
		return 0, false
	}
	n, err := strconv.Atoi(sub[1])
	if err != nil {
		return 0, false
	}
	return n, true
}

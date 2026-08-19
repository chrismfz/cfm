package mailruntime

import "os"

// DefaultEximConfPaths are the standard locations of the ACTIVE Exim config,
// tried in order. cPanel merges exim.conf.local into the generated /etc/exim.conf
// (so the final value lands there); the others cover DA/plain-Exim and Debian
// exim4 layouts. This is a fixed candidate list (like mail_log_tail's), never a
// caller-supplied path.
var DefaultEximConfPaths = []string{
	"/etc/exim.conf",
	"/etc/exim.conf.local",
	"/etc/exim/exim.conf",
	"/etc/exim4/exim4.conf",
}

// DiscoverEximMaxima reads the first readable Exim config that explicitly sets
// smtp_accept_max and returns its parsed maxima plus the path it came from
// (empty when none set it). It stops at the first EXPLICIT setting: a config
// that never mentions smtp_accept_max leaves the cap unresolved on purpose — we
// do NOT assume Exim's built-in default (20), because a cPanel box routinely
// raises it, and assuming 20 would flag a false 100% saturation. Unresolved →
// ResolvedMax.Known == false → SatUnknown (docs/whats-wrong-rootcause.md §3).
func DiscoverEximMaxima() (EximMaxima, string) {
	return discoverEximMaximaIn(DefaultEximConfPaths)
}

func discoverEximMaximaIn(paths []string) (EximMaxima, string) {
	for _, p := range paths {
		raw, err := os.ReadFile(p)
		if err != nil {
			continue // not present / not readable — try the next candidate
		}
		m := ParseEximMaxima(string(raw))
		if m.SMTPAcceptMaxFound {
			return m, p
		}
	}
	return EximMaxima{}, ""
}

// DiscoverSpamdMaxChildren reads spamd's --max-children from the master spamd
// process's command line. Returns (n, true) only when a master spamd is running
// AND carries an explicit --max-children/-m; otherwise (0, false) → unresolved →
// SatUnknown. spamd's own default (5) is deliberately NOT assumed here for the
// same reason as the Exim cap above.
func DiscoverSpamdMaxChildren() (int, bool) {
	return discoverSpamdMaxChildrenIn("/proc")
}

func discoverSpamdMaxChildrenIn(procRoot string) (int, bool) {
	cmd, ok := firstCmdlineWithComm(procRoot, "spamd")
	if !ok {
		return 0, false
	}
	return ParseSpamdMaxChildren(cmd)
}

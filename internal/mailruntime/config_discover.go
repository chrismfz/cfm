package mailruntime

import (
	"io"
	"os"
	"strings"
)

// maxEximConfBytes caps how much of an Exim config we read — a generous ceiling
// (a cPanel-generated exim.conf is a few hundred KB at most), so a pathological
// file can't be slurped whole on a periodic collector tick. smtp_accept_max sits
// in the main-config section near the top; truncation at worst yields unknown.
const maxEximConfBytes = 8 << 20 // 8 MiB

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
		raw, err := readCapped(p, maxEximConfBytes)
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

// readCapped reads at most max bytes from path, so a pathological config can't be
// slurped whole.
func readCapped(path string, max int64) ([]byte, error) {
	f, err := os.Open(path)
	if err != nil {
		return nil, err
	}
	defer f.Close()
	return io.ReadAll(io.LimitReader(f, max))
}

// DiscoverSpamdMaxChildren reads spamd's --max-children from the master spamd
// process's command line. Returns (n, true) only when a master spamd is running
// AND carries an explicit --max-children/-m; otherwise (0, false) → unresolved →
// SatUnknown. spamd's own default (5) is deliberately NOT assumed here for the
// same reason as the Exim cap above.
//
// It matches on the CMDLINE, not the COMM: on cPanel the master runs under perl
//
//	/usr/local/cpanel/3rdparty/perl/…/bin/perl -T -w …/bin/spamd --max-children=10 …
//
// so its COMM is "perl", not "spamd" (only the workers rewrite their task name to
// "spamd child"). Keying on COMM would silently miss the master fleet-wide. The
// master is the one spamd-mentioning process carrying --max-children; the "spamd
// child" workers mention spamd but have no such flag, so ParseSpamdMaxChildren
// rejects them.
func DiscoverSpamdMaxChildren() (int, bool) {
	return discoverSpamdMaxChildrenIn("/proc")
}

func discoverSpamdMaxChildrenIn(procRoot string) (int, bool) {
	for _, cmd := range allCmdlines(procRoot) {
		if !strings.Contains(strings.ToLower(cmd), "spamd") {
			continue
		}
		if n, ok := ParseSpamdMaxChildren(cmd); ok {
			return n, true
		}
	}
	return 0, false
}

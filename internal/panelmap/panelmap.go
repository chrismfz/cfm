// Package panelmap is the single canonical reader for the cPanel domain→owner
// maps (/etc/userdatadomains and /etc/userdomains). CFM had grown parallel
// copies of this parse (apiserver's scoped-MySQL owner derivation, the LSM
// domain→UID reader); this package exists so the "which hosting account owns
// this vhost?" mapping lives in exactly one place (CLAUDE.md §5 — no second
// copy of a matcher that can drift).
//
// Two shapes are served from the same line parser:
//   - HostOwners: host → single owning account (userdatadomains wins, then
//     userdomains fills gaps) — for attributing a vhost to one account.
//   - OwnerSet: the distinct set of owners across BOTH files for a host set —
//     the fail-closed scope derivation apiserver needs (a host somehow listed
//     under two owners contributes both, so scope can't silently widen).
package panelmap

import (
	"bufio"
	"os"
	"sort"
	"strings"
)

// Paths to the cPanel maps. Package vars so tests can point them at fixtures.
var (
	UserDataDomainsPath = "/etc/userdatadomains"
	UserDomainsPath     = "/etc/userdomains"
)

// parseOwnerLine extracts (host, owner) from a "domain: owner…" line. Both are
// lowercased and trimmed. userDataDomains lines carry "owner==type==…" after
// the colon (the owner is the field before the first "=="); userdomains lines
// are a bare "domain: owner". Returns ok=false for blank/malformed lines.
func parseOwnerLine(line string, userDataDomains bool) (host, owner string, ok bool) {
	line = strings.TrimSpace(line)
	if line == "" {
		return "", "", false
	}
	colon := strings.IndexByte(line, ':')
	if colon <= 0 || colon+1 >= len(line) {
		return "", "", false
	}
	host = strings.ToLower(strings.TrimSpace(line[:colon]))
	rest := strings.TrimSpace(line[colon+1:])
	if userDataDomains {
		owner = strings.ToLower(strings.TrimSpace(strings.SplitN(rest, "==", 2)[0]))
	} else {
		owner = strings.ToLower(strings.TrimSpace(rest))
	}
	if host == "" || owner == "" {
		return "", "", false
	}
	return host, owner, true
}

// collectFile scans one map file, invoking fn(host, owner) for each valid line
// whose host is in want (always non-empty here — both callers early-return on an
// empty host set). A missing/unreadable file is a silent no-op (the box may not
// be cPanel, or the file may not exist).
func collectFile(path string, userDataDomains bool, want map[string]struct{}, fn func(host, owner string)) {
	f, err := os.Open(path)
	if err != nil {
		return
	}
	defer f.Close()
	sc := bufio.NewScanner(f)
	// These files are one domain per line (short), but raise the cap well above
	// bufio.Scanner's 64 KiB default so an outsized line can't silently end the
	// scan and drop a host — which, on this scope-derivation path, would narrow a
	// scoped token's owner set (fail-closed, but still wrong).
	sc.Buffer(make([]byte, 0, 64*1024), 1024*1024)
	for sc.Scan() {
		host, owner, ok := parseOwnerLine(sc.Text(), userDataDomains)
		if !ok {
			continue
		}
		if _, keep := want[host]; !keep {
			continue
		}
		fn(host, owner)
	}
}

// hostSet lowercases a host slice into a lookup set (empty entries dropped).
func hostSet(hosts []string) map[string]struct{} {
	set := make(map[string]struct{}, len(hosts))
	for _, h := range hosts {
		h = strings.ToLower(strings.TrimSpace(h))
		if h != "" {
			set[h] = struct{}{}
		}
	}
	return set
}

// HostOwners returns a host→owner map for the given hosts. userdatadomains is
// consulted first and wins; userdomains only fills hosts not already resolved.
// Hosts absent from both files are absent from the map. An empty/nil hosts
// slice yields an empty map (nothing requested).
func HostOwners(hosts []string) map[string]string {
	want := hostSet(hosts)
	out := make(map[string]string, len(want))
	if len(want) == 0 {
		return out
	}
	collectFile(UserDataDomainsPath, true, want, func(host, owner string) {
		if _, seen := out[host]; !seen {
			out[host] = owner
		}
	})
	collectFile(UserDomainsPath, false, want, func(host, owner string) {
		if _, seen := out[host]; !seen {
			out[host] = owner
		}
	})
	return out
}

// OwnerSet returns the distinct, sorted set of owners across BOTH files for the
// given hosts. Unlike HostOwners it does not pick one owner per host: if a host
// is (pathologically) listed under two owners, both appear — so a scope derived
// from this can only ever be as wide as the union, never silently narrowed to
// the wrong single owner. Returns nil when nothing matches.
func OwnerSet(hosts []string) []string {
	want := hostSet(hosts)
	if len(want) == 0 {
		return nil
	}
	owners := map[string]struct{}{}
	add := func(_, owner string) { owners[owner] = struct{}{} }
	collectFile(UserDataDomainsPath, true, want, add)
	collectFile(UserDomainsPath, false, want, add)
	if len(owners) == 0 {
		return nil
	}
	out := make([]string, 0, len(owners))
	for o := range owners {
		out = append(out, o)
	}
	sort.Strings(out)
	return out
}

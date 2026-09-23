// internal/locate/fail2ban.go
//
// fail2ban probe. Primary path is `fail2ban-client banned` (0.11+),
// which dumps every jail with its banned entries in one call; on older
// versions we fall back to `status` + `status <jail>`. Entries can be
// plain IPs, CIDRs or ranges, so matching is containment-aware.
package locate

import (
	"context"
	"sort"
	"strings"

	"cfm/internal/ipquery"
)

// searchFail2Ban returns (locations, "") on success or (nil, why) when
// fail2ban isn't available.
func searchFail2Ban(ctx context.Context, qs []*query) ([][]Location, string) {
	if !binaryExists("fail2ban-client") {
		return nil, "not installed"
	}
	if !unitActive("fail2ban") {
		return nil, "service not active"
	}

	if out, err := runOut(ctx, "fail2ban-client", "banned"); err == nil {
		if jails, ok := parseF2BBannedDump(string(out)); ok {
			return matchF2BJails(jails, qs), ""
		}
	}

	// Fallback for fail2ban < 0.11: enumerate jails, then status each.
	out, err := runOut(ctx, "fail2ban-client", "status")
	if err != nil {
		return nil, "query failed: " + trimOut(out)
	}
	jails := map[string][]string{}
	for _, jail := range parseF2BJailList(string(out)) {
		jout, jerr := runOut(ctx, "fail2ban-client", "status", jail)
		if jerr != nil {
			continue
		}
		jails[jail] = parseF2BBannedLine(string(jout))
	}
	return matchF2BJails(jails, qs), ""
}

func matchF2BJails(jails map[string][]string, qs []*query) [][]Location {
	names := make([]string, 0, len(jails))
	for jail := range jails {
		names = append(names, jail)
	}
	sort.Strings(names)
	idx := ipquery.NewIndex[Location]()
	for _, jail := range names {
		for _, e := range jails[jail] {
			idx.Add(e, Location{Source: "fail2ban", List: jail, Action: ActionBlock, Match: e})
		}
	}
	return matchAll(idx, qs)
}

// parseF2BBannedDump parses the output of `fail2ban-client banned`,
// which is a Python repr like:
//
//	[{'sshd': ['1.2.3.4', '10.0.0.0/24']}, {'recidive': []}]
//
// Jail names and IPs never contain quotes/brackets, so a tolerant
// token scan is safer than pretending it's JSON.
func parseF2BBannedDump(s string) (map[string][]string, bool) {
	s = strings.TrimSpace(s)
	if !strings.HasPrefix(s, "[") {
		return nil, false
	}
	jails := map[string][]string{}
	cur := ""
	inStr := false
	var tok strings.Builder
	flush := func() {
		t := strings.TrimSpace(tok.String())
		tok.Reset()
		if t == "" {
			return
		}
		if cur == "" {
			return
		}
		jails[cur] = append(jails[cur], t)
	}
	for _, r := range s {
		switch r {
		case '\'', '"':
			if inStr {
				inStr = false
			} else {
				inStr = true
				continue
			}
		case ':':
			if !inStr {
				// token completed just before ':' is the jail name
				cur = strings.TrimSpace(tok.String())
				tok.Reset()
				if cur != "" {
					if _, dup := jails[cur]; !dup {
						jails[cur] = nil
					}
				}
				continue
			}
		case ',', ']', '[':
			if !inStr {
				flush()
				continue
			}
		case '}', '{':
			if !inStr {
				flush()
				cur = "" // dict boundary: never attribute later tokens to a previous jail
				continue
			}
		}
		if inStr {
			tok.WriteRune(r)
		} else if r == ':' || r == '.' || r == '-' || r == '/' || (r >= '0' && r <= '9') ||
			(r >= 'a' && r <= 'f') || (r >= 'A' && r <= 'F') {
			// bare tokens (unquoted IPs/ranges) — hex chars cover IPv6
			tok.WriteRune(r)
		}
	}
	flush()
	return jails, true
}

// parseF2BJailList extracts jail names from `fail2ban-client status`:
//
//	Status
//	|- Number of jail:	2
//	`- Jail list:	sshd, recidive
func parseF2BJailList(s string) []string {
	for _, line := range strings.Split(s, "\n") {
		if i := strings.Index(line, "Jail list:"); i >= 0 {
			raw := strings.TrimSpace(line[i+len("Jail list:"):])
			if raw == "" {
				return nil
			}
			parts := strings.Split(raw, ",")
			jails := make([]string, 0, len(parts))
			for _, p := range parts {
				if p = strings.TrimSpace(p); p != "" {
					jails = append(jails, p)
				}
			}
			return jails
		}
	}
	return nil
}

// parseF2BBannedLine extracts entries from a per-jail status:
//
//	`- Banned IP list:	1.2.3.4 5.6.7.8
func parseF2BBannedLine(s string) []string {
	for _, line := range strings.Split(s, "\n") {
		if i := strings.Index(line, "Banned IP list:"); i >= 0 {
			return strings.Fields(strings.TrimSpace(line[i+len("Banned IP list:"):]))
		}
	}
	return nil
}

func trimOut(b []byte) string {
	s := strings.TrimSpace(string(b))
	if len(s) > 200 {
		s = s[:200] + "…"
	}
	return s
}

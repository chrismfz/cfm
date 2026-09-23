// internal/locate/imunify.go
//
// imunify360 probe. Uses the documented read-only queries
//
//	imunify360-agent ip-list local list --by-ip <arg> --json
//	imunify360-agent ip-list local list --limit 10000 --json
//
// (--by-ip accepts an IP or a subnet in CIDR notation). Purposes map to
// actions: white=ALLOW, drop=BLOCK (BLACK bucket), captcha/splashscreen=
// CHALLENGE (GRAY bucket). One query asks --by-ip, and because --by-ip's
// containment semantics for subnet *entries* aren't guaranteed across
// versions, a miss falls back to listing the local list and matching
// containment ourselves. Many queries list once and match locally (see
// searchImunify).
package locate

import (
	"context"
	"encoding/json"
	"fmt"
	"math"
	"math/bits"
	"net"
	"strconv"
	"strings"
	"time"

	"cfm/internal/ipquery"
)

func imunifyUnitActive() bool {
	return unitActive("imunify360") || unitActive("imunify360-agent") ||
		unitActive("imunify360.service") || unitActive("imunify360-agent.service")
}

// imunifyListCap bounds the full-list read.
const imunifyListCap = 10000

// searchImunify returns each query's locations, or why imunify isn't
// available (why), or, per query, why that query went unanswered (skip).
//
// One query asks --by-ip first, and on a miss for a plain IP lists the local
// list and matches containment itself. Many queries list once and match
// locally. A list that reached the cap may be missing entries, so then every
// query is also asked --by-ip, as the single path would, while ctx allows.
// The same holds for a list that says it holds more than it returned, or has
// entries it couldn't read (imunifyIncomplete).
// NOTE: a covering subnet entry past the cap that --by-ip doesn't surface is
// missed, as before; the cap keeps the list read bounded — raise it if real
// lists approach it.
func searchImunify(ctx context.Context, qs []*query) (locs [][]Location, skip []string, why string) {
	if !binaryExists("imunify360-agent") {
		return nil, nil, "not installed"
	}
	if !imunifyUnitActive() {
		return nil, nil, "service not active"
	}

	// byIP asks --by-ip; unreadable reports output that isn't JSON (runOut
	// returns stderr with stdout, so a warning on stderr is enough).
	byIP := func(q *query) (l []Location, why string, unreadable bool) {
		out, err := runOut(ctx, "imunify360-agent", "ip-list", "local", "list", "--by-ip", q.raw, "--json")
		switch {
		case ctx.Err() != nil:
			return nil, "no time left to ask --by-ip", false
		case err != nil:
			return nil, "query failed: " + trimOut(out), false
		}
		items := parseImunifyList(out)
		if items == nil {
			return nil, "unreadable output: " + trimOut(out), true
		}
		return matchImunifyItems(items, []*query{q})[0], "", false
	}
	if len(qs) == 1 {
		// A miss (or an unreadable answer) for a plain IP goes on to the list.
		l, why, unreadable := byIP(qs[0])
		if (why != "" && !unreadable) || len(l) > 0 || qs[0].IsCIDR {
			return [][]Location{l}, nil, why
		}
		if unreadable {
			if out, err := runOut(ctx, "imunify360-agent", "ip-list", "local", "list", "--limit", strconv.Itoa(imunifyListCap), "--json"); err == nil {
				if items := parseImunifyList(out); items != nil {
					return matchImunifyItems(items, qs), nil, ""
				}
			}
			return nil, nil, why
		}
	}

	out, err := runOut(ctx, "imunify360-agent", "ip-list", "local", "list", "--limit", strconv.Itoa(imunifyListCap), "--json")
	if len(qs) == 1 {
		// As before: the --by-ip miss stands unless the list shows more.
		if err != nil {
			return [][]Location{nil}, nil, ""
		}
		return matchImunifyItems(parseImunifyList(out), qs), nil, ""
	}
	if err != nil {
		return nil, nil, "query failed: " + trimOut(out)
	}
	items := parseImunifyList(out)
	if items == nil {
		return nil, nil, "unreadable output: " + trimOut(out)
	}
	listed := matchImunifyItems(items, qs)
	incomplete := imunifyIncomplete(out, items)
	if incomplete == "" {
		return listed, nil, ""
	}
	skip = make([]string, len(qs))
	for i, q := range qs {
		if ctx.Err() != nil {
			skip[i] = fmt.Sprintf("local list incomplete (%s); no time left to ask --by-ip", incomplete)
			continue
		}
		l, why, _ := byIP(q)
		if why != "" {
			skip[i] = fmt.Sprintf("local list incomplete (%s); --by-ip: %s", incomplete, why)
			continue
		}
		seen := map[Location]bool{}
		for _, loc := range listed[i] {
			seen[loc] = true
		}
		for _, loc := range l {
			if !seen[loc] {
				listed[i] = append(listed[i], loc)
			}
		}
	}
	return listed, skip, ""
}

// imunifyArray is the list's entries: the "items" array (any key case) or a
// bare top-level array, and total, the number of entries the list says it
// holds (its "max_count"), or -1. ok is false for output that isn't JSON, or
// an object without an "items" array — read as an empty list, it would say
// that nothing is listed.
func imunifyArray(raw []byte) (arr []any, total int64, ok bool) {
	var root any
	if err := json.Unmarshal(raw, &root); err != nil {
		return nil, -1, false
	}
	switch v := root.(type) {
	case []any:
		return v, -1, true
	case map[string]any:
		total = -1
		for k, val := range v {
			switch {
			case strings.EqualFold(k, "items"):
				arr, ok = val.([]any)
			case strings.EqualFold(k, "max_count"):
				if n, isNum := val.(float64); isNum && n >= 0 && n < 1<<53 {
					total = int64(n)
				}
			}
		}
		return arr, total, ok
	}
	return nil, -1, false
}

// imunifyIncomplete says why a list read may be missing entries, or "": it
// reached the read's cap, it says it holds more entries than it returned
// (max_count), or some of its entries couldn't be read (no address or no
// purpose). An entry missed any of those ways would read as not listed. A
// country entry has no address and is no such miss: it isn't an IP entry.
func imunifyIncomplete(raw []byte, items []imunifyItem) string {
	arr, total, _ := imunifyArray(raw)
	var why []string
	if len(arr) >= imunifyListCap {
		why = append(why, fmt.Sprintf("it reached the read's cap of %d entries", imunifyListCap))
	} else if total > int64(len(arr)) {
		why = append(why, fmt.Sprintf("it holds %d entries, %d returned", total, len(arr)))
	}
	bad := len(arr) - len(items) - imunifyCountryEntries(arr)
	for _, it := range items {
		if it.Purpose == "" {
			bad++
		}
	}
	if bad > 0 {
		why = append(why, fmt.Sprintf("%d of its entries unreadable", bad))
	}
	return strings.Join(why, "; ")
}

// imunifyCountryEntries counts the entries that block or allow a country
// (imunify's "ip-list local … --by-type country"): no address, and a
// country or a type of "country".
func imunifyCountryEntries(arr []any) int {
	n := 0
	for _, e := range arr {
		m, ok := e.(map[string]any)
		if !ok {
			continue
		}
		var addr, country bool
		for k, v := range m {
			switch strings.ToLower(k) {
			case "ip", "network_address":
				addr = addr || (v != nil && v != "")
			case "country":
				country = country || (v != nil && v != "")
			case "type":
				t, _ := v.(string)
				country = country || strings.EqualFold(t, "country")
			}
		}
		if !addr && country {
			n++
		}
	}
	return n
}

// ImunifyEntry is one entry of imunify360's local IP list.
type ImunifyEntry struct {
	Entry   string // an address or a CIDR (imunifyEntryString)
	Purpose string // lowercased: white, drop, captcha, splashscreen, …
	Comment string
}

// ImunifyLocalList reads imunify360's local IP list once, up to
// imunifyListCap entries. incomplete, when not "", says why the list read may
// be missing entries (imunifyIncomplete).
//
// It parses stdout alone: a warning on stderr would make the whole list
// unreadable, and every unblock would delete blindly.
func ImunifyLocalList(ctx context.Context) (entries []ImunifyEntry, incomplete string, err error) {
	out, errOut, err := runStdout(ctx, "imunify360-agent", "ip-list", "local", "list", "--limit", strconv.Itoa(imunifyListCap), "--json")
	if err != nil {
		return nil, "", fmt.Errorf("%v: %s", err, trimOut(append(errOut, out...)))
	}
	items := parseImunifyList(out)
	if items == nil {
		return nil, "", fmt.Errorf("unreadable output: %s", trimOut(append(errOut, out...)))
	}
	for _, it := range items {
		entries = append(entries, ImunifyEntry{Entry: imunifyEntryString(it.IP, it.Netmask), Purpose: it.Purpose, Comment: it.Comment})
	}
	return entries, imunifyIncomplete(out, items), nil
}

// imunifyEntryString renders a list entry as an address or a CIDR. imunify
// writes a network as "addr/len" in ip (IPv6 only as a /64) and reports
// netmask as the mask itself — 4294967295 for one IPv4 address — not as its
// length; a netmask up to the family's width (32 or 128) is taken as a
// length. It was always taken as a length, so a single-address IPv4 entry read
// as "addr/4294967295", which parses as nothing: those entries were never
// found (network entries, written "addr/len", were).
func imunifyEntryString(ip string, netmask int64) string {
	ip = strings.TrimSpace(ip)
	if ip == "" || strings.Contains(ip, "/") {
		return ip
	}
	a := net.ParseIP(ip)
	if a == nil {
		return ip
	}
	full := int64(128)
	if a.To4() != nil {
		full = 32
	}
	plen := netmask
	if full == 32 && netmask > 32 && netmask <= math.MaxUint32 {
		m := uint32(netmask)
		plen = int64(bits.OnesCount32(m))
		if m != ^uint32(0)<<(32-plen) {
			return ip // not a mask: the address alone
		}
	}
	if plen < 1 || plen >= full {
		return ip // the address alone, or not a mask of its family
	}
	return fmt.Sprintf("%s/%d", ip, plen)
}

// imunifyItem is the part of an ip-list entry we care about, after
// key normalization.
type imunifyItem struct {
	IP         string
	Netmask    int64
	Purpose    string
	Comment    string
	Expiration int64
}

// parseImunifyList accepts either {"items": [...]} or a bare top-level
// array, with item keys in any case (docs show uppercase, agents emit
// lowercase).
func parseImunifyList(raw []byte) []imunifyItem {
	arr, _, ok := imunifyArray(raw)
	if !ok {
		return nil
	}
	items := make([]imunifyItem, 0, len(arr))
	for _, e := range arr {
		raw, ok := e.(map[string]any)
		if !ok {
			continue
		}
		// Normalize keys once: docs show uppercase, agents emit lowercase.
		m := make(map[string]any, len(raw))
		for k, v := range raw {
			m[strings.ToLower(k)] = v
		}
		str := func(key string) string {
			if s, ok := m[key].(string); ok {
				return s
			}
			return ""
		}
		num := func(key string) int64 {
			switch n := m[key].(type) {
			case float64:
				if n > 1<<62 || n < -(1<<62) {
					return -1 // an IPv6 netmask: past int64, and never needed
				}
				return int64(n)
			case string:
				if v, err := strconv.ParseInt(n, 10, 64); err == nil {
					return v
				}
			}
			return 0
		}
		it := imunifyItem{
			IP:         str("ip"),
			Netmask:    num("netmask"),
			Purpose:    strings.ToLower(str("purpose")),
			Comment:    str("comment"),
			Expiration: num("expiration"),
		}
		if it.IP == "" {
			// network_address is the address as a number (IPv4) in the
			// documented shape; some outputs give it as a string.
			switch n := m["network_address"].(type) {
			case string:
				it.IP = n
			case float64:
				if n >= 0 && n <= math.MaxUint32 && n == math.Trunc(n) {
					v := uint32(n)
					it.IP = net.IPv4(byte(v>>24), byte(v>>16), byte(v>>8), byte(v)).String()
				}
			}
		}
		if it.IP != "" {
			items = append(items, it)
		}
	}
	return items
}

func matchImunifyItems(items []imunifyItem, qs []*query) [][]Location {
	idx := ipquery.NewIndex[Location]()
	for _, it := range items {
		entry := imunifyEntryString(it.IP, it.Netmask)
		action := ActionMatch
		list := it.Purpose
		switch it.Purpose {
		case "white":
			action = ActionAllow
		case "drop":
			action = ActionBlock
			list = "drop (BLACK)"
		case "captcha", "splashscreen":
			action = ActionChallenge
			list = it.Purpose + " (GRAY)"
		}
		reason := it.Comment
		if it.Expiration > 0 {
			exp := "expires " + time.Unix(it.Expiration, 0).UTC().Format("2006-01-02 15:04 UTC")
			if reason != "" {
				reason += " (" + exp + ")"
			} else {
				reason = exp
			}
		}
		idx.Add(entry, Location{
			Source: "imunify360", List: list, Action: action,
			Match: entry, Reason: reason,
		})
	}
	return matchAll(idx, qs)
}

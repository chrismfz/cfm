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
	if imunifyListLen(out) < imunifyListCap {
		return listed, nil, ""
	}
	skip = make([]string, len(qs))
	for i, q := range qs {
		if ctx.Err() != nil {
			skip[i] = fmt.Sprintf("local list has %d+ entries; no time left to ask --by-ip", imunifyListCap)
			continue
		}
		l, why, _ := byIP(q)
		if why != "" {
			skip[i] = fmt.Sprintf("local list has %d+ entries; --by-ip: %s", imunifyListCap, why)
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
// bare top-level array. ok is false for output that isn't JSON.
func imunifyArray(raw []byte) (arr []any, ok bool) {
	var root any
	if err := json.Unmarshal(raw, &root); err != nil {
		return nil, false
	}
	switch v := root.(type) {
	case []any:
		arr = v
	case map[string]any:
		for k, val := range v {
			if strings.EqualFold(k, "items") {
				arr, _ = val.([]any)
				break
			}
		}
	}
	return arr, true
}

// imunifyListLen counts the list's entries, usable or not — what the cap
// applies to.
func imunifyListLen(raw []byte) int {
	arr, _ := imunifyArray(raw)
	return len(arr)
}

// ImunifyEntry is one entry of imunify360's local IP list.
type ImunifyEntry struct {
	IP      string // as listed; may carry "/len"
	Netmask int    // 0 when not given
	Purpose string // lowercased: white, drop, captcha, splashscreen, …
}

// ImunifyLocalList reads imunify360's local IP list once, up to
// imunifyListCap entries; capped reports a list that reached the cap, which
// may be missing entries.
func ImunifyLocalList(ctx context.Context) (entries []ImunifyEntry, capped bool, err error) {
	out, err := runOut(ctx, "imunify360-agent", "ip-list", "local", "list", "--limit", strconv.Itoa(imunifyListCap), "--json")
	if err != nil {
		return nil, false, fmt.Errorf("%v: %s", err, trimOut(out))
	}
	items := parseImunifyList(out)
	if items == nil {
		return nil, false, fmt.Errorf("unreadable output: %s", trimOut(out))
	}
	for _, it := range items {
		entries = append(entries, ImunifyEntry{IP: it.IP, Netmask: it.Netmask, Purpose: it.Purpose})
	}
	return entries, imunifyListLen(out) >= imunifyListCap, nil
}

// imunifyItem is the part of an ip-list entry we care about, after
// key normalization.
type imunifyItem struct {
	IP         string
	Netmask    int
	Purpose    string
	Comment    string
	Expiration int64
}

// parseImunifyList accepts either {"items": [...]} or a bare top-level
// array, with item keys in any case (docs show uppercase, agents emit
// lowercase).
func parseImunifyList(raw []byte) []imunifyItem {
	arr, ok := imunifyArray(raw)
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
			Netmask:    int(num("netmask")),
			Purpose:    strings.ToLower(str("purpose")),
			Comment:    str("comment"),
			Expiration: num("expiration"),
		}
		if it.IP == "" {
			it.IP = str("network_address")
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
		entry := it.IP
		if it.Netmask > 0 && !strings.Contains(entry, "/") {
			entry = fmt.Sprintf("%s/%d", entry, it.Netmask)
		}
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

// internal/locate/imunify.go
//
// imunify360 probe. Uses the documented read-only query
//
//	imunify360-agent ip-list local list --by-ip <arg> --json
//
// (--by-ip accepts an IP or a subnet in CIDR notation). Purposes map to
// actions: white=ALLOW, drop=BLOCK (BLACK bucket), captcha/splashscreen=
// CHALLENGE (GRAY bucket). Because --by-ip's containment semantics for
// subnet *entries* aren't guaranteed across versions, a miss falls back
// to listing the local list and matching containment ourselves.
package locate

import (
	"context"
	"encoding/json"
	"fmt"
	"strconv"
	"strings"
	"time"
)

func imunifyUnitActive() bool {
	return unitActive("imunify360") || unitActive("imunify360-agent") ||
		unitActive("imunify360.service") || unitActive("imunify360-agent.service")
}

// searchImunify returns (locations, "") on success or (nil, why) when
// imunify isn't available.
func searchImunify(ctx context.Context, q *query) ([]Location, string) {
	if !binaryExists("imunify360-agent") {
		return nil, "not installed"
	}
	if !imunifyUnitActive() {
		return nil, "service not active"
	}

	out, err := runOut(ctx, "imunify360-agent", "ip-list", "local", "list", "--by-ip", q.raw, "--json")
	if err != nil {
		return nil, "query failed: " + trimOut(out)
	}
	locs := matchImunifyItems(parseImunifyList(out), q)
	if len(locs) > 0 {
		return locs, ""
	}

	// Miss: a plain-IP query might still be covered by a subnet entry
	// --by-ip didn't surface. Pull the list (bounded) and match locally.
	// NOTE: entries beyond the 10k cap are not examined — on lists that
	// large a covering subnet entry past the cap would be missed. The cap
	// keeps the miss-path cost bounded; raise it if real lists approach it.
	if q.ip != nil {
		out, err = runOut(ctx, "imunify360-agent", "ip-list", "local", "list", "--limit", "10000", "--json")
		if err == nil {
			locs = matchImunifyItems(parseImunifyList(out), q)
		}
	}
	return locs, ""
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
	var root any
	if err := json.Unmarshal(raw, &root); err != nil {
		return nil
	}
	var arr []any
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

func matchImunifyItems(items []imunifyItem, q *query) []Location {
	var out []Location
	for _, it := range items {
		entry := it.IP
		if it.Netmask > 0 && !strings.Contains(entry, "/") {
			entry = fmt.Sprintf("%s/%d", entry, it.Netmask)
		}
		if !q.matchesEntry(entry) {
			continue
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
		out = append(out, Location{
			Source: "imunify360", List: list, Action: action,
			Match: entry, Reason: reason,
		})
	}
	return out
}

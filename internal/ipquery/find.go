// internal/ipquery/find.go
package ipquery

import (
	"bytes"
	enrichpkg "cfm/internal/enrich"
	"cfm/internal/firewall"
	"encoding/json"
	"fmt"
	"net"
	"os"
	"path/filepath"
	"strings"
)

type Hit struct {
	Set    string `json:"set"`
	Action string `json:"action"` // ALLOW/BLOCK
	Scope  string `json:"scope"`  // host/cidr
	Match  string `json:"match"`  // ip ή prefix
	Feed   string `json:"feed,omitempty"`
	Family string `json:"family"` // v4/v6
	Via    string `json:"via"`    // "host" ή "cidr"
}

type setDesc struct{ name, family, kind, action, feed string }

func classifyActionFromName(name string) string {
	if strings.HasPrefix(name, "allow_") {
		return "ALLOW"
	}
	if strings.HasPrefix(name, "block_") {
		return "BLOCK"
	}
	return "MATCH"
}

// Find τρέχει δυναμικά nft list table/set και επιστρέφει τα hits για IP ή CIDR.
func Find(be firewall.Backend, arg string) ([]Hit, error) {
	var nip net.IP
	var nnet *net.IPNet
	isCIDR := false

	if strings.Contains(arg, "/") {
		var err error
		nip, nnet, err = net.ParseCIDR(arg)
		if err != nil {
			return nil, fmt.Errorf("invalid CIDR")
		}
		isCIDR = true
	} else {
		nip = net.ParseIP(arg)
		if nip == nil {
			return nil, fmt.Errorf("invalid IP")
		}
	}

	tblOut, err := be.ListTableJSON("inet", "cfm")
	if err != nil {
		return nil, fmt.Errorf("cannot read nftables table inet cfm (maybe needs sudo?): %v\n%s", err, string(tblOut))
	}
	setNames := extractCfmSets(tblOut, nip)
	if len(setNames) == 0 {
		return []Hit{}, nil
	}

	var hits []Hit
	for _, s := range setNames {
		so, err := be.ListSetJSON("inet", "cfm", s.name)
		if err != nil {
			continue
		}
		var h []Hit
		if isCIDR {
			h = querySetForCIDR(so, nnet, s)
		} else {
			h = querySetForIP(so, nip, s)
		}
		hits = append(hits, h...)
	}
	return hits, nil
}

func extractCfmSets(tableJSON []byte, ip net.IP) []setDesc {
	var doc struct {
		Nftables []struct {
			Set *struct {
				Name  string   `json:"name"`
				Type  string   `json:"type"`
				Flags []string `json:"flags"`
			} `json:"set,omitempty"`
		} `json:"nftables"`
	}
	_ = json.Unmarshal(tableJSON, &doc)
	fam := "v4"
	if ip.To4() == nil {
		fam = "v6"
	}
	var out []setDesc
	for _, n := range doc.Nftables {
		if n.Set == nil {
			continue
		}
		t := n.Set.Type
		if fam == "v4" && t != "ipv4_addr" {
			continue
		}
		if fam == "v6" && t != "ipv6_addr" {
			continue
		}
		sd := classifySetName(n.Set.Name)
		if sd.name == "" || sd.family != fam {
			continue
		}
		out = append(out, sd)
	}
	return out
}

func classifySetName(name string) setDesc {
	// --- manual hosts ---
	if name == "allow_v4" {
		return setDesc{name: name, family: "v4", kind: "manual", action: "ALLOW"}
	}
	if name == "allow_v6" {
		return setDesc{name: name, family: "v6", kind: "manual", action: "ALLOW"}
	}
	if name == "block_v4" {
		return setDesc{name: name, family: "v4", kind: "manual", action: "BLOCK"}
	}
	if name == "block_v6" {
		return setDesc{name: name, family: "v6", kind: "manual", action: "BLOCK"}
	}

	// --- manual nets ---
	if name == "allow_v4_nets" {
		return setDesc{name: name, family: "v4", kind: "manual", action: "ALLOW"}
	}
	if name == "allow_v6_nets" {
		return setDesc{name: name, family: "v6", kind: "manual", action: "ALLOW"}
	}
	if name == "block_v4_nets" {
		return setDesc{name: name, family: "v4", kind: "manual", action: "BLOCK"}
	}
	if name == "block_v6_nets" {
		return setDesc{name: name, family: "v6", kind: "manual", action: "BLOCK"}
	}

	// --- dynamic hosts ---
	if name == "allow_dyn_v4" {
		return setDesc{name: name, family: "v4", kind: "hosts", action: "ALLOW"}
	}
	if name == "allow_dyn_v6" {
		return setDesc{name: name, family: "v6", kind: "hosts", action: "ALLOW"}
	}

	// --- generic cfm sets (ignore/self/debug/throttle/etc.) ---
	if strings.HasSuffix(name, "_v4") {
		return setDesc{name: name, family: "v4", kind: "hosts", action: classifyActionFromName(name)}
	}
	if strings.HasSuffix(name, "_v6") {
		return setDesc{name: name, family: "v6", kind: "hosts", action: classifyActionFromName(name)}
	}
	if strings.HasSuffix(name, "_v4_nets") {
		return setDesc{name: name, family: "v4", kind: "nets", action: classifyActionFromName(name)}
	}
	if strings.HasSuffix(name, "_v6_nets") {
		return setDesc{name: name, family: "v6", kind: "nets", action: classifyActionFromName(name)}
	}

	// --- external feeds (hosts or nets) ---
	parts := strings.Split(name, "_")
	if (len(parts) == 4 || len(parts) >= 5) &&
		(parts[0] == "allow" || parts[0] == "block") &&
		parts[1] == "ext" &&
		(parts[2] == "v4" || parts[2] == "v6") &&
		(parts[3] == "hosts" || parts[3] == "nets") {
		feed := ""
		if len(parts) >= 5 {
			feed = strings.Join(parts[4:], "_")
		}
		return setDesc{
			name:   name,
			family: parts[2],
			kind:   parts[3],
			action: strings.ToUpper(parts[0]),
			feed:   feed,
		}
	}

	// unknown set
	return setDesc{}
}

func netsOverlap(a, b *net.IPNet) bool {
	if (a.IP.To4() != nil) != (b.IP.To4() != nil) {
		return false
	}
	return a.Contains(b.IP) || b.Contains(a.IP)
}

func querySetForCIDR(so []byte, q *net.IPNet, s setDesc) []Hit {
	var hits []Hit
	var payload struct {
		Nftables []struct {
			Set *struct {
				Elem []interface{} `json:"elem"`
			} `json:"set,omitempty"`
		} `json:"nftables"`
	}
	if err := json.Unmarshal(so, &payload); err != nil {
		return hits
	}
	for _, top := range payload.Nftables {
		if top.Set == nil {
			continue
		}
		for _, raw := range top.Set.Elem {
			switch v := raw.(type) {
			case string:
				if hip := net.ParseIP(v); hip != nil && q.Contains(hip) {
					hits = append(hits, Hit{Set: s.name, Action: s.action, Scope: "host", Match: hip.String(), Feed: s.feed, Family: s.family, Via: "host"})
				}
			case map[string]interface{}:
				if p, ok := v["prefix"].(map[string]interface{}); ok {
					addr, _ := p["addr"].(string)
					lf, _ := p["len"].(float64)
					if addr == "" || lf == 0 {
						continue
					}
					plen := int(lf)
					if ip := net.ParseIP(addr); ip != nil {
						_, enet, err := net.ParseCIDR(fmt.Sprintf("%s/%d", ip.String(), plen))
						if err == nil && netsOverlap(q, enet) {
							hits = append(hits, Hit{
								Set: s.name, Action: s.action, Scope: "cidr",
								Match: fmt.Sprintf("%s/%d", ip.String(), plen),
								Feed:  s.feed, Family: s.family, Via: "cidr",
							})
						}
					}
				}
			}
		}
	}
	return hits
}

func ipLE(a, b net.IP) bool {
	a16 := a.To16()
	b16 := b.To16()
	if a16 == nil || b16 == nil {
		return false
	}
	return bytes.Compare(a16, b16) <= 0
}

func ipInRange(ip, from, to net.IP) bool {
	ip16 := ip.To16()
	if ip16 == nil {
		return false
	}
	return ipLE(from, ip16) && ipLE(ip16, to)
}

func querySetForIP(raw []byte, ip net.IP, sd setDesc) []Hit {
	var root map[string]any
	if err := json.Unmarshal(raw, &root); err != nil {
		return nil
	}
	arr, _ := root["nftables"].([]any)
	if arr == nil {
		return nil
	}
	mk := func(via, match string) Hit {
		return Hit{Set: sd.name, Action: sd.action, Scope: via, Match: match, Feed: sd.feed, Family: sd.family, Via: via}
	}
	var hits []Hit
	for _, it := range arr {
		m, _ := it.(map[string]any)
		setObj, ok := m["set"].(map[string]any)
		if !ok {
			continue
		}
		elems, _ := setObj["elem"].([]any)
		if len(elems) == 0 {
			elems, _ = setObj["elements"].([]any)
		}
		for _, e := range elems {
			switch v := e.(type) {
			case string:
				if parsed := net.ParseIP(v); parsed != nil && ip.Equal(parsed) {
					hits = append(hits, mk("host", ip.String()))
				}
			case map[string]any:
				if s, ok := v["elem"].(string); ok {
					if parsed := net.ParseIP(s); parsed != nil && ip.Equal(parsed) {
						hits = append(hits, mk("host", ip.String()))
						continue
					}
				}
				if inner, ok := v["elem"].(map[string]any); ok {
					if s, ok := inner["val"].(string); ok {
						if parsed := net.ParseIP(s); parsed != nil && ip.Equal(parsed) {
							hits = append(hits, mk("host", ip.String()))
							continue
						}
					}
					if pfx, ok := inner["prefix"].(map[string]any); ok {
						addr, _ := pfx["addr"].(string)
						l64, _ := pfx["len"].(float64)
						if addr != "" && l64 > 0 {
							cidr := fmt.Sprintf("%s/%d", addr, int(l64))
							if _, n, err := net.ParseCIDR(cidr); err == nil && n.Contains(ip) {
								hits = append(hits, mk("cidr", cidr))
							}
						}
					}
					if iv, ok := inner["interval"].(map[string]any); ok {
						fromStr, _ := iv["from"].(string)
						toStr, _ := iv["to"].(string)
						if fromStr != "" && toStr != "" {
							from := net.ParseIP(fromStr)
							to := net.ParseIP(toStr)
							if from != nil && to != nil && ipInRange(ip, from, to) {
								hits = append(hits, mk("cidr", fmt.Sprintf("%s-%s", fromStr, toStr)))
							}
						}
					}
				}
				if pfx, ok := v["prefix"].(map[string]any); ok {
					addr, _ := pfx["addr"].(string)
					l64, _ := pfx["len"].(float64)
					if addr != "" && l64 > 0 {
						cidr := fmt.Sprintf("%s/%d", addr, int(l64))
						if _, n, err := net.ParseCIDR(cidr); err == nil && n.Contains(ip) {
							hits = append(hits, mk("cidr", cidr))
						}
					}
					continue
				}
				if iv, ok := v["interval"].(map[string]any); ok {
					fromStr, _ := iv["from"].(string)
					toStr, _ := iv["to"].(string)
					if fromStr != "" && toStr != "" {
						from := net.ParseIP(fromStr)
						to := net.ParseIP(toStr)
						if from != nil && to != nil && ipInRange(ip, from, to) {
							hits = append(hits, mk("cidr", fmt.Sprintf("%s-%s", fromStr, toStr)))
						}
					}
					continue
				}
			}
		}
	}
	return hits
}

func preferExisting(paths ...string) []string {
	seen := map[string]struct{}{}
	var out []string
	for _, p := range paths {
		if p == "" {
			continue
		}
		abs := p
		if !filepath.IsAbs(abs) {
			if a, err := filepath.Abs(abs); err == nil {
				abs = a
			}
		}
		if _, ok := seen[abs]; ok {
			continue
		}
		seen[abs] = struct{}{}
		if fi, err := os.Stat(abs); err == nil && fi.IsDir() {
			out = append(out, abs)
		}
	}
	if len(out) == 0 {
		return paths
	}
	return out
}

// EnrichSuffix: προσπαθεί cfgDir (π.χ. ./configs), μετά /etc/cfm, /usr/share/GeoIP, /var/lib/GeoIP, ΚΑΙ /usr/share/cfm.
func EnrichSuffix(cfgDir, ipStr string) string {
	ip := net.ParseIP(ipStr)
	if ip == nil {
		return ""
	}

	paths := preferExisting(cfgDir, "/etc/cfm", "/var/lib/cfm/maxmind")
	enr, err := enrichpkg.New(paths...)
	if err != nil || enr == nil {
		return ""
	}
	defer enr.Close()

	info := enr.Lookup(ip.String())

	var parts []string
	if s := strings.TrimSpace(info.PTR); s != "" {
		parts = append(parts, s)
	}
	if info.ASN > 0 || strings.TrimSpace(info.ASNName) != "" {
		if info.ASN > 0 && strings.TrimSpace(info.ASNName) != "" {
			parts = append(parts, fmt.Sprintf("AS%d %s", info.ASN, strings.TrimSpace(info.ASNName)))
		} else if info.ASN > 0 {
			parts = append(parts, fmt.Sprintf("AS%d", info.ASN))
		} else {
			parts = append(parts, strings.TrimSpace(info.ASNName))
		}
	}
	loc := strings.TrimSpace(strings.Trim(strings.Join([]string{strings.TrimSpace(info.City), strings.TrimSpace(info.Country)}, ", "), ", "))
	if loc != "" {
		parts = append(parts, loc)
	}
	if len(parts) == 0 {
		return ""
	}
	return " — " + strings.Join(parts, " | ")
}

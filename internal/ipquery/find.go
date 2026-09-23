// internal/ipquery/find.go
package ipquery

import (
	"context"
	enrichpkg "cfm/internal/enrich"
	"cfm/internal/firewall"
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

// Find returns the cfm sets that hold an IP, or that overlap a CIDR. It is
// FindMany for one argument.
func Find(be firewall.Backend, arg string) ([]Hit, error) {
	res, err := FindMany(context.Background(), be, []string{arg})
	if err != nil {
		return nil, err
	}
	return res[arg], nil
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

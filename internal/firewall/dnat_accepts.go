package firewall

import (
	"strconv"
	"strings"
)

// Shared helpers for the scoped DNAT-accept machinery, kept in one place so the
// nft backend (rule placement) and the dnat CLI (status reporting) match the
// same source of truth. Duplicating either of these across packages has bitten
// us before: a drifted default-drop matcher is exactly how scoped accepts ended
// up appended after the drop.

// DNATDefaultFamily and DNATDefaultTable name CFM's web DNAT table, the one
// `cfm dnat on` installs. Both backends default an empty family/table to these
// and internal/dnat uses them, so there is one definition. The nftlib backend
// used to default to "cfm" (the filter table), which made its
// EnsureDNATAccepts look for the redirect rules in the wrong table and never
// reassert the web DNAT accepts after a ports-policy rewrite.
const (
	DNATDefaultFamily = "inet"
	DNATDefaultTable  = "cfm_redirect"
)

// Comment tags on the web DNAT accepts: the nft backend writes
// cfm_dnat_accept:<label>:<from>:<to>, nftlib cfm_edge_dnat_accept:…. Each
// backend's cleanup removes both, so accepts the other engine wrote (before a
// node switched engines, or from a CLI that ran the other one) don't linger.
// The dnat CLI's status report reads both.
const (
	WebDNATAcceptTagNFT    = "cfm_dnat_accept"
	WebDNATAcceptTagNFTLib = "cfm_edge_dnat_accept"
)

// IsInputDefaultDropLine reports whether a rendered `inet cfm input` chain line
// is the catch-all NEW-state default drop that ApplyPortsPolicy installs
// (`ct state new tcp|udp dport 0-65535 drop`). Scoped DNAT accepts must sit
// BEFORE this line to be effective, since nftables is first-match-wins within a
// chain. The checks are order-independent so they survive nft's canonical
// re-ordering of the rendered rule.
func IsInputDefaultDropLine(line string) bool {
	norm := strings.ReplaceAll(line, `"`, "")
	if !strings.Contains(norm, "ct state new") || !strings.Contains(norm, "dport 0-65535") || !strings.Contains(norm, " drop") {
		return false
	}
	return strings.Contains(norm, "tcp dport 0-65535") || strings.Contains(norm, "udp dport 0-65535")
}

// ParseDNATListenerPorts extracts the post-DNAT http/https listener ports from a
// `cfm_redirect` table dump — the unconditional
//
//	tcp dport 80  dnat to :9080
//	tcp dport 443 dnat to :9043
//	udp dport 443 dnat to :9043
//
// listener rules. It returns ok=false when either mapping is missing. Shared by
// the nft backend's accept re-assertion (EnsureDNATAccepts) and the dnat CLI
// status report so both resolve the scoped accepts against the ports actually
// installed rather than a CLI/env default.
func ParseDNATListenerPorts(dump string) (httpPort, httpsPort int, ok bool) {
	for _, line := range strings.Split(dump, "\n") {
		norm := strings.TrimSpace(strings.ReplaceAll(line, `"`, ""))
		if !strings.Contains(norm, "dnat to ") {
			continue
		}
		fields := strings.Fields(norm)
		// expected forms: "tcp dport 80 dnat to :9080", "udp dport 443 dnat to :9043"
		if len(fields) < 6 || fields[1] != "dport" {
			continue
		}
		from, err := strconv.Atoi(fields[2])
		if err != nil {
			continue
		}
		var target string
		for i := 3; i+1 < len(fields); i++ {
			if fields[i] == "to" {
				target = fields[i+1]
				break
			}
		}
		if target == "" {
			continue
		}
		// drop any leading host (":9080", "127.0.0.1:9080")
		if idx := strings.LastIndex(target, ":"); idx >= 0 {
			target = target[idx+1:]
		}
		to, err := strconv.Atoi(target)
		if err != nil || to <= 0 || to > 65535 {
			continue
		}
		switch from {
		case 80:
			if fields[0] == "tcp" {
				httpPort = to
			}
		case 443:
			// tcp+udp target the same https listener; either wins.
			if fields[0] == "tcp" || fields[0] == "udp" {
				httpsPort = to
			}
		}
	}
	return httpPort, httpsPort, httpPort > 0 && httpsPort > 0
}

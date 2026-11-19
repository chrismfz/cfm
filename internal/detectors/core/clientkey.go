package core

import (
	"strings"

	"cfm/internal/firewall"
)

// ClientKey is the counter key of a per-client kind ("…|ip"): an IPv6
// client counts as its /64 (firewall.CountKey; docs/edge-ipv6.md "IPv6 /64
// grouping"), so a client rotating its address inside the /64 fills one
// window instead of a fresh one per address; a /64 a guard keeps from being
// banned as a whole counts per address, as its ban is. Any other kind keeps
// key.
//
// Only the COUNT is grouped: the alert still carries a real address
// (Extra["ip"]), which the sink's allow / ignore / self checks read and
// which firewall.ExtendClientBlock widens to the /64 itself.
func ClientKey(kindKey, key string) string {
	if strings.HasSuffix(kindKey, "|ip") {
		return firewall.CountKey(key)
	}
	return key
}

// TagClient records the /64 an IPv6 address was counted as (Extra
// "client"), for the alert's reader; IPv4, ungrouped and guarded addresses
// add nothing.
func TagClient(extra map[string]string, ip string) {
	if c := firewall.CountKey(ip); strings.Contains(c, "/") && extra != nil {
		extra["client"] = c
	}
}

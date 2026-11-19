package core

import (
	"strings"

	"cfm/internal/ipkey"
)

// ClientKey is the counter key of a per-client kind ("…|ip"): an IPv6
// client counts as its /64 (ipkey.Client; docs/edge-ipv6.md "IPv6 /64
// grouping"), so a client rotating its address inside the /64 fills one
// window instead of a fresh one per address. Any other kind keeps key.
//
// Only the COUNT is grouped: the alert still carries a real address
// (Extra["ip"], the one seen last), which the sink's allow / ignore / self
// checks read and which firewall.ExtendClientBlock widens to the /64 itself.
func ClientKey(kindKey, key string) string {
	if strings.HasSuffix(kindKey, "|ip") {
		return ipkey.Client(key)
	}
	return key
}

// TagClient records the /64 an IPv6 address was counted as (Extra
// "client"), for the alert's reader; IPv4 and ungrouped addresses add
// nothing.
func TagClient(extra map[string]string, ip string) {
	if c := ipkey.Client(ip); strings.Contains(c, "/") && extra != nil {
		extra["client"] = c
	}
}

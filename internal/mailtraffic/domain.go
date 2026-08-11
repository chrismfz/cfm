package mailtraffic

import (
	"strings"

	"cfm/internal/mailmeter"
)

// domainOf returns the lowercased domain part of a mailbox address, used to key
// rows for scope filtering. An address with no usable domain (the host-wide "*"
// sentinel, or a local unix-user submitter such as "evafeiadis") maps to the
// host-wide sentinel, which is never in a scoped caller's vhost allowlist — so
// those rows are admin-only by construction.
func domainOf(addr string) string {
	if i := strings.LastIndexByte(addr, '@'); i > 0 && i < len(addr)-1 {
		return strings.ToLower(addr[i+1:])
	}
	return mailmeter.HostWide
}

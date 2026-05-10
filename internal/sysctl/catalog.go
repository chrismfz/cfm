package sysctl

import "cfm/internal/managedsysctl"

// managedKeys is the static set of dotted-form sysctl keys that
// internal/sysctl/sys_tweaks.go owns. Mirrors the persistent-file
// `keys` slice in persistSysctlFile() — every key sys_tweaks may
// write at runtime appears here.
//
// Compile-time-stable: the set must not depend on cfm.conf; what
// VALUES sys_tweaks writes can be config-driven (rp_filter strict
// vs loose, conntrack timeouts, etc.) but the set of keys it claims
// ownership of must not change at runtime so kernsec.Resolve can
// trust the cross-component ownership view.
var managedKeys = []string{
	"net.ipv4.tcp_syncookies",
	"net.ipv4.tcp_syn_retries",
	"net.ipv4.tcp_synack_retries",
	"net.ipv4.tcp_fin_timeout",
	"net.netfilter.nf_conntrack_max",
	"net.netfilter.nf_conntrack_tcp_timeout_time_wait",
	"net.netfilter.nf_conntrack_tcp_timeout_fin_wait",
	"net.netfilter.nf_conntrack_tcp_timeout_close_wait",
	"net.netfilter.nf_conntrack_tcp_loose",
	"net.ipv4.conf.all.rp_filter",
	"net.ipv4.conf.all.accept_redirects",
	"net.ipv4.conf.all.send_redirects",
	"net.ipv4.conf.default.rp_filter",
	"net.ipv4.conf.default.accept_redirects",
	"net.ipv4.conf.default.send_redirects",
	"net.ipv4.conf.all.route_localnet",
	"net.ipv4.conf.default.route_localnet",
	"net.ipv6.conf.all.accept_redirects",
	"net.ipv6.conf.all.send_redirects",
	"net.ipv6.conf.default.accept_redirects",
	"net.ipv6.conf.default.send_redirects",
}

// ManagedKeys returns a copy of the static set of sysctl keys this
// package owns. Used by the cfm-internal managedsysctl registry so
// kernsec / cfm-firewall / etc. can mark rules whose key falls in
// this set as "externally managed" rather than fight over them.
//
// Returns a copy so callers can't mutate the package-level slice.
//
// Trade-off: ownership is unconditional — the catalog claims these
// keys even when an operator has set `SYS_TWEAKS_ENABLE=0` in
// cfm.conf and ApplyTweaks short-circuits at sys_tweaks.go:18.
// kernsec.Resolve will still resolve KSEC-SCT-net.* rules to
// ManagedExternally; the live runtime value will reflect whatever
// the kernel/distro defaults are rather than what sys_tweaks would
// have written. This is intentional — the catalog must be
// compile-time-stable so kernsec.Resolve can trust the cross-
// component view across init() ordering. Operators who want
// kernsec to take ownership of these keys instead use
// `[rule "KSEC-SCT-net.X"] state = force` per docs/kernsec.md.
func ManagedKeys() []string {
	out := make([]string, len(managedKeys))
	copy(out, managedKeys)
	return out
}

// catalog implements managedsysctl.Catalog for sys_tweaks.
type catalog struct{}

func (catalog) Owner() managedsysctl.Owner { return managedsysctl.OwnerSysTweaks }
func (catalog) Keys() []string             { return ManagedKeys() }

// init registers sys_tweaks's catalog with the package-default
// managedsysctl registry. Runs in every cfm binary invocation
// (daemon AND `cfm kernsec ...` CLI) so kernsec.Resolve can see
// what sys_tweaks owns even though sys_tweaks itself only runs in
// the daemon.
func init() {
	managedsysctl.RegisterCatalog(catalog{})
}

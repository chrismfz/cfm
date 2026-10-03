package firewall

import (
	"fmt"
	"strings"
)

// OutputLoopbackAccept is the first rule of `inet cfm output`, written as nft
// prints it. It exempts loopback from the TCP_OUT/UDP_OUT egress allowlist the
// way `iif "lo" accept` exempts it from TCP_IN/UDP_IN on input.
//
// Without it, a strict TCP_OUT (say 25,53,80,443) silently cuts every local
// connection: PHP → MariaDB on 127.0.0.1:3306, the edge → its origin or an app
// on a loopback port, an app → its Valkey/Postgres on a 127.x address. Traffic
// to the host's own public address leaves through lo too. TCP_OUT exists to
// limit what the host sends to the network, and lo never reaches it; isolation
// between local accounts on loopback is the hosting panel's job (uid-scoped
// rules), not this allowlist's.
//
// It does not cover traffic that a local DNAT rewrites to a non-loopback
// interface (a rootful container port publish routes out through the bridge).
const OutputLoopbackAccept = `oif "lo" accept`

// OutputLoopbackScript returns the nft script that leaves exactly one
// OutputLoopbackAccept at the head of `<family> <table> output`, given that
// chain's `nft -a list chain` listing: an insert (the head of the chain, as on
// input) when it is missing, a delete for every copy below the first. "" means
// nothing to do. The caller must not call it with an unread listing: an empty
// one reads as "missing", and on a chain that holds the rule that writes a copy.
func OutputLoopbackScript(family, table, listing string) string {
	rules := ParseChainRules(listing)
	var lines []string
	if !rules.Has(OutputLoopbackAccept) {
		lines = append(lines, fmt.Sprintf("insert rule %s %s output %s", family, table, OutputLoopbackAccept))
	}
	for _, h := range rules.DuplicateHandles(OutputLoopbackAccept) {
		lines = append(lines, fmt.Sprintf("delete rule %s %s output handle %s", family, table, h))
	}
	return strings.Join(lines, "\n")
}

// EnsureOutputLoopback keeps exactly one OutputLoopbackAccept in the output
// chain, inserted at its head when missing. read returns the chain's
// `nft -a list chain` listing; exec runs an nft script. Each engine passes its
// own.
//
// It is best-effort: a failure is logged, never returned, so the rest of the
// egress policy is still applied (an unenforced TCP_OUT would be worse than a
// missing exemption), and it is retried on the next ports apply (daemon start
// or a cfm.conf change). An unread chain is skipped rather than planned from an
// empty listing, which would read as "missing" and stack a copy on every apply.
func EnsureOutputLoopback(family, table string, read func() (string, error), exec func(string) error, logf func(string, ...any)) {
	listing, err := read()
	if err != nil {
		logf("[ports] output loopback accept: reading the output chain failed, left for the next ports apply: %v", err)
		return
	}
	script := OutputLoopbackScript(family, table, listing)
	if script == "" {
		return
	}
	if err := exec(script); err != nil {
		logf("[ports] output loopback accept: %v", err)
	}
}

//go:build linux

// internal/firewall/nft/dnat.go

package nft

import (
	"fmt"
	"os"
	"strconv"
	"strings"
	"time"

	"cfm/internal/firewall"
)

// Defaults: keep same as your script expectations.
func dnatDefaults(fam, tbl string) (string, string) {
	fam = strings.TrimSpace(fam)
	tbl = strings.TrimSpace(tbl)
	if fam == "" {
		fam = firewall.DNATDefaultFamily
	}
	if tbl == "" {
		tbl = firewall.DNATDefaultTable
	}
	return fam, tbl
}

func (b *Backend) dnatTableExists(fam, tbl string) bool {
	// Reuse existing helper that runs "nft -f -" and returns output/error.
	_, err := b.nftOut(fmt.Sprintf("list table %s %s", fam, tbl))
	return err == nil
}

func (b *Backend) DNATStatus(fam, tbl string) (bool, error) {
	fam, tbl = dnatDefaults(fam, tbl)
	return b.dnatTableExists(fam, tbl), nil
}

func (b *Backend) DNATShow(fam, tbl string) (string, error) {
	fam, tbl = dnatDefaults(fam, tbl)
	return b.nftOut(fmt.Sprintf("list table %s %s", fam, tbl))
}

func dnatScript(fam, tbl string, httpPort, httpsPort int, priority int) string {
	// 1:1 with your dnatALL.sh heredoc, plus optional bypass rules.
	//
	// Source-IP bypass: peers listed in /etc/cfm/cfm.dnat_bypass skip the
	// web DNAT redirect entirely. Inserted between the `iif "lo" accept`
	// line and the dport DNAT rules so the source-IP match short-circuits
	// before NAT translation runs. First-match-wins in nftables prerouting
	// guarantees a single hit clears the chain. See LoadDNATBypass docs
	// for the file format.
	entries, skipped, _ := firewall.LoadDNATBypass(firewall.DNATBypassWebPath)
	bypassBlock := firewall.DNATBypassChainBlock(entries, skipped, "cfm.dnat_bypass")
	return fmt.Sprintf(`table %s %s {
  chain prerouting {
    type nat hook prerouting priority %d; policy accept;

    iif "lo" accept

%s    tcp dport 80  dnat to :%d
    tcp dport 443 dnat to :%d
    udp dport 443 dnat to :%d
  }
}
`, fam, tbl, priority, bypassBlock, httpPort, httpsPort, httpsPort)
}

type dnatAcceptRuleSpec struct {
	label string
	proto string
	from  int
	to    int
}

func dnatAcceptRuleSpecs(httpPort, httpsPort int) []dnatAcceptRuleSpec {
	return []dnatAcceptRuleSpec{
		{label: "web_http_tcp", proto: "tcp", from: 80, to: httpPort},
		{label: "web_https_tcp", proto: "tcp", from: 443, to: httpsPort},
		{label: "web_https_udp", proto: "udp", from: 443, to: httpsPort},
	}
}

func dnatAcceptRuleComment(label string, from, to int) string {
	return fmt.Sprintf("%s:%s:%d:%d", firewall.WebDNATAcceptTagNFT, label, from, to)
}

// dnatAcceptRuleBody is the accept for one mapping, as written after
// `add rule inet cfm input`.
func dnatAcceptRuleBody(spec dnatAcceptRuleSpec) string {
	body := fmt.Sprintf(`%s dport %d ct state new ct status dnat ct original proto-dst %d accept comment "%s"`, spec.proto, spec.to, spec.from, dnatAcceptRuleComment(spec.label, spec.from, spec.to))
	return strings.Join(strings.Fields(body), " ")
}

// ensureScopedDNATAccepts keeps one web DNAT accept per mapping above the
// default drop (firewall.EnsureInputAccepts): one already in place is kept, a
// missing one is inserted, and only then are the others (either engine's
// tag) deleted, all in one nft batch. It used to delete every accept and
// re-insert them one nft run at a time on each reload, a window in which
// DNAT'd web connections hit the default drop.
//
// The listing is argv mode (ListChainText): nftOut feeds its argument to
// `nft -f -` (script mode), where the `-a` handle flag is a syntax error. That
// once made the listing fail silently, so FirstInputDefaultDropHandle saw an
// error string, returned "", and the accepts were APPENDED after the default
// drop (never reached) instead of inserted before it.
func (b *Backend) ensureScopedDNATAccepts(httpPort, httpsPort int, prune bool) error {
	var want []string
	for _, spec := range dnatAcceptRuleSpecs(httpPort, httpsPort) {
		if spec.to > 0 {
			want = append(want, dnatAcceptRuleBody(spec))
		}
	}
	_, err := firewall.EnsureInputAccepts(b.inputAcceptOps(), want, firewall.IsWebDNATAccept, prune)
	return err
}

func (b *Backend) cleanupScopedDNATAccepts() error {
	// argv-mode listing (see ensureScopedDNATAccepts): a script-mode `-a` list
	// errors out, which would leave stale accepts undeleted and duplicated.
	out, err := b.ListChainText(family, tableName, "input")
	if err != nil {
		return nil
	}
	for _, line := range strings.Split(out, "\n") {
		// Both engines' tags (the same matcher EnsureInputAccepts uses): an
		// nftlib-written accept left behind after an engine switch would
		// otherwise stay forever.
		if !firewall.IsWebDNATAccept(line) {
			continue
		}
		if h := firewall.RuleHandle(line); h != "" {
			if err := b.nftCmd("delete rule inet cfm input handle " + h); err != nil {
				return err
			}
		}
	}
	return nil
}

func (b *Backend) DNATOn(fam, tbl string, httpPort, httpsPort int) (err error) {
	start := time.Now()
	b.logPhase("DNATOn", "start", 0, nil, fmt.Sprintf("op=dnat http_port=%d https_port=%d", httpPort, httpsPort))
	defer func() {
		st := "ok"
		if err != nil {
			st = "fail"
		}
		b.logPhase("DNATOn", st, time.Since(start), err, fmt.Sprintf("op=dnat http_port=%d https_port=%d", httpPort, httpsPort))
	}()
	fam, tbl = dnatDefaults(fam, tbl)

	if httpPort <= 0 || httpsPort <= 0 {
		return fmt.Errorf("invalid ports: http=%d https=%d", httpPort, httpsPort)
	}

	// Accepts for the new listener ports first, keeping any for the old ones:
	// the redirect still points there until it is replaced below.
	if err := b.ensureScopedDNATAccepts(httpPort, httpsPort, false); err != nil {
		return err
	}

	// Replace CFM's managed DNAT table in ONE transaction (replaceTableScript):
	// the redirect never lapses, and a script that fails changes nothing.
	// It used to be `delete table` and then the new table in a second nft
	// run: between the two, web traffic reached the backend directly (no
	// edge, WAF or challenge), and a second run that failed left web DNAT
	// off.
	if err := b.nftExpr(replaceTableScript(fam, tbl, dnatScript(fam, tbl, httpPort, httpsPort, b.dnatPriority()))); err != nil {
		// The old redirect, if any, is still in force: see
		// dropRedirectToOtherPorts in internal/dnat for `cfm dnat on`
		// moving to other listener ports.
		return err
	}
	// The redirect points at the new ports now: drop the accepts nobody wants,
	// best effort. Leftovers match only connections DNAT'd to their port, which
	// no redirect targets any more, and the next EnsureDNATAccepts prunes them.
	// Failing here would report the committed redirect as not installed.
	if err := b.ensureScopedDNATAccepts(httpPort, httpsPort, true); err != nil {
		b.logPhase("DNATOn", "warn", 0, err, "op=dnat leftover scoped accepts (inert without a redirect to their port)")
	}
	return nil
}

// parseDNATListenerPorts scans the `list table inet cfm_redirect` output for
// the unconditional listener rules created by dnatScript and returns the
// post-DNAT http/https ports. Delegates to firewall.ParseDNATListenerPorts so
// the dnat CLI status report resolves against the identical parse.
func parseDNATListenerPorts(out string) (httpPort, httpsPort int, ok bool) {
	return firewall.ParseDNATListenerPorts(out)
}

// EnsureDNATAccepts re-asserts the scoped `ct status dnat` accepts in the
// inet cfm input chain when web DNAT is active. No-op when the cfm_redirect
// table is absent. Safe to call repeatedly; runs after ApplyPortsPolicy so a
// fresh chain gets its accepts above the drops (the ports policy itself never
// deletes them).
func (b *Backend) EnsureDNATAccepts() error {
	fam, tbl := dnatDefaults("", "")
	if !b.dnatTableExists(fam, tbl) {
		return nil
	}
	show, err := b.nftOut(fmt.Sprintf("list table %s %s", fam, tbl))
	if err != nil {
		return nil
	}
	httpPort, httpsPort, ok := parseDNATListenerPorts(show)
	if !ok {
		return nil
	}
	return b.ensureScopedDNATAccepts(httpPort, httpsPort, true)
}

func (b *Backend) DNATOff(fam, tbl string) (err error) {
	start := time.Now()
	b.logPhase("DNATOff", "start", 0, nil, "op=dnat")
	defer func() {
		st := "ok"
		if err != nil {
			st = "fail"
		}
		b.logPhase("DNATOff", st, time.Since(start), err, "op=dnat")
	}()
	fam, tbl = dnatDefaults(fam, tbl)

	// Redirect first (idempotent), accepts last: removed first, a redirect
	// that then failed to go would send every web connection into the
	// default drop.
	if b.dnatTableExists(fam, tbl) {
		if err := b.nftCmd(fmt.Sprintf("delete table %s %s", fam, tbl)); err != nil {
			return err
		}
	}
	// With the redirect gone the accepts match nothing (they need ct status
	// dnat), so a failed cleanup is only a warning. Returning it would make
	// `cfm dnat off` fail without persisting intent OFF, and the daemon's
	// failsafe would turn DNAT back on.
	if err := b.cleanupScopedDNATAccepts(); err != nil {
		b.logPhase("DNATOff", "warn", 0, err, "op=dnat leftover scoped accepts (inert without the redirect)")
	}
	return nil
}

func getenvInt(key string, def int) int {
	v := strings.TrimSpace(os.Getenv(key))
	if v == "" {
		return def
	}
	n, err := strconv.ParseInt(v, 10, 32)
	if err != nil {
		return def
	}
	return int(n)
}

// ConfiguredDNATPriority implements firewall.DNATPriorityReporter.
func (b *Backend) ConfiguredDNATPriority() (int, bool) {
	return b.dnatPriority(), b != nil && b.cfg != nil
}

func (b *Backend) dnatPriority() int {
	prio := -99
	if b != nil && b.cfg != nil && b.cfg.NFT.DNATPriority != 0 {
		prio = b.cfg.NFT.DNATPriority
	} else {
		prio = getenvInt("NFT_DNAT_PRIORITY", prio)
	}
	if prio < -300 {
		return -300
	}
	if prio > 300 {
		return 300
	}
	return prio
}

// replaceTableScript prefixes an nft script that defines family/table with the
// statements that remove the table first, so `nft -f` replaces it in one
// kernel transaction: no moment without the table, and nothing changes when
// any statement fails. `add table` first makes the `delete` valid when the
// table does not exist yet.
func replaceTableScript(family, table, script string) string {
	return fmt.Sprintf("add table %s %s\ndelete table %s %s\n", family, table, family, table) + script
}

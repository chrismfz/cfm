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
		fam = "inet"
	}
	if tbl == "" {
		tbl = "cfm_redirect"
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
	return fmt.Sprintf("cfm_dnat_accept:%s:%d:%d", label, from, to)
}

func firstInputDefaultDropHandle(out string) string {
	for _, line := range strings.Split(out, "\n") {
		// Single source of truth for the default-drop predicate lives in
		// firewall.IsInputDefaultDropLine so it can't drift from the dnat CLI
		// reporter; here we additionally need the handle to insert before it.
		if !firewall.IsInputDefaultDropLine(line) {
			continue
		}
		norm := strings.ReplaceAll(line, `"`, "")
		if !strings.Contains(norm, " handle ") {
			continue
		}
		h := strings.TrimSpace(norm[strings.LastIndex(norm, " handle ")+8:])
		if fields := strings.Fields(h); len(fields) > 0 {
			return fields[0]
		}
	}
	return ""
}

func dnatAcceptRuleExpr(spec dnatAcceptRuleSpec, beforeHandle string) string {
	prefix := "add rule inet cfm input"
	if strings.TrimSpace(beforeHandle) != "" {
		prefix = "insert rule inet cfm input position " + strings.TrimSpace(beforeHandle)
	}
	expr := fmt.Sprintf(`%s %s dport %d ct state new ct status dnat ct original proto-dst %d accept comment "%s"`, prefix, spec.proto, spec.to, spec.from, dnatAcceptRuleComment(spec.label, spec.from, spec.to))
	return strings.Join(strings.Fields(expr), " ")
}

func (b *Backend) ensureScopedDNATAccepts(httpPort, httpsPort int) error {
	_ = b.nftExpr("add table inet cfm")
	_ = b.nftCmd("add chain inet cfm input { type filter hook input priority 0; policy accept; }")
	// MUST list via ListChainText (argv mode). nftOut feeds its argument to
	// `nft -f -` (script mode), where the `-a` handle flag is a syntax error —
	// that made the listing fail silently, so firstInputDefaultDropHandle saw an
	// error string, returned "", and the accepts were APPENDED after the default
	// drop (never reached) instead of inserted before it. Fail closed on a list
	// error rather than repeating that silent breakage.
	out, err := b.ListChainText(family, tableName, "input")
	if err != nil {
		return fmt.Errorf("list %s %s input chain for dnat accepts: %w", family, tableName, err)
	}
	beforeHandle := firstInputDefaultDropHandle(out)
	if err := b.cleanupScopedDNATAccepts(); err != nil {
		return err
	}
	for _, spec := range dnatAcceptRuleSpecs(httpPort, httpsPort) {
		if spec.to <= 0 {
			continue
		}
		if err := b.nftCmd(dnatAcceptRuleExpr(spec, beforeHandle)); err != nil {
			return err
		}
	}
	return nil
}

func (b *Backend) cleanupScopedDNATAccepts() error {
	// argv-mode listing (see ensureScopedDNATAccepts): a script-mode `-a` list
	// errors out, which would leave stale accepts undeleted and duplicated.
	out, err := b.ListChainText(family, tableName, "input")
	if err != nil {
		return nil
	}
	for _, line := range strings.Split(out, "\n") {
		norm := strings.ReplaceAll(line, `"`, "")
		if !strings.Contains(norm, "cfm_dnat_accept:") || !strings.Contains(norm, " handle ") {
			continue
		}
		h := strings.TrimSpace(norm[strings.LastIndex(norm, " handle ")+8:])
		if fields := strings.Fields(h); len(fields) > 0 {
			h = fields[0]
		}
		if h != "" {
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

	if err := b.ensureScopedDNATAccepts(httpPort, httpsPort); err != nil {
		return err
	}

	// Replace CFM's managed DNAT table so changed listener ports are applied.
	if b.dnatTableExists(fam, tbl) {
		if err := b.nftCmd(fmt.Sprintf("delete table %s %s", fam, tbl)); err != nil {
			return err
		}
	}

	// Reuse your multi-line nft expression runner
	return b.nftExpr(dnatScript(fam, tbl, httpPort, httpsPort, b.dnatPriority()))
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
// table is absent. Safe to call repeatedly; intended to run after
// ApplyPortsPolicy so the accepts survive the drop-rule rewrite.
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
	return b.ensureScopedDNATAccepts(httpPort, httpsPort)
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

	if err := b.cleanupScopedDNATAccepts(); err != nil {
		return err
	}

	// Idempotent
	if !b.dnatTableExists(fam, tbl) {
		return nil
	}

	// Reuse your single-expression runner (auto adds ;)
	return b.nftCmd(fmt.Sprintf("delete table %s %s", fam, tbl))
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

//go:build linux

package nftlib

import (
	"bytes"
	"fmt"
	"net"
	"os"
	"sort"
	"strconv"
	"strings"
	"time"

	"github.com/google/nftables"
	"github.com/google/nftables/expr"
)

const (
	dnatRuleTag             = "cfm-dnat-managed"
	defaultWebDNATHTTPPort  = 9080
	defaultWebDNATHTTPSPort = 9043
)

type dnatRuleSpec struct {
	proto  uint8
	dport  uint16
	toPort uint16
}

func (s dnatRuleSpec) id() string {
	return fmt.Sprintf("%s:v1:p%d:d%d:t%d", dnatRuleTag, s.proto, s.dport, s.toPort)
}

func parseDNATRuleSpecID(id string) (dnatRuleSpec, bool) {
	var spec dnatRuleSpec
	if !strings.HasPrefix(id, dnatRuleTag+":v1:") {
		return spec, false
	}
	parts := strings.Split(id, ":")
	if len(parts) != 5 {
		return spec, false
	}
	parsePart := func(prefix, part string) (uint64, bool) {
		if !strings.HasPrefix(part, prefix) {
			return 0, false
		}
		n, err := strconv.ParseUint(strings.TrimPrefix(part, prefix), 10, 16)
		return n, err == nil
	}
	proto, ok := parsePart("p", parts[2])
	if !ok || proto > 255 {
		return spec, false
	}
	dport, ok := parsePart("d", parts[3])
	if !ok {
		return spec, false
	}
	toPort, ok := parsePart("t", parts[4])
	if !ok {
		return spec, false
	}
	return dnatRuleSpec{proto: uint8(proto), dport: uint16(dport), toPort: uint16(toPort)}, true
}

func managedDNATRule(userData []byte) bool {
	return strings.HasPrefix(string(userData), dnatRuleTag)
}

func dnatRuleExprs(spec dnatRuleSpec) []expr.Any {
	toPort := []byte{byte(spec.toPort >> 8), byte(spec.toPort)}
	dport := []byte{byte(spec.dport >> 8), byte(spec.dport)}
	return []expr.Any{
		&expr.Meta{Key: expr.MetaKeyL4PROTO, Register: 1},
		&expr.Cmp{Op: expr.CmpOpEq, Register: 1, Data: []byte{spec.proto}},
		&expr.Payload{DestRegister: 1, Base: expr.PayloadBaseTransportHeader, Offset: 2, Len: 2},
		&expr.Cmp{Op: expr.CmpOpEq, Register: 1, Data: dport},
		&expr.Immediate{Register: 1, Data: toPort},
		&expr.NAT{Type: expr.NATTypeDestNAT, Family: uint32(nftables.TableFamilyIPv4), RegProtoMin: 1},
	}
}

func dnatRuleMatches(r *nftables.Rule, spec dnatRuleSpec) bool {
	if string(r.UserData) != spec.id() {
		return false
	}
	exprs := dnatRuleExprs(spec)
	if len(r.Exprs) != len(exprs) {
		return false
	}
	for i := range exprs {
		switch want := exprs[i].(type) {
		case *expr.Meta:
			got, ok := r.Exprs[i].(*expr.Meta)
			if !ok || got.Key != want.Key || got.Register != want.Register {
				return false
			}
		case *expr.Cmp:
			got, ok := r.Exprs[i].(*expr.Cmp)
			if !ok || got.Op != want.Op || got.Register != want.Register || !bytes.Equal(got.Data, want.Data) {
				return false
			}
		case *expr.Payload:
			got, ok := r.Exprs[i].(*expr.Payload)
			if !ok || got.DestRegister != want.DestRegister || got.Base != want.Base || got.Offset != want.Offset || got.Len != want.Len {
				return false
			}
		case *expr.Immediate:
			got, ok := r.Exprs[i].(*expr.Immediate)
			if !ok || got.Register != want.Register || !bytes.Equal(got.Data, want.Data) {
				return false
			}
		case *expr.NAT:
			got, ok := r.Exprs[i].(*expr.NAT)
			if !ok || got.Type != want.Type || got.Family != want.Family || got.RegProtoMin != want.RegProtoMin {
				return false
			}
		default:
			return false
		}
	}
	return true
}

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

func tableFamilyFromString(s string) nftables.TableFamily {
	switch strings.ToLower(strings.TrimSpace(s)) {
	case "ip":
		return nftables.TableFamilyIPv4
	case "ip6":
		return nftables.TableFamilyIPv6
	default:
		return nftables.TableFamilyINet
	}
}

func (b *Backend) SetChallengeRedirectEnabled(enabled bool) {
	b.mu.Lock()
	defer b.mu.Unlock()
	b.challengeRedirectEnabled = enabled
	if !enabled {
		_ = b.dnatOffUnlocked("", "")
	}
}

func (b *Backend) CleanupChallengeRedirect() error {
	return b.DNATOff("", "")
}

func (b *Backend) EnsureChallengeRedirect(httpListen, httpsListen string) (err error) {
	start := time.Now()
	b.logPhase("EnsureChallengeRedirect", "start", 0, nil, "")
	defer func() {
		st := "ok"
		if err != nil {
			st = "fail"
		}
		b.logPhase("EnsureChallengeRedirect", st, time.Since(start), err, "")
	}()
	if !b.challengeRedirectEnabled {
		return b.CleanupChallengeRedirect()
	}
	_, httpPort, okHTTP := parseListenHostPort(httpListen)
	_, httpsPort, okHTTPS := parseListenHostPort(httpsListen)
	if !okHTTP {
		httpPort = defaultWebDNATHTTPPort
	}
	if !okHTTPS {
		httpsPort = defaultWebDNATHTTPSPort
	}
	return b.DNATOn("", "", httpPort, httpsPort)
}

func (b *Backend) getDNATTableAndChain(family, table string) (*nftables.Table, *nftables.Chain, error) {
	tf := tableFamilyFromString(family)
	t := &nftables.Table{Name: table, Family: tf}
	chains, err := b.conn.ListChains()
	if err != nil {
		return nil, nil, err
	}
	var prerouting *nftables.Chain
	for _, ch := range chains {
		if ch.Table != nil && ch.Table.Name == t.Name && ch.Table.Family == t.Family && ch.Name == "prerouting" {
			prerouting = ch
			break
		}
	}
	return t, prerouting, nil
}

func (b *Backend) DNATStatus(family, table string) (bool, error) {
	family, table = dnatDefaults(family, table)
	b.mu.Lock()
	defer b.mu.Unlock()
	t, ch, err := b.getDNATTableAndChain(family, table)
	if err != nil || ch == nil {
		return false, err
	}
	on, _, err := b.scanManagedDNATRules(t, ch)
	if err != nil {
		return false, err
	}
	return on, nil
}

func (b *Backend) scanManagedDNATRules(t *nftables.Table, ch *nftables.Chain) (bool, []dnatRuleSpec, error) {
	rules, err := b.conn.GetRules(t, ch)
	if err != nil {
		return false, nil, err
	}
	found := make([]dnatRuleSpec, 0, 3)
	for _, r := range rules {
		spec, ok := parseDNATRuleSpecID(string(r.UserData))
		if !ok {
			continue
		}
		if dnatRuleMatches(r, spec) {
			found = append(found, spec)
		}
	}
	sort.Slice(found, func(i, j int) bool {
		if found[i].dport != found[j].dport {
			return found[i].dport < found[j].dport
		}
		return found[i].proto < found[j].proto
	})
	return len(found) > 0, found, nil
}

func (b *Backend) DNATShow(family, table string) (string, error) {
	family, table = dnatDefaults(family, table)
	b.mu.Lock()
	defer b.mu.Unlock()
	t, ch, err := b.getDNATTableAndChain(family, table)
	if err != nil {
		return "", err
	}
	if ch == nil {
		return "", nil
	}
	on, found, err := b.scanManagedDNATRules(t, ch)
	if err != nil {
		return "", err
	}
	if !on {
		return "", nil
	}
	var out strings.Builder
	fmt.Fprintf(&out, "table %s %s {\n", family, table)
	out.WriteString("  chain prerouting {\n")
	out.WriteString(fmt.Sprintf("    type nat hook prerouting priority %d; policy accept;\n\n", b.dnatPriority()))
	for _, spec := range found {
		proto := "tcp"
		if spec.proto == 17 {
			proto = "udp"
		}
		fmt.Fprintf(&out, "    %s dport %d dnat to :%d\n", proto, spec.dport, spec.toPort)
	}
	out.WriteString("  }\n}\n")
	return out.String(), nil
}

func dnatAcceptComment(label string, from, to int) string {
	return fmt.Sprintf("cfm_dnat_accept:%s:%d:%d", label, from, to)
}

func (b *Backend) cleanupScopedDNATAccepts() error {
	out, err := b.ListChainText("inet", "cfm", "input")
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
			if err := b.nftExec("delete rule inet cfm input handle " + h); err != nil {
				return err
			}
		}
	}
	return nil
}

func (b *Backend) ensureScopedDNATAccepts(httpPort, httpsPort int) error {
	_ = b.nftExec("add table inet cfm")
	_ = b.nftExec("add chain inet cfm input { type filter hook input priority 0; policy accept; }")
	if err := b.cleanupScopedDNATAccepts(); err != nil {
		return err
	}
	for _, spec := range []struct {
		label string
		from  int
		to    int
	}{
		{label: "web_http", from: 80, to: httpPort},
		{label: "web_https", from: 443, to: httpsPort},
	} {
		expr := fmt.Sprintf(`add rule inet cfm input ct state new ct status dnat ct original proto-dst %d tcp dport %d accept comment "%s"`, spec.from, spec.to, dnatAcceptComment(spec.label, spec.from, spec.to))
		if err := b.nftExec(expr); err != nil {
			return err
		}
	}
	return nil
}

func (b *Backend) DNATOn(family, table string, httpPort, httpsPort int) (err error) {
	start := time.Now()
	b.logPhase("DNATOn", "start", 0, nil, fmt.Sprintf("http_port=%d https_port=%d", httpPort, httpsPort))
	defer func() {
		st := "ok"
		if err != nil {
			st = "fail"
		}
		b.logPhase("DNATOn", st, time.Since(start), err, fmt.Sprintf("http_port=%d https_port=%d", httpPort, httpsPort))
	}()
	family, table = dnatDefaults(family, table)
	if httpPort <= 0 || httpsPort <= 0 {
		return fmt.Errorf("invalid ports: http=%d https=%d", httpPort, httpsPort)
	}
	if err := b.ensureScopedDNATAccepts(httpPort, httpsPort); err != nil {
		return err
	}
	b.mu.Lock()
	defer b.mu.Unlock()
	t, ch, err := b.getDNATTableAndChain(family, table)
	if err != nil {
		return err
	}
	if ch == nil {
		b.conn.AddTable(t)
		dstNat := nftables.ChainPriority(b.dnatPriority())
		policy := nftables.ChainPolicyAccept
		ch = &nftables.Chain{
			Name:     "prerouting",
			Table:    t,
			Type:     nftables.ChainTypeNAT,
			Hooknum:  nftables.ChainHookPrerouting,
			Priority: &dstNat,
			Policy:   &policy,
		}
		b.conn.AddChain(ch)
	}
	wanted := []dnatRuleSpec{
		{proto: 6, dport: 80, toPort: uint16(httpPort)},
		{proto: 6, dport: 443, toPort: uint16(httpsPort)},
		{proto: 17, dport: 443, toPort: uint16(httpsPort)},
	}
	rules, _ := b.conn.GetRules(t, ch)
	wantedByID := make(map[string]dnatRuleSpec, len(wanted))
	for _, spec := range wanted {
		wantedByID[spec.id()] = spec
	}

	seen := make(map[string]struct{}, len(wanted))
	for _, r := range rules {
		if !managedDNATRule(r.UserData) {
			continue
		}
		spec, ok := wantedByID[string(r.UserData)]
		if !ok || !dnatRuleMatches(r, spec) {
			b.conn.DelRule(r)
			continue
		}
		seen[string(r.UserData)] = struct{}{}
	}

	for _, spec := range wanted {
		if _, ok := seen[spec.id()]; ok {
			continue
		}
		b.conn.AddRule(&nftables.Rule{Table: t, Chain: ch, UserData: []byte(spec.id()), Exprs: dnatRuleExprs(spec)})
	}
	return b.conn.Flush()
}

// dnatOffUnlocked removes all managed DNAT rules. Must be called with b.mu held.
func (b *Backend) dnatOffUnlocked(family, table string) error {
	family, table = dnatDefaults(family, table)
	_, ch, err := b.getDNATTableAndChain(family, table)
	if err != nil || ch == nil {
		return err
	}
	rules, err := b.conn.GetRules(ch.Table, ch)
	if err != nil {
		return err
	}
	for _, r := range rules {
		if managedDNATRule(r.UserData) {
			b.conn.DelRule(r)
		}
	}
	return b.conn.Flush()
}

func (b *Backend) DNATOff(family, table string) (err error) {
	start := time.Now()
	b.logPhase("DNATOff", "start", 0, nil, "")
	defer func() {
		st := "ok"
		if err != nil {
			st = "fail"
		}
		b.logPhase("DNATOff", st, time.Since(start), err, "")
	}()
	if err := b.cleanupScopedDNATAccepts(); err != nil {
		return err
	}
	b.mu.Lock()
	defer b.mu.Unlock()
	return b.dnatOffUnlocked(family, table)
}

func parseListenHostPort(addr string) (host string, port int, ok bool) {
	addr = strings.TrimSpace(addr)
	if addr == "" {
		return "", 0, false
	}
	if p, err := strconv.Atoi(addr); err == nil {
		if p > 0 && p <= 65535 {
			return "", p, true
		}
		return "", 0, false
	}
	h, portStr, err := net.SplitHostPort(addr)
	if err != nil {
		return "", 0, false
	}
	p, err := strconv.Atoi(portStr)
	if err != nil || p <= 0 || p > 65535 {
		return strings.TrimSpace(h), 0, false
	}
	return strings.TrimSpace(h), p, true
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

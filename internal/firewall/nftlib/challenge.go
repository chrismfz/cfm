//go:build linux

package nftlib

import (
	"bytes"
	"encoding/binary"
	"fmt"
	"net"
	"os"
	"sort"
	"strconv"
	"strings"
	"time"

	"github.com/google/nftables"
	"github.com/google/nftables/expr"

	"cfm/internal/firewall"
)

const (
	dnatRuleTag                  = "cfm-dnat-managed"
	dnatLoopbackAcceptTag        = dnatRuleTag + ":loopback-accept:v1"
	dnatAcceptNamespaceEdge = "cfm_edge_dnat_accept"
	dnatRuleNamespaceEdge   = "edge"
)

type dnatRuleSpec struct {
	family    nftables.TableFamily
	proto     uint8
	dport     uint16
	toPort    uint16
	sourceSet string
	toAddr    net.IP
}

func (s dnatRuleSpec) id() string {
	return fmt.Sprintf("%s:v2:f%d:p%d:d%d:t%d:s%s:a%s", dnatRuleTag, s.family, s.proto, s.dport, s.toPort, s.sourceSet, dnatAddrID(s.toAddr))
}

func dnatAddrID(ip net.IP) string {
	if ip == nil {
		return "-"
	}
	return ip.String()
}

func parseDNATRuleSpecID(id string) (dnatRuleSpec, bool) {
	var spec dnatRuleSpec
	if !strings.HasPrefix(id, dnatRuleTag+":v2:") {
		return spec, false
	}
	parts := strings.Split(id, ":")
	if len(parts) < 8 {
		return spec, false
	}
	parseFamily := func(prefix, part string) (nftables.TableFamily, bool) {
		if !strings.HasPrefix(part, prefix) {
			return 0, false
		}
		n, err := strconv.ParseInt(strings.TrimPrefix(part, prefix), 10, 32)
		if err != nil {
			return 0, false
		}
		if n < 0 || n > 255 {
			return 0, false
		}
		return nftables.TableFamily(n), true
	}
	parseProtocol := func(prefix, part string) (uint8, bool) {
		if !strings.HasPrefix(part, prefix) {
			return 0, false
		}
		n, err := strconv.ParseInt(strings.TrimPrefix(part, prefix), 10, 32)
		if err != nil {
			return 0, false
		}
		if n < 0 || n > 255 {
			return 0, false
		}
		return uint8(n), true
	}
	parsePort := func(prefix, part string) (uint16, bool) {
		if !strings.HasPrefix(part, prefix) {
			return 0, false
		}
		n, err := strconv.ParseInt(strings.TrimPrefix(part, prefix), 10, 32)
		if err != nil {
			return 0, false
		}
		if n < 1 || n > 65535 {
			return 0, false
		}
		return uint16(n), true
	}
	fam, ok := parseFamily("f", parts[2])
	if !ok {
		return spec, false
	}
	proto, ok := parseProtocol("p", parts[3])
	if !ok {
		return spec, false
	}
	dport, ok := parsePort("d", parts[4])
	if !ok {
		return spec, false
	}
	toPort, ok := parsePort("t", parts[5])
	if !ok {
		return spec, false
	}
	if !strings.HasPrefix(parts[6], "s") {
		return spec, false
	}
	if !strings.HasPrefix(parts[7], "a") {
		return spec, false
	}
	addr := strings.TrimPrefix(strings.Join(parts[7:], ":"), "a")
	if addr != "-" {
		ip := net.ParseIP(addr)
		if ip == nil {
			return spec, false
		}
		spec.toAddr = ip
	}
	spec.family = fam
	spec.proto = proto
	spec.dport = dport
	spec.toPort = toPort
	spec.sourceSet = strings.TrimPrefix(parts[6], "s")
	return spec, true
}

func managedDNATRule(userData []byte) bool {
	return strings.HasPrefix(string(userData), dnatRuleTag)
}

func dnatAcceptNamespace(string) string {
	// Only the edge namespace exists — the per-IP challenge DNAT namespace is
	// retired (edge-unification Phase 1b).
	return dnatAcceptNamespaceEdge
}

func dnatRuleInNamespace(r *nftables.Rule, namespace string) bool {
	if string(r.UserData) == dnatLoopbackAcceptTag {
		return namespace == dnatRuleNamespaceEdge
	}
	spec, ok := parseDNATRuleSpecID(string(r.UserData))
	if !ok {
		return false
	}
	// Edge rules are unscoped; a sourceSet marks a stale rule from the retired
	// challenge namespace, which never matches (and gets cleaned as foreign).
	_ = namespace
	return spec.sourceSet == ""
}

func dnatRuleExprs(spec dnatRuleSpec) []expr.Any {
	toPort := make([]byte, 2)
	binary.BigEndian.PutUint16(toPort, spec.toPort)
	dport := make([]byte, 2)
	binary.BigEndian.PutUint16(dport, spec.dport)
	exprs := make([]expr.Any, 0, 9)
	if spec.sourceSet != "" {
		saddrLen, saddrOff := uint32(4), uint32(12)
		if spec.family == nftables.TableFamilyIPv6 {
			saddrLen, saddrOff = 16, 8
		}
		exprs = append(exprs,
			&expr.Payload{DestRegister: 1, Base: expr.PayloadBaseNetworkHeader, Offset: saddrOff, Len: saddrLen},
			&expr.Lookup{SourceRegister: 1, SetName: spec.sourceSet},
		)
	}
	exprs = append(exprs,
		&expr.Meta{Key: expr.MetaKeyL4PROTO, Register: 1},
		&expr.Cmp{Op: expr.CmpOpEq, Register: 1, Data: []byte{spec.proto}},
		&expr.Payload{DestRegister: 1, Base: expr.PayloadBaseTransportHeader, Offset: 2, Len: 2},
		&expr.Cmp{Op: expr.CmpOpEq, Register: 1, Data: dport},
	)
	regProto := uint32(1)
	if addr := dnatAddrBytes(spec); len(addr) > 0 {
		exprs = append(exprs, &expr.Immediate{Register: 1, Data: addr}, &expr.Immediate{Register: 2, Data: toPort}, &expr.NAT{Type: expr.NATTypeDestNAT, Family: uint32(spec.family), RegAddrMin: 1, RegProtoMin: 2})
		return exprs
	}
	exprs = append(exprs, &expr.Immediate{Register: 1, Data: toPort}, &expr.NAT{Type: expr.NATTypeDestNAT, Family: uint32(spec.family), RegProtoMin: regProto})
	return exprs
}

func dnatLoopbackAcceptExprs() []expr.Any {
	iifName := make([]byte, 16)
	copy(iifName, "lo")
	return []expr.Any{
		&expr.Meta{Key: expr.MetaKeyIIFNAME, Register: 1},
		&expr.Cmp{Op: expr.CmpOpEq, Register: 1, Data: iifName},
		&expr.Verdict{Kind: expr.VerdictAccept},
	}
}

func dnatLoopbackAcceptMatches(r *nftables.Rule) bool {
	if string(r.UserData) != dnatLoopbackAcceptTag {
		return false
	}
	exprs := dnatLoopbackAcceptExprs()
	if len(r.Exprs) != len(exprs) {
		return false
	}
	meta, ok := r.Exprs[0].(*expr.Meta)
	if !ok || meta.Key != expr.MetaKeyIIFNAME || meta.Register != 1 {
		return false
	}
	cmp, ok := r.Exprs[1].(*expr.Cmp)
	if !ok || cmp.Op != expr.CmpOpEq || cmp.Register != 1 || !bytes.Equal(cmp.Data, exprs[1].(*expr.Cmp).Data) {
		return false
	}
	verdict, ok := r.Exprs[2].(*expr.Verdict)
	return ok && verdict.Kind == expr.VerdictAccept
}

func dnatAddrBytes(spec dnatRuleSpec) []byte {
	if spec.toAddr == nil {
		return nil
	}
	if spec.family == nftables.TableFamilyIPv4 {
		return spec.toAddr.To4()
	}
	return spec.toAddr.To16()
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
		case *expr.Lookup:
			got, ok := r.Exprs[i].(*expr.Lookup)
			if !ok || got.SourceRegister != want.SourceRegister || got.SetName != want.SetName || got.Invert != want.Invert {
				return false
			}
		case *expr.Immediate:
			got, ok := r.Exprs[i].(*expr.Immediate)
			if !ok || got.Register != want.Register || !bytes.Equal(got.Data, want.Data) {
				return false
			}
		case *expr.NAT:
			got, ok := r.Exprs[i].(*expr.NAT)
			if !ok || got.Type != want.Type || got.Family != want.Family || got.RegAddrMin != want.RegAddrMin || got.RegProtoMin != want.RegProtoMin {
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
		tbl = cfmTableName
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
		if found[i].family != found[j].family {
			return found[i].family < found[j].family
		}
		if found[i].dport != found[j].dport {
			return found[i].dport < found[j].dport
		}
		if found[i].proto != found[j].proto {
			return found[i].proto < found[j].proto
		}
		return found[i].sourceSet < found[j].sourceSet
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
		fmt.Fprintf(&out, "    %s\n", dnatShowRuleLine(spec))
	}
	out.WriteString("  }\n}\n")
	return out.String(), nil
}

func dnatShowRuleLine(spec dnatRuleSpec) string {
	proto := "tcp"
	if spec.proto == 17 {
		proto = "udp"
	}
	if spec.sourceSet == "" {
		return fmt.Sprintf("%s dport %d dnat to %s", proto, spec.dport, dnatToString(spec))
	}
	return fmt.Sprintf("%s saddr @%s %s dport %d dnat to %s", dnatFamilyPrefix(spec.family), spec.sourceSet, proto, spec.dport, dnatToString(spec))
}

func dnatFamilyPrefix(fam nftables.TableFamily) string {
	if fam == nftables.TableFamilyIPv6 {
		return "ip6"
	}
	return "ip"
}

func dnatDaddrMatch(spec dnatRuleSpec) string {
	if spec.toAddr == nil {
		return ""
	}
	return fmt.Sprintf("%s daddr %s", dnatFamilyPrefix(spec.family), spec.toAddr.String())
}

func dnatToString(spec dnatRuleSpec) string {
	if spec.toAddr == nil {
		return fmt.Sprintf(":%d", spec.toPort)
	}
	if spec.family == nftables.TableFamilyIPv6 {
		return fmt.Sprintf("[%s]:%d", spec.toAddr.String(), spec.toPort)
	}
	return fmt.Sprintf("%s:%d", spec.toAddr.String(), spec.toPort)
}

func dnatAcceptLabel(spec dnatRuleSpec) string {
	portName := "web_https"
	if spec.dport == 80 {
		portName = "web_http"
	}
	if spec.sourceSet == "" && spec.toAddr == nil {
		return fmt.Sprintf("%s_%s", portName, dnatAcceptProtoName(spec.proto))
	}
	return fmt.Sprintf("%s_%s_%s", portName, dnatFamilyPrefix(spec.family), dnatAcceptProtoName(spec.proto))
}

func dnatAcceptProtoName(proto uint8) string {
	if proto == 17 {
		return "udp"
	}
	return "tcp"
}

func dnatUnscopedWantedSpecs(family nftables.TableFamily, httpPort, httpsPort int) []dnatRuleSpec {
	return []dnatRuleSpec{
		{family: family, proto: 6, dport: 80, toPort: uint16(httpPort)},
		{family: family, proto: 6, dport: 443, toPort: uint16(httpsPort)},
		{family: family, proto: 17, dport: 443, toPort: uint16(httpsPort)},
	}
}

func dnatTargetAddr(host string, fam nftables.TableFamily) (net.IP, bool) {
	host = strings.TrimSpace(host)
	if host == "" {
		return nil, true
	}
	ip := net.ParseIP(host)
	if ip == nil {
		return nil, true
	}
	if ip.IsUnspecified() {
		return nil, true
	}
	if fam == nftables.TableFamilyIPv4 {
		ip4 := ip.To4()
		if ip4 == nil {
			return nil, false
		}
		return ip4, true
	}
	if ip.To4() != nil {
		return nil, false
	}
	ip16 := ip.To16()
	if ip16 == nil {
		return nil, false
	}
	return ip16, true
}

func dnatAcceptComment(namespace, label string, from, to int) string {
	return fmt.Sprintf("%s:%s:%d:%d", namespace, label, from, to)
}

func scopedDNATAcceptHandles(out, namespace string) []string {
	namespace = strings.TrimSpace(namespace)
	if namespace == "" {
		return nil
	}
	prefix := namespace + ":"
	var handles []string
	for _, line := range strings.Split(out, "\n") {
		norm := strings.ReplaceAll(line, `"`, "")
		if !strings.Contains(norm, prefix) || !strings.Contains(norm, " handle ") {
			continue
		}
		h := strings.TrimSpace(norm[strings.LastIndex(norm, " handle ")+8:])
		if fields := strings.Fields(h); len(fields) > 0 {
			h = fields[0]
		}
		if h != "" {
			handles = append(handles, h)
		}
	}
	return handles
}

func (b *Backend) cleanupScopedDNATAccepts(namespace string) error {
	out, err := b.ListChainText("inet", "cfm", "input")
	if err != nil {
		return nil
	}
	for _, h := range scopedDNATAcceptHandles(out, namespace) {
		if err := b.nftExec("delete rule inet cfm input handle " + h); err != nil {
			return err
		}
	}
	return nil
}

func firstInputDefaultDropHandle(out string) string {
	for _, line := range strings.Split(out, "\n") {
		// Shared default-drop predicate (firewall.IsInputDefaultDropLine) so the
		// matcher can't drift between the nftlib backend, the nft backend and the
		// dnat CLI reporter; here we additionally need the handle to insert
		// before it.
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

func dnatAcceptKey(spec dnatRuleSpec) string {
	return fmt.Sprintf("f%d:p%d:d%d:t%d:a%s", spec.family, spec.proto, spec.dport, spec.toPort, dnatAddrID(spec.toAddr))
}

func dnatAcceptRuleExpr(namespace string, spec dnatRuleSpec, beforeHandle ...string) string {
	proto := "tcp"
	if spec.proto == 17 {
		proto = "udp"
	}
	prefix := "add rule inet cfm input"
	if len(beforeHandle) > 0 && strings.TrimSpace(beforeHandle[0]) != "" {
		prefix = "insert rule inet cfm input position " + strings.TrimSpace(beforeHandle[0])
	}
	expr := fmt.Sprintf(`%s %s %s dport %d ct state new ct status dnat ct original proto-dst %d accept comment "%s"`, prefix, dnatDaddrMatch(spec), proto, spec.toPort, spec.dport, dnatAcceptComment(namespace, dnatAcceptLabel(spec), int(spec.dport), int(spec.toPort)))
	return strings.Join(strings.Fields(expr), " ")
}

func (b *Backend) ensureScopedDNATAccepts(namespace string, specs []dnatRuleSpec) error {
	_ = b.nftExec("add table inet cfm")
	_ = b.nftExec("add chain inet cfm input { type filter hook input priority 0; policy accept; }")
	out, _ := b.ListChainText("inet", "cfm", "input")
	beforeHandle := firstInputDefaultDropHandle(out)
	if err := b.cleanupScopedDNATAccepts(namespace); err != nil {
		return err
	}
	seen := make(map[string]struct{})
	for _, spec := range specs {
		key := dnatAcceptKey(spec)
		if _, ok := seen[key]; ok {
			continue
		}
		seen[key] = struct{}{}
		if err := b.nftExec(dnatAcceptRuleExpr(namespace, spec, beforeHandle)); err != nil {
			return err
		}
	}
	return nil
}

func (b *Backend) DNATOn(family, table string, httpPort, httpsPort int) (err error) {
	start := time.Now()
	b.logPhase("DNATOn", "start", 0, nil, fmt.Sprintf("op=dnat http_port=%d https_port=%d", httpPort, httpsPort))
	defer func() {
		st := "ok"
		if err != nil {
			st = "fail"
		}
		b.logPhase("DNATOn", st, time.Since(start), err, fmt.Sprintf("op=dnat http_port=%d https_port=%d", httpPort, httpsPort))
	}()
	family, table = dnatDefaults(family, table)
	if httpPort <= 0 || httpsPort <= 0 || httpPort > 65535 || httpsPort > 65535 {
		return fmt.Errorf("invalid ports: http=%d https=%d", httpPort, httpsPort)
	}
	if err := b.EnsureBase(); err != nil {
		return err
	}
	return b.installDNATRules(family, table, dnatUnscopedWantedSpecs(tableFamilyFromString(family), httpPort, httpsPort), dnatRuleNamespaceEdge, true)
}

func (b *Backend) installDNATRules(family, table string, wanted []dnatRuleSpec, namespace string, includeLoopbackAccept bool) error {
	family, table = dnatDefaults(family, table)
	if len(wanted) == 0 {
		return nil
	}
	// Hold b.mu from the read through the rebuild, and read FIRST: a failure
	// then returns before anything has changed. The input-chain accepts below
	// must not move to the new ports while the prerouting rules still redirect
	// to the old ones — new connections would hit the default drop.
	b.mu.Lock()
	defer b.mu.Unlock()
	t, ch, err := b.getDNATTableAndChain(family, table)
	if err != nil {
		return err
	}
	var rules []*nftables.Rule
	if ch != nil {
		// A failed read must not pass for an empty chain: the rebuild below
		// would then append a second copy of the managed rules after the
		// live ones, and new bypass entries would never match.
		if rules, err = b.conn.GetRules(t, ch); err != nil {
			return fmt.Errorf("nftlib: read %s %s prerouting rules: %w", family, table, err)
		}
	}
	// nft CLI only (no b.mu inside), so safe to run under the lock.
	if err := b.ensureScopedDNATAccepts(dnatAcceptNamespace(namespace), wanted); err != nil {
		return err
	}
	if ch == nil {
		b.conn.AddTable(t)
		dstNat := b.dnatChainPriority()
		policy := nftables.ChainPolicyAccept
		ch = &nftables.Chain{
			Name:     "prerouting",
			Table:    t,
			Type:     nftables.ChainTypeNAT,
			Hooknum:  nftables.ChainHookPrerouting,
			Priority: &dstNat,
			Policy:   &policy,
		}
		b.conn.AddChain(ch) // new chain: no existing rules to read
	}

	// The edge namespace (the only one — the per-IP challenge namespace is
	// retired) owns the loopback accept and the source-IP bypass rules in
	// this chain. To guarantee the bypass rules land between loopback and
	// the dport DNAT rules — required for first-match-wins to short-circuit
	// NAT before it runs — we delete every edge-managed rule (loopback +
	// bypass + edge dport rules) and rebuild in deterministic order. An
	// earlier version preserved unchanged dport rules in place and then
	// re-added bypass at the chain tail; that worked on the first install
	// but on the second install (e.g. `cfm dnat bypass add`, which calls
	// DNATOn again) the bypass rules ended up AFTER the surviving dport
	// rules, silently breaking the bypass.
	return b.installEdgeDNATRules(t, ch, wanted, rules, includeLoopbackAccept)
}

// installEdgeDNATRules rebuilds the edge-namespace contents of the
// prerouting chain from scratch. Called by installDNATRules. The chain
// is rebuilt in three positional blocks, in this order:
//
//  1. `iif "lo" accept`                         (loopback exemption)
//  2. `ip[6] saddr <X> accept`                  (one rule per bypass entry)
//  3. `tcp dport N dnat to :M` (and udp)        (per spec in `wanted`)
//
// This guarantees first-match-wins evaluation: a packet from a bypass
// source matches block 2 and is accepted before any NAT translation
// runs in block 3. Unmanaged (foreign) rules elsewhere in the chain
// are untouched.
//
// b.mu MUST be held by the caller. This function calls Flush() itself
// and returns its error.
func (b *Backend) installEdgeDNATRules(t *nftables.Table, ch *nftables.Chain, wanted []dnatRuleSpec, existing []*nftables.Rule, includeLoopbackAccept bool) error {
	// 1. Delete every edge-owned rule currently in the chain. Loopback
	//    accept is edge-owned (cf. dnatRuleInNamespace at line ~156
	//    which only reports "edge" for it). Bypass rules carry the
	//    cfm_dnat_bypass UserData prefix and are also edge-owned.
	//
	//    DelRule errors are discarded: per github.com/google/nftables the
	//    only failure mode here is r.Handle == 0, which can't happen
	//    because every r came from GetRules which populates Handle. Real
	//    netlink failures surface at Flush() below and bubble up to the
	//    caller. The explicit `_ =` is required to satisfy gosec.
	for _, r := range existing {
		if dnatBypassIsManaged(r.UserData) {
			_ = b.conn.DelRule(r)
			continue
		}
		if !managedDNATRule(r.UserData) {
			continue
		}
		if string(r.UserData) == dnatLoopbackAcceptTag {
			_ = b.conn.DelRule(r)
			continue
		}
		if !dnatRuleInNamespace(r, dnatRuleNamespaceEdge) {
			continue
		}
		_ = b.conn.DelRule(r)
	}

	// 2. Re-add in deterministic order.
	if includeLoopbackAccept {
		b.conn.AddRule(&nftables.Rule{Table: t, Chain: ch, UserData: []byte(dnatLoopbackAcceptTag), Exprs: dnatLoopbackAcceptExprs()})
	}
	if _, warnings := b.dnatBypassAddRules(t, ch, firewall.DNATBypassScopeWeb); len(warnings) > 0 {
		for _, w := range warnings {
			b.logPhase("DNATOn", "warn", 0, nil, fmt.Sprintf("bypass entry: %s", w))
		}
	}
	for _, spec := range wanted {
		b.conn.AddRule(&nftables.Rule{Table: t, Chain: ch, UserData: []byte(spec.id()), Exprs: dnatRuleExprs(spec)})
	}
	return b.conn.Flush()
}

// dnatOffUnlocked removes managed DNAT rules in namespace. Must be called with b.mu held.
func (b *Backend) dnatOffUnlocked(family, table, namespace string) error {
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
		if managedDNATRule(r.UserData) && dnatRuleInNamespace(r, namespace) {
			b.conn.DelRule(r)
			continue
		}
		// Bypass rules carry their own UserData prefix (not the
		// dnatRuleTag namespace) so the managedDNATRule check above
		// skips them. Edge namespace owns them, however; when we
		// tear down the edge DNAT we must remove its bypass rules
		// too or they'll dangle in the chain as orphans and confuse
		// the next DNATOn / DNATShow.
		if namespace == dnatRuleNamespaceEdge && dnatBypassIsManaged(r.UserData) {
			b.conn.DelRule(r)
		}
	}
	return b.conn.Flush()
}

// EnsureDNATAccepts re-asserts the scoped `ct status dnat` accept rules in
// inet cfm/input for whatever unconditional (edge) web DNAT is currently
// active. No-op when the DNAT table is absent or no edge rules are present.
// Safe to call repeatedly; intended to run after ApplyPortsPolicy so the
// accepts survive the drop-rule rewrite.
func (b *Backend) EnsureDNATAccepts() error {
	family, table := dnatDefaults("", "")
	b.mu.Lock()
	t, ch, err := b.getDNATTableAndChain(family, table)
	if err != nil || ch == nil {
		b.mu.Unlock()
		return err
	}
	rules, err := b.conn.GetRules(t, ch)
	b.mu.Unlock()
	if err != nil {
		return err
	}
	wanted := make([]dnatRuleSpec, 0, 3)
	for _, r := range rules {
		if !managedDNATRule(r.UserData) || !dnatRuleInNamespace(r, dnatRuleNamespaceEdge) {
			continue
		}
		spec, ok := parseDNATRuleSpecID(string(r.UserData))
		if !ok {
			continue
		}
		if spec.sourceSet != "" {
			continue
		}
		wanted = append(wanted, spec)
	}
	if len(wanted) == 0 {
		return nil
	}
	return b.ensureScopedDNATAccepts(dnatAcceptNamespace(dnatRuleNamespaceEdge), wanted)
}

func (b *Backend) DNATOff(family, table string) (err error) {
	start := time.Now()
	b.logPhase("DNATOff", "start", 0, nil, "op=dnat")
	defer func() {
		st := "ok"
		if err != nil {
			st = "fail"
		}
		b.logPhase("DNATOff", st, time.Since(start), err, "op=dnat")
	}()
	if err := b.cleanupScopedDNATAccepts(dnatAcceptNamespaceEdge); err != nil {
		return err
	}
	b.mu.Lock()
	defer b.mu.Unlock()
	return b.dnatOffUnlocked(family, table, dnatRuleNamespaceEdge)
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

func (b *Backend) dnatChainPriority() nftables.ChainPriority {
	prio := b.dnatPriority()
	if prio < -300 {
		return nftables.ChainPriority(-300)
	}
	if prio > 300 {
		return nftables.ChainPriority(300)
	}
	return nftables.ChainPriority(prio)
}

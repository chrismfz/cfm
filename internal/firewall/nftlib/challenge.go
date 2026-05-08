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
)

const (
	dnatRuleTag             = "cfm-dnat-managed"
	defaultWebDNATHTTPPort  = 9080
	defaultWebDNATHTTPSPort = 9043
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
	if !strings.HasPrefix(parts[6], "s") || strings.TrimPrefix(parts[6], "s") == "" {
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

func dnatRuleExprs(spec dnatRuleSpec) []expr.Any {
	toPort := make([]byte, 2)
	binary.BigEndian.PutUint16(toPort, spec.toPort)
	dport := make([]byte, 2)
	binary.BigEndian.PutUint16(dport, spec.dport)
	saddrLen, saddrOff := uint32(4), uint32(12)
	if spec.family == nftables.TableFamilyIPv6 {
		saddrLen, saddrOff = 16, 8
	}
	exprs := []expr.Any{
		&expr.Payload{DestRegister: 1, Base: expr.PayloadBaseNetworkHeader, Offset: saddrOff, Len: saddrLen},
		&expr.Lookup{SourceRegister: 1, SetName: spec.sourceSet},
		&expr.Meta{Key: expr.MetaKeyL4PROTO, Register: 1},
		&expr.Cmp{Op: expr.CmpOpEq, Register: 1, Data: []byte{spec.proto}},
		&expr.Payload{DestRegister: 1, Base: expr.PayloadBaseTransportHeader, Offset: 2, Len: 2},
		&expr.Cmp{Op: expr.CmpOpEq, Register: 1, Data: dport},
	}
	regProto := uint32(1)
	if addr := dnatAddrBytes(spec); len(addr) > 0 {
		exprs = append(exprs, &expr.Immediate{Register: 1, Data: addr}, &expr.Immediate{Register: 2, Data: toPort}, &expr.NAT{Type: expr.NATTypeDestNAT, Family: uint32(spec.family), RegAddrMin: 1, RegProtoMin: 2})
		return exprs
	}
	exprs = append(exprs, &expr.Immediate{Register: 1, Data: toPort}, &expr.NAT{Type: expr.NATTypeDestNAT, Family: uint32(spec.family), RegProtoMin: regProto})
	return exprs
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
	httpHost, httpPort, okHTTP := parseListenHostPort(httpListen)
	httpsHost, httpsPort, okHTTPS := parseListenHostPort(httpsListen)
	if !okHTTP {
		httpPort = defaultWebDNATHTTPPort
	}
	if !okHTTPS {
		httpsPort = defaultWebDNATHTTPSPort
	}
	return b.dnatOnScoped("", "", httpHost, httpPort, httpsHost, httpsPort)
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
	return fmt.Sprintf("%s_%s_%s", portName, dnatFamilyPrefix(spec.family), dnatAcceptProtoName(spec.proto))
}

func dnatAcceptProtoName(proto uint8) string {
	if proto == 17 {
		return "udp"
	}
	return "tcp"
}

func dnatWantedSpecs(httpHost string, httpPort int, httpsHost string, httpsPort int) []dnatRuleSpec {
	var specs []dnatRuleSpec
	addListener := func(host string, dport uint16, proto uint8, toPort int) {
		if toPort < 1 {
			return
		}
		if toPort > 65535 {
			return
		}
		toPort16 := uint16(toPort)
		for _, fam := range []nftables.TableFamily{nftables.TableFamilyIPv4, nftables.TableFamilyIPv6} {
			addr, ok := dnatTargetAddr(host, fam)
			if !ok {
				continue
			}
			sets := []string{setChalV4, "self_v4"}
			if fam == nftables.TableFamilyIPv6 {
				sets = []string{setChalV6, "self_v6"}
			}
			for _, setName := range sets {
				specs = append(specs, dnatRuleSpec{family: fam, proto: proto, dport: dport, toPort: toPort16, sourceSet: setName, toAddr: addr})
			}
		}
	}
	addListener(httpHost, 80, 6, httpPort)
	addListener(httpsHost, 443, 6, httpsPort)
	addListener(httpsHost, 443, 17, httpsPort)
	return specs
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

func firstInputDefaultDropHandle(out string) string {
	for _, line := range strings.Split(out, "\n") {
		norm := strings.ReplaceAll(line, `"`, "")
		if !strings.Contains(norm, "ct state new") || !strings.Contains(norm, "dport 0-65535") || !strings.Contains(norm, " drop") || !strings.Contains(norm, " handle ") {
			continue
		}
		if !strings.Contains(norm, "tcp dport 0-65535") && !strings.Contains(norm, "udp dport 0-65535") {
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

func dnatAcceptRuleExpr(spec dnatRuleSpec, beforeHandle ...string) string {
	proto := "tcp"
	if spec.proto == 17 {
		proto = "udp"
	}
	prefix := "add rule inet cfm input"
	if len(beforeHandle) > 0 && strings.TrimSpace(beforeHandle[0]) != "" {
		prefix = "insert rule inet cfm input position " + strings.TrimSpace(beforeHandle[0])
	}
	expr := fmt.Sprintf(`%s ct state new ct status dnat ct original proto-dst %d %s %s dport %d accept comment "%s"`, prefix, spec.dport, dnatDaddrMatch(spec), proto, spec.toPort, dnatAcceptComment(dnatAcceptLabel(spec), int(spec.dport), int(spec.toPort)))
	return strings.Join(strings.Fields(expr), " ")
}

func (b *Backend) ensureScopedDNATAccepts(specs []dnatRuleSpec) error {
	_ = b.nftExec("add table inet cfm")
	_ = b.nftExec("add chain inet cfm input { type filter hook input priority 0; policy accept; }")
	out, _ := b.ListChainText("inet", "cfm", "input")
	beforeHandle := firstInputDefaultDropHandle(out)
	if err := b.cleanupScopedDNATAccepts(); err != nil {
		return err
	}
	seen := make(map[string]struct{})
	for _, spec := range specs {
		key := dnatAcceptKey(spec)
		if _, ok := seen[key]; ok {
			continue
		}
		seen[key] = struct{}{}
		if err := b.nftExec(dnatAcceptRuleExpr(spec, beforeHandle)); err != nil {
			return err
		}
	}
	return nil
}

func (b *Backend) DNATOn(family, table string, httpPort, httpsPort int) (err error) {
	return b.dnatOnScoped(family, table, "", httpPort, "", httpsPort)
}

func (b *Backend) dnatOnScoped(family, table, httpHost string, httpPort int, httpsHost string, httpsPort int) (err error) {
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
	if httpPort <= 0 || httpsPort <= 0 || httpPort > 65535 || httpsPort > 65535 {
		return fmt.Errorf("invalid ports: http=%d https=%d", httpPort, httpsPort)
	}
	if err := b.EnsureBase(); err != nil {
		return err
	}
	wanted := dnatWantedSpecs(httpHost, httpPort, httpsHost, httpsPort)
	if len(wanted) == 0 {
		return nil
	}
	if err := b.ensureScopedDNATAccepts(wanted); err != nil {
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
		b.conn.AddChain(ch)
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

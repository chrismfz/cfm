//go:build linux

package nftlib

import (
	"bytes"
	"fmt"
	"sort"
	"strings"

	"github.com/google/nftables"
	"github.com/google/nftables/expr"
)

const (
	dnatRuleTag = "cfm-dnat-managed"
)

type dnatRuleSpec struct {
	proto  uint8
	dport  uint16
	toPort uint16
}

func (s dnatRuleSpec) id() string {
	return fmt.Sprintf("%s:v1:p%d:d%d:t%d", dnatRuleTag, s.proto, s.dport, s.toPort)
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

func (b *Backend) EnsureChallengeRedirect(httpListen, httpsListen string) error {
	if !b.challengeRedirectEnabled {
		return b.CleanupChallengeRedirect()
	}
	return b.DNATOn("", "", 9080, 9043)
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
		for _, spec := range []dnatRuleSpec{
			{proto: 6, dport: 80, toPort: 9080},
			{proto: 6, dport: 443, toPort: 9043},
			{proto: 17, dport: 443, toPort: 9043},
		} {
			if dnatRuleMatches(r, spec) {
				found = append(found, spec)
				break
			}
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
	out.WriteString("    type nat hook prerouting priority dstnat; policy accept;\n\n")
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

func (b *Backend) DNATOn(family, table string, httpPort, httpsPort int) error {
	family, table = dnatDefaults(family, table)
	if httpPort <= 0 || httpsPort <= 0 {
		return fmt.Errorf("invalid ports: http=%d https=%d", httpPort, httpsPort)
	}
	b.mu.Lock()
	defer b.mu.Unlock()
	t, ch, err := b.getDNATTableAndChain(family, table)
	if err != nil {
		return err
	}
	if ch == nil {
		b.conn.AddTable(t)
		dstNat := *nftables.ChainPriorityNATDest
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

func (b *Backend) DNATOff(family, table string) error {
	b.mu.Lock()
	defer b.mu.Unlock()
	return b.dnatOffUnlocked(family, table)
}

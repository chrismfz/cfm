//go:build linux

package nftlib

import (
	"fmt"
	"strings"

	"github.com/google/nftables"
	"github.com/google/nftables/expr"
)

const (
	dnatRuleTag = "cfm-dnat-managed"
)

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
	b.challengeRedirectEnabled = enabled
	b.mu.Unlock()
	if !enabled {
		_ = b.CleanupChallengeRedirect()
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
	_, ch, err := b.getDNATTableAndChain(family, table)
	if err != nil || ch == nil {
		return false, err
	}
	rules, err := b.conn.GetRules(ch.Table, ch)
	if err != nil {
		return false, err
	}
	for _, r := range rules {
		if string(r.UserData) == dnatRuleTag {
			return true, nil
		}
	}
	return false, nil
}

func (b *Backend) DNATShow(family, table string) (string, error) {
	on, err := b.DNATStatus(family, table)
	if err != nil {
		return "", err
	}
	if on {
		return "cfm dnat: on", nil
	}
	return "cfm dnat: off", nil
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
	// idempotent: rely on stable comment tag identity.
	rules, _ := b.conn.GetRules(t, ch)
	for _, r := range rules {
		if string(r.UserData) == dnatRuleTag {
			return nil
		}
	}
	addRule := func(proto uint8, dport, toPort uint16) {
		b.conn.AddRule(&nftables.Rule{
			Table: t, Chain: ch,
			Exprs: []expr.Any{
				&expr.Meta{Key: expr.MetaKeyIIFNAME, Register: 1},
				&expr.Cmp{Op: expr.CmpOpEq, Register: 1, Data: []byte{'l', 'o', 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0}},
				&expr.Counter{},
				&expr.Verdict{Kind: expr.VerdictAccept},
			},
		})
		b.conn.AddRule(&nftables.Rule{Table: t, Chain: ch, UserData: []byte(dnatRuleTag), Exprs: []expr.Any{
			&expr.Meta{Key: expr.MetaKeyL4PROTO, Register: 1},
			&expr.Cmp{Op: expr.CmpOpEq, Register: 1, Data: []byte{proto}},
			&expr.Payload{DestRegister: 1, Base: expr.PayloadBaseTransportHeader, Offset: 2, Len: 2},
			&expr.Cmp{Op: expr.CmpOpEq, Register: 1, Data: []byte{byte(dport >> 8), byte(dport)}},
			&expr.NAT{Type: expr.NATTypeDestNAT, Family: uint32(nftables.TableFamilyIPv4), RegAddrMin: 0, RegProtoMin: 1},
			&expr.Immediate{Register: 1, Data: []byte{byte(toPort >> 8), byte(toPort)}},
		}})
	}
	addRule(6, 80, uint16(httpPort))
	addRule(6, 443, uint16(httpsPort))
	addRule(17, 443, uint16(httpsPort))
	return b.conn.Flush()
}

func (b *Backend) DNATOff(family, table string) error {
	family, table = dnatDefaults(family, table)
	b.mu.Lock()
	defer b.mu.Unlock()
	_, ch, err := b.getDNATTableAndChain(family, table)
	if err != nil || ch == nil {
		return err
	}
	rules, err := b.conn.GetRules(ch.Table, ch)
	if err != nil {
		return err
	}
	for _, r := range rules {
		if string(r.UserData) == dnatRuleTag {
			b.conn.DelRule(r)
		}
	}
	return b.conn.Flush()
}

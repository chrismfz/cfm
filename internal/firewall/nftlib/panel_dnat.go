//go:build linux

package nftlib

import (
	"bytes"
	"fmt"
	"sort"
	"strings"
	"time"

	"cfm/internal/firewall"

	"github.com/google/nftables"
	"github.com/google/nftables/binaryutil"
	"github.com/google/nftables/expr"
)

const (
	panelDNATTableName             = "cfm_panel_redirect"
	panelDNATAcceptUserData        = "cfm_cpanel_dnat"
	ctStatusDNAT            uint32 = 1 << 5
)

func panelDNATSpecs() []dnatRuleSpec {
	maps := firewall.PanelDNATMappings()
	specs := make([]dnatRuleSpec, 0, len(maps))
	for _, m := range maps {
		specs = append(specs, dnatRuleSpec{family: nftables.TableFamilyINet, proto: 6, dport: uint16(m.From), toPort: uint16(m.To)})
	}
	return specs
}

func panelDNATAcceptID(from, to int) string {
	return fmt.Sprintf("%s:%d:%d", panelDNATAcceptUserData, from, to)
}

func (b *Backend) PanelDNATOn(priority int) (err error) {
	start := time.Now()
	b.logPhase("PanelDNATOn", "start", 0, nil, fmt.Sprintf("op=dnat scope=cpanel priority=%d", priority))
	defer func() {
		st := "ok"
		if err != nil {
			st = "fail"
		}
		b.logPhase("PanelDNATOn", st, time.Since(start), err, fmt.Sprintf("op=dnat scope=cpanel priority=%d", priority))
	}()
	if priority < -300 {
		priority = -300
	}
	if priority > 300 {
		priority = 300
	}
	b.mu.Lock()
	defer b.mu.Unlock()
	t := &nftables.Table{Name: panelDNATTableName, Family: nftables.TableFamilyINet}
	if old, err := b.findTable(panelDNATTableName, nftables.TableFamilyINet); err == nil && old != nil {
		b.conn.DelTable(old)
		if err := b.conn.Flush(); err != nil {
			return err
		}
	}
	prio := nftables.ChainPriority(priority)
	policy := nftables.ChainPolicyAccept
	ch := &nftables.Chain{Name: "prerouting", Table: t, Type: nftables.ChainTypeNAT, Hooknum: nftables.ChainHookPrerouting, Priority: &prio, Policy: &policy}
	b.conn.AddTable(t)
	b.conn.AddChain(ch)
	b.conn.AddRule(&nftables.Rule{Table: t, Chain: ch, UserData: []byte(dnatLoopbackAcceptTag), Exprs: dnatLoopbackAcceptExprs()})
	// Source-IP bypass: peers in /etc/cfm/cfm.dnat_cpanel_bypass skip the
	// cPanel panel DNAT entirely. Added BETWEEN the loopback accept rule
	// and the dport DNAT rules so nftables first-match-wins guarantees
	// the bypass short-circuits before NAT translation runs. Since
	// PanelDNATOn rebuilds the table from scratch on every call, the
	// fresh add-order here is also the eval-order in the running chain.
	if _, warnings := b.dnatBypassAddRules(t, ch, firewall.DNATBypassScopeCpanel); len(warnings) > 0 {
		for _, w := range warnings {
			b.logPhase("PanelDNATOn", "warn", 0, nil, fmt.Sprintf("bypass entry: %s", w))
		}
	}
	for _, spec := range panelDNATSpecs() {
		b.conn.AddRule(&nftables.Rule{Table: t, Chain: ch, UserData: []byte(spec.id()), Exprs: dnatRuleExprs(spec)})
	}
	return b.conn.Flush()
}

func (b *Backend) PanelDNATOff() (err error) {
	start := time.Now()
	b.logPhase("PanelDNATOff", "start", 0, nil, "op=dnat scope=cpanel")
	defer func() {
		st := "ok"
		if err != nil {
			st = "fail"
		}
		b.logPhase("PanelDNATOff", st, time.Since(start), err, "op=dnat scope=cpanel")
	}()
	b.mu.Lock()
	defer b.mu.Unlock()
	t, ferr := b.findTable(panelDNATTableName, nftables.TableFamilyINet)
	if ferr != nil || t == nil {
		return ferr
	}
	b.conn.DelTable(t)
	return b.conn.Flush()
}

func (b *Backend) PanelDNATStatus() (bool, string, error) {
	b.mu.Lock()
	defer b.mu.Unlock()
	t, ch, err := b.getPanelDNATTableAndChain()
	if err != nil || ch == nil {
		return false, "", err
	}
	rules, err := b.conn.GetRules(t, ch)
	if err != nil {
		return false, "", err
	}
	if len(rules) == 0 {
		return false, "", nil
	}
	return true, panelDNATShowText(rules, b.dnatPriority()), nil
}

func panelDNATShowText(rules []*nftables.Rule, priority int) string {
	var out strings.Builder
	out.WriteString("table inet cfm_panel_redirect {\n")
	out.WriteString("  chain prerouting {\n")
	fmt.Fprintf(&out, "    type nat hook prerouting priority %d; policy accept;\n\n", priority)
	for _, r := range rules {
		if dnatLoopbackAcceptMatches(r) {
			out.WriteString("    iif \"lo\" accept\n")
			continue
		}
		spec, ok := parseDNATRuleSpecID(string(r.UserData))
		if ok && dnatRuleMatches(r, spec) {
			fmt.Fprintf(&out, "    %s\n", dnatShowRuleLine(spec))
		}
	}
	out.WriteString("  }\n}\n")
	return out.String()
}

func (b *Backend) getPanelDNATTableAndChain() (*nftables.Table, *nftables.Chain, error) {
	t := &nftables.Table{Name: panelDNATTableName, Family: nftables.TableFamilyINet}
	chains, err := b.conn.ListChains()
	if err != nil {
		return nil, nil, err
	}
	for _, ch := range chains {
		if ch.Table != nil && ch.Table.Name == panelDNATTableName && ch.Table.Family == nftables.TableFamilyINet && ch.Name == "prerouting" {
			return t, ch, nil
		}
	}
	return t, nil, nil
}

func (b *Backend) findTable(name string, family nftables.TableFamily) (*nftables.Table, error) {
	tables, err := b.conn.ListTables()
	if err != nil {
		return nil, err
	}
	for _, t := range tables {
		if t.Name == name && t.Family == family {
			return t, nil
		}
	}
	return nil, nil
}

func (b *Backend) EnsurePanelDNATAccepts() ([]string, error) {
	return b.setPanelDNATAccepts(true)
}

func (b *Backend) RemovePanelDNATAccepts() ([]string, error) {
	return b.setPanelDNATAccepts(false)
}

func (b *Backend) setPanelDNATAccepts(enable bool) ([]string, error) {
	b.mu.Lock()
	defer b.mu.Unlock()
	t, ch, err := b.ensureCFMInputChainUnlocked()
	if err != nil {
		return nil, err
	}
	rules, err := b.conn.GetRules(t, ch)
	if err != nil {
		return nil, err
	}
	changes := []string{}
	existing := map[string]*nftables.Rule{}
	for _, r := range rules {
		if strings.HasPrefix(string(r.UserData), panelDNATAcceptUserData+":") {
			existing[string(r.UserData)] = r
		}
	}
	for _, r := range existing {
		b.conn.DelRule(r)
	}
	for _, m := range firewall.PanelDNATMappings() {
		id := panelDNATAcceptID(m.From, m.To)
		_, had := existing[id]
		if enable {
			b.conn.InsertRule(&nftables.Rule{Table: t, Chain: ch, UserData: []byte(id), Exprs: panelDNATAcceptExprs(m.From, m.To)})
			if !had {
				changes = append(changes, fmt.Sprintf("opened scoped %d->%d (nft cfm/input)", m.From, m.To))
			}
		} else {
			if had {
				changes = append(changes, fmt.Sprintf("scoped %d->%d removed", m.From, m.To))
			} else {
				changes = append(changes, fmt.Sprintf("scoped %d->%d not found", m.From, m.To))
			}
		}
	}
	sort.Strings(changes)
	return changes, b.conn.Flush()
}

func (b *Backend) ensureCFMInputChainUnlocked() (*nftables.Table, *nftables.Chain, error) {
	t := &nftables.Table{Name: cfmTableName, Family: nftables.TableFamilyINet}
	chains, err := b.conn.ListChains()
	if err != nil {
		return nil, nil, err
	}
	for _, ch := range chains {
		if ch.Table != nil && ch.Table.Name == cfmTableName && ch.Table.Family == nftables.TableFamilyINet && ch.Name == "input" {
			return t, ch, nil
		}
	}
	if existing, err := b.findTable(cfmTableName, nftables.TableFamilyINet); err == nil && existing != nil {
		t = existing
	} else if err != nil {
		return nil, nil, err
	} else {
		b.conn.AddTable(t)
	}
	prio := nftables.ChainPriority(0)
	policy := nftables.ChainPolicyAccept
	ch := &nftables.Chain{Name: "input", Table: t, Type: nftables.ChainTypeFilter, Hooknum: nftables.ChainHookInput, Priority: &prio, Policy: &policy}
	b.conn.AddChain(ch)
	if err := b.conn.Flush(); err != nil {
		return nil, nil, err
	}
	return t, ch, nil
}

func panelDNATAcceptExprs(from, to int) []expr.Any {
	orig := make([]byte, 2)
	// Conntrack proto-src/proto-dst values are transport ports in network byte order.
	orig[0], orig[1] = byte(from>>8), byte(from)
	dport := make([]byte, 2)
	dport[0], dport[1] = byte(to>>8), byte(to)
	return []expr.Any{
		&expr.Ct{Register: 1, Key: expr.CtKeySTATE},
		&expr.Bitwise{SourceRegister: 1, DestRegister: 1, Len: 4, Mask: binaryutil.NativeEndian.PutUint32(expr.CtStateBitNEW), Xor: binaryutil.NativeEndian.PutUint32(0)},
		&expr.Cmp{Op: expr.CmpOpNeq, Register: 1, Data: binaryutil.NativeEndian.PutUint32(0)},
		&expr.Ct{Register: 1, Key: expr.CtKeySTATUS},
		&expr.Bitwise{SourceRegister: 1, DestRegister: 1, Len: 4, Mask: binaryutil.NativeEndian.PutUint32(ctStatusDNAT), Xor: binaryutil.NativeEndian.PutUint32(0)},
		&expr.Cmp{Op: expr.CmpOpNeq, Register: 1, Data: binaryutil.NativeEndian.PutUint32(0)},
		&expr.Ct{Register: 1, Key: expr.CtKeyPROTODST, Direction: 0},
		&expr.Cmp{Op: expr.CmpOpEq, Register: 1, Data: orig},
		&expr.Meta{Key: expr.MetaKeyL4PROTO, Register: 1},
		&expr.Cmp{Op: expr.CmpOpEq, Register: 1, Data: []byte{6}},
		&expr.Payload{DestRegister: 1, Base: expr.PayloadBaseTransportHeader, Offset: 2, Len: 2},
		&expr.Cmp{Op: expr.CmpOpEq, Register: 1, Data: dport},
		&expr.Verdict{Kind: expr.VerdictAccept},
	}
}

func panelDNATAcceptMatches(r *nftables.Rule, from, to int) bool {
	if string(r.UserData) != panelDNATAcceptID(from, to) {
		return false
	}
	want := panelDNATAcceptExprs(from, to)
	if len(r.Exprs) != len(want) {
		return false
	}
	for i := range want {
		switch w := want[i].(type) {
		case *expr.Ct:
			g, ok := r.Exprs[i].(*expr.Ct)
			if !ok || g.Key != w.Key || g.Register != w.Register || g.Direction != w.Direction {
				return false
			}
		case *expr.Bitwise:
			g, ok := r.Exprs[i].(*expr.Bitwise)
			if !ok || g.SourceRegister != w.SourceRegister || g.DestRegister != w.DestRegister || g.Len != w.Len || !bytes.Equal(g.Mask, w.Mask) || !bytes.Equal(g.Xor, w.Xor) {
				return false
			}
		case *expr.Cmp:
			g, ok := r.Exprs[i].(*expr.Cmp)
			if !ok || g.Op != w.Op || g.Register != w.Register || !bytes.Equal(g.Data, w.Data) {
				return false
			}
		case *expr.Meta:
			g, ok := r.Exprs[i].(*expr.Meta)
			if !ok || g.Key != w.Key || g.Register != w.Register {
				return false
			}
		case *expr.Payload:
			g, ok := r.Exprs[i].(*expr.Payload)
			if !ok || g.DestRegister != w.DestRegister || g.Base != w.Base || g.Offset != w.Offset || g.Len != w.Len {
				return false
			}
		case *expr.Verdict:
			g, ok := r.Exprs[i].(*expr.Verdict)
			if !ok || g.Kind != w.Kind {
				return false
			}
		}
	}
	return true
}

func (b *Backend) PanelDNATAcceptState() map[int]string {
	state := map[int]string{}
	for _, m := range firewall.PanelDNATMappings() {
		state[m.To] = "unknown"
	}
	b.mu.Lock()
	defer b.mu.Unlock()
	t := &nftables.Table{Name: cfmTableName, Family: nftables.TableFamilyINet}
	chains, err := b.conn.ListChains()
	if err != nil {
		return state
	}
	var ch *nftables.Chain
	for _, c := range chains {
		if c.Table != nil && c.Table.Name == cfmTableName && c.Name == "input" {
			ch = c
			break
		}
	}
	if ch == nil {
		return state
	}
	rules, err := b.conn.GetRules(t, ch)
	if err != nil {
		return state
	}
	for _, m := range firewall.PanelDNATMappings() {
		state[m.To] = "blocked"
		for _, r := range rules {
			if panelDNATAcceptMatches(r, m.From, m.To) {
				state[m.To] = "open"
				break
			}
		}
	}
	return state
}

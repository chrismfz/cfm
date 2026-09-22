//go:build linux

package nftlib

import (
	"encoding/binary"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"strings"
	"sync/atomic"
	"testing"

	"github.com/google/nftables"
	"github.com/mdlayher/netlink"
	"golang.org/x/sys/unix"

	"cfm/internal/firewall"
	"cfm/internal/firewall/selfip"
)

// fakeNFT puts an `nft` script first in PATH for this test, so the CLI side of
// the backend never touches the host's ruleset. It logs every invocation (its
// args, then any script it was fed on stdin) and answers
// `nft -a list chain inet cfm input` with listing.
func fakeNFT(t *testing.T, listing string) (logPath string) {
	t.Helper()
	return fakeNFTFailing(t, listing, "")
}

// fakeNFTFailing is fakeNFT, but a script (`nft -f -`) containing failOn
// exits 1, as a rule deleted meanwhile by another writer would.
func fakeNFTFailing(t *testing.T, listing, failOn string) (logPath string) {
	t.Helper()
	dir := t.TempDir()
	logPath = filepath.Join(dir, "nft.log")
	listPath := filepath.Join(dir, "listing")
	if err := os.WriteFile(listPath, []byte(listing), 0o600); err != nil {
		t.Fatal(err)
	}
	script := fmt.Sprintf(`#!/bin/sh
echo "ARGS $*" >> %[1]q
if [ "$1" = "-f" ]; then
	in=$(cat); printf '%%s\n' "$in" >> %[1]q
	if [ -n %[3]q ] && printf '%%s' "$in" | grep -qF %[3]q; then exit 1; fi
	exit 0
fi
if [ "$*" = "-a list chain inet cfm input" ]; then cat %[2]q; exit 0; fi
exit 0
`, logPath, listPath, failOn)
	if err := os.WriteFile(filepath.Join(dir, "nft"), []byte(script), 0o700); err != nil { // #nosec G306 -- test helper must be executable
		t.Fatal(err)
	}
	t.Setenv("PATH", dir+string(os.PathListSeparator)+os.Getenv("PATH"))
	return logPath
}

func readLog(t *testing.T, path string) string {
	t.Helper()
	b, err := os.ReadFile(path) // #nosec G304 -- test temp file
	if err != nil && !os.IsNotExist(err) {
		t.Fatal(err)
	}
	return string(b)
}

// An input chain as the old netlink writer left it: untagged panel accepts,
// rendered the way older nft shows them, before the default drop.
func legacyPanelChain() string {
	var b strings.Builder
	b.WriteString("table inet cfm {\n\tchain input { # handle 1\n\t\ttype filter hook input priority filter; policy accept;\n")
	h := 10
	for _, m := range firewall.PanelDNATMappings() {
		fmt.Fprintf(&b, "\t\tct state new ct status dnat ct original proto-dst %#x [invalid type] tcp dport %d accept # handle %d\n", m.From, m.To, h)
		h++
	}
	b.WriteString("\t\tct state new tcp dport 0-65535 drop # handle 5\n\t}\n}\n")
	return b.String()
}

// Panel accepts must go through the nft CLI: google/nftables can't decode
// the `ct original proto-dst` match they carry, so a netlink read of inet
// cfm/input fails once any exists (reproduced on a real kernel: the second
// EnsurePanelDNATAccepts returned "attribute 3 is not a uint32", and the
// state read "unknown" for every port).
func TestPanelDNATAccepts_UseNFTTextNotNetlink(t *testing.T) {
	var nlCalls atomic.Int32
	b := nlBackend(t, func([]netlink.Message) ([]netlink.Message, error) {
		nlCalls.Add(1)
		return nil, fmt.Errorf("netlink: attribute 3 is not a uint32; length: 1")
	})
	log := fakeNFT(t, legacyPanelChain())

	for port, st := range b.PanelDNATAcceptState() {
		if st != "open" {
			t.Errorf("port %d: %q, want open (a legacy accept before the drop admits traffic)", port, st)
		}
	}

	changes, err := b.EnsurePanelDNATAccepts()
	if err != nil {
		t.Fatalf("EnsurePanelDNATAccepts: %v", err)
	}
	if len(changes) != len(firewall.PanelDNATMappings()) {
		t.Errorf("changes = %q, want every legacy accept re-created", changes)
	}
	got := readLog(t, log)
	for _, m := range firewall.PanelDNATMappings() {
		if want := fmt.Sprintf(`insert rule inet cfm input position 5 tcp dport %d ct state new ct status dnat ct original proto-dst %d accept comment "%s"`,
			m.To, m.From, firewall.PanelDNATAcceptComment(m.From, m.To)); !strings.Contains(got, want) {
			t.Errorf("missing %q in nft log:\n%s", want, got)
		}
	}
	if n := strings.Count(got, "delete rule inet cfm input handle "); n != len(firewall.PanelDNATMappings()) {
		t.Errorf("%d deletes, want one per legacy accept:\n%s", n, got)
	}

	if _, err := b.RemovePanelDNATAccepts(); err != nil {
		t.Fatalf("RemovePanelDNATAccepts: %v", err)
	}
	if n := nlCalls.Load(); n != 0 {
		t.Fatalf("%d netlink calls; the panel accepts must be handled through nft text only", n)
	}
}

// EnsureDNATAccepts must look for the web redirect in cfm_redirect, the table
// `cfm dnat on` uses. It used to default to "cfm", found no prerouting chain
// there, and silently never reasserted the web accepts.
func TestEnsureDNATAccepts_ReadsTheRedirectTable(t *testing.T) {
	var readTable string
	b := nlBackend(t, func(req []netlink.Message) ([]netlink.Message, error) {
		switch nftMsgType(req[0]) {
		case unix.NFT_MSG_GETCHAIN:
			m := chainMsg(firewall.DNATDefaultTable, "prerouting")
			m.Header.Sequence = req[0].Header.Sequence
			return []netlink.Message{m}, nil
		case unix.NFT_MSG_GETRULE:
			ad, err := netlink.NewAttributeDecoder(req[0].Data[4:])
			if err != nil {
				t.Fatal(err)
			}
			for ad.Next() {
				if ad.Type() == unix.NFTA_RULE_TABLE {
					readTable = ad.String()
				}
			}
			return nil, io.EOF
		}
		return nil, io.EOF
	})
	fakeNFT(t, "")
	_ = b.EnsureDNATAccepts()
	if readTable != firewall.DNATDefaultTable {
		t.Fatalf("read the prerouting rules of table %q, want %q", readTable, firewall.DNATDefaultTable)
	}
}

func tableMsg(name string) netlink.Message {
	ae := netlink.NewAttributeEncoder()
	ae.String(unix.NFTA_TABLE_NAME, name)
	attrs, _ := ae.Encode()
	return netlink.Message{
		Header: netlink.Header{Type: netlink.HeaderType(unix.NFNL_SUBSYS_NFTABLES<<8 | unix.NFT_MSG_NEWTABLE)},
		Data:   append([]byte{unix.NFPROTO_INET, 0, 0, 0}, attrs...),
	}
}

// dnatOffBackend answers table/chain listings with table's prerouting chain
// and records whether a batch deleted a table.
func dnatOffBackend(t *testing.T, table string, deletedTable *bool) *Backend {
	return nlBackend(t, func(req []netlink.Message) ([]netlink.Message, error) {
		if isBatch(req) {
			for _, m := range req {
				if nftMsgType(m) == unix.NFT_MSG_DELTABLE {
					*deletedTable = true
				}
			}
			return nil, io.EOF
		}
		var m netlink.Message
		switch nftMsgType(req[0]) {
		case unix.NFT_MSG_GETTABLE:
			m = tableMsg(table)
		case unix.NFT_MSG_GETCHAIN:
			m = chainMsg(table, "prerouting")
		case unix.NFT_MSG_GETRULE:
			return nil, io.EOF
		default:
			return nil, io.EOF
		}
		m.Header.Sequence = req[0].Header.Sequence
		return []netlink.Message{m}, nil
	})
}

// DNATOff removes CFM's own redirect table whole, as the nft backend does, so
// a redirect nftlib didn't tag (e.g. the copy an exec-backend `cfm dnat on`
// wrote) can't keep redirecting while DNATStatus reports off.
func TestDNATOff_DeletesTheRedirectTable(t *testing.T) {
	fakeNFT(t, "")
	var deleted bool
	b := dnatOffBackend(t, firewall.DNATDefaultTable, &deleted)
	if err := b.DNATOff("", ""); err != nil {
		t.Fatalf("DNATOff: %v", err)
	}
	if !deleted {
		t.Fatal("DNATOff must delete the cfm_redirect table")
	}
}

// Any other table is not CFM's to delete: only the tagged rules go.
func TestDNATOff_CustomTableKeepsTheTable(t *testing.T) {
	fakeNFT(t, "")
	var deleted bool
	b := dnatOffBackend(t, "operator_nat", &deleted)
	_ = b.DNATOff("inet", "operator_nat")
	if deleted {
		t.Fatal("DNATOff deleted a table that is not cfm_redirect")
	}
}

// baseChainMsg is a dump entry for an inet base chain at prio.
func baseChainMsg(table, name string, hook *nftables.ChainHook, prio int32) netlink.Message {
	h := netlink.NewAttributeEncoder()
	h.ByteOrder = binary.BigEndian
	h.Uint32(unix.NFTA_HOOK_HOOKNUM, uint32(*hook))
	h.Uint32(unix.NFTA_HOOK_PRIORITY, uint32(prio))
	hb, _ := h.Encode()
	ae := netlink.NewAttributeEncoder()
	ae.String(unix.NFTA_CHAIN_TABLE, table)
	ae.String(unix.NFTA_CHAIN_NAME, name)
	ae.Bytes(unix.NLA_F_NESTED|unix.NFTA_CHAIN_HOOK, hb)
	attrs, _ := ae.Encode()
	return netlink.Message{
		Header: netlink.Header{Type: netlink.HeaderType(unix.NFNL_SUBSYS_NFTABLES<<8 | unix.NFT_MSG_NEWCHAIN)},
		Data:   append([]byte{unix.NFPROTO_INET, 0, 0, 0}, attrs...),
	}
}

// EnsureBase must not re-declare an input chain that already exists: with
// another priority the kernel rejects the whole batch (EOPNOTSUPP, seen on a
// real kernel), which failed every later EnsureBase and DNATOn. A one-shot
// `cfm dnat on` builds its backend with no config, so its priority is the
// -50 default whatever NFT_INPUT_PRIORITY the chain was created with.
func TestEnsureBase_KeepsAnExistingInputChain(t *testing.T) {
	fakeNFT(t, "")
	var declaredInput bool
	b := nlBackend(t, func(req []netlink.Message) ([]netlink.Message, error) {
		if isBatch(req) {
			for _, m := range req {
				if nftMsgType(m) != unix.NFT_MSG_NEWCHAIN {
					continue
				}
				ad, _ := netlink.NewAttributeDecoder(m.Data[4:])
				for ad.Next() {
					if ad.Type() == unix.NFTA_CHAIN_NAME && ad.String() == "input" {
						declaredInput = true
					}
				}
			}
			return nil, io.EOF
		}
		if nftMsgType(req[0]) == unix.NFT_MSG_GETCHAIN {
			m := baseChainMsg(cfmTableName, "input", nftables.ChainHookInput, 50)
			m.Header.Sequence = req[0].Header.Sequence
			return []netlink.Message{m}, nil
		}
		return nil, io.EOF
	})
	b.selfResolver = selfip.New()
	if err := b.EnsureBase(); err != nil {
		t.Fatalf("EnsureBase: %v", err)
	}
	if declaredInput {
		t.Fatal("EnsureBase re-declared the existing input chain; with another priority that fails the whole batch")
	}
}

// ruleMsg is a dump entry for one rule of table/chain, tagged with userData
// (nil = a rule this backend didn't write).
func ruleMsg(table, chain string, handle uint64, userData []byte) netlink.Message {
	ae := netlink.NewAttributeEncoder()
	ae.String(unix.NFTA_RULE_TABLE, table)
	ae.String(unix.NFTA_RULE_CHAIN, chain)
	ae.Uint64(unix.NFTA_RULE_HANDLE, handle)
	if userData != nil {
		ae.Bytes(unix.NFTA_RULE_USERDATA, userData)
	}
	attrs, _ := ae.Encode()
	return netlink.Message{
		Header: netlink.Header{Type: netlink.HeaderType(unix.NFNL_SUBSYS_NFTABLES<<8 | unix.NFT_MSG_NEWRULE)},
		Data:   append([]byte{unix.NFPROTO_INET, 0, 0, 0}, attrs...),
	}
}

// dnatPrioBackend serves a prerouting chain of table at livePrio holding
// rules, and records the message types of each batch (transaction) sent.
func dnatPrioBackend(t *testing.T, table string, livePrio int32, rules []netlink.Message, batches *[][]int) *Backend {
	return nlBackend(t, func(req []netlink.Message) ([]netlink.Message, error) {
		if len(req) == 0 {
			return nil, io.EOF
		}
		if isBatch(req) {
			var types []int
			for _, m := range req {
				types = append(types, nftMsgType(m))
			}
			*batches = append(*batches, types)
			return nil, io.EOF
		}
		seq := req[0].Header.Sequence
		switch nftMsgType(req[0]) {
		case unix.NFT_MSG_GETCHAIN:
			m := baseChainMsg(table, "prerouting", nftables.ChainHookPrerouting, livePrio)
			m.Header.Sequence = seq
			return []netlink.Message{m}, nil
		case unix.NFT_MSG_GETRULE:
			var out []netlink.Message
			for _, r := range rules {
				r.Header.Sequence = seq
				r.Header.Flags = netlink.Multi
				out = append(out, r)
			}
			return append(out, netlink.Message{Header: netlink.Header{Type: netlink.Done, Flags: netlink.Multi, Sequence: seq}}), nil
		}
		return nil, io.EOF
	})
}

func contains(xs []int, x int) bool { return index(xs, x) >= 0 }

func index(xs []int, x int) int {
	for i, v := range xs {
		if v == x {
			return i
		}
	}
	return -1
}

func count(xs []int, x int) (n int) {
	for _, v := range xs {
		if v == x {
			n++
		}
	}
	return n
}

// hermeticBypass points the web bypass list at a temp file with one entry,
// so tests never read the host's /etc/cfm/cfm.dnat_bypass.
func hermeticBypass(t *testing.T) {
	t.Helper()
	path := filepath.Join(t.TempDir(), "cfm.dnat_bypass")
	if err := os.WriteFile(path, []byte("192.0.2.55\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	orig := firewall.DNATBypassWebPath
	firewall.DNATBypassWebPath = path
	t.Cleanup(func() { firewall.DNATBypassWebPath = orig })
}

// CFM's own table is rebuilt whole, in ONE batch (delete first, then the
// table, chain, loopback, bypass and 3 DNAT rules), whenever a rule-by-rule
// update can't produce the wanted chain:
//   - the priority differs: it can't change in place, so `cfm dnat on
//     --priority X` used to keep the old one while reporting X;
//   - the chain holds a rule nftlib didn't write, e.g. the nft backend's form
//     of the redirect, which sits ahead of ours and keeps winning.
func TestDNATOn_RebuildsTheRedirectTableWhenNeeded(t *testing.T) {
	fakeNFT(t, "")
	hermeticBypass(t)
	t.Setenv("NFT_DNAT_PRIORITY", "-101")
	wanted := dnatUnscopedWantedSpecs(nftables.TableFamilyINet, 9080, 9043)
	tbl := firewall.DNATDefaultTable
	foreign := []netlink.Message{ruleMsg(tbl, "prerouting", 4, nil)}
	managed := []netlink.Message{ruleMsg(tbl, "prerouting", 4, []byte(dnatLoopbackAcceptTag))}
	stale := dnatRuleSpec{family: nftables.TableFamilyIPv4, proto: 6, dport: 80, toPort: 9080, sourceSet: "challenge_v4"}
	staleManaged := []netlink.Message{ruleMsg(tbl, "prerouting", 4, []byte(stale.id()))}

	for _, tc := range []struct {
		name    string
		table   string
		prio    int32
		rules   []netlink.Message
		rebuild bool
	}{
		{"priority -99 → -101", tbl, -99, nil, true},
		{"foreign rule at the wanted priority", tbl, -101, foreign, true},
		{"managed rule the rebuild wouldn't replace", tbl, -101, staleManaged, true},
		{"only our rules, wanted priority", tbl, -101, managed, false},
		{"another table, other priority", "operator_nat", -99, foreign, false},
	} {
		var batches [][]int
		b := dnatPrioBackend(t, tc.table, tc.prio, tc.rules, &batches)
		if err := b.installDNATRules("inet", tc.table, wanted, dnatRuleNamespaceEdge, true); err != nil {
			t.Fatalf("%s: installDNATRules: %v", tc.name, err)
		}
		deletes := 0
		for _, sent := range batches {
			deletes += count(sent, unix.NFT_MSG_DELTABLE)
		}
		if !tc.rebuild {
			if deletes > 0 {
				t.Errorf("%s: deleted the table; batches %v", tc.name, batches)
			}
			continue
		}
		// One transaction: a second one would leave a moment with no redirect.
		if len(batches) != 1 {
			t.Fatalf("%s: %d transactions, want the rebuild in exactly one; batches %v", tc.name, len(batches), batches)
		}
		sent := batches[0]
		del := index(sent, unix.NFT_MSG_DELTABLE)
		if del < 0 || del > index(sent, unix.NFT_MSG_NEWTABLE) || del > index(sent, unix.NFT_MSG_NEWCHAIN) {
			t.Errorf("%s: want the delete first, then the new table and chain; sent %v", tc.name, sent)
		}
		if n := count(sent, unix.NFT_MSG_NEWRULE); n != 5 {
			t.Errorf("%s: %d rules re-added, want 5 (loopback + 1 bypass + 3 DNAT); sent %v", tc.name, n, sent)
		}
	}
}

// `cfm flush` empties block_v4/block_v6. Deleting a set a rule references is
// refused (EBUSY), so the old delete-and-recreate failed on every nftlib node
// once the CLI ran nftlib; the elements are now flushed in place.
func TestFlushSet_FlushesElementsInPlace(t *testing.T) {
	var sent []int
	b := nlBackend(t, func(req []netlink.Message) ([]netlink.Message, error) {
		if isBatch(req) {
			for _, m := range req {
				sent = append(sent, nftMsgType(m))
			}
		}
		return nil, io.EOF
	})
	b.namedSets[setBlockV4] = &nftables.Set{Name: setBlockV4, Table: &nftables.Table{Name: cfmTableName, Family: nftables.TableFamilyINet}}
	if err := b.FlushSet("inet", cfmTableName, setBlockV4); err != nil {
		t.Fatalf("FlushSet: %v", err)
	}
	if contains(sent, unix.NFT_MSG_DELSET) || !contains(sent, unix.NFT_MSG_DELSETELEM) {
		t.Fatalf("want an element flush and no set delete; sent %v", sent)
	}
}

// DNATOff/DNATOn clean both engines' web accept tags, so accepts the exec
// backend wrote (e.g. an earlier `cfm dnat on` from the CLI) don't linger.
func TestCleanupScopedDNATAccepts_RemovesBothEnginesTags(t *testing.T) {
	log := fakeNFT(t, `table inet cfm {
	chain input { # handle 1
		tcp dport 9080 ct state new ct status dnat ct original proto-dst 80 accept comment "cfm_dnat_accept:web_http_tcp:80:9080" # handle 21
		tcp dport 9080 ct state new ct status dnat ct original proto-dst 80 accept comment "cfm_edge_dnat_accept:web_http_tcp:80:9080" # handle 22
		tcp dport 12083 ct state new ct status dnat ct original proto-dst 2083 accept comment "cfm_cpanel_dnat:2083:12083" # handle 23
	}
}
`)
	b := &Backend{}
	if err := b.cleanupScopedDNATAccepts(dnatAcceptNamespaceEdge); err != nil {
		t.Fatal(err)
	}
	got := readLog(t, log)
	for _, h := range []string{"21", "22"} {
		if !strings.Contains(got, "delete rule inet cfm input handle "+h+";") {
			t.Errorf("web accept handle %s not deleted:\n%s", h, got)
		}
	}
	if strings.Contains(got, "handle 23") {
		t.Errorf("deleted the panel accept:\n%s", got)
	}
}

// DNATOff removes the redirect before its accepts: in the other order, a
// redirect that then failed to go would drop every web connection at the
// default drop.
func TestDNATOff_RemovesTheRedirectBeforeItsAccepts(t *testing.T) {
	log := fakeNFT(t, `table inet cfm {
	chain input { # handle 1
		tcp dport 9080 ct state new ct status dnat ct original proto-dst 80 accept comment "cfm_edge_dnat_accept:web_http_tcp:80:9080" # handle 21
	}
}
`)
	var acceptsGoneFirst, deleted bool
	b := nlBackend(t, func(req []netlink.Message) ([]netlink.Message, error) {
		if len(req) == 0 {
			return nil, io.EOF
		}
		if isBatch(req) {
			deleted = true
			acceptsGoneFirst = strings.Contains(readLog(t, log), "delete rule")
			return nil, io.EOF
		}
		if nftMsgType(req[0]) == unix.NFT_MSG_GETTABLE {
			m := tableMsg(firewall.DNATDefaultTable)
			m.Header.Sequence = req[0].Header.Sequence
			return []netlink.Message{m}, nil
		}
		return nil, io.EOF
	})
	if err := b.DNATOff("", ""); err != nil {
		t.Fatalf("DNATOff: %v", err)
	}
	if !deleted || acceptsGoneFirst {
		t.Fatalf("table deleted=%v, accepts removed before it=%v; want the table first", deleted, acceptsGoneFirst)
	}
	if !strings.Contains(readLog(t, log), "delete rule inet cfm input handle 21;") {
		t.Fatalf("the accept was not removed afterwards:\n%s", readLog(t, log))
	}
}

// Once the redirect is gone its accepts match nothing, so a failed cleanup
// must not fail DNATOff: `cfm dnat off` would then skip persisting intent
// OFF, and the daemon's failsafe would turn DNAT back on ~10s later.
func TestDNATOff_LeftoverAcceptsAreNotAnError(t *testing.T) {
	log := fakeNFTFailing(t, `table inet cfm {
	chain input { # handle 1
		tcp dport 9080 ct state new ct status dnat ct original proto-dst 80 accept comment "cfm_edge_dnat_accept:web_http_tcp:80:9080" # handle 21
	}
}
`, "delete rule")
	var deleted bool
	b := dnatOffBackend(t, firewall.DNATDefaultTable, &deleted)
	if err := b.DNATOff("", ""); err != nil {
		t.Fatalf("DNATOff: %v; a leftover accept is inert once the redirect is gone", err)
	}
	if !deleted || !strings.Contains(readLog(t, log), "delete rule inet cfm input handle 21") {
		t.Fatalf("want the table deleted and the accept delete attempted (deleted=%v):\n%s", deleted, readLog(t, log))
	}
}

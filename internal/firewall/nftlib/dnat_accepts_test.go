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
	dir := t.TempDir()
	logPath = filepath.Join(dir, "nft.log")
	listPath := filepath.Join(dir, "listing")
	if err := os.WriteFile(listPath, []byte(listing), 0o600); err != nil {
		t.Fatal(err)
	}
	script := fmt.Sprintf(`#!/bin/sh
echo "ARGS $*" >> %[1]q
if [ "$1" = "-f" ]; then cat >> %[1]q; exit 0; fi
if [ "$*" = "-a list chain inet cfm input" ]; then cat %[2]q; exit 0; fi
exit 0
`, logPath, listPath)
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

// dnatPrioBackend serves a prerouting chain of table at livePrio with no rules,
// and records the message types of every batch sent.
func dnatPrioBackend(t *testing.T, table string, livePrio int32, sent *[]int) *Backend {
	return nlBackend(t, func(req []netlink.Message) ([]netlink.Message, error) {
		if len(req) == 0 {
			return nil, io.EOF
		}
		if isBatch(req) {
			for _, m := range req {
				*sent = append(*sent, nftMsgType(m))
			}
			return nil, io.EOF
		}
		seq := req[0].Header.Sequence
		switch nftMsgType(req[0]) {
		case unix.NFT_MSG_GETCHAIN:
			m := baseChainMsg(table, "prerouting", nftables.ChainHookPrerouting, livePrio)
			m.Header.Sequence = seq
			return []netlink.Message{m}, nil
		case unix.NFT_MSG_GETRULE: // an empty chain: just the end of the dump
			return []netlink.Message{{Header: netlink.Header{Type: netlink.Done, Flags: netlink.Multi, Sequence: seq}}}, nil
		}
		return nil, io.EOF
	})
}

func contains(xs []int, x int) bool {
	for _, v := range xs {
		if v == x {
			return true
		}
	}
	return false
}

// A chain's priority can't change in place, so `cfm dnat on --priority X`
// used to keep the old one silently on nftlib while reporting X. On CFM's own
// table the rebuild now deletes and recreates it in the same batch.
func TestDNATOn_PriorityChangeRebuildsTheRedirectTable(t *testing.T) {
	fakeNFT(t, "")
	t.Setenv("NFT_DNAT_PRIORITY", "-101")
	wanted := dnatUnscopedWantedSpecs(nftables.TableFamilyINet, 9080, 9043)

	var sent []int
	b := dnatPrioBackend(t, firewall.DNATDefaultTable, -99, &sent)
	if err := b.installDNATRules("inet", firewall.DNATDefaultTable, wanted, dnatRuleNamespaceEdge, true); err != nil {
		t.Fatalf("installDNATRules: %v", err)
	}
	if !contains(sent, unix.NFT_MSG_DELTABLE) || !contains(sent, unix.NFT_MSG_NEWCHAIN) {
		t.Fatalf("priority -99 → -101 must rebuild the table (delete + new chain) in one batch; sent %v", sent)
	}

	sent = nil
	same := dnatPrioBackend(t, firewall.DNATDefaultTable, -101, &sent)
	if err := same.installDNATRules("inet", firewall.DNATDefaultTable, wanted, dnatRuleNamespaceEdge, true); err != nil {
		t.Fatalf("installDNATRules: %v", err)
	}
	if contains(sent, unix.NFT_MSG_DELTABLE) {
		t.Fatalf("same priority: the table must be kept; sent %v", sent)
	}

	sent = nil
	custom := dnatPrioBackend(t, "operator_nat", -99, &sent)
	if err := custom.installDNATRules("inet", "operator_nat", wanted, dnatRuleNamespaceEdge, true); err != nil {
		t.Fatalf("installDNATRules: %v", err)
	}
	if contains(sent, unix.NFT_MSG_DELTABLE) {
		t.Fatalf("a table that isn't cfm_redirect must never be deleted; sent %v", sent)
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

//go:build linux

package nftlib

import (
	"fmt"
	"io"
	"os"
	"path/filepath"
	"strings"
	"sync/atomic"
	"testing"

	"github.com/mdlayher/netlink"
	"golang.org/x/sys/unix"

	"cfm/internal/firewall"
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

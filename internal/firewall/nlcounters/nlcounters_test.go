//go:build linux

package nlcounters

import (
	"context"
	"encoding/binary"
	"os"
	"os/exec"
	"regexp"
	"strconv"
	"strings"
	"testing"

	"github.com/mdlayher/netlink"
	"golang.org/x/sys/unix"
)

func objMsgIn(t *testing.T, family uint8, table string, msgType uint16, name string, objType uint32, withPkts bool, pkts, bytes uint64) netlink.Message {
	t.Helper()
	ae := netlink.NewAttributeEncoder()
	ae.ByteOrder = binary.BigEndian
	ae.String(unix.NFTA_OBJ_TABLE, table)
	if name != "" {
		ae.String(unix.NFTA_OBJ_NAME, name)
	}
	ae.Uint32(unix.NFTA_OBJ_TYPE, objType)
	ae.Nested(unix.NFTA_OBJ_DATA, func(nae *netlink.AttributeEncoder) error {
		nae.Uint64(unix.NFTA_COUNTER_BYTES, bytes)
		if withPkts {
			nae.Uint64(unix.NFTA_COUNTER_PACKETS, pkts)
		}
		return nil
	})
	ae.Uint64(6, 7) // NFTA_OBJ_HANDLE: an attribute Decode ignores
	b, err := ae.Encode()
	if err != nil {
		t.Fatal(err)
	}
	return netlink.Message{
		Header: netlink.Header{Type: netlink.HeaderType(unix.NFNL_SUBSYS_NFTABLES<<8 | msgType)},
		Data:   append([]byte{family, 0, 0, 0}, b...),
	}
}

func objMsg(t *testing.T, msgType uint16, name string, objType uint32, withPkts bool, pkts, bytes uint64) netlink.Message {
	return objMsgIn(t, unix.NFPROTO_INET, "cfm", msgType, name, objType, withPkts, pkts, bytes)
}

func TestDecode(t *testing.T) {
	msgs := []netlink.Message{
		objMsg(t, unix.NFT_MSG_NEWOBJ, "badflags_drop", unix.NFT_OBJECT_COUNTER, true, 12, 720),
		objMsg(t, unix.NFT_MSG_NEWOBJ, "newrate_v4", unix.NFT_OBJECT_COUNTER, true, 0, 0),
		objMsg(t, unix.NFT_MSG_NEWOBJ, "q", unix.NFT_OBJECT_QUOTA, true, 1, 1),            // not a counter
		objMsg(t, unix.NFT_MSG_NEWOBJ, "nopkts", unix.NFT_OBJECT_COUNTER, false, 0, 1),    // no packets
		objMsg(t, unix.NFT_MSG_NEWOBJ, "", unix.NFT_OBJECT_COUNTER, true, 3, 3),           // no name
		objMsg(t, unix.NFT_MSG_NEWTABLE, "wrongmsg", unix.NFT_OBJECT_COUNTER, true, 3, 3), // other message
		{Header: netlink.Header{Type: netlink.HeaderType(unix.NFNL_SUBSYS_NFTABLES<<8 | unix.NFT_MSG_NEWOBJ)}, Data: []byte{1}},
		// Not inet cfm: the kernel filters these out, Decode does too.
		objMsgIn(t, unix.NFPROTO_INET, "other", unix.NFT_MSG_NEWOBJ, "badflags_drop", unix.NFT_OBJECT_COUNTER, true, 99, 99),
		objMsgIn(t, unix.NFPROTO_IPV4, "cfm", unix.NFT_MSG_NEWOBJ, "badflags_drop", unix.NFT_OBJECT_COUNTER, true, 98, 98),
	}
	got := Decode(msgs, "cfm")
	if len(got) != 2 {
		t.Fatalf("Decode = %v, want badflags_drop and newrate_v4 only", got)
	}
	if got["badflags_drop"] != (Counter{Packets: 12, Bytes: 720}) {
		t.Errorf("badflags_drop = %+v", got["badflags_drop"])
	}
	if c, ok := got["newrate_v4"]; !ok || c.Packets != 0 {
		t.Errorf("a zero counter must be reported as zero, got %+v ok=%v", c, ok)
	}
}

func TestInterrupted(t *testing.T) {
	m := objMsg(t, unix.NFT_MSG_NEWOBJ, "a", unix.NFT_OBJECT_COUNTER, true, 1, 1)
	if interrupted([]netlink.Message{m}) {
		t.Fatal("a plain reply read as interrupted")
	}
	m.Header.Flags |= netlink.DumpInterrupted
	if !interrupted([]netlink.Message{objMsg(t, unix.NFT_MSG_NEWOBJ, "b", unix.NFT_OBJECT_COUNTER, true, 1, 1), m}) {
		t.Fatal("NLM_F_DUMP_INTR on any reply must mark the dump interrupted")
	}
}

func TestRequestFiltersTableAndCounterType(t *testing.T) {
	m := Request("cfm")
	if m.Header.Type != netlink.HeaderType(unix.NFNL_SUBSYS_NFTABLES<<8|unix.NFT_MSG_GETOBJ) {
		t.Fatalf("type = %v", m.Header.Type)
	}
	if m.Header.Flags&netlink.Dump != netlink.Dump || m.Header.Flags&netlink.Request == 0 {
		t.Fatalf("flags = %v, want a dump request", m.Header.Flags)
	}
	if m.Data[0] != unix.NFPROTO_INET {
		t.Fatalf("family = %d, want inet", m.Data[0])
	}
	ad, err := netlink.NewAttributeDecoder(m.Data[4:])
	if err != nil {
		t.Fatal(err)
	}
	ad.ByteOrder = binary.BigEndian
	var table string
	var typ uint32
	for ad.Next() {
		switch ad.Type() {
		case unix.NFTA_OBJ_TABLE:
			table = ad.String()
		case unix.NFTA_OBJ_TYPE:
			typ = ad.Uint32()
		}
	}
	if table != "cfm" || typ != unix.NFT_OBJECT_COUNTER {
		t.Fatalf("filter table=%q type=%d", table, typ)
	}
}

// TestLiveNFTCounters checks Dump against a real kernel: the counters nft
// lists, with the same packet counts, and an absent table as an empty answer.
//
//	unshare -rn env CFM_NFT_INTEGRATION=1 go test ./internal/firewall/nlcounters/ -run LiveNFTCounters -v
func TestLiveNFTCounters(t *testing.T) {
	if os.Getenv("CFM_NFT_INTEGRATION") != "1" {
		t.Skip("set CFM_NFT_INTEGRATION=1 (root + nft, isolated netns) to run")
	}
	if os.Geteuid() != 0 {
		t.Skip("needs root (unshare -rn)")
	}
	if _, err := exec.LookPath("nft"); err != nil {
		t.Skip("nft not installed")
	}
	const other = "cfm_nlcounters_test_other"
	if exec.Command("nft", "list", "table", "inet", other).Run() == nil {
		t.Fatalf("refusing to run: table inet %s already exists", other)
	}
	if out, err := exec.Command("nft", "list", "table", "inet", "cfm").CombinedOutput(); err == nil {
		if s := string(out); strings.Contains(s, "block_v4") || strings.Contains(s, "hook input") {
			t.Fatalf("refusing to run: a populated `inet cfm` table exists — run inside an isolated netns (unshare -rn)")
		}
	}
	run := func(script string) {
		cmd := exec.Command("nft", "-f", "-")
		cmd.Stdin = strings.NewReader(script)
		if out, err := cmd.CombinedOutput(); err != nil {
			t.Fatalf("nft: %v\n%s", err, out)
		}
	}
	run("add table inet cfm\ndelete table inet cfm\n")
	if got, err := Dump(context.Background(), "cfm"); err != nil || len(got) != 0 {
		t.Fatalf("absent table: Dump = %v, %v; want empty, nil", got, err)
	}
	run(strings.ReplaceAll(`add table inet cfm
add counter inet cfm badflags_drop { packets 12 bytes 720 }
add counter inet cfm newrate_v4
add counter inet cfm portflood_80_tcp { packets 42 bytes 1234 }
add quota inet cfm q { over 1 mbytes }
add set inet cfm big { type ipv4_addr; flags interval; }
add element inet cfm big { 10.0.0.0/24, 10.0.2.0/24 }
add table inet OTHER
add counter inet OTHER badflags_drop { packets 99 bytes 99 }
`, "OTHER", other))
	t.Cleanup(func() {
		_ = exec.Command("nft", "delete", "table", "inet", "cfm").Run()
		_ = exec.Command("nft", "delete", "table", "inet", other).Run()
	})
	got, err := Dump(context.Background(), "cfm")
	if err != nil {
		t.Fatal(err)
	}
	out, err := exec.Command("nft", "list", "counters", "table", "inet", "cfm").CombinedOutput()
	if err != nil {
		t.Fatalf("nft list counters: %v\n%s", err, out)
	}
	want := map[string]uint64{}
	re := regexp.MustCompile(`counter (\S+) \{\s*packets (\d+) bytes \d+`)
	for _, m := range re.FindAllStringSubmatch(string(out), -1) {
		n, _ := strconv.ParseUint(m[2], 10, 64)
		want[m[1]] = n
	}
	if len(want) != 3 || len(got) != len(want) {
		t.Fatalf("Dump = %v, nft lists %v", got, want)
	}
	for name, p := range want {
		if c, ok := got[name]; !ok || c.Packets != p {
			t.Errorf("%s: Dump %+v (ok=%v), nft %d", name, c, ok, p)
		}
	}
}

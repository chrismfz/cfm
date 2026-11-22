//go:build linux

package nftlib

import (
	"os"
	"syscall"
	"testing"

	cfgpkg "cfm/internal/config"
	"cfm/internal/firewall/autoblock"

	"github.com/google/nftables"
	"github.com/mdlayher/netlink"
	"github.com/mdlayher/netlink/nltest"
	"golang.org/x/sys/unix"
)

const getTableType = netlink.HeaderType((unix.NFNL_SUBSYS_NFTABLES << 8) | unix.NFT_MSG_GETTABLE)

// tableLookupBackend returns a Backend whose every inet cfm table lookup gets
// reply, with EnsureBase replaced by a counter, and the count of GETTABLE
// requests the kernel saw.
func tableLookupBackend(t *testing.T, reply func([]netlink.Message) ([]netlink.Message, error)) (b *Backend, repairs, gets *int) {
	t.Helper()
	repairs, gets = new(int), new(int)
	var st nlStats
	conn := nlTestConn(t, &st, func(req []netlink.Message) ([]netlink.Message, error) {
		if len(req) > 0 && req[0].Header.Type == getTableType {
			*gets++
			return reply(req)
		}
		return nil, nil
	})
	cfg := &cfgpkg.Config{}
	cfg.Throttle.Enabled = true
	b = &Backend{
		conn:       conn,
		namedSets:  map[string]*nftables.Set{},
		last:       map[string]uint64{},
		ab:         autoblock.New(),
		cfg:        cfg,
		repairBase: func() error { *repairs++; return nil },
	}
	return b, repairs, gets
}

// CLAUDE.md §2: a failed or unknown read never starts a repair; only a
// definite "table absent" (the kernel's ENOENT answer to GETTABLE) does. And
// a failed counter read (log-only) never skips the throttle autoblock pass.
func TestDumpFloodCounters_RepairsOnlyADefiniteAbsence(t *testing.T) {
	cases := []struct {
		name       string
		reply      func([]netlink.Message) ([]netlink.Message, error)
		wantRepair int
	}{
		{"deadline", func([]netlink.Message) ([]netlink.Message, error) { return nil, os.ErrDeadlineExceeded }, 0},
		{"enobufs", func([]netlink.Message) ([]netlink.Message, error) { return nil, syscall.ENOBUFS }, 0},
		{"kernel EBUSY", func(r []netlink.Message) ([]netlink.Message, error) { return nltest.Error(int(unix.EBUSY), r) }, 0},
		{"absent (ENOENT)", func(r []netlink.Message) ([]netlink.Message, error) { return nltest.Error(int(unix.ENOENT), r) }, 1},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			b, repairs, gets := tableLookupBackend(t, tc.reply)
			b.dumpFloodCountersOnce()
			if *repairs != tc.wantRepair {
				t.Fatalf("repairs = %d, want %d", *repairs, tc.wantRepair)
			}
			// The counter read asks once; every further GETTABLE is the
			// throttle pass reading its sets, so it ran this tick.
			if *gets < 2 {
				t.Fatalf("GETTABLE requests = %d: the throttle pass did not run after the failed counter read", *gets)
			}
		})
	}
}

func TestLookupTable_ClassifiesAbsence(t *testing.T) {
	b, _, _ := tableLookupBackend(t, func(r []netlink.Message) ([]netlink.Message, error) { return nltest.Error(int(unix.ENOENT), r) })
	b.mu.Lock()
	_, err := b.lookupTable()
	b.mu.Unlock()
	if !tableAbsent(err) || !isNotFound(err) {
		t.Fatalf("ENOENT must read as absent (and stay isNotFound for DropEverything): %v", err)
	}
	b, _, _ = tableLookupBackend(t, func([]netlink.Message) ([]netlink.Message, error) { return nil, os.ErrDeadlineExceeded })
	b.mu.Lock()
	_, err = b.lookupTable()
	b.mu.Unlock()
	if err == nil || tableAbsent(err) {
		t.Fatalf("a deadline must not read as absent: %v", err)
	}
}

//go:build linux

package nft

import (
	"errors"
	"os"
	"strings"
	"testing"
)

// The flood dump runs on every 20 s main-loop tick. It used to run `nft list
// counters table inet cfm`, which makes nft load every set element of the
// table first: 2.8-18.5 s per run on the EL8 nodes (nft 1.0.4; earth, mars,
// virgo, orion, 2026-11-22), holding one of the four nft slots every tick.
// The counters now come from one netlink GETOBJ dump (0.3-1.2 ms on the same
// nodes). These tests pin that profile and the repair rule: only a table
// probeTable calls absent is repaired, never an unknown read.

func stubCounters(t *testing.T, cs map[string]uint64, err error) {
	t.Helper()
	old := readCounters
	readCounters = func() (map[string]uint64, error) { return cs, err }
	t.Cleanup(func() { readCounters = old })
}

// A tick on a healthy node runs no nft command at all.
func TestFloodDump_NetlinkRunsNoNFT(t *testing.T) {
	log := fakeNFTOpts(t, fakeOpts{chains: "ok"})
	stubCounters(t, map[string]uint64{
		"badflags_drop": 12, "newrate_v4": 22, "synrate_v4": 195,
		"smtpblock_hits": 7, // not a flood counter: not tracked
	}, nil)
	b := New()
	b.dumpFloodCountersOnce()
	if got, err := os.ReadFile(log); err == nil && len(got) > 0 { // no log = no nft run
		t.Errorf("a netlink read must run no nft command, ran:\n%s", got)
	}
	if b.last["badflags_drop"] != 12 || b.last["newrate_v4"] != 22 || b.last["synrate_v4"] != 195 {
		t.Errorf("baseline = %v", b.last)
	}
	if _, ok := b.last["smtpblock_hits"]; ok {
		t.Errorf("a non-flood counter was tracked: %v", b.last)
	}
	// A second tick moves the baseline; a counter reset just resets it.
	stubCounters(t, map[string]uint64{"badflags_drop": 15, "newrate_v4": 3}, nil)
	b.dumpFloodCountersOnce()
	if b.last["badflags_drop"] != 15 || b.last["newrate_v4"] != 3 {
		t.Errorf("baseline after the second tick = %v", b.last)
	}
}

// Netlink failing falls back to the CLI listing (the old cost, but correct).
func TestFloodDump_NetlinkFailureFallsBackToCLI(t *testing.T) {
	log := fakeNFTOpts(t, fakeOpts{chains: "ok"})
	stubCounters(t, nil, errors.New("netlink: operation not permitted"))
	b := New()
	b.dumpFloodCountersOnce()
	got := readFile(t, log)
	if !strings.Contains(got, "ARGS list counters table inet cfm") {
		t.Errorf("no CLI fallback after a netlink failure:\n%s", got)
	}
	if strings.Contains(got, "add table inet cfm") {
		t.Errorf("a present table was repaired:\n%s", got)
	}
}

// A read that fails both ways is unknown: no repair unless the table is
// absent, and an unknown probe is not absent.
func TestFloodDump_FailedReadRepairsOnlyAnAbsentTable(t *testing.T) {
	for _, tc := range []struct {
		chains     string
		wantRepair bool
	}{
		{"ok", false},   // present
		{"fail", false}, // unknown
		{"empty", true}, // absent
	} {
		t.Run(tc.chains, func(t *testing.T) {
			log := fakeNFTOpts(t, fakeOpts{chains: tc.chains, countersFail: true})
			stubCounters(t, nil, errors.New("netlink: timeout"))
			New().dumpFloodCountersOnce()
			got := readFile(t, log)
			if repaired := strings.Contains(got, "add table inet cfm"); repaired != tc.wantRepair {
				t.Errorf("chains=%s: EnsureBase ran=%v, want %v:\n%s", tc.chains, repaired, tc.wantRepair, got)
			}
		})
	}
}

// An empty netlink answer is what an absent table gives: it is checked with
// the cheap probe, and only an absent table is repaired.
func TestFloodDump_EmptyNetlinkAnswerProbesTheTable(t *testing.T) {
	for _, tc := range []struct {
		chains     string
		wantRepair bool
	}{
		{"ok", false},
		{"fail", false},
		{"empty", true},
	} {
		t.Run(tc.chains, func(t *testing.T) {
			log := fakeNFTOpts(t, fakeOpts{chains: tc.chains})
			stubCounters(t, map[string]uint64{}, nil)
			New().dumpFloodCountersOnce()
			got := readFile(t, log)
			if strings.Contains(got, "list counters") {
				t.Errorf("an empty netlink answer fell back to the element-loading listing:\n%s", got)
			}
			if !strings.Contains(got, "ARGS list chains inet") {
				t.Errorf("an empty netlink answer was not probed:\n%s", got)
			}
			if repaired := strings.Contains(got, "add table inet cfm"); repaired != tc.wantRepair {
				t.Errorf("chains=%s: EnsureBase ran=%v, want %v:\n%s", tc.chains, repaired, tc.wantRepair, got)
			}
		})
	}
}

func TestParseCounterListing(t *testing.T) {
	out := `table inet cfm {
	counter badflags_drop {
		packets 12 bytes 720
	}
	counter portflood_80_tcp {
		packets 42 bytes 1234
	}
	counter broken {
	}
	counter newrate_v4 {
		packets 22 bytes 8532
	}
}
`
	got := parseCounterListing(out)
	want := map[string]uint64{"badflags_drop": 12, "portflood_80_tcp": 42, "newrate_v4": 22}
	if len(got) != len(want) {
		t.Fatalf("got %v, want %v", got, want)
	}
	for k, v := range want {
		if got[k] != v {
			t.Errorf("%s = %d, want %d", k, got[k], v)
		}
	}
}

package cli

import (
	"testing"

	"cfm/internal/firewall"
	"cfm/internal/ttlban"
)

type flushRecorder struct {
	firewall.Backend
	flushed []string
	failOn  string
}

func (f *flushRecorder) FlushSet(_, _, set string) error {
	if set == f.failOn {
		return errString("Error: No such file or directory")
	}
	f.flushed = append(f.flushed, set)
	return nil
}

type errString string

func (e errString) Error() string { return string(e) }

// `cfm flush` empties every set the TTL bans live in, the automatic IPv6
// client /64s included (the review of cdfafe2: it left block_v6_clients, and
// the daemon's next snapshot persisted those bans again).
func TestRunFlushEmptiesTheClientSlash64s(t *testing.T) {
	defer ttlban.SetPathForTest(t.TempDir() + "/ttlbans.json")()
	f := &flushRecorder{}
	if rc := RunFlush(nil, f, func() bool { return true }); rc != 0 {
		t.Fatalf("rc=%d", rc)
	}
	want := map[string]bool{}
	for _, s := range ttlban.Sets {
		want[s] = true
	}
	if !want[firewall.BlockV6Clients] || len(f.flushed) != len(want) {
		t.Fatalf("flushed %v, want %v", f.flushed, ttlban.Sets)
	}
	// A table an older daemon built (no such set): a warning, not a failure.
	g := &flushRecorder{failOn: firewall.BlockV6Clients}
	if rc := RunFlush(nil, g, func() bool { return true }); rc != 0 {
		t.Fatalf("missing client set: rc=%d", rc)
	}
}

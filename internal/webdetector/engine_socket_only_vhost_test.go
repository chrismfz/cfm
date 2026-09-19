package webdetector

import (
	"context"
	"errors"
	"io"
	"testing"
	"time"

	core "cfm/internal/detectors/core"
)

// TestRunOnce_SocketOnlyStillPushesForcedVhosts locks the fix for the
// socket-ingest-only regression: when no LOG_PATH file exists,
// webdetector_register never calls SetSource, so e.src is nil. RunOnce used to
// `return nil` at the `e.src == nil` guard BEFORE the periodic reconcile — so
// emitIPChallenges never ran and the CHALLENGE_VHOST forced-vhost list was
// never pushed to the edge bridge (active_vhosts stayed empty), even though the
// Unix ingest socket was feeding data and the in-path WAF still fired.
//
// With the fix, RunOnce skips only the file drain when e.src is nil and still
// runs the reconcile, so the forced vhosts reach the bridge with no file at all.
func TestRunOnce_SocketOnlyStillPushesForcedVhosts(t *testing.T) {
	e := NewEngine(Config{
		Every:  time.Second,
		Window: 2 * time.Minute,
		// Non-empty sock path → bridge is Enabled; the path does not exist so the
		// fire-and-forget POST fails fast, but ChallengeVhostWithReason records
		// the vhost in local state before posting, which is what we assert on.
		OpenRestySock:  "/nonexistent/cfm_test_socket.sock",
		ChallengeVHost: []string{"cpanel.*", "webmail.*", "whm.*"},
	})

	if e.src != nil {
		t.Fatal("precondition: expected nil file source (socket-only mode)")
	}
	if e.nginxBridge == nil {
		t.Fatal("precondition: expected an nginx bridge in OpenResty mode")
	}

	out := make(chan core.Alert, 16)
	if err := e.RunOnce(context.Background(), out); err != nil {
		t.Fatalf("RunOnce returned error in socket-only mode: %v", err)
	}

	active := map[string]bool{}
	for _, v := range e.nginxBridge.Status().ActiveVhosts {
		active[v] = true
	}
	for _, want := range []string{"cpanel.*", "webmail.*", "whm.*"} {
		if !active[want] {
			t.Fatalf("forced vhost %q was not pushed to the bridge in socket-only mode; active=%v",
				want, e.nginxBridge.Status().ActiveVhosts)
		}
	}
}

// failOpenSource is a LineSource whose Open() always fails — models a log that
// is momentarily unopenable (rotation race, EMFILE, brief permission/mount
// blip, not-yet-recreated file).
type failOpenSource struct{}

func (failOpenSource) Open() error                              { return errors.New("boom: log not openable") }
func (failOpenSource) ReadNext(context.Context) (string, error) { return "", io.EOF }
func (failOpenSource) Position() (uint64, uint64, int64)        { return 0, 0, 0 }
func (failOpenSource) Close() error                             { return nil }
func (failOpenSource) Shutdown() error                          { return nil }

// TestRunOnce_OpenFailureDoesNotClobberSavedOffset locks the resume-offset guard
// that came with decoupling the reconcile from the file source. Because RunOnce
// no longer returns early on an Open() failure, the tail-position Put at the end
// of the tick would otherwise run with a zeroed/stale Position() (the tailer
// never seeked) and overwrite the saved resume offset with {0,0} — after which
// recovery seeks to end (START_AT_END) and silently skips every line written in
// the meantime. The srcDrained guard must skip the Put on any Open/read failure.
func TestRunOnce_OpenFailureDoesNotClobberSavedOffset(t *testing.T) {
	st, err := core.LoadState(t.TempDir())
	if err != nil {
		t.Fatalf("LoadState: %v", err)
	}
	const key = "webdet_offset_guard_test"
	saved := core.Position{Offset: 5000, Inode: 12345, TS: 111}
	st.Put(key, saved)

	e := NewEngine(Config{Every: time.Second, Window: 2 * time.Minute})
	e.SetSource(failOpenSource{})
	e.SetState(st, key)

	out := make(chan core.Alert, 8)
	// RunOnce surfaces the open error (expected); we only care about the offset.
	_ = e.RunOnce(context.Background(), out)

	got, ok := st.Get(key)
	if !ok {
		t.Fatal("saved resume offset was deleted by an Open-failure tick")
	}
	if got.Offset != saved.Offset || got.Inode != saved.Inode {
		t.Fatalf("Open-failure tick clobbered the saved resume offset: got {off=%d ino=%d}, want {off=%d ino=%d}",
			got.Offset, got.Inode, saved.Offset, saved.Inode)
	}
}

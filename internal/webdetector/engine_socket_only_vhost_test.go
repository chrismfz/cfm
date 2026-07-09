package webdetector

import (
	"context"
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
		Every:         time.Second,
		Window:        2 * time.Minute,
		OpenRestyMode: true,
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

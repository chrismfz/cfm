package webdetector

import (
	"errors"
	"fmt"
	"io"
	"net"
	"net/http"
	"os"
	"path/filepath"
	"testing"
	"time"
)

// TestBridgeServerTimeouts guards the F51 timeout wiring on the bridge
// http.Server. Every deadline must be set (a zero value is unbounded — the
// goroutine-pin the fix closes), IdleTimeout must stay above the edge's
// keepalive idle so pooled connections aren't reaped mid-pool, and the
// read/write deadlines must clear the edge's own per-RPC budget by a wide
// margin so they can never fire on legitimate traffic.
func TestBridgeServerTimeouts(t *testing.T) {
	srv := newBridgeHTTPServer(http.NewServeMux())

	if srv.ReadHeaderTimeout <= 0 {
		t.Errorf("ReadHeaderTimeout must be set, got %v", srv.ReadHeaderTimeout)
	}
	if srv.ReadTimeout <= 0 {
		t.Errorf("ReadTimeout must be set (0 = unbounded body read = F51 goroutine pin), got %v", srv.ReadTimeout)
	}
	if srv.WriteTimeout <= 0 {
		t.Errorf("WriteTimeout must be set, got %v", srv.WriteTimeout)
	}
	if srv.IdleTimeout <= 0 {
		t.Errorf("IdleTimeout must be set EXPLICITLY, got %v — 0 makes Go reuse ReadTimeout as the idle timeout, tearing down the edge keepalive pool", srv.IdleTimeout)
	}

	// Keepalive-safety invariant: never reap a connection the edge still holds
	// idle in its pool.
	if srv.IdleTimeout <= edgeBridgeKeepaliveIdle {
		t.Fatalf("IdleTimeout (%v) must exceed the edge keepalive idle (%v), else pooled connections get reaped mid-pool", srv.IdleTimeout, edgeBridgeKeepaliveIdle)
	}

	// Read/Write deadlines must clear the edge's own ~300ms per-RPC budget
	// (cfm.lua settimeouts(300,300,300)) by a wide margin — the edge abandons a
	// call at 300ms, so a multi-second server deadline only ever bites a
	// stalled/abandoned connection, never a legit request.
	const edgeRPCBudget = 300 * time.Millisecond
	if srv.ReadTimeout < 10*edgeRPCBudget {
		t.Errorf("ReadTimeout (%v) is too tight vs the edge's %v RPC budget; keep wide margin so it never fires on legit traffic", srv.ReadTimeout, edgeRPCBudget)
	}
	if srv.WriteTimeout < 10*edgeRPCBudget {
		t.Errorf("WriteTimeout (%v) is too tight vs the edge's %v RPC budget", srv.WriteTimeout, edgeRPCBudget)
	}
}

// TestBridgeReadTimeoutReapsStalledBody demonstrates the property F51 relies on:
// a connection that sends valid headers then stalls mid-body is closed by
// ReadTimeout instead of pinning a goroutine forever. It builds a bespoke server
// with a short timeout (not newBridgeHTTPServer / the production 15s) so the test
// is fast — so it is ILLUSTRATIVE of the mechanism, not a guard of the shipped
// config. TestBridgeServerTimeouts is the guard that production wires a non-zero
// ReadTimeout.
func TestBridgeReadTimeoutReapsStalledBody(t *testing.T) {
	sock := filepath.Join(t.TempDir(), "b.sock")
	ln, err := net.Listen("unix", sock)
	if err != nil {
		t.Fatalf("listen: %v", err)
	}

	// The handler reads the whole body; without a ReadTimeout this blocks forever
	// on a never-completing body (the pinned goroutine). With one, the body read
	// hits the deadline and the connection is torn down.
	handler := http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		_, _ = io.Copy(io.Discard, r.Body)
		w.WriteHeader(http.StatusOK)
	})
	srv := &http.Server{Handler: handler, ReadTimeout: 300 * time.Millisecond}
	go func() { _ = srv.Serve(ln) }()
	defer func() { _ = srv.Close() }()

	c, err := net.Dial("unix", sock)
	if err != nil {
		t.Fatalf("dial: %v", err)
	}
	defer func() { _ = c.Close() }()

	// Announce a 1000-byte body, send only 10, then stall.
	if _, err := fmt.Fprint(c, "POST /x HTTP/1.1\r\nHost: l\r\nContent-Length: 1000\r\n\r\n0123456789"); err != nil {
		t.Fatalf("write: %v", err)
	}

	// The server closes (or error-responds) once ReadTimeout fires; our read then
	// returns EOF/reset or response bytes — either way, NOT a deadline. A read
	// that hits our own 3s deadline means the connection was never reaped.
	_ = c.SetReadDeadline(time.Now().Add(3 * time.Second))
	_, rerr := c.Read(make([]byte, 64))
	if errors.Is(rerr, os.ErrDeadlineExceeded) {
		t.Fatal("stalled-body connection was NOT reaped: still open 3s after a 300ms ReadTimeout (a goroutine would be pinned)")
	}
}

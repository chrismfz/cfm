package webdetector

import (
	"context"
	"errors"
	"net"
	"os"
	"path/filepath"
	"testing"
	"time"
)

// TestIngestSocketConnCap verifies the concurrent-connection ceiling added for
// audit F52: the accept loop admits up to maxConns connections and refuses
// (closes) any beyond it instead of spawning an unbounded goroutine + buffer,
// and slots are released when connections close.
//
// A held connection sends no newline, so its serveConn goroutine blocks in
// ReadSlice (holding its semaphore slot) without ever touching the Engine — so a
// zero-value Engine is fine here.
func TestIngestSocketConnCap(t *testing.T) {
	const (
		capN  = 3
		extra = 4
	)
	sock := filepath.Join(t.TempDir(), "ingest.sock")
	s := &IngestSocket{sockPath: sock, maxConns: capN}
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()

	done := make(chan struct{})
	go func() { _ = s.Serve(ctx, &Engine{}); close(done) }()

	waitUntil(t, time.Second, func() bool { return s.Listening() }, "socket to start listening")

	// Open capN+extra connections and hold them all open (send nothing).
	conns := make([]net.Conn, 0, capN+extra)
	for i := 0; i < capN+extra; i++ {
		c, err := net.Dial("unix", sock)
		if err != nil {
			t.Fatalf("dial %d: %v", i, err)
		}
		conns = append(conns, c)
	}

	// The server accepts capN and refuses the rest. Poll the refusal counter.
	waitUntil(t, 2*time.Second, func() bool { return s.connRefused.Load() >= extra },
		"the excess connections to be refused")
	if got := s.connRefused.Load(); got < int64(extra) {
		t.Fatalf("expected >= %d refused connections, got %d", extra, got)
	}

	// Exactly the excess should be server-closed (refused); the rest are held.
	closed, held := 0, 0
	for _, c := range conns {
		if isServerClosed(c) {
			closed++
		} else {
			held++
		}
	}
	if closed != extra {
		t.Fatalf("expected exactly %d refused (server-closed) connections, got %d", extra, closed)
	}
	if held != capN {
		t.Fatalf("expected exactly %d held (accepted) connections, got %d", capN, held)
	}

	// Free the slots and confirm a fresh connection is now ACCEPTED (held), not
	// refused — the cap is a ceiling, not a permanent lockout.
	for _, c := range conns {
		_ = c.Close()
	}
	accepted := false
	deadline := time.Now().Add(2 * time.Second)
	for time.Now().Before(deadline) {
		c, err := net.Dial("unix", sock)
		if err != nil {
			time.Sleep(10 * time.Millisecond)
			continue
		}
		if !isServerClosed(c) { // held == accepted
			accepted = true
			_ = c.Close()
			break
		}
		_ = c.Close()
		time.Sleep(10 * time.Millisecond)
	}
	if !accepted {
		t.Fatal("slots did not free after closing held connections (fresh connection kept being refused)")
	}

	cancel()
	select {
	case <-done:
	case <-time.After(2 * time.Second):
		t.Fatal("Serve did not return after context cancel")
	}
}

// TestIngestSocketMaxConnsDefault confirms the production constructor installs
// the generous default cap (so a real deployment is never accidentally capped
// low), and that Serve falls back to the default for a zero/negative value.
func TestIngestSocketMaxConnsDefault(t *testing.T) {
	if got := NewIngestSocket().maxConns; got != defaultMaxIngestConns {
		t.Fatalf("NewIngestSocket maxConns = %d, want %d", got, defaultMaxIngestConns)
	}
	if got := (&IngestSocket{}).maxConnsOrDefault(); got != defaultMaxIngestConns {
		t.Fatalf("maxConnsOrDefault() with zero value = %d, want %d", got, defaultMaxIngestConns)
	}
	// Floor: the realistic peak is workers × per-worker keepalive-pool depth, which
	// on a large box mid-reload can approach ~512 (see defaultMaxIngestConns). Keep
	// a generous margin over that so a future edit can't silently under-size it.
	if defaultMaxIngestConns < 512 {
		t.Fatalf("defaultMaxIngestConns = %d is not generous enough (want >= 512 for large-box worker/keepalive-pool/reload headroom)", defaultMaxIngestConns)
	}
}

// isServerClosed reports whether the server has closed conn (a refused
// connection): a short read returns EOF/reset. A held (accepted) connection has
// no data to read, so the read hits the deadline instead.
func isServerClosed(conn net.Conn) bool {
	_ = conn.SetReadDeadline(time.Now().Add(200 * time.Millisecond))
	_, err := conn.Read(make([]byte, 1))
	if err == nil {
		return false // unexpected data, but not closed
	}
	return !errors.Is(err, os.ErrDeadlineExceeded)
}

func waitUntil(t *testing.T, d time.Duration, cond func() bool, what string) {
	t.Helper()
	deadline := time.Now().Add(d)
	for time.Now().Before(deadline) {
		if cond() {
			return
		}
		time.Sleep(2 * time.Millisecond)
	}
	t.Fatalf("timed out waiting for %s", what)
}

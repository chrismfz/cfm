package webdetector

import (
	"context"
	"net"
	"strings"
	"sync"
	"testing"
	"time"
)

// recordingAdapter captures every line handed to Parse — the point where a
// complete line emitted by serveConn enters the pipeline. It reports parse
// failure so the heavier ingest path is not exercised; we only assert on which
// lines reached this boundary.
type recordingAdapter struct {
	mu    sync.Mutex
	lines []string
}

func (a *recordingAdapter) Parse(line string) (LogRec, bool) {
	a.mu.Lock()
	a.lines = append(a.lines, line)
	a.mu.Unlock()
	return LogRec{}, false
}

func (a *recordingAdapter) snapshot() []string {
	a.mu.Lock()
	defer a.mu.Unlock()
	out := make([]string, len(a.lines))
	copy(out, a.lines)
	return out
}

func runServeConn(t *testing.T, payload string) []string {
	t.Helper()

	e := NewEngine(Config{Every: time.Second, Window: 2 * time.Minute})
	adapter := &recordingAdapter{}
	e.adapter = adapter

	s := NewIngestSocket()
	client, server := net.Pipe()

	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()

	done := make(chan struct{})
	go func() {
		s.serveConn(ctx, e, server)
		close(done)
	}()

	// net.Pipe is unbuffered: write from a goroutine so reads and writes
	// interleave, then close to deliver EOF.
	go func() {
		_, _ = client.Write([]byte(payload))
		_ = client.Close()
	}()

	select {
	case <-done:
	case <-time.After(5 * time.Second):
		cancel()
		t.Fatal("serveConn did not return within 5s (possible unbounded read / hang)")
	}

	got := adapter.snapshot()
	for _, l := range got {
		if len(l) > 256*1024 {
			t.Fatalf("an oversized line (%d bytes) reached the adapter — not bounded", len(l))
		}
	}
	return got
}

// A newline-free blob larger than the 256 KB per-line buffer must be dropped
// (never accumulated — the pre-fix ReadString would have grown a []byte without
// bound), and ingestion must resync at the next newline so surrounding lines
// still flow. Guards audit F26.
func TestIngestServeConn_DropsOversizedLineAndResyncs(t *testing.T) {
	oversized := strings.Repeat("A", 300*1024) // > maxLine (256 KB)
	payload := "first-line\n" + oversized + "\n" + "second-line\n"

	got := runServeConn(t, payload)

	want := []string{"first-line", "second-line"}
	if len(got) != len(want) {
		t.Fatalf("got %d lines %q, want %d %q", len(got), got, len(want), want)
	}
	for i := range want {
		if got[i] != want[i] {
			t.Fatalf("line %d = %q, want %q", i, got[i], want[i])
		}
	}
}

// A single line that never terminates (a flood past maxDrain) must make
// serveConn give up and close the connection rather than read forever — memory
// stays bounded and the goroutine is released. Lines before it still ingest.
func TestIngestServeConn_ClosesOnUnboundedFloodLine(t *testing.T) {
	flood := strings.Repeat("B", 10*1024*1024) // > maxDrain (8 MB), no newline, never terminated
	payload := "before\n" + flood

	got := runServeConn(t, payload)

	// Only the terminated line before the flood should have reached the adapter;
	// the flood line is dropped and the connection closed at the drain cap.
	if len(got) != 1 || got[0] != "before" {
		t.Fatalf("got %q, want exactly [\"before\"] (flood line must not be ingested)", got)
	}
}

package core

import (
	"bufio"
	"context"
	"strings"
	"testing"
)

// The docker / journal readers route through readBoundedLine. Drive their real
// ReadNext (with an injected reader, no subprocess) to confirm: a CRLF line is
// trimmed, an oversized line is dropped (not returned), and ingestion resyncs at
// the next line. Covers the F26-family fix through the actual callers.
func TestDockerTailer_LineBounding(t *testing.T) {
	oversized := strings.Repeat("A", 300*1024) // > 256 KB buffer
	input := "line1\r\n" + oversized + "\n" + "line2\n"
	d := &DockerTailer{reader: bufio.NewReaderSize(strings.NewReader(input), 256*1024)}
	ctx := context.Background()

	// CRLF: readBoundedLine strips \n, docker strips the trailing \r -> "line1".
	if l, err := d.ReadNext(ctx); err != nil || l != "line1" {
		t.Fatalf("CRLF line: got %q,%v want line1 (CR stripped)", l, err)
	}
	// Oversized line: dropped -> empty, and the giant blob is never returned.
	l, err := d.ReadNext(ctx)
	if err != nil || l != "" {
		t.Fatalf("oversized: got %q (%d bytes),%v want empty skip", l, len(l), err)
	}
	// Resync to the next real line.
	if l, err := d.ReadNext(ctx); err != nil || l != "line2" {
		t.Fatalf("resync: got %q,%v want line2", l, err)
	}
}

func TestJournalTailer_LineBounding(t *testing.T) {
	oversized := strings.Repeat("A", 300*1024)
	// journald format is "<secs>.<usec> <rest>"; the reader strips the ts prefix.
	input := "1720800000.123456 hello world\n" + oversized + "\n" + "1720800001.0 after\n"
	j := &JournalTailer{reader: bufio.NewReaderSize(strings.NewReader(input), 256*1024)}
	ctx := context.Background()

	if l, err := j.ReadNext(ctx); err != nil || l != "hello world" {
		t.Fatalf("normal record: got %q,%v want 'hello world'", l, err)
	}
	l, err := j.ReadNext(ctx)
	if err != nil || l != "" {
		t.Fatalf("oversized: got %q (%d bytes),%v want empty skip", l, len(l), err)
	}
	if l, err := j.ReadNext(ctx); err != nil || l != "after" {
		t.Fatalf("resync: got %q,%v want after", l, err)
	}
}

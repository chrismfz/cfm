package core

import (
	"bufio"
	"io"
	"strings"
	"testing"
)

// readBoundedLine backs the docker / journal readers. It must return complete
// lines, DROP an oversized (buffer-exceeding) line and resync at the next
// newline (bounded memory — the pre-fix ReadString accumulated without bound),
// and surface a never-terminated flood as an error rather than reading forever.
func TestReadBoundedLine(t *testing.T) {
	const buf = 256 * 1024
	newr := func(s string) *bufio.Reader { return bufio.NewReaderSize(strings.NewReader(s), buf) }

	t.Run("normal lines", func(t *testing.T) {
		r := newr("hello\nworld\n")
		if l, err := readBoundedLine(r); err != nil || l != "hello" {
			t.Fatalf("got %q,%v want hello", l, err)
		}
		if l, err := readBoundedLine(r); err != nil || l != "world" {
			t.Fatalf("got %q,%v want world", l, err)
		}
	})

	t.Run("oversized line dropped, resync to next", func(t *testing.T) {
		oversized := strings.Repeat("A", 300*1024) // > buffer
		r := newr("a\n" + oversized + "\n" + "b\n")

		if l, err := readBoundedLine(r); err != nil || l != "a" {
			t.Fatalf("got %q,%v want a", l, err)
		}
		l, err := readBoundedLine(r) // the oversized line
		if err != nil || l != "" {
			t.Fatalf("oversized line must drop to (\"\",nil), got %q,%v", l, err)
		}
		if len(l) > buf {
			t.Fatalf("oversized content (%d bytes) was returned — not bounded", len(l))
		}
		if l, err := readBoundedLine(r); err != nil || l != "b" {
			t.Fatalf("resync: got %q,%v want b", l, err)
		}
	})

	t.Run("never-terminated flood errors, not forever", func(t *testing.T) {
		flood := strings.Repeat("B", 10*1024*1024) // > maxLineDrain (8 MB), no newline
		r := newr(flood)
		if l, err := readBoundedLine(r); err != errOversizedLine {
			t.Fatalf("flood must return errOversizedLine, got %q,%v", l, err)
		}
	})

	t.Run("EOF", func(t *testing.T) {
		r := newr("")
		if _, err := readBoundedLine(r); err != io.EOF {
			t.Fatalf("empty input want io.EOF, got %v", err)
		}
	})

	t.Run("strips only trailing newline (caller trims CR)", func(t *testing.T) {
		r := newr("foo\r\n")
		if l, err := readBoundedLine(r); err != nil || l != "foo\r" {
			t.Fatalf("helper strips only \\n (caller does \\r), got %q,%v", l, err)
		}
	})
}

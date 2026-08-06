package kmsg

import (
	"fmt"
	"testing"
)

func TestTailFilter(t *testing.T) {
	lines := make([]string, 100)
	for i := range lines {
		lines[i] = fmt.Sprintf("line %d", i)
	}

	// last-N window + truncated flag.
	got, trunc := tailFilter(lines, 10, "")
	if len(got) != 10 || !trunc {
		t.Fatalf("window: len=%d trunc=%v, want 10,true", len(got), trunc)
	}
	if got[0] != "line 90" || got[9] != "line 99" {
		t.Fatalf("window kept wrong slice: %q..%q", got[0], got[9])
	}

	// fewer than limit → not truncated.
	got, trunc = tailFilter(lines[:5], 10, "")
	if len(got) != 5 || trunc {
		t.Fatalf("no-trunc: len=%d trunc=%v, want 5,false", len(got), trunc)
	}

	// default when lines<=0, cap when too large.
	got, _ = tailFilter(lines, 0, "")
	if len(got) != 100 { // 100 < DefaultLines(80)? no: 100 > 80 → last 80
		if len(got) != DefaultLines {
			t.Fatalf("default: len=%d, want %d", len(got), DefaultLines)
		}
	}
	got, _ = tailFilter(lines, 100000, "")
	if len(got) != 100 {
		t.Fatalf("cap: len=%d, want 100 (all, since <MaxLines)", len(got))
	}
}

func TestTailFilter_Grep(t *testing.T) {
	in := []string{
		"[ts] usb 1-1: new device",
		"[ts] Out of memory: Killed process 123 (lsphp)",
		"[ts] EXT4-fs error (device sda1): I/O error",
		"[ts] nft: dropped packet",
	}
	// case-insensitive substring
	got, _ := tailFilter(in, 100, "OOM")
	if len(got) != 0 {
		t.Fatalf("grep OOM matched %d (expected 0 — string is 'Out of memory')", len(got))
	}
	got, _ = tailFilter(in, 100, "memory")
	if len(got) != 1 || got[0] != in[1] {
		t.Fatalf("grep memory = %v, want the OOM line", got)
	}
	got, _ = tailFilter(in, 100, "I/O ERROR")
	if len(got) != 1 || got[0] != in[2] {
		t.Fatalf("grep I/O ERROR (case-insensitive) = %v", got)
	}
}

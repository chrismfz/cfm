package lsm

import (
	"os"
	"regexp"
	"strconv"
	"strings"
	"testing"
)

// bpf_wire_test.go — source-level guardrails on the BPF/Go wire contract.
//
// verify-bpf-bindings (the Makefile pre-build check) compares program/map
// NAME sets between the .o and the bpf2go bindings; it does NOT check that
// the event record is fully initialized, nor that the C struct layout
// matches the Go parser. These two tests close that gap by reading the BPF
// C sources directly, so a divergence fails `go test` (a CI gate) rather
// than shipping stale ringbuf bytes or silently mis-decoding every field.

// TestBPFEmitSitesInitializeTail asserts every cfm_events ring-buffer emit
// site is paired with a cfm_event_fill_kin(e) call. bpf_ringbuf_reserve
// does NOT zero the record, so a reserve that forgets the helper would emit
// the Tier B ppid/aux_pid/aux_uid tail as stale bytes from a prior record
// (a garbage-parent / garbage-target info leak). A future policy adding an
// emit site trips this if it omits the initializer.
func TestBPFEmitSitesInitializeTail(t *testing.T) {
	src := readBPFSource(t, "bpf/cfmlsm.bpf.c")
	// Match the code idiom `... = bpf_ringbuf_reserve(&cfm_events`, which
	// excludes any mention inside a comment (those lack the `= `).
	reserves := strings.Count(src, "= bpf_ringbuf_reserve(&cfm_events")
	fills := strings.Count(src, "cfm_event_fill_kin(e)")
	if reserves == 0 {
		t.Fatal("no cfm_events emit sites found — did the reserve idiom change?")
	}
	if reserves != fills {
		t.Errorf("cfm_events reserve sites = %d but cfm_event_fill_kin(e) calls = %d; "+
			"every emit site MUST initialise the non-zeroed ppid/aux tail (see common.bpf.h)",
			reserves, fills)
	}
}

// TestBPFEventStructMatchesWireSize computes the byte size of the C
// `struct cfm_lsm_event` from common.bpf.h and asserts it equals the Go
// parser's wireEventSize. This catches the C↔Go drift that verify-bpf-
// bindings (name-only) and TestWireEventSize_Stable (a Go-const formula
// compared to itself) cannot: a field added / resized / reordered on the C
// side that isn't mirrored in events.go's offsets would otherwise decode
// silently wrong.
func TestBPFEventStructMatchesWireSize(t *testing.T) {
	src := readBPFSource(t, "bpf/common.bpf.h")
	const marker = "struct cfm_lsm_event {"
	start := strings.Index(src, marker)
	if start < 0 {
		t.Fatalf("%q not found in common.bpf.h", marker)
	}
	body := src[start+len(marker):]
	if end := strings.Index(body, "}"); end >= 0 {
		body = body[:end]
	} else {
		t.Fatal("struct cfm_lsm_event has no closing brace")
	}

	typeSize := map[string]int{"__u64": 8, "__s64": 8, "__u32": 4, "__s32": 4, "__u16": 2, "__u8": 1, "char": 1}
	arrayDim := map[string]int{"CFM_TASK_COMM_LEN": bpfTaskCommLen, "CFM_FILENAME_LEN": bpfFilenameLen}
	fieldRe := regexp.MustCompile(`^(__u64|__s64|__u32|__s32|__u16|__u8|char)\s+\w+(?:\[(\w+)\])?\s*;`)

	total := 0
	for _, raw := range strings.Split(body, "\n") {
		line := strings.TrimSpace(stripCComment(raw))
		m := fieldRe.FindStringSubmatch(line)
		if m == nil {
			continue // comment / continuation / blank
		}
		sz := typeSize[m[1]]
		if m[2] != "" { // array field
			dim, ok := arrayDim[m[2]]
			if !ok {
				n, err := strconv.Atoi(m[2])
				if err != nil {
					t.Fatalf("unknown array dimension %q in struct field %q", m[2], line)
				}
				dim = n
			}
			sz *= dim
		}
		total += sz
	}
	if total != wireEventSize {
		t.Errorf("struct cfm_lsm_event (common.bpf.h) computes to %d bytes but wireEventSize = %d; "+
			"C struct and Go parser diverged — update events.go offsets + wireEventSize and regenerate the .o",
			total, wireEventSize)
	}
}

func readBPFSource(t *testing.T, rel string) string {
	t.Helper()
	b, err := os.ReadFile(rel)
	if err != nil {
		t.Fatalf("read %s: %v", rel, err)
	}
	return string(b)
}

// stripCComment drops a trailing `/* ... ` or `// ...` fragment so a field
// line with an inline comment still matches the type regex. Block-comment
// continuation lines don't start with a type token, so the regex skips them.
func stripCComment(s string) string {
	if i := strings.Index(s, "/*"); i >= 0 {
		s = s[:i]
	}
	if i := strings.Index(s, "//"); i >= 0 {
		s = s[:i]
	}
	return s
}

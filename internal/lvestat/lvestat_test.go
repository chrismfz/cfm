package lvestat

import (
	"strings"
	"testing"
)

// Real header + rows captured from a live CloudLinux 8 node (orion). TAB-
// separated; note the system LVE "0,0" has a BLANK lCPU field, which is exactly
// why the parser must split on \t (not on runs of whitespace, which would
// collapse the empty column and misalign every field after it).
const (
	hdr     = "10:LVE\tlCPU\tlCPUW\tnCPU\tlEP\tlNPROC\tlMEM\tlMEMPHY\tlIO\tlIOPS\tlNETO\tlNETI\tEP\tCPU\tMEM\tIO\tfMEM\tfEP\tMEMPHY\tfMEMPHY\tNPROC\tfNPROC\tIOPS\tNETO\tNETI"
	rowSys  = "0,0\t\t10000\t100\t1\t40\t100\t0\t262144\t2048\t100\t0\t0\t0\t0\t0\t0\t0\t0\t0\t0\t0\t0\t0\t0" // blank lCPU (25 fields)
	row1004 = "0,1004\t20000\t100\t2\t30\t80\t0\t524288\t4096\t2048\t0\t0\t1\t59560034260019\t0\t75977964\t0\t0\t522068\t574\t43\t0\t6171530\t108667620\t577163539"
	row1010 = "0,1010\t30000\t100\t3\t60\t100\t0\t786432\t12288\t4096\t0\t0\t1\t416185289379288\t0\t32022872\t0\t0\t27241\t0\t3\t0\t2527902\t67733257\t559251101"
)

func find(s Snapshot, uid int64) (LVE, bool) {
	for _, e := range s.Entries {
		if e.UID == uid {
			return e, true
		}
	}
	return LVE{}, false
}

func TestParse_RealFixture(t *testing.T) {
	in := strings.Join([]string{hdr, rowSys, row1004, row1010}, "\n") + "\n"
	snap, err := Parse(strings.NewReader(in))
	if err != nil {
		t.Fatalf("Parse: %v", err)
	}
	if snap.Version != 10 {
		t.Fatalf("version = %d, want 10", snap.Version)
	}
	if len(snap.Entries) != 3 {
		t.Fatalf("entries = %d, want 3", len(snap.Entries))
	}

	// Normal tenant: CPU usage + limits parsed from the NAMED columns.
	e, ok := find(snap, 1004)
	if !ok {
		t.Fatal("uid 1004 missing")
	}
	if e.Reseller != 0 {
		t.Errorf("1004 reseller = %d, want 0", e.Reseller)
	}
	if e.CPUUsage != 59560034260019 {
		t.Errorf("1004 CPUUsage = %d, want 59560034260019", e.CPUUsage)
	}
	if e.LimitCPU != 20000 || e.NumCPU != 2 {
		t.Errorf("1004 limits = lCPU %d nCPU %d, want 20000/2", e.LimitCPU, e.NumCPU)
	}
	if e.EP != 1 || e.NProc != 43 {
		t.Errorf("1004 EP/NPROC = %d/%d, want 1/43", e.EP, e.NProc)
	}
	if e.IOUsage != 75977964 || e.MemUsage != 0 {
		t.Errorf("1004 IO/MEM = %d/%d, want 75977964/0", e.IOUsage, e.MemUsage)
	}

	if e, _ := find(snap, 1010); e.CPUUsage != 416185289379288 || e.NumCPU != 3 {
		t.Errorf("1010 CPUUsage/nCPU = %d/%d, want 416185289379288/3", e.CPUUsage, e.NumCPU)
	}

	// System LVE 0,0: blank lCPU must parse as 0 (unlimited), NOT shift columns —
	// the tell that tab-splitting kept alignment. CPU usage is 0.
	sys, ok := find(snap, 0)
	if !ok {
		t.Fatal("system LVE 0,0 missing")
	}
	if sys.LimitCPU != 0 {
		t.Errorf("0,0 LimitCPU = %d, want 0 (blank field)", sys.LimitCPU)
	}
	if sys.CPUUsage != 0 {
		t.Errorf("0,0 CPUUsage = %d, want 0", sys.CPUUsage)
	}
}

func TestParse_SkipsMalformedAndNonID(t *testing.T) {
	in := strings.Join([]string{
		hdr,
		row1004,
		"0,9999\t1\t2\t3", // too few fields → skipped
		"garbage line without id",
		"", // blank → skipped
	}, "\n")
	snap, err := Parse(strings.NewReader(in))
	if err != nil {
		t.Fatalf("Parse: %v", err)
	}
	if len(snap.Entries) != 1 || snap.Entries[0].UID != 1004 {
		t.Fatalf("entries = %+v, want only uid 1004 (malformed rows skipped)", snap.Entries)
	}
}

func TestParse_Empty(t *testing.T) {
	snap, err := Parse(strings.NewReader(""))
	if err != nil {
		t.Fatalf("Parse empty: %v", err)
	}
	if len(snap.Entries) != 0 || snap.Version != 0 {
		t.Fatalf("empty input should yield no entries, got %+v", snap)
	}
}

// A header without an LVE column can't be keyed → no entries (no panic).
func TestParse_HeaderMissingLVEColumn(t *testing.T) {
	snap, err := Parse(strings.NewReader("10:FOO\tCPU\n0,1\t123\n"))
	if err != nil {
		t.Fatalf("Parse: %v", err)
	}
	if len(snap.Entries) != 0 {
		t.Fatalf("entries = %d, want 0 (no LVE column)", len(snap.Entries))
	}
}

// Header without the "<version>:" prefix still parses (version 0).
func TestParse_NoVersionPrefix(t *testing.T) {
	snap, err := Parse(strings.NewReader("LVE\tCPU\tlCPU\n0,3000\t99\t100\n"))
	if err != nil {
		t.Fatalf("Parse: %v", err)
	}
	if snap.Version != 0 {
		t.Errorf("version = %d, want 0 (no prefix)", snap.Version)
	}
	if e, ok := find(snap, 3000); !ok || e.CPUUsage != 99 || e.LimitCPU != 100 {
		t.Errorf("uid 3000 = %+v (ok=%v), want CPUUsage 99 / LimitCPU 100", e, ok)
	}
}

// A non-numeric cell in a mapped column yields 0 (documented contract), and the
// row is still returned (only bad LVE id / field-count mismatch drop a row).
func TestParse_NonNumericCellIsZero(t *testing.T) {
	snap, err := Parse(strings.NewReader("10:LVE\tCPU\tlCPU\n0,4000\tNaN\t100\n"))
	if err != nil {
		t.Fatalf("Parse: %v", err)
	}
	e, ok := find(snap, 4000)
	if !ok {
		t.Fatal("uid 4000 missing (row should not be dropped for a bad cell)")
	}
	if e.CPUUsage != 0 {
		t.Errorf("non-numeric CPU cell → CPUUsage %d, want 0", e.CPUUsage)
	}
	if e.LimitCPU != 100 {
		t.Errorf("LimitCPU = %d, want 100 (unaffected by the bad CPU cell)", e.LimitCPU)
	}
}

// Header-driven: a future format that REORDERS columns must still map correctly.
func TestParse_ColumnReorderByHeaderName(t *testing.T) {
	// Minimal header with CPU before the limits, plus a bumped version prefix.
	rh := "11:LVE\tCPU\tlCPU\tnCPU\tEP\tNPROC\tMEM\tIO"
	rr := "0,2000\t12345\t50000\t4\t7\t9\t111\t222"
	snap, err := Parse(strings.NewReader(rh + "\n" + rr + "\n"))
	if err != nil {
		t.Fatalf("Parse: %v", err)
	}
	if snap.Version != 11 {
		t.Errorf("version = %d, want 11", snap.Version)
	}
	e, ok := find(snap, 2000)
	if !ok {
		t.Fatal("uid 2000 missing")
	}
	if e.CPUUsage != 12345 || e.LimitCPU != 50000 || e.NumCPU != 4 || e.EP != 7 || e.NProc != 9 || e.MemUsage != 111 || e.IOUsage != 222 {
		t.Errorf("reordered parse wrong: %+v", e)
	}
}

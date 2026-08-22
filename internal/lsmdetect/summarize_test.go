package lsmdetect

import (
	"encoding/json"
	"strconv"
	"testing"
)

func TestSummarizeRanksAndAggregates(t *testing.T) {
	lines := []string{
		ts + " [lsm] T: pid=1 (sssd) policy=CFML-CRED-002 path=sssd user=root(0) exe=/usr/sbin/sssd sha256=" + longSHA,
		ts + " [lsm] T: pid=2 (sssd) policy=CFML-CRED-002 path=sssd user=root(0) exe=/usr/sbin/sssd sha256=" + longSHA,
		ts + " [lsm] T: pid=3 (sssd_kcm) policy=CFML-CRED-002 path=sssd_kcm user=root(0) exe=/usr/libexec/sssd/sssd_kcm",
		ts + " [lsm] T: pid=4 (Fix mailman pac) policy=CFML-CRED-002 path=perl user=root(0) exe=/usr/local/cpanel/3rdparty/perl/542/bin/perl",
		ts + " [lsm] T: pid=5 (webproc) policy=CFML-EXEC-006 user=anon(1000) exe=/tmp/drop (deleted)",
		ts + " [lsm] CFML-CRED-002 suppressed=40 in_last=60s (cfm.log+notify)",
		ts + " [lsm] lifecycle noise line — must be ignored",
	}
	s := Summarize(lines)

	if s.TotalEvents != 5 || s.TotalSuppressed != 40 {
		t.Fatalf("totals events=%d suppressed=%d want 5/40", s.TotalEvents, s.TotalSuppressed)
	}
	if s.UniquePolicies != 2 {
		t.Fatalf("UniquePolicies=%d want 2", s.UniquePolicies)
	}
	if len(s.Policies) != 2 ||
		s.Policies[0].Policy != "CFML-CRED-002" || s.Policies[0].Count != 4 || s.Policies[0].Suppressed != 40 ||
		s.Policies[1].Policy != "CFML-EXEC-006" {
		t.Fatalf("policy blocks wrong: %+v", s.Policies)
	}
	p0 := s.Policies[0]
	if p0.TopComm[0].Key != "sssd" || p0.TopComm[0].Count != 2 {
		t.Fatalf("top_comm wrong: %+v", p0.TopComm)
	}

	// Top offender = the repeated sssd pair; hash abbreviated.
	top := s.TopOffenders[0]
	if top.Policy != "CFML-CRED-002" || top.Comm != "sssd" ||
		top.Exe != "/usr/sbin/sssd" || top.Count != 2 || top.User != "root" {
		t.Fatalf("top offender wrong: %+v", top)
	}
	if len(top.SHA256) != shaShortLen {
		t.Fatalf("sha not abbreviated: %q", top.SHA256)
	}

	var foundDeleted bool
	for _, o := range s.TopOffenders {
		if o.Exe == "/tmp/drop" && o.DeletedEvents == 1 {
			foundDeleted = true
		}
	}
	if !foundDeleted {
		t.Fatalf("deleted-exe offender missing: %+v", s.TopOffenders)
	}
}

func TestSummarizeExeFallbackToPath(t *testing.T) {
	// enrichment off: CRED-002 emits the exe basename as path — still a row.
	lines := []string{
		ts + " [lsm] T: pid=1 (cagefsctl) policy=CFML-CRED-002 path=cagefsctl uid=0",
		ts + " [lsm] T: pid=2 (cagefsctl) policy=CFML-CRED-002 path=cagefsctl uid=0",
	}
	s := Summarize(lines)
	if len(s.TopOffenders) != 1 {
		t.Fatalf("want exactly one offender, got %+v", s.TopOffenders)
	}
	o := s.TopOffenders[0]
	if o.Count != 2 || o.Exe != "" || o.Comm != "cagefsctl" {
		t.Fatalf("offender wrong: %+v", o)
	}
	if p := s.Policies[0]; p.TopExe[0].Key != "cagefsctl" {
		t.Fatalf("exe fallback to path failed: %+v", p.TopExe)
	}
}

func TestSummarizeEmptyAndDeterministic(t *testing.T) {
	if s := Summarize(nil); s.TotalEvents != 0 || len(s.Policies) != 0 {
		t.Fatalf("empty summary wrong: %+v", s)
	}
	lines := make([]string, 0, 50)
	for i := 0; i < 25; i++ {
		n := strconv.Itoa(i)
		lines = append(lines,
			ts+" [lsm] T: pid="+n+" (a) policy=CFML-CRED-002 user=root(0)",
			ts+" [lsm] T: pid="+n+" (b) policy=CFML-EXEC-006 user=u(1)")
	}
	a := Summarize(lines)
	b := Summarize(lines)
	if mustJSON(a) != mustJSON(b) {
		t.Fatalf("summary not deterministic")
	}
	// offender cap
	if len(a.TopOffenders) > topOffendMax {
		t.Fatalf("offender cap exceeded: %d", len(a.TopOffenders))
	}
}

func TestTopKVCapsAndSorts(t *testing.T) {
	m := map[string]int{"b": 2, "a": 2, "c": 9}
	got := topKV(m, 2)
	if len(got) != 2 || got[0].Key != "c" || got[1].Key != "a" {
		t.Fatalf("topKV wrong: %+v", got)
	}
}

const longSHA = "5e6f528d2fac0123456789abcdef0123456789abcdef0123456789abcdef0123"

func mustJSON(v any) string {
	b, _ := json.Marshal(v)
	return string(b)
}

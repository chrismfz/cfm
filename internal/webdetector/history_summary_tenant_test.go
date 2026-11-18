package webdetector

import (
	"path/filepath"
	"testing"
	"time"
)

// A tenant's summary of the node's hostname does not count the node's own
// fault rows (mail_*, backup_*); the operator's does.
func TestSummarizeTenantSkipsServerOnlyRows(t *testing.T) {
	hs, err := NewHistoryStore(filepath.Join(t.TempDir(), "history.jsonl"), 30, time.Hour, 0)
	if err != nil {
		t.Fatalf("NewHistoryStore: %v", err)
	}
	defer hs.Close()
	now := time.Now().Unix()
	host := "node.example"
	hs.Append(HistoryEvent{TsUnix: now - 60, Type: "challenge_issued", Host: host, IP: "1.1.1.1"})
	hs.Append(HistoryEvent{TsUnix: now - 50, Type: "mail_spike", Host: host})
	hs.Append(HistoryEvent{TsUnix: now - 40, Type: "backup_failed", Host: host})

	admin, err := hs.Summarize(host, "", 1)
	if err != nil {
		t.Fatal(err)
	}
	tenant, err := hs.SummarizeTenant(host, "", 1)
	if err != nil {
		t.Fatal(err)
	}
	if admin.TotalEvents != 3 {
		t.Fatalf("admin total_events = %d, want 3", admin.TotalEvents)
	}
	if tenant.TotalEvents != 1 || tenant.ChallengeIssued != 1 {
		t.Fatalf("tenant summary = %+v, want total 1 (the challenge only)", tenant)
	}
	r, err := hs.SummarizeRangeTenant(host, "", now-3600, now+1)
	if err != nil || r.TotalEvents != 1 {
		t.Fatalf("SummarizeRangeTenant total = %d (err %v), want 1", r.TotalEvents, err)
	}
}

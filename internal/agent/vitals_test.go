package agent

import (
	"testing"
	"time"

	"cfm/internal/healthstore"
	"cfm/internal/mailq"
)

func stubVitals(t *testing.T, store *healthstore.RingStore, node string, now time.Time) {
	t.Helper()
	origStore, origNode, origNow, origMail, origUptime :=
		vitalsStore, vitalsNodeID, vitalsNow, vitalsMailLatest, readUptimeFile
	t.Cleanup(func() {
		vitalsStore, vitalsNodeID, vitalsNow, vitalsMailLatest, readUptimeFile =
			origStore, origNode, origNow, origMail, origUptime
	})
	vitalsStore = func() *healthstore.RingStore { return store }
	vitalsNodeID = func() string { return node }
	vitalsNow = func() time.Time { return now }
	vitalsMailLatest = func() (mailq.Measurement, bool) { return mailq.Measurement{}, false }
	readUptimeFile = func() ([]byte, error) { return []byte("6785343.17 216456478.11\n"), nil }
}

func TestCollectVitals(t *testing.T) {
	now := time.Date(2026, 7, 18, 12, 0, 0, 0, time.UTC)
	store := healthstore.NewRingStore(8)
	stubVitals(t, store, "node-a", now)

	store.Append("node-a", healthstore.Sample{
		NodeID:      "node-a",
		CollectedAt: now.Add(-15 * time.Second),
		Load1:       3.63,
		CPUPct:      11.7,
		RamUsedPct:  18.3,
		SwapUsedPct: 2.5,
		DiskRootPct: 13.9,
	})

	v := collectVitals()
	if v == nil {
		t.Fatal("expected vitals")
	}
	if v.Load1 != 3.63 || v.CPUPct != 11.7 || v.RamUsedPct != 18.3 || v.SwapUsedPct != 2.5 || v.DiskRootPct != 13.9 {
		t.Fatalf("vitals = %+v", v)
	}
	if v.UptimeSeconds != 6785343 {
		t.Fatalf("uptime = %d", v.UptimeSeconds)
	}
	if v.MailMTA != "" || v.MailQueued != 0 {
		t.Fatalf("mail must be empty without a queue detector: %+v", v)
	}
}

func TestCollectVitalsMailQueue(t *testing.T) {
	now := time.Date(2026, 7, 18, 12, 0, 0, 0, time.UTC)
	store := healthstore.NewRingStore(8)
	stubVitals(t, store, "node-a", now)
	store.Append("node-a", healthstore.Sample{NodeID: "node-a", CollectedAt: now.Add(-5 * time.Second), Load1: 1})
	vitalsMailLatest = func() (mailq.Measurement, bool) {
		return mailq.Measurement{MTA: "exim", Total: 42, Frozen: 3, MeasuredAt: now}, true
	}

	v := collectVitals()
	if v == nil || v.MailMTA != "exim" || v.MailQueued != 42 || v.MailFrozen != 3 {
		t.Fatalf("vitals = %+v", v)
	}
}

func TestCollectVitalsStaleOrMissing(t *testing.T) {
	now := time.Date(2026, 7, 18, 12, 0, 0, 0, time.UTC)
	store := healthstore.NewRingStore(8)
	stubVitals(t, store, "node-a", now)

	if v := collectVitals(); v != nil {
		t.Fatalf("no sample must yield nil, got %+v", v)
	}

	store.Append("node-a", healthstore.Sample{NodeID: "node-a", CollectedAt: now.Add(-3 * time.Minute), Load1: 9})
	if v := collectVitals(); v != nil {
		t.Fatalf("stale sample must yield nil, got %+v", v)
	}
}

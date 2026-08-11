package mailtraffic

import (
	"testing"
	"time"

	"cfm/internal/mailmeter"
)

func outboundReport(addr string, n int) mailmeter.Report {
	r := mailmeter.NewReport()
	r.OutboundBySender[addr] = n
	r.OutboundTotal = n
	return r
}

// seedBaseline writes `perHour` outbound for addr into each of the `hours`
// baseline buckets ending 3h before T (i.e. inside the baseline window, clear
// of the 2h recent window).
func seedBaseline(t *testing.T, st *Store, T time.Time, addr string, hours, perHour int) {
	t.Helper()
	for h := 3; h < 3+hours; h++ {
		if err := st.AddReport(T.Add(-time.Duration(h)*time.Hour), outboundReport(addr, perHour)); err != nil {
			t.Fatal(err)
		}
	}
}

func anomalyFor(list []Anomaly, addr string) *Anomaly {
	for i := range list {
		if list[i].Addr == addr {
			return &list[i]
		}
	}
	return nil
}

func TestAnomalies(t *testing.T) {
	st := openTemp(t)
	T := time.Unix(1_700_000_000, 0)

	// spammy: steady 2/h for 48h, then a 200-message burst in the recent window.
	seedBaseline(t, st, T, "spammy@x.gr", 48, 2)
	// busy: constant high volume — 100/h baseline AND 200 in the recent 2h (same
	// rate) → must NOT be flagged.
	seedBaseline(t, st, T, "busy@x.gr", 48, 100)
	// small: tiny sender, 1/h baseline, 3 recent → below the spike floor.
	seedBaseline(t, st, T, "small@x.gr", 48, 1)
	// evil@other.gr: same spike shape but a DIFFERENT domain (for the scope test).
	seedBaseline(t, st, T, "evil@other.gr", 48, 2)

	// Recent window (last 2h): place bursts at T-1h.
	recent := T.Add(-1 * time.Hour)
	if err := st.AddReport(recent, outboundReport("spammy@x.gr", 200)); err != nil {
		t.Fatal(err)
	}
	if err := st.AddReport(recent, outboundReport("busy@x.gr", 200)); err != nil {
		t.Fatal(err)
	}
	if err := st.AddReport(recent, outboundReport("small@x.gr", 3)); err != nil {
		t.Fatal(err)
	}
	if err := st.AddReport(recent, outboundReport("evil@other.gr", 200)); err != nil {
		t.Fatal(err)
	}
	// fresh@x.gr: never seen in the baseline, 60 in the recent window → new-sender.
	if err := st.AddReport(recent, outboundReport("fresh@x.gr", 60)); err != nil {
		t.Fatal(err)
	}

	// ---- admin view ----
	sum, err := st.trafficSummaryAt(T, 24, nil, 20)
	if err != nil {
		t.Fatal(err)
	}
	got := sum.Anomalies

	if a := anomalyFor(got, "spammy@x.gr"); a == nil || a.Kind != "spike" {
		t.Fatalf("spammy should be a spike: %+v", got)
	} else if a.Recent != 200 || a.BaselinePerHour != 2 || a.Ratio < 40 {
		t.Fatalf("spammy spike numbers off: %+v", *a)
	}
	if a := anomalyFor(got, "fresh@x.gr"); a == nil || a.Kind != "new-sender" {
		t.Fatalf("fresh should be new-sender: %+v", got)
	}
	if anomalyFor(got, "busy@x.gr") != nil {
		t.Fatalf("constant high-volume sender must NOT be flagged: %+v", got)
	}
	if anomalyFor(got, "small@x.gr") != nil {
		t.Fatalf("tiny sender below the floor must NOT be flagged: %+v", got)
	}
	// new-senders sort ahead of spikes.
	if len(got) >= 2 && got[0].Kind != "new-sender" {
		t.Fatalf("new-sender should sort first: %+v", got)
	}

	// ---- scoped view (owns x.gr only) ----
	scoped, err := st.trafficSummaryAt(T, 24, map[string]struct{}{"x.gr": {}}, 20)
	if err != nil {
		t.Fatal(err)
	}
	if anomalyFor(scoped.Anomalies, "evil@other.gr") != nil {
		t.Fatalf("scoped x.gr caller must not see other.gr anomalies: %+v", scoped.Anomalies)
	}
	if anomalyFor(scoped.Anomalies, "spammy@x.gr") == nil {
		t.Fatalf("scoped caller should see its own domain's spike: %+v", scoped.Anomalies)
	}
}

// A sender active in fewer than anomalyMinActiveHours baseline hours has too
// little history to trust a ratio, so it is not spike-evaluated (only the
// new-sender floor applies) — but a big new sender still trips new-sender.
func TestAnomaliesColdStart(t *testing.T) {
	st := openTemp(t)
	T := time.Unix(1_700_000_000, 0)

	// Only 2 active baseline hours (< anomalyMinActiveHours) at 2/h, then 30 recent.
	seedBaseline(t, st, T, "steady@x.gr", 2, 2)
	if err := st.AddReport(T.Add(-1*time.Hour), outboundReport("steady@x.gr", 30)); err != nil {
		t.Fatal(err)
	}
	// steady@ sent 30 (>= spike floor) but < new-sender floor, and has too few
	// active baseline hours for a ratio → not flagged.
	if err := st.AddReport(T.Add(-1*time.Hour), outboundReport("blast@x.gr", 80)); err != nil {
		t.Fatal(err)
	}

	sum, err := st.trafficSummaryAt(T, 24, nil, 20)
	if err != nil {
		t.Fatal(err)
	}
	if anomalyFor(sum.Anomalies, "steady@x.gr") != nil {
		t.Fatalf("cold-start must not flag a steady sender as a spike: %+v", sum.Anomalies)
	}
	if a := anomalyFor(sum.Anomalies, "blast@x.gr"); a == nil || a.Kind != "new-sender" {
		t.Fatalf("a big sender during cold-start should still be new-sender: %+v", sum.Anomalies)
	}
}

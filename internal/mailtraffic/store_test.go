package mailtraffic

import (
	"path/filepath"
	"testing"
	"time"

	"cfm/internal/mailmeter"
)

func openTemp(t *testing.T) *Store {
	t.Helper()
	st, err := Open(filepath.Join(t.TempDir(), "mt.db"))
	if err != nil {
		t.Fatalf("open: %v", err)
	}
	t.Cleanup(func() { _ = st.Close() })
	return st
}

func sampleReport() mailmeter.Report {
	r := mailmeter.NewReport()
	r.OutboundBySender["support@ordermusic.gr"] = 100
	r.OutboundBySender["info@axidwear.com"] = 40
	r.OutboundTotal = 140
	r.InboundByMailbox["box@nac.gr"] = 5
	r.InboundTotal = 5
	r.LocalSubmitByUser["evafeiadis"] = 20
	r.LocalSubmitTotal = 20
	r.AuthFailByMailbox["victim@nac.gr"] = 3
	r.AuthFailByMailbox[mailmeter.HostWide] = 9
	r.RejectedTotal = 7
	return r
}

func find(list []mailmeter.AddrCount, addr string) int {
	for _, a := range list {
		if a.Addr == addr {
			return a.Count
		}
	}
	return -1
}

func TestAddReportAndAdminSummary(t *testing.T) {
	st := openTemp(t)
	now := time.Unix(1_700_000_000, 0)
	if err := st.AddReport(now, sampleReport()); err != nil {
		t.Fatal(err)
	}
	sum, err := st.trafficSummaryAt(now, 24, nil, 10) // nil scope = admin
	if err != nil {
		t.Fatal(err)
	}
	if sum.Scope != "admin" {
		t.Fatalf("expected admin summary, got scope %q", sum.Scope)
	}
	if got := find(sum.TopOutboundSenders, "support@ordermusic.gr"); got != 100 {
		t.Fatalf("top outbound support = %d, want 100", got)
	}
	if sum.TopOutboundSenders[0].Addr != "support@ordermusic.gr" {
		t.Fatalf("outbound not sorted desc: %+v", sum.TopOutboundSenders)
	}
	if got := find(sum.MostSentDomains, "ordermusic.gr"); got != 100 {
		t.Fatalf("most sent domain ordermusic.gr = %d, want 100", got)
	}
	if got := find(sum.TopLocalSubmitters, "evafeiadis"); got != 20 {
		t.Fatalf("local submitter evafeiadis = %d, want 20 (admin sees it)", got)
	}
	if got := find(sum.TopAuthFailed, mailmeter.HostWide); got != 9 {
		t.Fatalf("host-wide auth-fail = %d, want 9", got)
	}
	if sum.Totals.Outbound != 140 || sum.Totals.Rejected != 7 || sum.Totals.AuthFailed != 12 || sum.Totals.LocalSubmit != 20 {
		t.Fatalf("totals wrong: %+v", sum.Totals)
	}
}

func TestScopedSummaryFiltersToDomains(t *testing.T) {
	st := openTemp(t)
	now := time.Unix(1_700_000_000, 0)
	if err := st.AddReport(now, sampleReport()); err != nil {
		t.Fatal(err)
	}
	scope := map[string]struct{}{"ordermusic.gr": {}}
	sum, err := st.trafficSummaryAt(now, 24, scope, 10)
	if err != nil {
		t.Fatal(err)
	}
	if sum.Scope != "scoped" {
		t.Fatalf("scope label = %q", sum.Scope)
	}
	if len(sum.TopOutboundSenders) != 1 || sum.TopOutboundSenders[0].Addr != "support@ordermusic.gr" {
		t.Fatalf("scoped outbound should be only ordermusic.gr sender: %+v", sum.TopOutboundSenders)
	}
	if len(sum.TopLocalSubmitters) != 0 {
		t.Fatalf("scoped user must not see local unix submitters: %+v", sum.TopLocalSubmitters)
	}
	if len(sum.TopAuthFailed) != 0 {
		t.Fatalf("victim@nac.gr and host-wide are out of scope: %+v", sum.TopAuthFailed)
	}
	if sum.Totals.Outbound != 100 || sum.Totals.Rejected != 0 || sum.Totals.AuthFailed != 0 || sum.Totals.LocalSubmit != 0 {
		t.Fatalf("scoped totals must exclude other domains + host-wide: %+v", sum.Totals)
	}
}

func TestScopedEmptyOwnsNothing(t *testing.T) {
	st := openTemp(t)
	now := time.Unix(1_700_000_000, 0)
	if err := st.AddReport(now, sampleReport()); err != nil {
		t.Fatal(err)
	}
	sum, err := st.trafficSummaryAt(now, 24, map[string]struct{}{}, 10) // scoped, empty
	if err != nil {
		t.Fatal(err)
	}
	if sum.Scope != "scoped" {
		t.Fatalf("expected scoped summary, got scope %q", sum.Scope)
	}
	if len(sum.TopOutboundSenders) != 0 || sum.Totals.Outbound != 0 {
		t.Fatalf("empty-scope caller must see nothing: %+v", sum)
	}
}

func TestWindowExcludesOldBuckets(t *testing.T) {
	st := openTemp(t)
	now := time.Unix(1_700_000_000, 0)
	old := now.Add(-48 * time.Hour)

	oldR := mailmeter.NewReport()
	oldR.OutboundBySender["ancient@x.gr"] = 5
	if err := st.AddReport(old, oldR); err != nil {
		t.Fatal(err)
	}
	if err := st.AddReport(now, sampleReport()); err != nil {
		t.Fatal(err)
	}

	sum, err := st.trafficSummaryAt(now, 24, nil, 10)
	if err != nil {
		t.Fatal(err)
	}
	if find(sum.TopOutboundSenders, "ancient@x.gr") != -1 {
		t.Fatalf("48h-old bucket leaked into a 24h window: %+v", sum.TopOutboundSenders)
	}
	if find(sum.TopOutboundSenders, "support@ordermusic.gr") != 100 {
		t.Fatalf("recent bucket missing: %+v", sum.TopOutboundSenders)
	}
}

// Flush writes counters and advances the tail position together; a reader sees
// both after one call.
func TestFlushWritesCountersAndTailPos(t *testing.T) {
	st := openTemp(t)
	now := time.Unix(1_700_000_000, 0)
	r := mailmeter.NewReport()
	r.OutboundBySender["a@x.gr"] = 3
	if err := st.Flush(now, r, nil, "/var/log/exim_mainlog", 42, 1024); err != nil {
		t.Fatal(err)
	}
	sum, _ := st.trafficSummaryAt(now, 24, nil, 10)
	if find(sum.TopOutboundSenders, "a@x.gr") != 3 {
		t.Fatalf("Flush did not persist counters: %+v", sum.TopOutboundSenders)
	}
	ino, off, ok := st.LoadTailPos("/var/log/exim_mainlog")
	if !ok || ino != 42 || off != 1024 {
		t.Fatalf("Flush did not persist tail pos: ino=%d off=%d ok=%v", ino, off, ok)
	}
	// An empty report still advances the offset (non-event chunk).
	if err := st.Flush(now, mailmeter.NewReport(), nil, "/var/log/exim_mainlog", 42, 2048); err != nil {
		t.Fatal(err)
	}
	if _, off, _ := st.LoadTailPos("/var/log/exim_mainlog"); off != 2048 {
		t.Fatalf("empty-report Flush must still advance offset, got %d", off)
	}
}

// Deliverability aggregates the mail_delivery counters per provider/outcome and
// surfaces top non-ok reasons — for admins only.
func TestDeliverabilitySummary(t *testing.T) {
	st := openTemp(t)
	now := time.Unix(1_700_000_000, 0)
	deliv := map[DeliveryKey]int64{
		{Provider: "google", Outcome: int(mailmeter.Delivered), Reason: "ok"}:                      40,
		{Provider: "google", Outcome: int(mailmeter.Deferred), Reason: "unsolicited-rate-limited"}: 12,
		{Provider: "google", Outcome: int(mailmeter.Bounced), Reason: "unsolicited-blocked"}:       3,
		{Provider: "microsoft", Outcome: int(mailmeter.Delivered), Reason: "ok"}:                   10,
	}
	if err := st.Flush(now, mailmeter.NewReport(), deliv, "/var/log/exim_mainlog", 1, 100); err != nil {
		t.Fatal(err)
	}

	// Admin (nil scope) gets the deliverability block.
	sum, err := st.trafficSummaryAt(now, 24, nil, 10)
	if err != nil {
		t.Fatal(err)
	}
	if sum.Deliverability == nil {
		t.Fatal("admin summary must include deliverability")
	}
	dl := sum.Deliverability
	if dl.Delivered != 50 || dl.Deferred != 12 || dl.Bounced != 3 {
		t.Fatalf("totals wrong: %+v", dl)
	}
	if len(dl.ByProvider) != 2 || dl.ByProvider[0].Provider != "google" { // google most active
		t.Fatalf("by_provider wrong: %+v", dl.ByProvider)
	}
	if dl.ByProvider[0].Delivered != 40 || dl.ByProvider[0].Deferred != 12 || dl.ByProvider[0].Bounced != 3 {
		t.Fatalf("google outcomes wrong: %+v", dl.ByProvider[0])
	}
	// top_reasons excludes "ok"; unsolicited-rate-limited (12) ranks above unsolicited-blocked (3).
	if len(dl.TopReasons) != 2 || dl.TopReasons[0].Reason != "unsolicited-rate-limited" || dl.TopReasons[0].Count != 12 {
		t.Fatalf("top_reasons wrong: %+v", dl.TopReasons)
	}

	// Scoped callers do NOT get host-wide deliverability.
	scoped, _ := st.trafficSummaryAt(now, 24, map[string]struct{}{"x.gr": {}}, 10)
	if scoped.Deliverability != nil {
		t.Fatalf("scoped caller must not receive deliverability, got %+v", scoped.Deliverability)
	}
}

func TestAddReportAccumulatesSameBucket(t *testing.T) {
	st := openTemp(t)
	now := time.Unix(1_700_000_000, 0)
	r1 := mailmeter.NewReport()
	r1.OutboundBySender["a@x.gr"] = 3
	r2 := mailmeter.NewReport()
	r2.OutboundBySender["a@x.gr"] = 4
	if err := st.AddReport(now, r1); err != nil {
		t.Fatal(err)
	}
	if err := st.AddReport(now.Add(30*time.Second), r2); err != nil { // same hour bucket
		t.Fatal(err)
	}
	sum, _ := st.trafficSummaryAt(now, 24, nil, 10)
	if find(sum.TopOutboundSenders, "a@x.gr") != 7 {
		t.Fatalf("same-bucket increments should accumulate to 7: %+v", sum.TopOutboundSenders)
	}
}

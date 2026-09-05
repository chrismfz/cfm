package enrich

import (
	"testing"
	"time"
)

// TestPTRRetryDue: a cached Result whose PTR fetch failed is retried after
// ptrRetryInterval — not pinned empty for the 24h geo TTL — but only when PTR
// resolution is enabled, the IP is routable, and the entry really has no PTR.
func TestPTRRetryDue(t *testing.T) {
	now := time.Now()
	e := &Enricher{enablePTR: true}
	fresh := Result{PTR: "", ts: now.Add(-time.Minute)}
	old := Result{PTR: "", ts: now.Add(-ptrRetryInterval - time.Second)}
	resolved := Result{PTR: "crawl.googlebot.com", ts: now.Add(-time.Hour)}

	if e.ptrRetryDue(fresh, "66.249.66.1", now) {
		t.Fatalf("a recent PTR miss must not be retried yet")
	}
	if !e.ptrRetryDue(old, "66.249.66.1", now) {
		t.Fatalf("an old PTR miss on a routable IP must be retried")
	}
	if e.ptrRetryDue(resolved, "66.249.66.1", now) {
		t.Fatalf("a resolved PTR is never retried by this path")
	}
	if e.ptrRetryDue(old, "10.0.0.5", now) {
		t.Fatalf("non-routable IPs are never resolved")
	}
	if e.ptrRetryDue(old, "not-an-ip", now) {
		t.Fatalf("unparsable IP must not retry")
	}
	off := &Enricher{enablePTR: false}
	if off.ptrRetryDue(old, "66.249.66.1", now) {
		t.Fatalf("PTR disabled → never retried")
	}
	var nilE *Enricher
	if nilE.ptrRetryDue(old, "66.249.66.1", now) {
		t.Fatalf("nil receiver must be safe and false")
	}
}

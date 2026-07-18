package healthmodel

import (
	"testing"
	"time"

	"cfm/internal/mailq"
)

func TestLatestMailQueueStatus(t *testing.T) {
	mailq.TestOnlyReset()
	t.Cleanup(mailq.TestOnlyReset)

	if got := latestMailQueueStatus(); got != nil {
		t.Fatalf("no measurement published → nil, got %+v", got)
	}

	mailq.Publish(mailq.Measurement{MTA: "exim", Total: 42, Frozen: 3, MeasuredAt: time.Now().Add(-90 * time.Second)})
	got := latestMailQueueStatus()
	if got == nil {
		t.Fatalf("expected status after publish")
	}
	if got.MTA != "exim" || got.Queued != 42 || got.Frozen != 3 {
		t.Fatalf("status=%+v want exim/42/3", got)
	}
	if got.AgeSeconds < 85 || got.AgeSeconds > 120 {
		t.Fatalf("age_seconds=%d want ~90", got.AgeSeconds)
	}
}

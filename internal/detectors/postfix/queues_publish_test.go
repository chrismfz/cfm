package postfix

import (
	"context"
	"testing"

	core "cfm/internal/detectors/core"
	"cfm/internal/mailq"
)

func TestQueuesRunOnce_PublishesMailqMeasurement(t *testing.T) {
	mailq.TestOnlyReset()
	t.Cleanup(mailq.TestOnlyReset)

	q := NewQueues(QueuesConfig{
		TotalCmd: "echo 3",
		ListCmd:  "printf 'ABC123 deferred\\n'",
	})
	out := make(chan core.Alert, 4)
	if err := q.RunOnce(context.Background(), out); err != nil {
		t.Fatalf("RunOnce: %v", err)
	}

	m, ok := mailq.Latest()
	if !ok {
		t.Fatalf("expected a published measurement")
	}
	if m.MTA != "postfix" || m.Total != 3 || m.Frozen != 1 {
		t.Fatalf("measurement=%+v want postfix/3/1", m)
	}
}

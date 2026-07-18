package exim

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
		TotalCmd: "echo 7",
		ListCmd:  "printf 'msg-a\\n1h  1.2K abc *** frozen ***\\n'",
	})
	out := make(chan core.Alert, 4)
	if err := q.RunOnce(context.Background(), out); err != nil {
		t.Fatalf("RunOnce: %v", err)
	}

	m, ok := mailq.Latest()
	if !ok {
		t.Fatalf("expected a published measurement")
	}
	if m.MTA != "exim" || m.Total != 7 || m.Frozen != 1 {
		t.Fatalf("measurement=%+v want exim/7/1", m)
	}
}

func TestQueuesRunOnce_NoPublishOnCountFailure(t *testing.T) {
	mailq.TestOnlyReset()
	t.Cleanup(mailq.TestOnlyReset)

	q := NewQueues(QueuesConfig{
		TotalCmd: "false",
		ListCmd:  "true",
	})
	out := make(chan core.Alert, 4)
	_ = q.RunOnce(context.Background(), out)

	if _, ok := mailq.Latest(); ok {
		t.Fatalf("failed count must not publish a fake empty queue")
	}
}

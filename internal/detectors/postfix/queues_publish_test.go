package postfix

import (
	"context"
	"testing"

	core "cfm/internal/detectors/core"
	"cfm/internal/mailq"
	"cfm/internal/mailqueue"
)

// RunOnce derives Total and Frozen from the PARSED listing (an exact message
// count + the `!` hold marker), not from a line-counting shell command or a
// "deferred" substring. Feed a 3-message listing with one held (`!`) message
// and assert both the health measurement and the rich report reflect 3/1.
func TestQueuesRunOnce_PublishesFromParsedListing(t *testing.T) {
	mailq.TestOnlyReset()
	mailqueue.TestOnlyReset()
	t.Cleanup(mailq.TestOnlyReset)
	t.Cleanup(mailqueue.TestOnlyReset)

	listing := "ABC123 1234 Wed Aug 5 10:00:33 a@x.gr\\n" +
		"DEF456! 2048 Wed Aug 5 09:00:00 b@y.gr\\n" +
		"GHI789 4096 Wed Aug 5 08:00:00 c@z.gr\\n"

	q := NewQueues(QueuesConfig{
		ListCmd: "printf '" + listing + "'",
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

	// The rich report must agree (same source listing).
	rep, ok := mailqueue.Latest()
	if !ok {
		t.Fatalf("expected a published report")
	}
	if rep.MTA != "postfix" || rep.Total != 3 || rep.Frozen != 1 {
		t.Fatalf("report=%+v want postfix total=3 frozen=1", rep)
	}
}

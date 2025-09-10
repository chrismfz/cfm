package detectors

import (
	"context"
//	"log"
	"time"

	"cfm/internal/logging"
	core "cfm/internal/detectors/core"
)

type LoggerSink struct{}

func (LoggerSink) Publish(a core.Alert) {
    lim := ""
    if a.Extra != nil {
        lim = a.Extra["limit"]
    }
    if lim != "" {
        logging.Logf(
            "\nTime:  %s\nType:  %s, %s\nCount: %d (limit: %s)\nBlocked: No\n\nSample of the first %d lines:\n\n%s\n",
            a.When.Format("Mon Jan 2 15:04:05 2006 -0700"),
            a.Kind, a.Key, a.Count, lim,
            len(a.Samples),
            joinLines(a.Samples),
        )
    } else {
        logging.Logf(
            "\nTime:  %s\nType:  %s, %s\nCount: %d\nBlocked: No\n\nSample of the first %d lines:\n\n%s\n",
            a.When.Format("Mon Jan 2 15:04:05 2006 -0700"),
            a.Kind, a.Key, a.Count,
            len(a.Samples),
            joinLines(a.Samples),
        )
    }
}




func joinLines(ss []string) string {
	out := ""
	for _, s := range ss {
		out += s + "\n"
	}
	return out
}

func RunPeriodic(ctx context.Context, d core.PeriodicDetector, sink core.Sink) error {
	out := make(chan core.Alert, 8)
	defer close(out)

	go func() {
		for a := range out {
			sink.Publish(a)
		}
	}()

	every := d.Every()
	if every <= 0 {
		every = 60 * time.Second
	}

	logging.Logf("[detectors] %s started (every=%s)", d.Name(), every)

	_ = d.RunOnce(ctx, out)

	t := time.NewTicker(every)
	defer t.Stop()

	for {
		select {
		case <-ctx.Done():
			return ctx.Err()
		case <-t.C:
			_ = d.RunOnce(ctx, out)
		}
	}
}

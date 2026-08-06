// internal/detectors/postfix/queues.go
package postfix

import (
	"bufio"
	"context"
	"fmt"
	"os/exec"
	"strconv"
	"strings"
	"sync"
	"time"

	core "cfm/internal/detectors/core"
	"cfm/internal/mailq"
	"cfm/internal/mailqueue"
)

type QueuesConfig struct {
	// TotalCmd is only used as a fallback when the queue listing exceeds the
	// parse cap (>20k messages); normally the total comes from the parsed
	// listing. It must print an EXACT message count — count header lines
	// (queue-id + numeric size), not raw lines. Default below; override per node.
	TotalCmd    string        // default: count `mailq` header lines
	ListCmd     string        // default: "mailq"
	Every       time.Duration // default: 60s
	Timeout     time.Duration // default: 8s
	MaxTotal    int           // alert threshold
	MaxFrozen   int           // alert threshold (used for deferred/held etc. if you like)
	SampleLimit int           // default: 10
	Cooldown    time.Duration // default: 10m
}

type Queues struct {
	cfg  QueuesConfig
	gate *core.AlertGate
	mu   sync.Mutex
}

func NewQueues(cfg QueuesConfig) *Queues {
	if cfg.TotalCmd == "" {
		// Count message HEADER lines only (queue id followed by a numeric size),
		// never raw lines — a message spans a header + optional reason + N
		// recipient lines. The grep exits non-zero on an empty queue, so the
		// pipeline ends in `wc -l` (always exit 0) to keep the count at 0.
		cfg.TotalCmd = `mailq | grep -E '^[A-Za-z0-9]+ +[0-9]' | wc -l`
	}
	if cfg.ListCmd == "" {
		cfg.ListCmd = "mailq"
	}
	if cfg.Every == 0 {
		cfg.Every = 60 * time.Second
	}
	if cfg.Timeout == 0 {
		cfg.Timeout = 8 * time.Second
	}
	if cfg.SampleLimit == 0 {
		cfg.SampleLimit = 10
	}
	if cfg.Cooldown == 0 {
		cfg.Cooldown = 10 * time.Minute
	}
	return &Queues{
		cfg:  cfg,
		gate: core.NewAlertGate(cfg.Cooldown),
	}
}

func (q *Queues) Name() string         { return "postfix/queues" }
func (q *Queues) Every() time.Duration { return q.cfg.Every }

// Τοπικές σταθερές (ίδιες με exim αλλά σε άλλο package)
const (
	QueueTotal  core.AlertKind = "QUEUE_TOTAL"
	QueueFrozen core.AlertKind = "QUEUE_FROZEN"
)

func (q *Queues) RunOnce(ctx context.Context, out chan<- core.Alert) error {
	start := time.Now()

	// A single `postqueue -p` listing is the source of truth for postfix: the
	// parser yields an exact message count and the frozen/hold count (from the
	// `!` marker) — unlike a line-counting shell command, which over-counts by
	// ~3-5× (a message spans a header + optional reason + N recipient lines).
	// A failed probe (postfix absent, timeout) must publish nothing rather than
	// a fake empty queue.
	samples, rawList, listErr := q.listQueue(ctx)
	if listErr != nil {
		return nil
	}

	now := time.Now()
	rep := mailqueue.BuildPostfixReport(rawList, now, 0, mailqueue.DefaultTop)
	rep.MeasuredAt = now
	// Only past the parse cap (a >20k queue, Truncated=true) does the parsed
	// count under-report; fall back to the optional external count command for
	// the true total.
	if rep.Truncated {
		if ext, err := q.totalCount(ctx); err == nil && ext > rep.Total {
			rep.Total = ext
		}
	}

	total, frozen := rep.Total, rep.Frozen

	// Rich report (mail_queue_summary / CLI / WebUI) + health snapshot, both
	// from the same listing — no extra probe.
	mailqueue.Publish(rep)
	mailq.Publish(mailq.Measurement{MTA: "postfix", Total: total, Frozen: frozen, MeasuredAt: now})

	if q.cfg.MaxTotal > 0 && total > q.cfg.MaxTotal &&
		q.gate.Allow(string(QueueTotal), now, total, q.cfg.MaxTotal) {
		out <- core.Alert{
			When:    now,
			Kind:    QueueTotal,
			Key:     "postfix-queue",
			Count:   total,
			Samples: trimSamples(samples, q.cfg.SampleLimit),
			Extra: map[string]string{
				"total":    strconv.Itoa(total),
				"frozen":   strconv.Itoa(frozen),
				"duration": time.Since(start).String(),
			},
		}
	}

	if q.cfg.MaxFrozen > 0 && frozen > q.cfg.MaxFrozen &&
		q.gate.Allow(string(QueueFrozen), now, frozen, q.cfg.MaxFrozen) {
		out <- core.Alert{
			When:    now,
			Kind:    QueueFrozen,
			Key:     "postfix-queue",
			Count:   frozen,
			Samples: trimSamples(filterFrozen(samples), q.cfg.SampleLimit),
			Extra: map[string]string{
				"total":    strconv.Itoa(total),
				"frozen":   strconv.Itoa(frozen),
				"duration": time.Since(start).String(),
			},
		}
	}

	return nil
}

func (q *Queues) totalCount(ctx context.Context) (int, error) {
	cmd := shell(q.cfg.TotalCmd)
	if q.cfg.Timeout > 0 {
		var cancel context.CancelFunc
		ctx, cancel = context.WithTimeout(ctx, q.cfg.Timeout)
		defer cancel()
	}
	out, err := cmd.Output()
	if err != nil {
		return 0, err
	}
	return parseCountOutput(string(out))
}

// parseCountOutput extracts the count from the command's stdout. The
// command runs under a login shell (`sh -lc`), so profile noise (motd,
// /etc/profile.d chatter) can precede the number — take the last line
// that parses as an integer instead of requiring clean output.
func parseCountOutput(raw string) (int, error) {
	n, found := 0, false
	for _, line := range strings.Split(raw, "\n") {
		if v, err := strconv.Atoi(strings.TrimSpace(line)); err == nil {
			n, found = v, true
		}
	}
	if !found {
		return 0, fmt.Errorf("parse total: no numeric line in %q", strings.TrimSpace(raw))
	}
	return n, nil
}

// listQueue runs the `postqueue -p` / `mailq` listing once and returns a bounded
// set of sample lines plus the full raw output (which feeds
// mailqueue.BuildPostfixReport for the exact count / frozen / age / domains /
// reasons — no separate count exec).
func (q *Queues) listQueue(ctx context.Context) ([]string, string, error) {
	cmd := shell(q.cfg.ListCmd)
	if q.cfg.Timeout > 0 {
		var cancel context.CancelFunc
		ctx, cancel = context.WithTimeout(ctx, q.cfg.Timeout)
		defer cancel()
	}
	out, err := cmd.Output()
	if err != nil {
		return nil, "", err
	}

	samples := make([]string, 0, q.cfg.SampleLimit)
	sc := bufio.NewScanner(strings.NewReader(string(out)))
	sc.Buffer(make([]byte, 0, 64*1024), 1024*1024)
	for sc.Scan() {
		if len(samples) < q.cfg.SampleLimit {
			samples = append(samples, sc.Text())
		}
	}
	return samples, string(out), nil
}

func trimSamples(a []string, n int) []string {
	if len(a) <= n {
		return a
	}
	return a[:n]
}

// filterFrozen keeps the held/frozen sample lines — postfix marks a held
// message with a `!` suffix on its queue id (the header line's first field).
func filterFrozen(lines []string) []string {
	out := make([]string, 0, len(lines))
	for _, l := range lines {
		if f := strings.Fields(l); len(f) > 0 && strings.HasSuffix(f[0], "!") {
			out = append(out, l)
		}
	}
	if len(out) == 0 {
		return lines
	}
	return out
}

func shell(s string) *exec.Cmd {
	return exec.Command("/bin/sh", "-lc", s)
}

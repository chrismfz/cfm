package exim

import (
	"bufio"
	"context"
	"fmt"
	"os"
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
	TotalCmd    string        // default: "exim -bpc"
	ListCmd     string        // default: "exim -bp"
	Every       time.Duration // default: 60s
	Timeout     time.Duration // default: 8s
	MaxTotal    int           // alert threshold
	MaxFrozen   int           // alert threshold
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
		cfg.TotalCmd = "exim -bpc"
	}
	if cfg.ListCmd == "" {
		cfg.ListCmd = "exim -bp"
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

	return &Queues{cfg: cfg, gate: core.NewAlertGate(cfg.Cooldown)}
}

func (q *Queues) Name() string         { return "exim/queues" }
func (q *Queues) Every() time.Duration { return q.cfg.Every }

// Τοπικές σταθερές (σκόπιμα εδώ, όχι στο core)
const (
	QueueTotal  core.AlertKind = "QUEUE_TOTAL"
	QueueFrozen core.AlertKind = "QUEUE_FROZEN"
)

func (q *Queues) RunOnce(ctx context.Context, out chan<- core.Alert) error {
	start := time.Now()

	total, totalErr := q.totalCount(ctx)
	frozen, samples, rawBP, _ := q.frozenCountAndSamples(ctx)

	now := time.Now()
	// Publish for the health snapshot (cfm health / dashboard). Only on a
	// successful count — a failed probe (exim absent, timeout) must not
	// surface as a fake empty queue.
	if totalErr == nil {
		mailq.Publish(mailq.Measurement{MTA: "exim", Total: total, Frozen: frozen, MeasuredAt: now})

		// Publish the MTA-agnostic rich report (mail_queue_summary / _defer_reasons
		// / CLI / WebUI) from the SAME `exim -bp` output — no extra probe. Defer
		// reasons come from a bounded mainlog tail, only when the queue is non-empty.
		rep := mailqueue.BuildEximReport(rawBP, total, frozen, mailqueue.DefaultTop)
		rep.MeasuredAt = now
		if total > 0 {
			if lines := q.tailMainlog(ctx); len(lines) > 0 {
				rep.DeferReasons = mailqueue.ParseEximDeferReasons(lines, mailqueue.DefaultTop)
			}
		}
		mailqueue.Publish(rep)
	}
	if q.cfg.MaxTotal > 0 && total > q.cfg.MaxTotal &&
		q.gate.Allow(string(QueueTotal), now, total, q.cfg.MaxTotal) {
		out <- core.Alert{
			When:    now,
			Kind:    QueueTotal,
			Key:     "exim-queue",
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
			Key:     "exim-queue",
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

func (q *Queues) frozenCountAndSamples(ctx context.Context) (int, []string, string, error) {
	cmd := shell(q.cfg.ListCmd)
	if q.cfg.Timeout > 0 {
		var cancel context.CancelFunc
		ctx, cancel = context.WithTimeout(ctx, q.cfg.Timeout)
		defer cancel()
	}
	out, err := cmd.Output()
	if err != nil {
		return 0, nil, "", err
	}

	frozen := 0
	samples := make([]string, 0, q.cfg.SampleLimit)

	sc := bufio.NewScanner(strings.NewReader(string(out)))
	sc.Buffer(make([]byte, 0, 64*1024), 1024*1024)
	for sc.Scan() {
		line := sc.Text()
		if strings.Contains(line, "*** frozen ***") {
			frozen++
		}
		if len(samples) < q.cfg.SampleLimit {
			samples = append(samples, line)
		}
	}
	// The full output feeds mailqueue.BuildEximReport (age/domains/oldest) with
	// no extra `exim -bp` call.
	return frozen, samples, string(out), nil
}

// eximMainlogCandidates are the standard exim mainlog locations (mirrors the
// exim/relays resolver).
var eximMainlogCandidates = []string{
	"/var/log/exim_mainlog", "/var/log/exim4/mainlog", "/var/log/exim/mainlog",
}

// mainlogTailLines bounds how much of the mainlog is scanned for defer reasons.
const mainlogTailLines = 4000

// tailMainlog returns the last mainlogTailLines of the exim mainlog (bounded,
// best-effort). Empty when no mainlog is found. Uses `tail` so a multi-GB log is
// read backward, not whole.
func (q *Queues) tailMainlog(ctx context.Context) []string {
	path := ""
	for _, p := range eximMainlogCandidates {
		if fi, err := os.Stat(p); err == nil && fi.Mode().IsRegular() {
			path = p
			break
		}
	}
	if path == "" {
		return nil
	}
	cctx, cancel := context.WithTimeout(ctx, q.cfg.Timeout)
	defer cancel()
	out, err := exec.CommandContext(cctx, "tail", "-n", strconv.Itoa(mainlogTailLines), path).Output()
	if err != nil {
		return nil
	}
	return strings.Split(strings.TrimRight(string(out), "\n"), "\n")
}

func trimSamples(a []string, n int) []string {
	if len(a) <= n {
		return a
	}
	return a[:n]
}

func filterFrozen(lines []string) []string {
	out := make([]string, 0, len(lines))
	for _, l := range lines {
		if strings.Contains(l, "*** frozen ***") {
			out = append(out, l)
		}
	}
	if len(out) == 0 {
		return lines
	}
	return out
}

func shell(s string) *exec.Cmd { return exec.Command("/bin/sh", "-lc", s) }

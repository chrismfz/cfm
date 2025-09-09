package exim

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
	cfg      QueuesConfig
	lastFire map[core.AlertKind]time.Time
	mu       sync.Mutex
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
	return &Queues{
		cfg:      cfg,
		lastFire: make(map[core.AlertKind]time.Time),
	}
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

	total, _ := q.totalCount(ctx)
	frozen, samples, _ := q.frozenCountAndSamples(ctx)

	now := time.Now()
	if q.cfg.MaxTotal > 0 && total > q.cfg.MaxTotal && q.cool(QueueTotal, now) {
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
	if q.cfg.MaxFrozen > 0 && frozen > q.cfg.MaxFrozen && q.cool(QueueFrozen, now) {
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
	s := strings.TrimSpace(string(out))
	n, err := strconv.Atoi(s)
	if err != nil {
		return 0, fmt.Errorf("parse total: %w (got %q)", err, s)
	}
	return n, nil
}

func (q *Queues) frozenCountAndSamples(ctx context.Context) (int, []string, error) {
	cmd := shell(q.cfg.ListCmd)
	if q.cfg.Timeout > 0 {
		var cancel context.CancelFunc
		ctx, cancel = context.WithTimeout(ctx, q.cfg.Timeout)
		defer cancel()
	}
	out, err := cmd.Output()
	if err != nil {
		return 0, nil, err
	}

	frozen := 0
	samples := make([]string, 0, q.cfg.SampleLimit)

	sc := bufio.NewScanner(strings.NewReader(string(out)))
	for sc.Scan() {
		line := sc.Text()
		if strings.Contains(line, "*** frozen ***") {
			frozen++
		}
		if len(samples) < q.cfg.SampleLimit {
			samples = append(samples, line)
		}
	}
	return frozen, samples, nil
}

func (q *Queues) cool(kind core.AlertKind, now time.Time) bool {
	q.mu.Lock()
	defer q.mu.Unlock()
	last := q.lastFire[kind]
	if now.Sub(last) < q.cfg.Cooldown {
		return false
	}
	q.lastFire[kind] = now
	return true
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

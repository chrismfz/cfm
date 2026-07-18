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
)

type QueuesConfig struct {
    TotalCmd    string        // default: "mailq | tail -n +2 | grep -v 'Mail queue is empty' | wc -l"
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
        // Very generic default; you can override in cfg:
        // e.g. TOTAL_CMD = "postqueue -p | tail -n +2 | awk 'NF && !/Mail queue is empty/' | wc -l"
        cfg.TotalCmd = "mailq | tail -n +2 | grep -v 'Mail queue is empty' | wc -l"
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

    total, totalErr := q.totalCount(ctx)
    frozen, samples, _ := q.frozenCountAndSamples(ctx)

    now := time.Now()
    // Publish for the health snapshot (cfm health / dashboard). Only on a
    // successful count — a failed probe (postfix absent, timeout) must not
    // surface as a fake empty queue.
    if totalErr == nil {
        mailq.Publish(mailq.Measurement{MTA: "postfix", Total: total, Frozen: frozen, MeasuredAt: now})
    }

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
        // Για postfix μπορείς να προσαρμόσεις το κριτήριο "frozen":
        // π.χ. deferred/hold lines. Για αρχή, άστο κενό και μετράμε όλα.
        if strings.Contains(strings.ToLower(line), "deferred") {
            frozen++
        }
        if len(samples) < q.cfg.SampleLimit {
            samples = append(samples, line)
        }
    }
    return frozen, samples, nil
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
        if strings.Contains(strings.ToLower(l), "deferred") {
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

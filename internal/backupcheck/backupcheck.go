// Package backupcheck answers "is this node's backup actually happening?" for
// the backup systems the fleet runs: JetBackup 5 (cPanel, DirectAdmin),
// Virtualmin scheduled backups and Proxmox VE vzdump. Each adapter reads its system's own CLI/API, and pure
// evaluate functions turn that into Findings: a failed or partial last run, no
// successful run for too long, a run stuck for days, guests no job covers, or
// a backup destination that is offline or full.
//
// The rule that shaped it (orion, Sep 2026): a job can look healthy while no
// backup has succeeded for weeks. JetBackup's `last_completed` advances on a
// FAILED run too, so freshness is measured from the last SUCCESSFUL run in the
// job's log history, never from the job's own timestamps.
//
// The package only reads. It never starts, stops or edits a backup.
package backupcheck

import (
	"bytes"
	"context"
	"fmt"
	"os/exec"
	"sort"
	"strconv"
	"strings"
	"syscall"
	"time"
)

// Finding types — these are detection_history event types (<= 32 chars), so a
// change here is a wire change for cfm-web's ingestor.
const (
	TypeFailed    = "backup_failed"    // the latest run failed
	TypePartial   = "backup_partial"   // the latest run finished with some items failed
	TypeStale     = "backup_stale"     // no successful run for longer than the job's schedule allows
	TypeStuck     = "backup_stuck"     // a run has been going for longer than StuckAfter
	TypeUncovered = "backup_uncovered" // guests/accounts that no backup job includes
	TypeDest      = "backup_dest"      // a backup destination is offline or nearly full
	TypeNoJob     = "backup_no_job"    // the backup system is installed but nothing is scheduled
)

const (
	SevCritical = "critical"
	SevWarning  = "warning"
)

// Finding is one problem with one backup subject.
type Finding struct {
	Type     string `json:"type"`
	Severity string `json:"severity"`
	Adapter  string `json:"adapter"`
	// Key identifies the subject within Type across checks (a job id, a run id,
	// a storage name): the caller publishes a finding once on entry and re-arms
	// when the key stops appearing.
	Key     string `json:"key"`
	Message string `json:"message"`
	// Members, when set, is the set the finding is about (uncovered guest ids).
	// The caller re-publishes when a NEW member appears, not when one leaves.
	Members []string `json:"members,omitempty"`
}

// Job is the per-job summary shown in the status.
type Job struct {
	Name        string     `json:"name"`
	ID          string     `json:"id,omitempty"`
	Disabled    bool       `json:"disabled,omitempty"`
	Running     bool       `json:"running,omitempty"`
	LastSuccess *time.Time `json:"last_success,omitempty"`
	LastResult  string     `json:"last_result,omitempty"` // ok | partial | failed | unknown
	Schedule    string     `json:"schedule,omitempty"`
}

// AdapterStatus is what one adapter saw on this check.
type AdapterStatus struct {
	Name     string    `json:"name"`
	Error    string    `json:"error,omitempty"` // the adapter could not read its system
	Jobs     []Job     `json:"jobs"`
	Findings []Finding `json:"findings"`
	// Unknown lists finding keys this check could not judge (a side read
	// failed): neither present nor resolved, so the caller keeps them armed.
	Unknown []string `json:"unknown,omitempty"`
}

// Status is the whole check. Adapters is empty on a node that runs none of the
// supported backup systems.
type Status struct {
	CheckedAt time.Time       `json:"checked_at"`
	Adapters  []AdapterStatus `json:"adapters"`
}

// Findings flattens every adapter's findings, worst first.
func (s Status) Findings() []Finding {
	var out []Finding
	for _, a := range s.Adapters {
		out = append(out, a.Findings...)
	}
	sort.SliceStable(out, func(i, j int) bool {
		return SevRank(out[i].Severity) > SevRank(out[j].Severity)
	})
	return out
}

// SevRank orders severities (critical > warning > anything else).
func SevRank(s string) int {
	switch s {
	case SevCritical:
		return 2
	case SevWarning:
		return 1
	}
	return 0
}

// Thresholds tune the evaluation. Zero values take the defaults.
type Thresholds struct {
	// StuckAfter: a run still going after this long is stuck (default 24h).
	StuckAfter time.Duration
	// StaleFactor/StaleGrace: a job is stale when its last success is older
	// than period*StaleFactor + StaleGrace, the period being the job's own
	// schedule interval (defaults 1.5 and 2h; a daily job alerts after 38h).
	StaleFactor float64
	StaleGrace  time.Duration
	// ProxmoxStaleAfter: vzdump schedules are calendar expressions, so the
	// Proxmox adapter uses one fixed age instead (default 8 days, for the
	// common weekly job).
	ProxmoxStaleAfter time.Duration
	// DestFreeMinPct: a destination with less free space than this is
	// reported (default 5; negative turns the free-space check off).
	DestFreeMinPct float64
}

func (t Thresholds) withDefaults() Thresholds {
	if t.StuckAfter <= 0 {
		t.StuckAfter = 24 * time.Hour
	}
	if t.StaleFactor <= 0 {
		t.StaleFactor = 1.5
	}
	if t.StaleGrace <= 0 {
		t.StaleGrace = 2 * time.Hour
	}
	if t.ProxmoxStaleAfter <= 0 {
		t.ProxmoxStaleAfter = 8 * 24 * time.Hour
	}
	if t.DestFreeMinPct == 0 {
		t.DestFreeMinPct = 5
	}
	return t
}

// Runner runs a command and returns its stdout. Tests substitute it.
type Runner func(ctx context.Context, name string, args ...string) ([]byte, error)

// maxOutput caps what one CLI call may return (a truncated reply fails to
// decode and is reported as a check error, never read as "healthy").
const maxOutput = 16 << 20

// ExecRunner runs the real binary. It cannot hang the check: on the context
// deadline the whole process group is killed (a wrapper script's children
// included), and WaitDelay bounds the wait for pipes a grandchild might hold
// open. A failure carries the CLI's stderr, so an alert says why.
func ExecRunner(ctx context.Context, name string, args ...string) ([]byte, error) {
	cmd := exec.CommandContext(ctx, name, args...)
	cmd.SysProcAttr = &syscall.SysProcAttr{Setpgid: true}
	cmd.Cancel = func() error {
		if cmd.Process == nil {
			return nil
		}
		return syscall.Kill(-cmd.Process.Pid, syscall.SIGKILL)
	}
	cmd.WaitDelay = 5 * time.Second
	stdout, stderr := &capped{max: maxOutput}, &capped{max: 4096}
	cmd.Stdout, cmd.Stderr = stdout, stderr
	err := cmd.Run()
	if err != nil {
		if msg := strings.TrimSpace(stderr.buf.String()); msg != "" {
			if len(msg) > 300 {
				msg = msg[:300] + "…"
			}
			err = fmt.Errorf("%w: %s", err, msg)
		}
		return nil, err
	}
	if stdout.over {
		return nil, fmt.Errorf("output over %d bytes", maxOutput)
	}
	return stdout.buf.Bytes(), nil
}

// capped is a writer that keeps at most max bytes and remembers it dropped
// some. The buffer is a NAMED field on purpose: embedding bytes.Buffer would
// promote its ReadFrom, io.Copy would use it, and Write — the cap — would
// never run.
type capped struct {
	buf  bytes.Buffer
	max  int
	over bool
}

func (c *capped) Write(p []byte) (int, error) {
	if room := c.max - c.buf.Len(); room < len(p) {
		c.over = true
		if room > 0 {
			c.buf.Write(p[:room])
		}
		return len(p), nil
	}
	return c.buf.Write(p)
}

// lookPath is a var so tests can pretend a binary exists.
var lookPath = exec.LookPath

// Options configure one Check.
type Options struct {
	Run        Runner
	Now        time.Time
	Thresholds Thresholds
	// Node is this host's Proxmox node name (os.Hostname short form).
	Node string
	// PerCommandTimeout bounds each CLI call (default 60s).
	PerCommandTimeout time.Duration
}

// Check runs every adapter whose system is installed on this host.
func Check(ctx context.Context, o Options) Status {
	if o.Run == nil {
		o.Run = ExecRunner
	}
	if o.Now.IsZero() {
		o.Now = time.Now()
	}
	if o.PerCommandTimeout <= 0 {
		o.PerCommandTimeout = 60 * time.Second
	}
	o.Thresholds = o.Thresholds.withDefaults()

	run := func(name string, args ...string) ([]byte, error) {
		cctx, cancel := context.WithTimeout(ctx, o.PerCommandTimeout)
		defer cancel()
		return o.Run(cctx, name, args...)
	}

	st := Status{CheckedAt: o.Now}
	if _, err := lookPath(jetbackupCLI); err == nil {
		st.Adapters = append(st.Adapters, checkJetBackup(run, o.Now, o.Thresholds))
	}
	if _, err := lookPath(virtualminCLI); err == nil {
		st.Adapters = append(st.Adapters, checkVirtualmin(run, o.Now, o.Thresholds))
	}
	if _, err := lookPath(pveshCLI); err == nil {
		st.Adapters = append(st.Adapters, checkProxmox(run, o.Node, o.Now, o.Thresholds))
	}
	return st
}

// cmdFunc is Check's per-call runner as the adapters see it.
type cmdFunc func(name string, args ...string) ([]byte, error)

func clampDur(d, lo, hi time.Duration) time.Duration {
	if d < lo {
		return lo
	}
	if d > hi {
		return hi
	}
	return d
}

// Ago renders a duration for a message: "3d 4h", "17h", "45m".
func Ago(d time.Duration) string {
	if d < time.Hour {
		return strconv.Itoa(int(d/time.Minute)) + "m"
	}
	days, hours := int(d/(24*time.Hour)), int((d%(24*time.Hour))/time.Hour)
	switch {
	case days == 0:
		return strconv.Itoa(hours) + "h"
	case hours == 0:
		return strconv.Itoa(days) + "d"
	}
	return strconv.Itoa(days) + "d " + strconv.Itoa(hours) + "h"
}

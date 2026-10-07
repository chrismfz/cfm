package health

// backup.go runs internal/backupcheck from the health detector and turns its
// findings into durable node-fault events (detection_history type
// backup_failed / backup_stale / backup_stuck / ...), the same path the
// RAID/SMART/ECC faults take to cfm-web. It does NOT emit a local
// core.Alert: backups are reported centrally (cfm-web → Mattermost), and a
// per-node mail would only add to the logs@ inbox this replaces.
//
// The check shells out to the backup systems' CLIs (seconds, up to a minute),
// so it runs in its own goroutine every BackupEvery; RunOnce only starts it
// and publishes the result of the previous one. Edge-triggered like the other
// node faults: a finding is published once when it appears (again if its
// severity rises or, for a set, a new member joins), re-armed when it is gone,
// and an adapter that cannot be read keeps its findings armed (unknown is not
// healthy).
//
// The edge state is PACKAGE-level, not per Detector: the manager rebuilds every
// detector on a detectors.conf save and on a watched log's rotation, and a
// per-Detector state re-published every open finding fleet-wide each time.
// A daemon restart still re-publishes what is true once.

import (
	"context"
	"fmt"
	"runtime/debug"
	"strings"
	"sync"
	"sync/atomic"
	"time"

	"cfm/internal/backupcheck"
	"cfm/internal/logging"
)

// TypeBackupCheckError is published when an installed backup system cannot be
// read — without it, a broken CLI would look exactly like "no problems".
const TypeBackupCheckError = "backup_check_error"

const (
	// backupErrorAfter: an adapter must fail this many checks in a row before
	// backup_check_error is published (a CLI slow during the nightly run must
	// not alert, then clear, then alert).
	backupErrorAfter = 2
	// backupCheckTimeout bounds one whole check; one still "running" past
	// backupHungAfter is reported, since nothing else would ever say so.
	backupCheckTimeout = 5 * time.Minute
	backupHungAfter    = 3 * backupCheckTimeout
)

// backupCheckFunc is a var so tests can substitute the check.
var backupCheckFunc = backupcheck.Check

var lastBackupStatus atomic.Pointer[backupcheck.Status]

// LastBackupStatus is the most recent completed backup check on this node, or
// nil before the first one (or when the check is disabled).
func LastBackupStatus() *backupcheck.Status { return lastBackupStatus.Load() }

type publishedBackup struct {
	adapter  string
	severity string
	members  map[string]bool
}

type backupState struct {
	mu         sync.Mutex
	running    bool
	startedAt  time.Time
	next       time.Time
	pending    *backupcheck.Status
	published  map[string]publishedBackup // finding key → what was published
	errStreak  map[string]int             // adapter → consecutive unreadable checks
	hungPublic bool
}

// backup is the one backup edge state of this process (see the file comment).
var backup = &backupState{}

// resetBackupStateForTest gives a test a fresh process-level state.
func resetBackupStateForTest() {
	backup = &backupState{}
	lastBackupStatus.Store(nil)
}

// tickBackup is called from RunOnce: publish a finished check, start a new one
// when due. Never blocks on the check itself.
func (d *Detector) tickBackup(now time.Time, host string) {
	if !d.cfg.BackupAlert {
		return
	}
	b := backup
	b.mu.Lock()
	defer b.mu.Unlock()

	if st := b.pending; st != nil {
		b.pending = nil
		lastBackupStatus.Store(st)
		b.publishLocked(*st, host, now)
	}
	if b.running {
		if now.Sub(b.startedAt) > backupHungAfter && !b.hungPublic {
			if publishNodeFaultEvent(NodeFaultEvent{
				Type: TypeBackupCheckError, Severity: backupcheck.SevWarning, Host: host,
				Key: "backupcheck:hung", When: now,
				Message: fmt.Sprintf("backup check has not finished for %s — a backup CLI is hanging", ago(now.Sub(b.startedAt))),
			}) {
				b.hungPublic = true
			}
		}
		return
	}
	if now.Before(b.next) {
		return
	}
	every := d.cfg.BackupEvery
	if every <= 0 {
		every = 15 * time.Minute
	}
	b.next = now.Add(every)
	b.running, b.startedAt = true, now
	node := host
	if i := strings.IndexByte(node, '.'); i > 0 {
		node = node[:i]
	}
	opts := backupcheck.Options{
		Node: node,
		Thresholds: backupcheck.Thresholds{
			StuckAfter:        d.cfg.BackupStuckAfter,
			ProxmoxStaleAfter: d.cfg.BackupProxmoxStaleAfter,
			DestFreeMinPct:    d.cfg.BackupDestFreeMinPct,
		},
	}
	go func() {
		st := runBackupCheck(opts)
		b.mu.Lock()
		b.pending, b.running, b.hungPublic = &st, false, false
		b.mu.Unlock()
	}()
}

// runBackupCheck runs one check; a panic in a parser becomes a check error
// (logged, and published as backup_check_error) instead of silence.
func runBackupCheck(opts backupcheck.Options) (st backupcheck.Status) {
	defer func() {
		if r := recover(); r != nil {
			logging.Logf("[health] backup check panicked: %v\n%s", r, debug.Stack())
			st = backupcheck.Status{CheckedAt: time.Now(), Adapters: []backupcheck.AdapterStatus{{
				Name: "backupcheck", Error: fmt.Sprintf("internal error: %v", r),
			}}}
		}
	}()
	ctx, cancel := context.WithTimeout(context.Background(), backupCheckTimeout)
	defer cancel()
	return backupCheckFunc(ctx, opts)
}

// publishBackup applies the edge rules to one completed check.
func (d *Detector) publishBackup(st backupcheck.Status, host string, now time.Time) {
	backup.mu.Lock()
	defer backup.mu.Unlock()
	backup.publishLocked(st, host, now)
}

func (b *backupState) publishLocked(st backupcheck.Status, host string, now time.Time) {
	if b.published == nil {
		b.published = map[string]publishedBackup{}
	}
	if b.errStreak == nil {
		b.errStreak = map[string]int{}
	}
	findings := st.Findings()
	erred := map[string]bool{}
	for _, a := range st.Adapters {
		if a.Error == "" {
			delete(b.errStreak, a.Name)
			continue
		}
		erred[a.Name] = true
		b.errStreak[a.Name]++
		if b.errStreak[a.Name] >= backupErrorAfter {
			findings = append(findings, backupcheck.Finding{
				Type: TypeBackupCheckError, Severity: backupcheck.SevWarning, Adapter: a.Name,
				Key: a.Name + ":error", Message: "cannot read " + a.Name + " backup state: " + a.Error,
			})
		}
	}

	current := map[string]bool{}
	for _, f := range findings {
		current[f.Key] = true
		prev, seen := b.published[f.Key]
		members := toSet(f.Members)
		if seen && !sevRose(prev.severity, f.Severity) {
			grew := false
			for m := range members {
				if !prev.members[m] {
					grew = true
				}
			}
			if !grew {
				// unchanged, shrunk or calmer: remember the current state so a
				// member that comes back, or a severity that rises again, is news
				b.published[f.Key] = publishedBackup{adapter: f.Adapter, severity: f.Severity, members: members}
				continue
			}
		}
		if publishNodeFaultEvent(NodeFaultEvent{
			Type: f.Type, Severity: f.Severity, Host: host, Key: f.Key,
			Message: f.Message, When: now,
		}) {
			b.published[f.Key] = publishedBackup{adapter: f.Adapter, severity: f.Severity, members: members}
		}
	}
	for key, p := range b.published {
		// An erroring adapter keeps its findings armed, but not its own error
		// finding: that one clears the moment the adapter reads again.
		if !current[key] && (!erred[p.adapter] || strings.HasSuffix(key, ":error")) {
			delete(b.published, key)
		}
	}
}

func sevRose(from, to string) bool {
	rank := func(s string) int {
		switch s {
		case backupcheck.SevCritical:
			return 2
		case backupcheck.SevWarning:
			return 1
		}
		return 0
	}
	return rank(to) > rank(from)
}

func toSet(xs []string) map[string]bool {
	m := make(map[string]bool, len(xs))
	for _, x := range xs {
		m[x] = true
	}
	return m
}

// ago renders a duration for a message: "3d 4h", "17h", "45m".
func ago(d time.Duration) string {
	if d < time.Hour {
		return d.Truncate(time.Minute).String()
	}
	days, hours := int(d/(24*time.Hour)), int((d%(24*time.Hour))/time.Hour)
	switch {
	case days == 0:
		return fmt.Sprintf("%dh", hours)
	case hours == 0:
		return fmt.Sprintf("%dd", days)
	}
	return fmt.Sprintf("%dd %dh", days, hours)
}

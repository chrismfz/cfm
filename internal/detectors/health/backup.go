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
// node faults: a finding is published once when it appears, re-armed when it
// is gone, and an adapter that cannot be read keeps its findings armed
// (unknown is not healthy).

import (
	"context"
	"strings"
	"sync/atomic"
	"time"

	"cfm/internal/backupcheck"
)

// TypeBackupCheckError is published when an installed backup system cannot be
// read at all — without it, a broken CLI would look exactly like "no problems".
const TypeBackupCheckError = "backup_check_error"

// backupCheckFunc is a var so tests can substitute the check.
var backupCheckFunc = backupcheck.Check

var lastBackupStatus atomic.Pointer[backupcheck.Status]

// LastBackupStatus is the most recent completed backup check on this node, or
// nil before the first one (or when the check is disabled).
func LastBackupStatus() *backupcheck.Status { return lastBackupStatus.Load() }

type publishedBackup struct {
	adapter string
	members map[string]bool
}

type backupState struct {
	running   atomic.Bool
	next      time.Time
	pending   atomic.Pointer[backupcheck.Status]
	published map[string]publishedBackup // finding key → what was published
}

// tickBackup is called from RunOnce: publish a finished check, start a new one
// when due. Never blocks on the check itself.
func (d *Detector) tickBackup(now time.Time, host string) {
	if !d.cfg.BackupAlert {
		return
	}
	if st := d.backup.pending.Swap(nil); st != nil {
		lastBackupStatus.Store(st)
		d.publishBackup(*st, host, now)
	}
	if now.Before(d.backup.next) || !d.backup.running.CompareAndSwap(false, true) {
		return
	}
	every := d.cfg.BackupEvery
	if every <= 0 {
		every = 15 * time.Minute
	}
	d.backup.next = now.Add(every)
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
		defer d.backup.running.Store(false)
		defer func() { _ = recover() }() // a parser panic must never take the detector down
		ctx, cancel := context.WithTimeout(context.Background(), 5*time.Minute)
		defer cancel()
		st := backupCheckFunc(ctx, opts)
		d.backup.pending.Store(&st)
	}()
}

// publishBackup applies the edge rules to one completed check.
func (d *Detector) publishBackup(st backupcheck.Status, host string, now time.Time) {
	if d.backup.published == nil {
		d.backup.published = map[string]publishedBackup{}
	}
	findings := st.Findings()
	erred := map[string]bool{}
	for _, a := range st.Adapters {
		if a.Error != "" {
			erred[a.Name] = true
			findings = append(findings, backupcheck.Finding{
				Type: TypeBackupCheckError, Severity: backupcheck.SevWarning, Adapter: a.Name,
				Key: a.Name + ":error", Message: "cannot read " + a.Name + " backup state: " + a.Error,
			})
		}
	}

	current := map[string]bool{}
	for _, f := range findings {
		current[f.Key] = true
		prev, seen := d.backup.published[f.Key]
		members := toSet(f.Members)
		if seen {
			grew := false
			for m := range members {
				if !prev.members[m] {
					grew = true
				}
			}
			if !grew {
				// unchanged or shrunk: remember the smaller set so a member that
				// comes back is news again
				if len(f.Members) > 0 {
					d.backup.published[f.Key] = publishedBackup{adapter: f.Adapter, members: members}
				}
				continue
			}
		}
		if publishNodeFaultEvent(NodeFaultEvent{
			Type: f.Type, Severity: f.Severity, Host: host, Key: f.Key,
			Message: f.Message, When: now,
		}) {
			d.backup.published[f.Key] = publishedBackup{adapter: f.Adapter, members: members}
		}
	}
	for key, p := range d.backup.published {
		if !current[key] && !erred[p.adapter] {
			delete(d.backup.published, key)
		}
	}
}

func toSet(xs []string) map[string]bool {
	m := make(map[string]bool, len(xs))
	for _, x := range xs {
		m[x] = true
	}
	return m
}

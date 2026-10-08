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
// healthy). A finding the check positively sees gone is announced as
// backup_recovered under the same key, so cfm-web closes the open alert
// instead of reminding about a backup that already works again.
//
// The edge state is PACKAGE-level, not per Detector: the manager rebuilds every
// detector on a detectors.conf save and on a watched log's rotation, and a
// per-Detector state re-published every open finding fleet-wide each time.
// It is also saved to backupStatePath, so a daemon restart (every package
// upgrade) does not re-announce every open finding on every node either.
//
// The events reach cfm-web through the webdetector history store (the node
// fault sink): a node without the webdetector, or with its history off,
// records nothing — see docs/backup-check.md.

import (
	"context"
	"encoding/json"
	"fmt"
	"os"
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

// TypeBackupRecovered resolves an earlier finding: same Key, severity info.
const TypeBackupRecovered = "backup_recovered"

// hungKey is the key of the "check never finished" finding.
const hungKey = "backupcheck:hung"

const (
	// backupErrorAfter: an adapter must fail this many checks in a row before
	// backup_check_error is published (a CLI slow during the nightly run must
	// not alert, then clear, then alert).
	backupErrorAfter = 2
	// backupGoneAfter: an adapter not seen for this long (uninstalled, the
	// node migrated off it) has its open findings resolved as gone.
	backupGoneAfter = 24 * time.Hour
	// backupCheckTimeout bounds one whole check (each CLI call has its own
	// 60s bound; the slowest adapter makes 6 of them); one still "running"
	// past backupHungAfter is reported, since nothing else would ever say so.
	backupCheckTimeout = 12 * time.Minute
	backupHungAfter    = 3 * backupCheckTimeout
)

// backupCheckFunc is a var so tests can substitute the check.
var backupCheckFunc = backupcheck.Check

// backupStatePath keeps what has been published across daemon restarts. A var
// so tests point it at a temp dir (CLAUDE.md §5); "" disables persistence.
var backupStatePath = "/var/lib/cfm/backup_published.json"

var (
	lastBackupStatus atomic.Pointer[backupcheck.Status]
	backupEnabled    atomic.Bool
)

// LastBackupStatus is the most recent completed backup check on this node, or
// nil before the first one (or when the check is disabled).
func LastBackupStatus() *backupcheck.Status { return lastBackupStatus.Load() }

// BackupCheckEnabled reports whether the health detector is running the backup
// check (it is set on every health tick, so false also covers a node whose
// health detector is off).
func BackupCheckEnabled() bool { return backupEnabled.Load() }

type publishedBackup struct {
	Adapter  string          `json:"adapter"`
	Severity string          `json:"severity"`
	Members  map[string]bool `json:"members,omitempty"`
	// Type and Message word the recovery; absent in a state file written
	// before backup_recovered existed.
	Type    string `json:"type,omitempty"`
	Message string `json:"message,omitempty"`
}

type backupState struct {
	mu        sync.Mutex
	running   bool
	startedAt time.Time
	next      time.Time
	pending   *backupcheck.Status
	published map[string]publishedBackup // finding key → what was published (the hung check's too)
	seenAt    map[string]time.Time       // adapter → last check it was present in
	loaded    bool                       // published read from backupStatePath
	errStreak map[string]int             // adapter → consecutive unreadable checks
}

// backupStateFile is the persisted edge state. A file written before seenAt
// existed is the bare published map; loadLocked reads both.
type backupStateFile struct {
	Published map[string]publishedBackup `json:"published"`
	SeenAt    map[string]time.Time       `json:"seen_at,omitempty"`
}

func (b *backupState) loadLocked() {
	if b.loaded {
		return
	}
	b.loaded = true
	b.published = map[string]publishedBackup{}
	b.seenAt = map[string]time.Time{}
	if backupStatePath == "" {
		return
	}
	raw, err := os.ReadFile(backupStatePath)
	if err != nil {
		return
	}
	var f backupStateFile
	if err := json.Unmarshal(raw, &f); err == nil && f.Published != nil {
		b.published = f.Published
		if f.SeenAt != nil {
			b.seenAt = f.SeenAt
		}
		return
	}
	if err := json.Unmarshal(raw, &b.published); err != nil {
		// every open finding will be announced again: say why
		logging.Logf("[health] backup state %s unreadable, starting over: %v", backupStatePath, err)
		b.published = map[string]publishedBackup{}
	}
}

func (b *backupState) saveLocked() {
	if backupStatePath == "" {
		return
	}
	raw, err := json.Marshal(backupStateFile{Published: b.published, SeenAt: b.seenAt})
	if err != nil {
		return
	}
	tmp := backupStatePath + ".tmp"
	if err := os.WriteFile(tmp, raw, 0o600); err != nil {
		logging.Logf("[health] backup state not saved: %v", err)
		return
	}
	if err := os.Rename(tmp, backupStatePath); err != nil {
		logging.Logf("[health] backup state not saved: %v", err)
	}
}

// backup is the one backup edge state of this process (see the file comment).
var backup = &backupState{}

// resetBackupStateForTest gives a test a fresh process-level state, as after
// a daemon restart WITHOUT a saved state file.
func resetBackupStateForTest() {
	backup = &backupState{}
	lastBackupStatus.Store(nil)
	backupEnabled.Store(false)
	if backupStatePath != "" {
		_ = os.Remove(backupStatePath)
	}
}

// tickBackup is called from RunOnce: publish a finished check, start a new one
// when due. Never blocks on the check itself.
func (d *Detector) tickBackup(now time.Time, host string) {
	backupEnabled.Store(d.cfg.BackupAlert)
	if !d.cfg.BackupAlert {
		lastBackupStatus.Store(nil) // the API must not keep serving an old check
		return
	}
	b := backup
	b.mu.Lock()
	defer b.mu.Unlock()
	b.loadLocked()

	if st := b.pending; st != nil {
		b.pending = nil
		lastBackupStatus.Store(st)
		// the hung finding is persisted like any other, so a restart (the
		// obvious remedy for a hung CLI) still resolves it
		if _, hung := b.published[hungKey]; hung && publishNodeFaultEvent(NodeFaultEvent{
			Type: TypeBackupRecovered, Severity: backupcheck.SevInfo, Host: host,
			Key: hungKey, When: now, Message: "backup check finished again",
		}) {
			delete(b.published, hungKey)
		}
		b.publishLocked(*st, host, now)
	}
	if b.running {
		if _, hung := b.published[hungKey]; now.Sub(b.startedAt) > backupHungAfter && !hung {
			msg := fmt.Sprintf("backup check has not finished for %s — a backup CLI is hanging", ago(now.Sub(b.startedAt)))
			if publishNodeFaultEvent(NodeFaultEvent{
				Type: TypeBackupCheckError, Severity: backupcheck.SevWarning, Host: host,
				Key: hungKey, When: now, Message: msg,
			}) {
				b.published[hungKey] = publishedBackup{Adapter: "backupcheck", Severity: backupcheck.SevWarning, Type: TypeBackupCheckError, Message: msg}
				b.saveLocked()
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
		b.pending, b.running = &st, false
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
	b.loadLocked()
	if b.errStreak == nil {
		b.errStreak = map[string]int{}
	}
	if b.seenAt == nil {
		b.seenAt = map[string]time.Time{}
	}
	findings := foldRunFindings(st.Findings())
	erred := map[string]bool{}
	seen := map[string]bool{}
	unknown := map[string]bool{}
	jobs := map[string]backupcheck.Job{} // "<adapter>:<job id>" → job, for wording a recovery
	panicked := false
	for _, a := range st.Adapters {
		seen[a.Name] = true
		b.seenAt[a.Name] = now
		for _, k := range a.Unknown {
			unknown[k] = true
		}
		for _, j := range a.Jobs {
			jobs[a.Name+":"+j.ID] = j
		}
		if a.Name == "backupcheck" && a.Error != "" {
			panicked = true
		}
	}
	for name := range b.errStreak {
		if !seen[name] {
			delete(b.errStreak, name) // an adapter that left (or a panic that did not recur) starts over
		}
	}
	for _, a := range st.Adapters {
		if a.Error == "" {
			delete(b.errStreak, a.Name)
			continue
		}
		erred[a.Name] = true
		b.errStreak[a.Name]++
		key := a.Name + ":error"
		if b.errStreak[a.Name] >= backupErrorAfter {
			findings = append(findings, backupcheck.Finding{
				Type: TypeBackupCheckError, Severity: backupcheck.SevWarning, Adapter: a.Name,
				Key: key, Message: "cannot read " + a.Name + " backup state: " + a.Error,
			})
		} else if _, open := b.published[key]; open {
			// the streak is in memory: after a restart a still-unreadable
			// adapter starts over at 1, which must not "recover" its open error
			unknown[key] = true
		}
	}

	current := map[string]bool{}
	subjects := map[string]backupcheck.Finding{} // run subject → the finding now standing for it
	for _, f := range findings {
		if subj, _ := runSubject(f.Key); subj != "" {
			subjects[subj] = f
		}
	}
	// A key this check could not judge is still superseded by a worse finding
	// of the same job that it could: one job, one alert.
	for k := range unknown {
		subj, kind := runSubject(k)
		if f, ok := subjects[subj]; ok && subj != "" {
			if _, fk := runSubject(f.Key); runKinds[fk] > runKinds[kind] {
				delete(unknown, k)
			}
		}
	}
	for _, f := range findings {
		current[f.Key] = true
		prev, seen := b.published[f.Key]
		members := toSet(f.Members)
		if seen && !sevRose(prev.Severity, f.Severity) {
			grew := false
			for m := range members {
				if !prev.Members[m] {
					grew = true
				}
			}
			if !grew {
				// unchanged, shrunk or calmer: remember the current state so a
				// member that comes back, or a severity that rises again, is news
				b.published[f.Key] = publishedBackup{Adapter: f.Adapter, Severity: f.Severity, Members: members, Type: f.Type, Message: f.Message}
				continue
			}
		}
		if publishNodeFaultEvent(NodeFaultEvent{
			Type: f.Type, Severity: f.Severity, Host: host, Key: f.Key,
			Message: f.Message, When: now,
		}) {
			b.published[f.Key] = publishedBackup{Adapter: f.Adapter, Severity: f.Severity, Members: members, Type: f.Type, Message: f.Message}
		}
	}
	for key, p := range b.published {
		if current[key] || unknown[key] || key == hungKey {
			continue
		}
		// Re-arm only what this check positively saw resolved: the adapter
		// read fine (an erroring one keeps its findings armed — but not its
		// own error finding, which clears the moment it reads again), it was
		// in this check at all (a CLI briefly off PATH proves nothing), and the
		// check did not panic. An adapter gone for a day is uninstalled: its
		// findings are resolved as such rather than kept open forever.
		if panicked {
			continue
		}
		var msg string
		switch {
		case isErrorKey(key, p):
			msg = recoveredMessage(key, p)
		case seen[p.Adapter] && !erred[p.Adapter]:
			msg = b.resolvedMessage(key, p, subjects, jobs)
		case !seen[p.Adapter] && !b.seenAt[p.Adapter].IsZero() && now.Sub(b.seenAt[p.Adapter]) >= backupGoneAfter:
			msg = clipBackup(p.Adapter + " is no longer on this node (was: " + wasOf(key, p) + ")")
		default:
			if !seen[p.Adapter] && b.seenAt[p.Adapter].IsZero() {
				b.seenAt[p.Adapter] = now // start the clock for a key from an older state file
			}
			continue
		}
		// Forget it only once the recovery is delivered; without a sink it
		// stays armed and is announced on a later check.
		if publishNodeFaultEvent(NodeFaultEvent{
			Type: TypeBackupRecovered, Severity: backupcheck.SevInfo, Host: host,
			Key: key, When: now, Message: msg,
		}) {
			delete(b.published, key)
		}
	}
	b.saveLocked()
}

// runKinds rank the per-run findings of one job / node, worst first: a stuck
// run explains a failure and both explain staleness, so only the worst stands.
var runKinds = map[string]int{"stuck": 4, "failed": 3, "stale": 2, "partial": 1}

// runSubject splits a per-run key ("jb:failed:<id>", "pve:stale:<node>") into
// its subject ("jb:<id>") and kind; "" for any other key. A Proxmox stuck key
// carries the task's UPID ("pve:stuck:UPID:<node>:…"): its subject is the node,
// like the node's failed / stale keys.
func runSubject(key string) (subject, kind string) {
	parts := strings.SplitN(key, ":", 3)
	if len(parts) != 3 || runKinds[parts[1]] == 0 {
		return "", ""
	}
	id := parts[2]
	if parts[0] == "pve" && strings.HasPrefix(id, "UPID:") {
		if f := strings.SplitN(id, ":", 3); len(f) >= 2 && f[1] != "" {
			id = f[1]
		}
	}
	return parts[0] + ":" + id, parts[1]
}

// foldRunFindings keeps, per job / node, only its worst per-run finding: a job
// that keeps failing would otherwise page backup_failed AND, a day later,
// backup_stale — two pinned criticals, reminded twice, for one problem.
func foldRunFindings(fs []backupcheck.Finding) []backupcheck.Finding {
	worst := map[string]int{}
	for _, f := range fs {
		if subj, kind := runSubject(f.Key); subj != "" && runKinds[kind] > worst[subj] {
			worst[subj] = runKinds[kind]
		}
	}
	out := fs[:0:0]
	for _, f := range fs {
		if subj, kind := runSubject(f.Key); subj != "" && runKinds[kind] < worst[subj] {
			continue
		}
		out = append(out, f)
	}
	return out
}

// resolvedMessage words a finding that this check no longer has: the same job
// now has another finding (failed → stale, stuck → failed), the job was
// disabled or removed, or it is fine.
func (b *backupState) resolvedMessage(key string, p publishedBackup, subjects map[string]backupcheck.Finding, jobs map[string]backupcheck.Job) string {
	was := wasOf(key, p)
	subj, _ := runSubject(key)
	if subj == "" {
		return clipBackup("backup OK again (was: " + was + ")")
	}
	if f, ok := subjects[subj]; ok {
		return clipBackup("now " + strings.TrimPrefix(f.Type, "backup_") + ": " + f.Message + " (was: " + was + ")")
	}
	if p.Adapter == "jetbackup" || p.Adapter == "virtualmin" {
		id := subj[strings.IndexByte(subj, ':')+1:]
		j, ok := jobs[p.Adapter+":"+id]
		switch {
		case !ok:
			return clipBackup("job removed — no longer checked (was: " + was + ")")
		case j.Disabled:
			return clipBackup("job disabled — no longer checked (was: " + was + ")")
		}
	}
	return clipBackup("backup OK again (was: " + was + ")")
}

func isErrorKey(key string, p publishedBackup) bool {
	return p.Type == TypeBackupCheckError || (p.Type == "" && strings.HasSuffix(key, ":error"))
}

func wasOf(key string, p publishedBackup) string {
	if p.Message == "" {
		return key
	}
	return p.Message
}

// clipBackup keeps a message inside cfm-web's 255-character event column.
func clipBackup(s string) string {
	if r := []rune(s); len(r) > 240 {
		return string(r[:239]) + "…"
	}
	return s
}

// recoveredMessage words the resolution of an error finding.
func recoveredMessage(key string, p publishedBackup) string {
	return clipBackup("backup state readable again (was: " + wasOf(key, p) + ")")
}

func sevRose(from, to string) bool {
	return backupcheck.SevRank(to) > backupcheck.SevRank(from)
}

func toSet(xs []string) map[string]bool {
	m := make(map[string]bool, len(xs))
	for _, x := range xs {
		m[x] = true
	}
	return m
}

func ago(d time.Duration) string { return backupcheck.Ago(d) }

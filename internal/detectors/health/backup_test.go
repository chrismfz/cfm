package health

import (
	"context"
	"sync"
	"testing"
	"time"

	"cfm/internal/backupcheck"
)

type faultRecorder struct {
	mu  sync.Mutex
	evs []NodeFaultEvent
}

func (r *faultRecorder) take() []NodeFaultEvent {
	r.mu.Lock()
	defer r.mu.Unlock()
	out := r.evs
	r.evs = nil
	return out
}

func recordFaults(t *testing.T) *faultRecorder {
	t.Helper()
	r := &faultRecorder{}
	SetNodeFaultEventSink(func(ev NodeFaultEvent) {
		r.mu.Lock()
		r.evs = append(r.evs, ev)
		r.mu.Unlock()
	})
	t.Cleanup(func() { SetNodeFaultEventSink(nil) })
	return r
}

func status(adapters ...backupcheck.AdapterStatus) backupcheck.Status {
	return backupcheck.Status{CheckedAt: time.Now(), Adapters: adapters}
}

var (
	failedRun = backupcheck.Finding{Type: backupcheck.TypeFailed, Severity: "critical", Adapter: "jetbackup", Key: "jb:run:r21", Message: "failed"}
	uncovered = func(m ...string) backupcheck.Finding {
		return backupcheck.Finding{Type: backupcheck.TypeUncovered, Severity: "warning", Adapter: "proxmox", Key: "pve:uncovered", Message: "uncovered", Members: m}
	}
)

func TestPublishBackupIsEdgeTriggered(t *testing.T) {
	resetBackupStateForTest()
	rec := recordFaults(t)
	d := New(Config{BackupAlert: true})
	now := time.Now()

	d.publishBackup(status(
		backupcheck.AdapterStatus{Name: "jetbackup", Findings: []backupcheck.Finding{failedRun}},
		backupcheck.AdapterStatus{Name: "proxmox", Findings: []backupcheck.Finding{uncovered("117", "122")}},
	), "vega", now)
	if evs := rec.take(); len(evs) != 2 || evs[0].Host != "vega" {
		t.Fatalf("first sight: want 2 events, got %+v", evs)
	}

	// Same state: nothing new.
	d.publishBackup(status(
		backupcheck.AdapterStatus{Name: "jetbackup", Findings: []backupcheck.Finding{failedRun}},
		backupcheck.AdapterStatus{Name: "proxmox", Findings: []backupcheck.Finding{uncovered("117", "122")}},
	), "vega", now)
	if evs := rec.take(); len(evs) != 0 {
		t.Fatalf("unchanged: want 0 events, got %+v", evs)
	}

	// A guest left the uncovered set: no event. A new one appears: one event.
	d.publishBackup(status(backupcheck.AdapterStatus{Name: "jetbackup", Findings: []backupcheck.Finding{failedRun}},
		backupcheck.AdapterStatus{Name: "proxmox", Findings: []backupcheck.Finding{uncovered("117")}}), "vega", now)
	if evs := rec.take(); len(evs) != 0 {
		t.Fatalf("shrunk set: want 0 events, got %+v", evs)
	}
	d.publishBackup(status(backupcheck.AdapterStatus{Name: "jetbackup", Findings: []backupcheck.Finding{failedRun}},
		backupcheck.AdapterStatus{Name: "proxmox", Findings: []backupcheck.Finding{uncovered("117", "122")}}), "vega", now)
	if evs := rec.take(); len(evs) != 1 || evs[0].Type != backupcheck.TypeUncovered {
		t.Fatalf("a guest became uncovered again: want 1 event, got %+v", evs)
	}

	// The failure clears (next run OK), then a different run fails: new event.
	d.publishBackup(status(backupcheck.AdapterStatus{Name: "jetbackup"}), "vega", now)
	next := failedRun
	next.Key = "jb:run:r22"
	d.publishBackup(status(backupcheck.AdapterStatus{Name: "jetbackup", Findings: []backupcheck.Finding{next}}), "vega", now)
	if evs := rec.take(); len(evs) != 1 || evs[0].Key != "jb:run:r22" {
		t.Fatalf("a new failed run: want 1 event, got %+v", evs)
	}
}

func TestPublishBackupUnreadableAdapterIsNotHealthy(t *testing.T) {
	resetBackupStateForTest()
	rec := recordFaults(t)
	d := New(Config{BackupAlert: true})
	now := time.Now()
	d.publishBackup(status(backupcheck.AdapterStatus{Name: "jetbackup", Findings: []backupcheck.Finding{failedRun}}), "orion", now)
	rec.take()

	// The CLI breaks: one bad read is a blip (nothing), two in a row is an
	// error event; the failed run stays armed throughout.
	broken := status(backupcheck.AdapterStatus{Name: "jetbackup", Error: "listLogs: exit status 1"})
	d.publishBackup(broken, "orion", now)
	if evs := rec.take(); len(evs) != 0 {
		t.Fatalf("one failed read must not alert: %+v", evs)
	}
	d.publishBackup(broken, "orion", now)
	evs := rec.take()
	if len(evs) != 1 || evs[0].Type != TypeBackupCheckError || evs[0].Severity != "warning" {
		t.Fatalf("want one backup_check_error, got %+v", evs)
	}
	// It reads again and the same run is still the latest failed one: no repeat.
	d.publishBackup(status(backupcheck.AdapterStatus{Name: "jetbackup", Findings: []backupcheck.Finding{failedRun}}), "orion", now)
	if evs := rec.take(); len(evs) != 0 {
		t.Fatalf("an unreadable spell must not re-arm findings: got %+v", evs)
	}
}

func TestPublishBackupRetriesWhenNoSinkYet(t *testing.T) {
	resetBackupStateForTest()
	SetNodeFaultEventSink(nil)
	d := New(Config{BackupAlert: true})
	d.publishBackup(status(backupcheck.AdapterStatus{Name: "jetbackup", Findings: []backupcheck.Finding{failedRun}}), "orion", time.Now())
	rec := recordFaults(t)
	d.publishBackup(status(backupcheck.AdapterStatus{Name: "jetbackup", Findings: []backupcheck.Finding{failedRun}}), "orion", time.Now())
	if evs := rec.take(); len(evs) != 1 {
		t.Fatalf("undelivered event must be retried: got %+v", evs)
	}
}

func TestTickBackupRunsInBackgroundAndPublishesNextTick(t *testing.T) {
	resetBackupStateForTest()
	rec := recordFaults(t)
	calls := make(chan backupcheck.Options, 4)
	orig := backupCheckFunc
	backupCheckFunc = func(_ context.Context, o backupcheck.Options) backupcheck.Status {
		calls <- o
		return status(backupcheck.AdapterStatus{Name: "jetbackup", Findings: []backupcheck.Finding{failedRun}})
	}
	t.Cleanup(func() { backupCheckFunc = orig })

	d := New(Config{BackupAlert: true, BackupEvery: time.Hour})
	now := time.Now()
	d.tickBackup(now, "vega.myip.gr")
	select {
	case o := <-calls:
		if o.Node != "vega" {
			t.Fatalf("proxmox node name must be the short hostname, got %q", o.Node)
		}
	case <-time.After(5 * time.Second):
		t.Fatal("check never ran")
	}
	waitPending(t)
	d.tickBackup(now.Add(time.Minute), "vega.myip.gr") // publishes; not due again yet
	if evs := rec.take(); len(evs) != 1 {
		t.Fatalf("want the finding published on the next tick, got %+v", evs)
	}
	if LastBackupStatus() == nil {
		t.Fatal("LastBackupStatus not stored")
	}
	select {
	case <-calls:
		t.Fatal("ran again before BACKUP_EVERY elapsed")
	case <-time.After(100 * time.Millisecond):
	}
}

func waitPending(t *testing.T) {
	t.Helper()
	deadline := time.Now().Add(5 * time.Second)
	for time.Now().Before(deadline) {
		backup.mu.Lock()
		done := backup.pending != nil
		backup.mu.Unlock()
		if done {
			return
		}
		time.Sleep(10 * time.Millisecond)
	}
	t.Fatal("check result never arrived")
}

// A detector rebuild (detectors.conf save, log rotation) must not re-publish
// what is already out, nor start a check before BACKUP_EVERY.
func TestBackupStateSurvivesADetectorRebuild(t *testing.T) {
	resetBackupStateForTest()
	rec := recordFaults(t)
	calls := 0
	var mu sync.Mutex
	orig := backupCheckFunc
	backupCheckFunc = func(context.Context, backupcheck.Options) backupcheck.Status {
		mu.Lock()
		calls++
		mu.Unlock()
		return status(backupcheck.AdapterStatus{Name: "proxmox", Findings: []backupcheck.Finding{uncovered("117")}})
	}
	t.Cleanup(func() { backupCheckFunc = orig })

	now := time.Now()
	old := New(Config{BackupAlert: true, BackupEvery: time.Hour})
	old.tickBackup(now, "vega")
	waitPending(t)
	old.tickBackup(now.Add(time.Minute), "vega")
	if evs := rec.take(); len(evs) != 1 {
		t.Fatalf("first publish: %+v", evs)
	}

	rebuilt := New(Config{BackupAlert: true, BackupEvery: time.Hour})
	rebuilt.tickBackup(now.Add(2*time.Minute), "vega")
	time.Sleep(50 * time.Millisecond)
	mu.Lock()
	n := calls
	mu.Unlock()
	if n != 1 {
		t.Fatalf("a rebuilt detector must not start a check before BACKUP_EVERY: %d calls", n)
	}
	rebuilt.publishBackup(status(backupcheck.AdapterStatus{Name: "proxmox", Findings: []backupcheck.Finding{uncovered("117")}}), "vega", now)
	if evs := rec.take(); len(evs) != 0 {
		t.Fatalf("a rebuild must not re-publish: %+v", evs)
	}
}

func TestPublishBackupSeverityRiseIsNews(t *testing.T) {
	resetBackupStateForTest()
	rec := recordFaults(t)
	d := New(Config{BackupAlert: true})
	low := backupcheck.Finding{Type: backupcheck.TypeDest, Severity: "warning", Adapter: "proxmox", Key: "pve:dest:geros", Message: "3% free"}
	off := backupcheck.Finding{Type: backupcheck.TypeDest, Severity: "critical", Adapter: "proxmox", Key: "pve:dest:geros", Message: "offline"}
	d.publishBackup(status(backupcheck.AdapterStatus{Name: "proxmox", Findings: []backupcheck.Finding{low}}), "vega", time.Now())
	rec.take()
	d.publishBackup(status(backupcheck.AdapterStatus{Name: "proxmox", Findings: []backupcheck.Finding{off}}), "vega", time.Now())
	if evs := rec.take(); len(evs) != 1 || evs[0].Severity != "critical" {
		t.Fatalf("low → offline must be published: %+v", evs)
	}
	d.publishBackup(status(backupcheck.AdapterStatus{Name: "proxmox", Findings: []backupcheck.Finding{low}}), "vega", time.Now())
	if evs := rec.take(); len(evs) != 0 {
		t.Fatalf("calming down is not news: %+v", evs)
	}
}

func TestBackupCheckPanicBecomesACheckError(t *testing.T) {
	orig := backupCheckFunc
	backupCheckFunc = func(context.Context, backupcheck.Options) backupcheck.Status { panic("bad json") }
	t.Cleanup(func() { backupCheckFunc = orig })
	st := runBackupCheck(backupcheck.Options{})
	if len(st.Adapters) != 1 || st.Adapters[0].Error == "" {
		t.Fatalf("want an adapter error, got %+v", st)
	}
}

func TestTickBackupDisabledDoesNothing(t *testing.T) {
	orig := backupCheckFunc
	backupCheckFunc = func(context.Context, backupcheck.Options) backupcheck.Status {
		t.Fatal("check ran with BACKUP_ALERT off")
		return backupcheck.Status{}
	}
	t.Cleanup(func() { backupCheckFunc = orig })
	d := New(Config{BackupAlert: false})
	d.tickBackup(time.Now(), "h")
	time.Sleep(50 * time.Millisecond)
}

// A daemon restart (fresh process state, saved file present) must not
// re-announce what is still open; without the file it would.
func TestBackupStateSurvivesARestart(t *testing.T) {
	resetBackupStateForTest()
	rec := recordFaults(t)
	d := New(Config{BackupAlert: true})
	open := status(backupcheck.AdapterStatus{Name: "proxmox", Findings: []backupcheck.Finding{uncovered("117")}})
	d.publishBackup(open, "vega", time.Now())
	if evs := rec.take(); len(evs) != 1 {
		t.Fatalf("first publish: %+v", evs)
	}
	backup = &backupState{} // restart: memory gone, file kept
	New(Config{BackupAlert: true}).publishBackup(open, "vega", time.Now())
	if evs := rec.take(); len(evs) != 0 {
		t.Fatalf("restart re-announced an open finding: %+v", evs)
	}
}

func TestBackupFindingsStayArmedWhenTheCheckCannotJudge(t *testing.T) {
	resetBackupStateForTest()
	rec := recordFaults(t)
	d := New(Config{BackupAlert: true})
	now := time.Now()
	open := status(
		backupcheck.AdapterStatus{Name: "jetbackup", Findings: []backupcheck.Finding{failedRun}},
		backupcheck.AdapterStatus{Name: "proxmox", Findings: []backupcheck.Finding{uncovered("117")}},
	)
	d.publishBackup(open, "vega", now)
	rec.take()

	for name, st := range map[string]backupcheck.Status{
		"panic":           status(backupcheck.AdapterStatus{Name: "backupcheck", Error: "internal error: boom"}),
		"adapter missing": status(backupcheck.AdapterStatus{Name: "proxmox", Findings: []backupcheck.Finding{uncovered("117")}}),
		"unknown key":     status(backupcheck.AdapterStatus{Name: "jetbackup", Findings: []backupcheck.Finding{failedRun}}, backupcheck.AdapterStatus{Name: "proxmox", Unknown: []string{"pve:uncovered"}}),
	} {
		d.publishBackup(st, "vega", now)
		d.publishBackup(open, "vega", now)
		if evs := rec.take(); len(evs) != 0 {
			t.Fatalf("%s: findings were re-armed and re-published: %+v", name, evs)
		}
	}
}

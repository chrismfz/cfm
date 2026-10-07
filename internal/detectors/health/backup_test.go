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
	rec := recordFaults(t)
	d := New(Config{BackupAlert: true})
	now := time.Now()
	d.publishBackup(status(backupcheck.AdapterStatus{Name: "jetbackup", Findings: []backupcheck.Finding{failedRun}}), "orion", now)
	rec.take()

	// The CLI breaks: an error event, and the failed run stays armed.
	d.publishBackup(status(backupcheck.AdapterStatus{Name: "jetbackup", Error: "listLogs: exit status 1"}), "orion", now)
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
	deadline := time.Now().Add(5 * time.Second)
	for d.backup.pending.Load() == nil && time.Now().Before(deadline) {
		time.Sleep(10 * time.Millisecond)
	}
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

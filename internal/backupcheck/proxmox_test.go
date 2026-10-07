package backupcheck

import (
	"strings"
	"testing"
	"time"
)

// Fixtures: vega's real pvesh output, 7 Oct 2026 (PVE 9.2).

const vegaJobs = `[
 {"comment":"VAULT SERRES","enabled":1,"id":"backup-a39236a0-50b8","mode":"snapshot","schedule":"sun 02:00","storage":"vaultserres","type":"vzdump","vmid":"116,100,102"},
 {"enabled":1,"id":"backup-282d04aa-74e1","mode":"snapshot","schedule":"sun 05:00","storage":"geros","type":"vzdump","vmid":"100,102,103"}
]`

const vegaUncovered = `[{"name":"seo-cloud6.myipservers.gr","type":"qemu","vmid":2575},{"name":"w2025","type":"qemu","vmid":122},{"name":"ngm","type":"qemu","vmid":117}]`

const vegaStorage = `[
 {"storage":"local-zfs","active":1,"enabled":1,"used_fraction":0.618458862370249,"avail":651256328192},
 {"storage":"vaultserres","active":1,"enabled":1,"used_fraction":0.491433142601556,"avail":13935150366720},
 {"storage":"mailpool-storage","active":0,"enabled":0,"used_fraction":null,"avail":0},
 {"storage":"geros","active":1,"enabled":1,"used_fraction":0.465077840188676,"avail":5767666073600}
]`

// newest first, as pvesh returns them; the first is running right now.
const vegaTasks = `[
 {"upid":"UPID:vega:00278614:07B4AAEB:6AC56ADD:vzdump::root@pam:","status":"RUNNING","starttime":1791322845,"endtime":null},
 {"upid":"UPID:vega:000831DD:0640E944:6AC1B32B:vzdump::root@pam:","status":"job errors","starttime":1791079211,"endtime":1791104356},
 {"upid":"UPID:vega:0006B0EB:06306D36:6AC188F8:vzdump::root@pam:","status":"OK","starttime":1791068408,"endtime":1791076882},
 {"upid":"UPID:vega:0015CAA3:03EFAC2E:6ABBC47A:vzdump::root@pam:","status":"could not activate storage 'geros': storage 'geros' is not online","starttime":1790690426,"endtime":1790690426},
 {"upid":"UPID:vega:0004921D:0031A737:6AB22FF2:vzdump:2675:hlias@pam:","status":"OK","starttime":1790062578,"endtime":1790063082}
]`

var vegaNow = time.Unix(1791322845, 0).Add(3 * time.Hour)

func TestProxmoxVegaToday(t *testing.T) {
	jobs, fs, err := evalProxmox("vega", []byte(vegaJobs), []byte(vegaUncovered), []byte(vegaTasks), []byte(vegaStorage), vegaNow, Thresholds{})
	if err != nil {
		t.Fatal(err)
	}
	if len(jobs) != 2 || jobs[0].Name != "VAULT SERRES (backup-a39236a0-50b8)" {
		t.Fatalf("jobs: %+v", jobs)
	}
	got := byType(fs)
	// latest FINISHED run: "job errors" → partial warning
	if f := got[TypePartial]; f.Severity != SevWarning || f.Key != "pve:task:UPID:vega:000831DD:0640E944:6AC1B32B:vzdump::root@pam:" {
		t.Fatalf("want backup_partial for the job-errors run, got %+v", fs)
	}
	// uncovered guests, as one finding with members
	u := got[TypeUncovered]
	if u.Key != "pve:uncovered" || len(u.Members) != 3 || !strings.Contains(u.Message, "ngm (117)") {
		t.Fatalf("want one uncovered finding naming ngm, got %+v", u)
	}
	for _, typ := range []string{TypeFailed, TypeStale, TypeStuck, TypeDest} {
		if _, ok := got[typ]; ok {
			t.Fatalf("unexpected %s: %+v", typ, fs)
		}
	}
}

func TestProxmoxStorageOfflineAndFailedRun(t *testing.T) {
	storage := strings.Replace(vegaStorage, `{"storage":"geros","active":1`, `{"storage":"geros","active":0`, 1)
	tasks := `[{"upid":"U1","status":"could not activate storage 'geros': storage 'geros' is not online","starttime":1791322845,"endtime":1791322846},
	           {"upid":"U0","status":"OK","starttime":1791068408,"endtime":1791076882}]`
	_, fs, err := evalProxmox("vega", []byte(vegaJobs), []byte(`[]`), []byte(tasks), []byte(storage), vegaNow, Thresholds{})
	if err != nil {
		t.Fatal(err)
	}
	got := byType(fs)
	if f := got[TypeFailed]; f.Severity != SevCritical || !strings.Contains(f.Message, "geros") {
		t.Fatalf("want backup_failed naming the storage error, got %+v", fs)
	}
	if f := got[TypeDest]; f.Key != "pve:dest:geros" || f.Severity != SevCritical {
		t.Fatalf("want geros offline, got %+v", fs)
	}
	// mailpool-storage is disabled and in no job: never reported
	for _, f := range fs {
		if strings.Contains(f.Message, "mailpool") {
			t.Fatalf("reported a storage no job uses: %+v", f)
		}
	}
}

func TestProxmoxStuckAndStale(t *testing.T) {
	now := time.Unix(1791322845, 0).Add(30 * time.Hour)
	tasks := `[{"upid":"RUN","status":"RUNNING","starttime":1791322845,"endtime":null},
	           {"upid":"OLD","status":"OK","starttime":1790062578,"endtime":1790063082}]`
	_, fs, err := evalProxmox("vega", []byte(vegaJobs), []byte(`[]`), []byte(tasks), []byte(vegaStorage), now, Thresholds{})
	if err != nil {
		t.Fatal(err)
	}
	got := byType(fs)
	if f := got[TypeStuck]; f.Key != "pve:stuck:RUN" {
		t.Fatalf("want stuck, got %+v", fs)
	}
	if f := got[TypeStale]; f.Key != "pve:stale:vega" {
		t.Fatalf("last OK was ~15 days ago: want stale, got %+v", fs)
	}
}

func TestProxmoxJobPinnedToAnotherNodeIsNotOurs(t *testing.T) {
	jobs := `[{"enabled":1,"id":"j","schedule":"sun 02:00","storage":"geros","node":"other"}]`
	_, fs, err := evalProxmox("vega", []byte(jobs), []byte(`[]`), []byte(`[]`), []byte(vegaStorage), vegaNow, Thresholds{})
	if err != nil {
		t.Fatal(err)
	}
	if len(fs) != 0 {
		t.Fatalf("a job pinned to another node must not make this node stale: %+v", fs)
	}
}

func TestProxmoxNoTasksWithActiveJobsIsStale(t *testing.T) {
	_, fs, err := evalProxmox("vega", []byte(vegaJobs), []byte(`[]`), []byte(`[]`), []byte(vegaStorage), vegaNow, Thresholds{})
	if err != nil {
		t.Fatal(err)
	}
	if f := byType(fs)[TypeStale]; f.Type == "" {
		t.Fatalf("active jobs and no task on record: want stale, got %+v", fs)
	}
}

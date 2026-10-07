package backupcheck

import (
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"
)

// Fixtures: gde's real Virtualmin output (7 Oct 2026), domain lists trimmed.

const gdeScheds = `{"command":"list-scheduled-backups","status":"success","data":[
 {"name":"17899324032606664","values":{"destination":["/backups/daily/%Y-%m-%d"],"enabled":["Yes"],"running":["No"]}},
 {"name":"17899324822607494","values":{"destination":["/backups/weekly/%Y-W%V"],"enabled":["Yes"],"running":["No"],"cron_schedule":["weekly"]}},
 {"name":"17909627033334733","values":{"destination":["ssh://user@rosso:65535:/opt/store1/x/%Y-W%V"],"enabled":["Yes"],"running":["No"]}}
]}`

func vmLog(epoch int64, sched, from, status string, failed int) string {
	doms := strings.TrimSpace(strings.Repeat("d.gr ", failed))
	return fmt.Sprintf(`{"name":"%d-1-1","values":{"scheduled_backup_id":[%q],"run_from":[%q],"final_status":[%q],"failed_domains":[%q]}}`, epoch, sched, from, status, doms)
}

const daily, weekly, rosso = "17899324032606664", "17899324822607494", "17909627033334733"

func gdeLogs(extra ...string) string {
	rows := []string{
		vmLog(1789952402, daily, "sched", "Failed", 90), // 21 Sep, all 90 domains failed
		vmLog(1790038852, daily, "sched", "OK", 0),
		vmLog(1791075642, daily, "sched", "OK", 0),
		vmLog(1791162052, daily, "sched", "OK", 0),
		vmLog(1791248446, daily, "sched", "OK", 0),
		vmLog(1791334846, daily, "sched", "OK", 0), // 7 Oct 01:00
		vmLog(1790467247, weekly, "sched", "OK", 0),
		vmLog(1791072047, weekly, "sched", "OK", 0),   // 4 Oct
		vmLog(1790963477, rosso, "cgi", "Failed", 90), // a manual test run
		vmLog(1790964127, rosso, "cgi", "OK", 0),
		vmLog(1791104920, rosso, "sched", "OK", 0), // 4 Oct 09:00
	}
	rows = append(rows, extra...)
	return `{"command":"list-backup-logs","status":"success","data":[` + strings.Join(rows, ",") + `]}`
}

var gdeNow = time.Date(2026, 10, 7, 19, 0, 0, 0, time.UTC)

// gde's schedule files: daily at 01:00, special=weekly, Sundays 09:00 — all
// in place long before these runs.
var gdeSince = time.Date(2026, 8, 1, 0, 0, 0, 0, time.UTC)

var gdePeriods = map[string]vmSchedInfo{
	daily:  {cronPeriod(map[string]string{"mins": "0", "hours": "1", "days": "*", "months": "*", "weekdays": "*"}), gdeSince},
	weekly: {cronPeriod(map[string]string{"special": "weekly"}), gdeSince},
	rosso:  {cronPeriod(map[string]string{"mins": "0", "hours": "9", "days": "*", "months": "*", "weekdays": "0"}), gdeSince},
}

func TestVirtualminGdeTodayIsHealthy(t *testing.T) {
	jobs, fs, err := evalVirtualmin([]byte(gdeScheds), []byte(gdeLogs()), gdePeriods, gdeNow, Thresholds{})
	if err != nil {
		t.Fatal(err)
	}
	if len(fs) != 0 {
		t.Fatalf("healthy gde reported %+v", fs)
	}
	if len(jobs) != 3 || jobs[0].LastResult != "ok" || jobs[0].LastSuccess == nil {
		t.Fatalf("jobs: %+v", jobs)
	}
}

func TestVirtualminFailedScheduledRun(t *testing.T) {
	logs := gdeLogs(vmLog(1791421246, daily, "sched", "Failed", 90)) // 8 Oct 01:00
	_, fs, err := evalVirtualmin([]byte(gdeScheds), []byte(logs), gdePeriods, gdeNow.Add(8*time.Hour), Thresholds{})
	if err != nil {
		t.Fatal(err)
	}
	f := byType(fs)[TypeFailed]
	if f.Severity != SevCritical || f.Key != "vm:failed:"+daily || !strings.Contains(f.Message, "90 domain(s) failed") {
		t.Fatalf("want failed run, got %+v", fs)
	}
}

func TestVirtualminManualTestRunsAreNotScheduleHealth(t *testing.T) {
	// A failed UI test run AFTER the last scheduled one changes nothing.
	logs := gdeLogs(vmLog(1791380000, rosso, "cgi", "Failed", 90))
	_, fs, err := evalVirtualmin([]byte(gdeScheds), []byte(logs), gdePeriods, gdeNow, Thresholds{})
	if err != nil {
		t.Fatal(err)
	}
	if len(fs) != 0 {
		t.Fatalf("a cgi run must not count: %+v", fs)
	}
}

func TestVirtualminDailyStoppedRunningIsStale(t *testing.T) {
	// No daily run since 7 Oct 01:00; on 9 Oct 06:00 that is >38h.
	_, fs, err := evalVirtualmin([]byte(gdeScheds), []byte(gdeLogs()), gdePeriods, time.Date(2026, 10, 9, 6, 0, 0, 0, time.UTC), Thresholds{})
	if err != nil {
		t.Fatal(err)
	}
	f := byType(fs)[TypeStale]
	if f.Key != "vm:stale:"+daily {
		t.Fatalf("want daily stale, got %+v", fs)
	}
	for _, x := range fs {
		if x.Key == "vm:stale:"+weekly {
			t.Fatalf("weekly (last 4 Oct) is not stale on 9 Oct: %+v", x)
		}
	}
}

func TestVirtualminEnabledScheduleWithNoRunsIsStaleOnlyOnceItIsOldEnough(t *testing.T) {
	scheds := strings.TrimSuffix(gdeScheds, "\n]}") + `,
 {"name":"999","values":{"destination":["/backups/never"],"enabled":["Yes"],"running":["No"]}}
]}`
	info := map[string]vmSchedInfo{daily: gdePeriods[daily], weekly: gdePeriods[weekly], rosso: gdePeriods[rosso],
		"999": {24 * time.Hour, gdeNow.Add(-6 * time.Hour)}} // created this morning
	_, fs, err := evalVirtualmin([]byte(scheds), []byte(gdeLogs()), info, gdeNow, Thresholds{})
	if err != nil {
		t.Fatal(err)
	}
	if len(fs) != 0 {
		t.Fatalf("a schedule created 6h ago must not be judged yet: %+v", fs)
	}
	info["999"] = vmSchedInfo{24 * time.Hour, gdeNow.Add(-10 * 24 * time.Hour)}
	_, fs, err = evalVirtualmin([]byte(scheds), []byte(gdeLogs()), info, gdeNow, Thresholds{})
	if err != nil {
		t.Fatal(err)
	}
	if f := byType(fs)[TypeStale]; f.Key != "vm:stale:999" {
		t.Fatalf("10 days and never ran: want stale, got %+v", fs)
	}
}

func TestVirtualminRunInProgressIsNeitherFailedNorStuck(t *testing.T) {
	scheds := strings.Replace(gdeScheds, `"enabled":["Yes"],"running":["No"]}},
 {"name":"17899324822607494"`, `"enabled":["Yes"],"running":["Yes"]}},
 {"name":"17899324822607494"`, 1)
	at := time.Date(2026, 10, 8, 1, 15, 0, 0, time.UTC)
	// 8 Oct 01:00 run logged with no final status yet.
	logs := gdeLogs(vmLog(1791421246, daily, "sched", "", 0))
	_, fs, err := evalVirtualmin([]byte(scheds), []byte(logs), gdePeriods, at, Thresholds{})
	if err != nil {
		t.Fatal(err)
	}
	if len(fs) != 0 {
		t.Fatalf("a run in progress is not a failure nor stuck: %+v", fs)
	}
	// Same, but not logged at all yet: still nothing.
	_, fs, err = evalVirtualmin([]byte(scheds), []byte(gdeLogs()), gdePeriods, at, Thresholds{})
	if err != nil || len(fs) != 0 {
		t.Fatalf("running without a log record yet: %v %+v", err, fs)
	}
	// 30 h later the logged run is still going: stuck.
	_, fs, err = evalVirtualmin([]byte(scheds), []byte(logs), gdePeriods, at.Add(30*time.Hour), Thresholds{})
	if err != nil {
		t.Fatal(err)
	}
	if f := byType(fs)[TypeStuck]; f.Key != "vm:stuck:"+daily {
		t.Fatalf("want stuck after 30h, got %+v", fs)
	}
}

func TestVirtualminNoEnabledScheduleIsAWarning(t *testing.T) {
	scheds := strings.ReplaceAll(gdeScheds, `"enabled":["Yes"]`, `"enabled":["No"]`)
	_, fs, err := evalVirtualmin([]byte(scheds), []byte(gdeLogs()), gdePeriods, gdeNow, Thresholds{})
	if err != nil {
		t.Fatal(err)
	}
	if f := byType(fs)[TypeNoJob]; f.Severity != SevWarning || f.Key != "vm:nojob" {
		t.Fatalf("want backup_no_job, got %+v", fs)
	}
}

func TestVirtualminDisabledScheduleIsIgnored(t *testing.T) {
	scheds := strings.Replace(gdeScheds, `"/backups/daily/%Y-%m-%d"],"enabled":["Yes"]`, `"/backups/daily/%Y-%m-%d"],"enabled":["No"]`, 1)
	_, fs, err := evalVirtualmin([]byte(scheds), []byte(gdeLogs(vmLog(1791421246, daily, "sched", "Failed", 1))), gdePeriods, gdeNow.Add(48*time.Hour), Thresholds{})
	if err != nil {
		t.Fatal(err)
	}
	for _, f := range fs {
		if strings.Contains(f.Key, daily) {
			t.Fatalf("disabled schedule reported: %+v", f)
		}
	}
}

func TestCronPeriodIsTheLongestGap(t *testing.T) {
	for _, c := range []struct {
		kv   map[string]string
		want time.Duration
	}{
		{map[string]string{"special": "weekly"}, 7 * 24 * time.Hour},
		{map[string]string{"hours": "1", "days": "*", "weekdays": "*"}, 24 * time.Hour},
		{map[string]string{"hours": "9", "weekdays": "0"}, 7 * 24 * time.Hour},
		{map[string]string{"hours": "9", "weekdays": "7"}, 7 * 24 * time.Hour},   // Sunday as 7
		{map[string]string{"hours": "2", "weekdays": "1-5"}, 3 * 24 * time.Hour}, // Mon–Fri: Fri→Mon
		{map[string]string{"hours": "2", "weekdays": "1,4"}, 4 * 24 * time.Hour}, // Thu→Mon
		{map[string]string{"hours": "2", "weekdays": "0-6"}, 24 * time.Hour},     // every day
		{map[string]string{"hours": "1-5", "weekdays": "*"}, 20 * time.Hour},     // 05→01
		{map[string]string{"hours": "*/6", "weekdays": "*"}, 6 * time.Hour},
		{map[string]string{"hours": "3", "days": "1"}, 32 * 24 * time.Hour},  // monthly
		{map[string]string{"hours": "3", "days": "*/2"}, 3 * 24 * time.Hour}, // every other day (+1 for the month end)
		{map[string]string{"hours": "3", "days": "1-31"}, 24 * time.Hour},    // every day
		{map[string]string{"hours": "3", "days": "*", "months": "1,7"}, 31 * 24 * time.Hour},
		{map[string]string{"special": ""}, 0},
	} {
		if got := cronPeriod(c.kv); got != c.want {
			t.Errorf("%v: got %s want %s", c.kv, got, c.want)
		}
	}
}

func TestScheduleInfoReadsTheScheduleFile(t *testing.T) {
	dir := t.TempDir()
	orig := virtualminSchedDir
	virtualminSchedDir = dir
	t.Cleanup(func() { virtualminSchedDir = orig })
	if err := os.WriteFile(filepath.Join(dir, "123"), []byte("mins=0\nhours=9\ndays=*\nmonths=*\nweekdays=0\nenabled=2\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	got := scheduleInfo([]string{"123", "missing", "../etc"})
	if got["123"].period != 7*24*time.Hour || got["123"].since.IsZero() {
		t.Fatalf("got %+v", got)
	}
	if _, ok := got["missing"]; ok {
		t.Fatal("missing file must be absent")
	}
	if _, ok := got["../etc"]; ok {
		t.Fatal("a path-like id must never be read")
	}
}

func TestRedactURLDropsCredentials(t *testing.T) {
	for in, want := range map[string]string{
		"ssh://user:s3cret@rosso.myip.gr:65535:/opt/x/%Y":                              "ssh://user:***@rosso.myip.gr:65535:/opt/x/%Y",
		"ssh://athensescorts:|root|.ssh|id_rsa_backup@rosso.myip.gr:65535:/opt/store1": "ssh://athensescorts:***@rosso.myip.gr:65535:/opt/store1",
		"s3://AKIA:abc/def@bucket/path":                                                "s3://AKIA:***@bucket/path",
		"/backups/daily/%Y-%m-%d":                                                      "/backups/daily/%Y-%m-%d",
		"ftp://anon@host/dir":                                                          "ftp://anon@host/dir",
	} {
		if got := redactURL(in); got != want {
			t.Errorf("%q: got %q want %q", in, got, want)
		}
	}
}

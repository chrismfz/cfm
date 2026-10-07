package backupcheck

import (
	"fmt"
	"strings"
	"testing"
	"time"
)

// Fixtures are trimmed from orion's real JetBackup 5.4.1.4 output (7 Oct 2026):
// destination options/credentials removed, everything evaluated kept as-is.

const orionDest = `[{"_id":"603f828586d07b034e267ee2","name":"Rosso","disabled":false,"disk_usage":{"usage":14839891664896,"free":953824305152,"total":15793715970048}}]`

func orionJobs(running bool, lastRun, lastCompleted, nextRun string) string {
	return fmt.Sprintf(`{"success":1,"message":"","data":{"jobs":[
 {"_id":"603f828986d07b034e267ee4","name":"JetBackup Config","type":3,"next_run":"2026-10-07T23:00:00+00:00","last_run":"2026-10-06T23:00:01+00:00","last_completed":"2026-10-06T23:00:11+00:00","running":false,"disabled":0,"schedules":[{"name":"JetBackup Config Daily"}],"destination_details":%s},
 {"_id":"603f830764375f7820538382","name":"Daily-Monthly","type":1,"next_run":%q,"last_run":%q,"last_completed":%q,"running":%t,"disabled":0,"schedules":[{"name":"Daily7"},{"name":"Monthly6"}],"destination_details":%s}
],"total":2}}`, orionDest, nextRun, lastRun, lastCompleted, running, orionDest)
}

// orionLogs: the Daily-Monthly runs of 18–21 Sep (status 1, 4, 4, then the
// 16-day run), the daily config job, and the plugin/integrity noise that
// shares the log stream. end21 = "" means the 21 Sep run is still going.
func orionLogs(end21 string, status21 int) string {
	run21 := fmt.Sprintf(`{"_id":"run21","start_time":"2026-09-21T01:15:00+00:00","end_time":%q,"status":%d,"type":1,"info":{"Backup":"Daily-Monthly","ID":"603f830764375f7820538382","Total Accounts":199}}`, end21, status21)
	return `{"success":1,"message":"","data":{"logs":[
 {"_id":"cfg06","start_time":"2026-10-06T23:00:00+00:00","end_time":"2026-10-06T23:00:11+00:00","status":1,"type":1,"info":{"Backup":"JetBackup Config","ID":"603f828986d07b034e267ee4","Type":"JB Config"}},
 {"_id":"imu","start_time":"2026-10-06T19:37:12+00:00","end_time":"2026-10-06T19:37:14+00:00","status":2,"type":8,"info":{"Plugin":"Imunify360","Infected Files":1}},
 {"_id":"integ","start_time":"2026-09-27T15:24:50+00:00","end_time":"2026-10-07T10:28:09+00:00","status":4,"type":4,"info":{"Type":"Integrity Check","Backup Job":"Daily-Monthly","Destination":"Rosso"}},
 {"_id":"cfg21","start_time":"2026-09-21T23:00:00+00:00","end_time":"2026-09-21T23:00:10+00:00","status":1,"type":1,"info":{"Backup":"JetBackup Config","ID":"603f828986d07b034e267ee4","Type":"JB Config"}},
 ` + run21 + `,
 {"_id":"run20","start_time":"2026-09-20T01:15:00+00:00","end_time":"2026-09-20T02:24:17+00:00","status":4,"type":1,"info":{"Backup":"Daily-Monthly","ID":"603f830764375f7820538382","Total Accounts":199}},
 {"_id":"run19","start_time":"2026-09-19T01:15:00+00:00","end_time":"2026-09-19T02:24:21+00:00","status":4,"type":1,"info":{"Backup":"Daily-Monthly","ID":"603f830764375f7820538382","Total Accounts":199}},
 {"_id":"cfg18","start_time":"2026-09-18T23:00:00+00:00","end_time":"2026-09-18T23:00:09+00:00","status":1,"type":1,"info":{"Backup":"JetBackup Config","ID":"603f828986d07b034e267ee4","Type":"JB Config"}},
 {"_id":"run18","start_time":"2026-09-18T01:15:00+00:00","end_time":"2026-09-18T02:23:01+00:00","status":1,"type":1,"info":{"Backup":"Daily-Monthly","ID":"603f830764375f7820538382","Total Accounts":199}},
 {"_id":"run17","start_time":"2026-09-17T01:15:00+00:00","end_time":"2026-09-17T02:22:40+00:00","status":1,"type":1,"info":{"Backup":"Daily-Monthly","ID":"603f830764375f7820538382","Total Accounts":199}}
],"total":9}}`
}

func ts(s string) time.Time {
	t, err := time.Parse(time.RFC3339, s)
	if err != nil {
		panic(err)
	}
	return t
}

func byType(fs []Finding) map[string]Finding {
	m := map[string]Finding{}
	for _, f := range fs {
		m[f.Type] = f
	}
	return m
}

// 19 Sep, after the first failed run: the failure is reported at once, and
// nothing is stale yet (last success 18 Sep ~02:23, a daily job allows 38h).
func TestJetBackupOrion19SepFailedRunIsCritical(t *testing.T) {
	jobs := orionJobs(false, "2026-09-19T01:15:02+00:00", "2026-09-19T02:24:21+00:00", "2026-09-20T01:15:00+00:00")
	// keep only the runs that existed on 19 Sep 03:00
	logs := removeLogs(orionLogs("", 0), "run21", "run20", "cfg21", "cfg06", "integ", "imu")
	_, fs, err := evalJetBackup([]byte(jobs), []byte(logs), ts("2026-09-19T03:00:00Z"), Thresholds{})
	if err != nil {
		t.Fatal(err)
	}
	got := byType(fs)
	f, ok := got[TypeFailed]
	if !ok || f.Severity != SevCritical || f.Key != "jb:failed:603f830764375f7820538382" || !strings.Contains(f.Message, "Daily-Monthly") {
		t.Fatalf("want critical backup_failed for run19, got %+v", fs)
	}
	if _, ok := got[TypeStale]; ok {
		t.Fatalf("not stale yet on 19 Sep: %+v", fs)
	}
}

// 23 Sep: the 21 Sep run has been going for ~2 days, no success since 18 Sep.
func TestJetBackupOrionStuckRunIsStuckAndStale(t *testing.T) {
	jobs := orionJobs(true, "2026-09-21T01:15:02+00:00", "2026-09-20T02:24:17+00:00", "2026-09-22T01:15:00+00:00")
	logs := removeLogs(orionLogs("", 0), "cfg06", "integ", "imu")
	jobsOut, fs, err := evalJetBackup([]byte(jobs), []byte(logs), ts("2026-09-23T09:00:00Z"), Thresholds{})
	if err != nil {
		t.Fatal(err)
	}
	got := byType(fs)
	if f := got[TypeStuck]; f.Severity != SevCritical || f.Key != "jb:stuck:603f830764375f7820538382" {
		t.Fatalf("want backup_stuck, got %+v", fs)
	}
	if f := got[TypeStale]; f.Severity != SevCritical || !strings.Contains(f.Message, "2026-09-18T02:23:01Z") {
		t.Fatalf("want backup_stale measured from the 18 Sep success, got %+v", fs)
	}
	// the latest FINISHED run (20 Sep) failed too
	if f := got[TypeFailed]; f.Key != "jb:failed:603f830764375f7820538382" || !strings.Contains(f.Message, "2026-09-20T02:24:17Z") {
		t.Fatalf("want backup_failed for run20, got %+v", fs)
	}
	for _, j := range jobsOut {
		if j.Name == "Daily-Monthly" && (!j.Running || j.LastSuccess == nil || !j.LastSuccess.Equal(ts("2026-09-18T02:23:01Z"))) {
			t.Fatalf("job summary wrong: %+v", j)
		}
	}
}

// 7 Oct (today): the run ended — failed — and last_completed reads TODAY.
// It must still be stale: last_completed advances on failed runs.
func TestJetBackupLastCompletedOnAFailedRunIsNotFreshness(t *testing.T) {
	jobs := orionJobs(false, "2026-09-21T01:15:02+00:00", "2026-10-07T10:28:07+00:00", "2026-10-08T01:15:00+00:00")
	_, fs, err := evalJetBackup([]byte(jobs), []byte(orionLogs("2026-10-07T10:28:07+00:00", 4)), ts("2026-10-07T19:00:00Z"), Thresholds{})
	if err != nil {
		t.Fatal(err)
	}
	got := byType(fs)
	if f := got[TypeStale]; f.Type == "" || !strings.Contains(f.Message, "19d") {
		t.Fatalf("want stale ~19d despite last_completed=today, got %+v", fs)
	}
	if f := got[TypeFailed]; f.Key != "jb:failed:603f830764375f7820538382" || !strings.Contains(f.Message, "2026-10-07T10:28:07Z") {
		t.Fatalf("want the 16-day run reported failed, got %+v", fs)
	}
	if _, ok := got[TypeStuck]; ok {
		t.Fatalf("not running any more, must not be stuck: %+v", fs)
	}
}

// earth on a good night: nothing to report, and plugin/integrity runs (types
// 8/4) never count as backup runs.
func TestJetBackupHealthyJobReportsNothing(t *testing.T) {
	jobs := orionJobs(false, "2026-09-21T01:15:02+00:00", "2026-09-21T02:30:00+00:00", "2026-09-22T01:15:00+00:00")
	logs := orionLogs("2026-09-21T02:30:00+00:00", 1) // still carries the failed integrity check (type 4)
	_, fs, err := evalJetBackup([]byte(jobs), []byte(logs), ts("2026-09-21T09:00:00Z"), Thresholds{})
	if err != nil {
		t.Fatal(err)
	}
	if len(fs) != 0 {
		t.Fatalf("healthy job reported %+v", fs)
	}
}

func TestJetBackupPartialRunIsAWarning(t *testing.T) {
	jobs := orionJobs(false, "2026-09-21T01:15:02+00:00", "2026-09-21T02:30:00+00:00", "2026-09-22T01:15:00+00:00")
	_, fs, err := evalJetBackup([]byte(jobs), []byte(orionLogs("2026-09-21T02:30:00+00:00", 2)), ts("2026-09-21T09:00:00Z"), Thresholds{})
	if err != nil {
		t.Fatal(err)
	}
	got := byType(fs)
	if f := got[TypePartial]; f.Severity != SevWarning {
		t.Fatalf("want backup_partial warning, got %+v", fs)
	}
	if _, ok := got[TypeStale]; ok {
		t.Fatal("a partial run is a success for freshness")
	}
}

func TestJetBackupDisabledJobIsIgnoredAndDestinationLowIsWarned(t *testing.T) {
	jobs := orionJobs(false, "2026-09-21T01:15:02+00:00", "2026-09-20T02:24:17+00:00", "2026-09-22T01:15:00+00:00")
	jobs = strings.ReplaceAll(jobs, `"free":953824305152`, `"free":153824305152`) // ~1% free
	jobs = strings.Replace(jobs, `"running":false,"disabled":0,"schedules":[{"name":"Daily7"}`, `"running":false,"disabled":1,"schedules":[{"name":"Daily7"}`, 1)
	_, fs, err := evalJetBackup([]byte(jobs), []byte(orionLogs("", 0)), ts("2026-10-07T19:00:00Z"), Thresholds{})
	if err != nil {
		t.Fatal(err)
	}
	for _, f := range fs {
		if strings.Contains(f.Message, "Daily-Monthly") {
			t.Fatalf("disabled job reported: %+v", f)
		}
	}
	got := byType(fs)
	if f := got[TypeDest]; f.Key != "jb:dest:603f828586d07b034e267ee2" || f.Severity != SevWarning {
		t.Fatalf("want one low-space warning for Rosso, got %+v", fs)
	}
	n := 0
	for _, f := range fs {
		if f.Type == TypeDest {
			n++
		}
	}
	if n != 1 {
		t.Fatalf("a destination shared by two jobs must be reported once, got %d", n)
	}
}

func TestJetBackupAPIErrorIsAnErrorNotSilence(t *testing.T) {
	_, _, err := evalJetBackup([]byte(`{"success":0,"message":"No permission","data":[]}`), []byte(orionLogs("", 0)), time.Now(), Thresholds{})
	if err == nil || !strings.Contains(err.Error(), "No permission") {
		t.Fatalf("want api error surfaced, got %v", err)
	}
}

// removeLogs drops log entries by _id from a fixture.
func removeLogs(logs string, ids ...string) string {
	lines := strings.Split(logs, "\n")
	var keep []string
	for _, l := range lines {
		drop := false
		for _, id := range ids {
			if strings.Contains(l, `"_id":"`+id+`"`) {
				drop = true
			}
		}
		if !drop {
			keep = append(keep, l)
		}
	}
	out := strings.Join(keep, "\n")
	// fix a trailing comma left before the closing bracket
	out = strings.Replace(out, "},\n],", "}\n],", 1)
	return out
}

func jbLogsFrom(jobID string, starts []string, status int) string {
	var rows []string
	for i, st := range starts {
		t := ts(st)
		rows = append(rows, fmt.Sprintf(`{"_id":"r%d","start_time":%q,"end_time":%q,"status":%d,"type":1,"info":{"ID":%q}}`,
			i, t.Format(time.RFC3339), t.Add(time.Hour).Format(time.RFC3339), status, jobID))
	}
	return `{"success":1,"message":"","data":{"logs":[` + strings.Join(rows, ",") + `]}}`
}

func oneJob(lastRun, nextRun string, running bool) string {
	return fmt.Sprintf(`{"success":1,"message":"","data":{"jobs":[{"_id":"J","name":"wk","type":1,"disabled":0,"running":%t,"last_run":%q,"next_run":%q}]}}`, running, lastRun, nextRun)
}

// A Mon–Fri job seen on Sunday evening: its last success is Friday's, 62h ago.
func TestJetBackupWeekdayJobIsNotStaleAtTheWeekend(t *testing.T) {
	starts := []string{
		"2026-09-21T01:00:00Z", "2026-09-22T01:00:00Z", "2026-09-23T01:00:00Z", "2026-09-24T01:00:00Z", "2026-09-25T01:00:00Z",
		"2026-09-28T01:00:00Z", "2026-09-29T01:00:00Z", "2026-09-30T01:00:00Z", "2026-10-01T01:00:00Z", "2026-10-02T01:00:00Z",
	}
	_, fs, err := evalJetBackup([]byte(oneJob("2026-10-02T01:00:00Z", "2026-10-05T01:00:00Z", false)), []byte(jbLogsFrom("J", starts, 1)), ts("2026-10-04T18:00:00Z"), Thresholds{})
	if err != nil {
		t.Fatal(err)
	}
	if len(fs) != 0 {
		t.Fatalf("Mon–Fri job on Sunday: %+v", fs)
	}
}

// A weekly job with a single run in the window, 3 days after it succeeded.
func TestJetBackupWeeklyJobWithOneRunIsNotStale(t *testing.T) {
	_, fs, err := evalJetBackup([]byte(oneJob("2026-10-04T01:00:00Z", "2026-10-11T01:00:00Z", false)), []byte(jbLogsFrom("J", []string{"2026-10-04T01:00:00Z"}, 1)), ts("2026-10-07T18:00:00Z"), Thresholds{})
	if err != nil {
		t.Fatal(err)
	}
	if len(fs) != 0 {
		t.Fatalf("weekly job 3 days after a success: %+v", fs)
	}
}

// A job with no run in the history read: an old last_run proves "has not run";
// a recent one (it advances on FAILED runs) proves nothing — unknown, an error.
func TestJetBackupJobWithoutRunsInHistory(t *testing.T) {
	noRuns := `{"success":1,"message":"","data":{"logs":[],"total":0}}`
	_, fs, err := evalJetBackup([]byte(oneJob("2026-10-07T01:00:00Z", "2026-10-08T01:00:00Z", false)), []byte(noRuns), ts("2026-10-07T10:00:00Z"), Thresholds{})
	if err == nil || len(fs) != 0 {
		t.Fatalf("recent last_run, no log of it: want an error (unknown), got %v %+v", err, fs)
	}
	_, fs, err = evalJetBackup([]byte(oneJob("2026-09-20T01:00:00Z", "2026-09-21T01:00:00Z", false)), []byte(noRuns), ts("2026-10-07T18:00:00Z"), Thresholds{})
	if err != nil {
		t.Fatal(err)
	}
	if f := byType(fs)[TypeStale]; !strings.Contains(f.Message, "has not run since") {
		t.Fatalf("want stale from last_run, got %+v", fs)
	}
	_, _, err = evalJetBackup([]byte(oneJob("2026-10-07T01:00:00Z", "2026-10-08T01:00:00Z", false)), []byte(`{"success":1,"message":"","data":{"logs":null}}`), ts("2026-10-07T10:00:00Z"), Thresholds{})
	if err == nil {
		t.Fatal("logs:null with a job that ran: want unknown")
	}
}

func TestJetBackupNoEnabledAccountJobIsAWarning(t *testing.T) {
	jobs := `{"success":1,"message":"","data":{"jobs":[{"_id":"C","name":"JetBackup Config","type":3,"disabled":0},{"_id":"A","name":"accts","type":1,"disabled":1}]}}`
	_, fs, err := evalJetBackup([]byte(jobs), []byte(`{"success":1,"message":"","data":{"logs":[]}}`), time.Now(), Thresholds{})
	if err != nil {
		t.Fatal(err)
	}
	if f := byType(fs)[TypeNoJob]; f.Key != "jb:nojob" {
		t.Fatalf("want backup_no_job, got %+v", fs)
	}
	_, fs, err = evalJetBackup([]byte(`{"success":1,"message":"","data":{"jobs":null}}`), []byte(`{"success":1,"message":"","data":{"logs":[]}}`), time.Now(), Thresholds{})
	if err != nil || byType(fs)[TypeNoJob].Type == "" {
		t.Fatalf("jobs:null: want backup_no_job, got %v %+v", err, fs)
	}
}

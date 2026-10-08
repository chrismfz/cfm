package backupcheck

import (
	"encoding/json"
	"fmt"
	"sort"
	"strings"
	"time"
)

// JetBackup 5 (cPanel and DirectAdmin share the same CLI).
//
// Two reads per check: the jobs (`listBackupJobs`) and the recent run history
// (`listLogs`, newest first). Observed on the fleet (5.4.1.4):
//   - a log's `status` is JetBackup's LOG_STATUS_*: 1 completed, 2 failed,
//     3 aborted, 4 partially completed, 5 never finished (read from its UI
//     code on titan, 8 Oct 2026; every run's log ends with that word). A
//     partial run is the common case on a hosting node — one account over its
//     own disk quota makes the whole job "Partially Completed" (orion and
//     virgo, most nights) — so it is a warning, and it counts as a backup for
//     freshness. Anything but 1/4 is treated as failed.
//   - `type` 1 is a backup-job run; other types (8 = plugin scans, …) are
//     ignored. A run's `info.ID` is the job's `_id`.
//   - `last_completed` advances on FAILED runs too — see the package doc.
const (
	jetbackupCLI = "jetbackup5api"
	// jetbackupLogLimit bounds the history read. The whole retained history
	// (orion and earth held ~210 entries) fits many times over; plugin scans
	// and integrity checks share the stream, so a small window could push a
	// daily job's runs out of it — and then a failing job would be judged on
	// its own timestamps, which advance on failure. A history that does not
	// fit is reported as a check error rather than guessed at.
	jetbackupLogLimit = 5000
)

type jbTime string

func (t jbTime) parse() (time.Time, bool) {
	s := strings.TrimSpace(string(t))
	if s == "" {
		return time.Time{}, false
	}
	v, err := time.Parse(time.RFC3339, s)
	if err != nil {
		return time.Time{}, false
	}
	return v, true
}

// jbFlex accepts a JSON number, bool or string (fleets run mixed JetBackup
// versions; a field's JSON type is not something to bet a check on).
type jbFlex string

func (f *jbFlex) UnmarshalJSON(b []byte) error {
	s := strings.Trim(strings.TrimSpace(string(b)), `"`)
	if s == "null" {
		s = ""
	}
	*f = jbFlex(s)
	return nil
}

func (f jbFlex) truthy() bool {
	switch strings.ToLower(string(f)) {
	case "1", "true", "yes":
		return true
	}
	return false
}

type jbDestination struct {
	ID        string `json:"_id"`
	Name      string `json:"name"`
	Disabled  jbFlex `json:"disabled"`
	DiskUsage struct {
		Usage float64 `json:"usage"`
		Free  float64 `json:"free"`
		Total float64 `json:"total"`
	} `json:"disk_usage"`
}

type jbJob struct {
	ID            string          `json:"_id"`
	Name          string          `json:"name"`
	Type          jbFlex          `json:"type"`
	Disabled      jbFlex          `json:"disabled"`
	Running       jbFlex          `json:"running"`
	LastRun       jbTime          `json:"last_run"`
	LastCompleted jbTime          `json:"last_completed"`
	NextRun       jbTime          `json:"next_run"`
	Destinations  []jbDestination `json:"destination_details"`
	Schedules     []struct {
		Name string `json:"name"`
	} `json:"schedules"`
}

type jbLog struct {
	ID        string `json:"_id"`
	StartTime jbTime `json:"start_time"`
	EndTime   jbTime `json:"end_time"`
	Status    jbFlex `json:"status"`
	Type      jbFlex `json:"type"`
	Info      struct {
		ID     string `json:"ID"`
		Backup string `json:"Backup"`
	} `json:"info"`
}

type jbEnvelope struct {
	Success jbFlex          `json:"success"`
	Message string          `json:"message"`
	Data    json.RawMessage `json:"data"`
}

func checkJetBackup(run cmdFunc, now time.Time, th Thresholds) AdapterStatus {
	st := AdapterStatus{Name: "jetbackup"}
	jobsOut, err := run(jetbackupCLI, "-F", "listBackupJobs", "-O", "json")
	if err != nil {
		st.Error = "listBackupJobs: " + err.Error()
		return st
	}
	logsOut, err := run(jetbackupCLI, "-F", "listLogs", "-O", "json",
		"-D", fmt.Sprintf("limit=%d&sort[start_time]=-1", jetbackupLogLimit))
	if err != nil {
		st.Error = "listLogs: " + err.Error()
		return st
	}
	jobs, findings, unknown, err := evalJetBackup(jobsOut, logsOut, now, th)
	st.Jobs = jobs
	st.Findings = findings
	st.Unknown = unknown
	if err != nil {
		st.Error = err.Error()
	}
	return st
}

func decodeJB(raw []byte, field string, into any) error {
	var env jbEnvelope
	if err := json.Unmarshal(raw, &env); err != nil {
		return fmt.Errorf("decode: %w", err)
	}
	if !env.Success.truthy() {
		return fmt.Errorf("api error: %s", strings.TrimSpace(env.Message))
	}
	var data map[string]json.RawMessage
	if err := json.Unmarshal(env.Data, &data); err != nil {
		return fmt.Errorf("decode data: %w", err)
	}
	if err := json.Unmarshal(data[field], into); err != nil {
		return fmt.Errorf("decode %s: %w", field, err)
	}
	return nil
}

// evalJetBackup is the pure evaluation over the two API responses.
//
// unknown lists the finding keys of jobs this check could not judge (a job that
// has run recently but has no run in the log history read): kept armed,
// neither raised nor resolved — one such job must not turn the whole adapter
// into an error and freeze every other job's findings.
func evalJetBackup(jobsRaw, logsRaw []byte, now time.Time, th Thresholds) (_ []Job, _ []Finding, unknown []string, err error) {
	th = th.withDefaults()
	var jobs []jbJob
	if err := decodeJB(jobsRaw, "jobs", &jobs); err != nil {
		return nil, nil, nil, fmt.Errorf("listBackupJobs %w", err)
	}
	var logs []jbLog
	if err := decodeJB(logsRaw, "logs", &logs); err != nil {
		return nil, nil, nil, fmt.Errorf("listLogs %w", err)
	}
	var total int
	_ = decodeJB(logsRaw, "total", &total)
	complete := total <= len(logs)

	// Newest finished run and newest SUCCESSFUL run per job. logs arrive newest
	// first; don't rely on it.
	type runs struct {
		latest, success *jbLog
		starts          []time.Time
	}
	byJob := map[string]*runs{}
	for i := range logs {
		l := &logs[i]
		if string(l.Type) != "1" || l.Info.ID == "" {
			continue
		}
		r := byJob[l.Info.ID]
		if r == nil {
			r = &runs{}
			byJob[l.Info.ID] = r
		}
		if t, ok := l.StartTime.parse(); ok {
			r.starts = append(r.starts, t)
		}
		end, ok := l.EndTime.parse()
		if !ok {
			continue // still running; the job's running flag covers it
		}
		if r.latest == nil || laterEnd(end, r.latest) {
			r.latest = l
		}
		if res := jbResult(string(l.Status)); (res == "ok" || res == "partial") && (r.success == nil || laterEnd(end, r.success)) {
			r.success = l
		}
	}

	var out []Job
	var findings []Finding
	seenDest := map[string]bool{}
	enabledAccountJobs := 0
	for _, j := range jobs {
		job := Job{Name: j.Name, ID: j.ID, Disabled: j.Disabled.truthy(), Running: j.Running.truthy(), LastResult: "unknown"}
		for _, s := range j.Schedules {
			if s.Name != "" {
				job.Schedule = strings.TrimSpace(job.Schedule + ", " + s.Name)
			}
		}
		job.Schedule = strings.TrimPrefix(job.Schedule, ", ")
		r := byJob[j.ID]
		if r != nil && r.success != nil {
			if t, ok := r.success.EndTime.parse(); ok {
				job.LastSuccess = &t
			}
		}
		if r != nil && r.latest != nil {
			job.LastResult = jbResult(string(r.latest.Status))
		}
		out = append(out, job)
		if job.Disabled {
			continue
		}
		if string(j.Type) == "1" {
			enabledAccountJobs++
		}
		label := fmt.Sprintf("JetBackup job %q", j.Name)

		// 1. The latest finished run.
		if r != nil && r.latest != nil {
			end, _ := r.latest.EndTime.parse()
			switch job.LastResult {
			case "failed":
				findings = append(findings, Finding{
					Type: TypeFailed, Severity: SevCritical, Adapter: "jetbackup",
					Key:     "jb:failed:" + j.ID,
					Message: fmt.Sprintf("%s: last run %s (ended %s)", label, jbStatusName(string(r.latest.Status)), end.UTC().Format(time.RFC3339)),
				})
			case "partial":
				findings = append(findings, Finding{
					Type: TypePartial, Severity: SevInfo, Adapter: "jetbackup",
					Key:     "jb:partial:" + j.ID,
					Message: fmt.Sprintf("%s: last run only PARTIALLY completed — some accounts were not backed up (ended %s)", label, end.UTC().Format(time.RFC3339)),
				})
			}
		}

		// 2. Stuck: still running long after it started.
		if job.Running {
			if started, ok := j.LastRun.parse(); ok && now.Sub(started) > th.StuckAfter {
				findings = append(findings, Finding{
					Type: TypeStuck, Severity: SevCritical, Adapter: "jetbackup",
					Key:     "jb:stuck:" + j.ID,
					Message: fmt.Sprintf("%s: running for %s (started %s) — likely stuck on an account", label, Ago(now.Sub(started)), started.UTC().Format(time.RFC3339)),
				})
			}
		}

		// 3. Stale: no SUCCESSFUL run within the job's own period. The period
		// comes from how often the job actually STARTED, not next_run-last_run:
		// a run stuck for 16 days pins last_run, which made a daily job look
		// like a 17-day one and hid exactly the case this check exists for.
		// With too few runs to measure, the job's own schedule (when it is not
		// mid-run) or a conservative 8 days decides.
		var starts []time.Time
		if r != nil {
			starts = r.starts
		}
		period := jbPeriod(starts, j)
		limit := time.Duration(float64(period)*th.StaleFactor) + th.StaleGrace
		switch {
		case job.LastSuccess != nil:
			if age := now.Sub(*job.LastSuccess); age > limit {
				findings = append(findings, Finding{
					Type: TypeStale, Severity: SevCritical, Adapter: "jetbackup",
					Key:     "jb:stale:" + j.ID,
					Message: fmt.Sprintf("%s: no successful backup for %s (last success %s)", label, Ago(age), job.LastSuccess.UTC().Format(time.RFC3339)),
				})
			}
		case len(starts) > 0:
			// Runs in the history, none successful: stale once THIS job's own
			// history reaches back past the limit (a new job is not judged
			// before then).
			if first := earliest(starts); now.Sub(first) > limit {
				findings = append(findings, Finding{
					Type: TypeStale, Severity: SevCritical, Adapter: "jetbackup",
					Key:     "jb:stale:" + j.ID,
					Message: fmt.Sprintf("%s: no successful backup since at least %s (every run in the history failed)", label, first.UTC().Format(time.RFC3339)),
				})
			}
		default:
			// No run of this job in the history read. last_run can only prove
			// "has not run" — it advances on FAILED runs, so a recent one with no
			// log of it means the history is incomplete (purged, truncated, an
			// empty API answer): unknown, never healthy.
			lr, ok := j.LastRun.parse()
			switch {
			case ok && now.Sub(lr) > limit:
				findings = append(findings, Finding{
					Type: TypeStale, Severity: SevCritical, Adapter: "jetbackup",
					Key:     "jb:stale:" + j.ID,
					Message: fmt.Sprintf("%s: has not run since %s", label, lr.UTC().Format(time.RFC3339)),
				})
			case ok || !complete:
				unknown = append(unknown, "jb:failed:"+j.ID, "jb:partial:"+j.ID, "jb:stale:"+j.ID)
			}
		}

		// 4. Destinations (shared between jobs; report each once).
		for _, d := range j.Destinations {
			if th.DestFreeMinPct < 0 || d.ID == "" || seenDest[d.ID] || d.Disabled.truthy() || d.DiskUsage.Total <= 0 {
				continue
			}
			seenDest[d.ID] = true
			freePct := d.DiskUsage.Free / d.DiskUsage.Total * 100
			if freePct < th.DestFreeMinPct {
				findings = append(findings, Finding{
					Type: TypeDest, Severity: SevWarning, Adapter: "jetbackup",
					Key:     "jb:dest:" + d.ID,
					Message: fmt.Sprintf("JetBackup destination %q has %.1f%% free (%.0f GiB)", d.Name, freePct, d.DiskUsage.Free/(1<<30)),
				})
			}
		}
	}
	if enabledAccountJobs == 0 {
		findings = append(findings, Finding{
			Type: TypeNoJob, Severity: SevWarning, Adapter: "jetbackup",
			Key:     "jb:nojob",
			Message: fmt.Sprintf("JetBackup is installed but no account backup job is enabled (%d job(s) configured)", len(jobs)),
		})
	}
	return out, findings, unknown, nil
}

// jbPeriod is the gap a job's schedule leaves between runs: measured from its
// run starts when there are enough, else next_run-last_run when the job is not
// mid-run (a running job's last_run may be days old), else 8 days.
func jbPeriod(starts []time.Time, j jbJob) time.Duration {
	if len(starts) >= 3 {
		return runPeriod(starts)
	}
	if !j.Running.truthy() {
		if lr, ok := j.LastRun.parse(); ok {
			if nr, ok := j.NextRun.parse(); ok && nr.After(lr) {
				return clampDur(nr.Sub(lr), time.Hour, 31*24*time.Hour)
			}
		}
	}
	return 8 * 24 * time.Hour
}

func earliest(ts []time.Time) time.Time {
	e := ts[0]
	for _, t := range ts[1:] {
		if t.Before(e) {
			e = t
		}
	}
	return e
}

func laterEnd(end time.Time, than *jbLog) bool {
	t, ok := than.EndTime.parse()
	return !ok || end.After(t)
}

// jbResult maps JetBackup's LOG_STATUS_* (see the file comment).
func jbResult(status string) string {
	switch status {
	case "1":
		return "ok"
	case "4":
		return "partial"
	case "":
		return "unknown"
	}
	return "failed"
}

// jbStatusName words a failed run's status as JetBackup's UI does.
func jbStatusName(status string) string {
	switch status {
	case "2":
		return "FAILED"
	case "3":
		return "was ABORTED"
	case "5":
		return "NEVER FINISHED"
	}
	return "FAILED (status " + status + ")"
}

// runPeriod is the LONG gap between a job's run starts — the 90th percentile,
// so a Mon–Fri job's Friday→Monday gap counts and a one-off missed day does
// not — clamped to [1h, 31d]; 24h with fewer than two runs.
func runPeriod(starts []time.Time) time.Duration {
	if len(starts) < 2 {
		return 24 * time.Hour
	}
	sorted := append([]time.Time(nil), starts...)
	sort.Slice(sorted, func(a, b int) bool { return sorted[a].Before(sorted[b]) })
	gaps := make([]time.Duration, 0, len(sorted)-1)
	for i := 1; i < len(sorted); i++ {
		if g := sorted[i].Sub(sorted[i-1]); g > 0 {
			gaps = append(gaps, g)
		}
	}
	if len(gaps) == 0 {
		return 24 * time.Hour
	}
	sort.Slice(gaps, func(a, b int) bool { return gaps[a] < gaps[b] })
	i := (len(gaps)*9+9)/10 - 1 // nearest-rank p90
	if i < 0 {
		i = 0
	}
	return clampDur(gaps[i], time.Hour, 31*24*time.Hour)
}

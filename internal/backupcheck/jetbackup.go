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
//   - a log's `status` is 1 for a completed run and 2 for a partial one; a
//     failed run read 4 on orion (the "Backup Failed" runs of 19–21 Sep 2026).
//     Anything but 1/2 is treated as failed and the raw status is reported.
//   - `type` 1 is a backup-job run; other types (8 = plugin scans, …) are
//     ignored. A run's `info.ID` is the job's `_id`.
//   - `last_completed` advances on FAILED runs too — see the package doc.
const (
	jetbackupCLI = "jetbackup5api"
	// jetbackupLogLimit bounds the history read. 300 runs is ~6 weeks for a
	// daily job plus the daily config job and plugin runs on a busy node.
	jetbackupLogLimit = 300
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
	jobs, findings, err := evalJetBackup(jobsOut, logsOut, now, th)
	st.Jobs = jobs
	st.Findings = findings
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
func evalJetBackup(jobsRaw, logsRaw []byte, now time.Time, th Thresholds) ([]Job, []Finding, error) {
	th = th.withDefaults()
	var jobs []jbJob
	if err := decodeJB(jobsRaw, "jobs", &jobs); err != nil {
		return nil, nil, fmt.Errorf("listBackupJobs %w", err)
	}
	var logs []jbLog
	if err := decodeJB(logsRaw, "logs", &logs); err != nil {
		return nil, nil, fmt.Errorf("listLogs %w", err)
	}

	// Newest finished run and newest SUCCESSFUL run per job. logs arrive newest
	// first; don't rely on it.
	type runs struct {
		latest, success *jbLog
		starts          []time.Time
	}
	byJob := map[string]*runs{}
	oldestRead := now
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
			if t.Before(oldestRead) {
				oldestRead = t
			}
			r.starts = append(r.starts, t)
		}
		end, ok := l.EndTime.parse()
		if !ok {
			continue // still running; the job's running flag covers it
		}
		if r.latest == nil || laterEnd(end, r.latest) {
			r.latest = l
		}
		if s := string(l.Status); (s == "1" || s == "2") && (r.success == nil || laterEnd(end, r.success)) {
			r.success = l
		}
	}

	var out []Job
	var findings []Finding
	seenDest := map[string]bool{}
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
		label := fmt.Sprintf("JetBackup job %q", j.Name)

		// 1. The latest finished run.
		if r != nil && r.latest != nil {
			end, _ := r.latest.EndTime.parse()
			switch job.LastResult {
			case "failed":
				findings = append(findings, Finding{
					Type: TypeFailed, Severity: SevCritical, Adapter: "jetbackup",
					Key:     "jb:run:" + r.latest.ID,
					Message: fmt.Sprintf("%s: last run FAILED (status %s, ended %s)", label, r.latest.Status, end.UTC().Format(time.RFC3339)),
				})
			case "partial":
				findings = append(findings, Finding{
					Type: TypePartial, Severity: SevWarning, Adapter: "jetbackup",
					Key:     "jb:run:" + r.latest.ID,
					Message: fmt.Sprintf("%s: last run only PARTIALLY completed (ended %s)", label, end.UTC().Format(time.RFC3339)),
				})
			}
		}

		// 2. Stuck: still running long after it started.
		if job.Running {
			if started, ok := j.LastRun.parse(); ok && now.Sub(started) > th.StuckAfter {
				findings = append(findings, Finding{
					Type: TypeStuck, Severity: SevCritical, Adapter: "jetbackup",
					Key:     "jb:stuck:" + j.ID,
					Message: fmt.Sprintf("%s: running for %s (started %s) — likely stuck on an account", label, ago(now.Sub(started)), started.UTC().Format(time.RFC3339)),
				})
			}
		}

		// 3. Stale: no SUCCESSFUL run within the job's own period. The period
		// comes from how often the job actually STARTED, not next_run-last_run:
		// a run stuck for 16 days pins last_run, which made a daily job look
		// like a 17-day one and hid exactly the case this check exists for.
		var starts []time.Time
		if r != nil {
			starts = r.starts
		}
		period := runPeriod(starts)
		limit := time.Duration(float64(period)*th.StaleFactor) + th.StaleGrace
		switch {
		case job.LastSuccess != nil:
			if age := now.Sub(*job.LastSuccess); age > limit {
				findings = append(findings, Finding{
					Type: TypeStale, Severity: SevCritical, Adapter: "jetbackup",
					Key:     "jb:stale:" + j.ID,
					Message: fmt.Sprintf("%s: no successful backup for %s (last success %s)", label, ago(age), job.LastSuccess.UTC().Format(time.RFC3339)),
				})
			}
		case now.Sub(oldestRead) > limit:
			// The history we read reaches back further than the limit and holds
			// no success: that IS stale. (If the history is shorter — a new
			// node, a pruned log — we cannot tell, and say nothing.)
			if _, ran := j.LastRun.parse(); ran {
				findings = append(findings, Finding{
					Type: TypeStale, Severity: SevCritical, Adapter: "jetbackup",
					Key:     "jb:stale:" + j.ID,
					Message: fmt.Sprintf("%s: no successful backup in the last %s of run history", label, ago(now.Sub(oldestRead))),
				})
			}
		}

		// 4. Destinations (shared between jobs; report each once).
		for _, d := range j.Destinations {
			if d.ID == "" || seenDest[d.ID] || d.Disabled.truthy() || d.DiskUsage.Total <= 0 {
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
	return out, findings, nil
}

func laterEnd(end time.Time, than *jbLog) bool {
	t, ok := than.EndTime.parse()
	return !ok || end.After(t)
}

func jbResult(status string) string {
	switch status {
	case "1":
		return "ok"
	case "2":
		return "partial"
	case "":
		return "unknown"
	}
	return "failed"
}

// runPeriod is the median gap between a job's run starts (default 24h with
// fewer than two runs), clamped to [1h, 31d].
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
	return clampDur(gaps[len(gaps)/2], time.Hour, 31*24*time.Hour)
}

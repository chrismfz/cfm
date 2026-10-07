package backupcheck

import (
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"
	"strconv"
	"strings"
	"time"
)

// Virtualmin scheduled backups. Two reads:
//   - `virtualmin list-scheduled-backups --json`  the schedules (enabled, running,
//     destination)
//   - `virtualmin list-backup-logs --json --start` the run history
//
// Observed on gde (Virtualmin 7, Oct 2026): every field is a one-element list
// under `values`; a run's `name` starts with its start time as a unix epoch
// ("1790730052-2221883-1") — used instead of the `started` text, which is in
// the server's local time and 12-hour format; `run_from` is "sched" for
// scheduled runs and "cgi" for a run started from the UI (a manual test run
// there failed on 2 Oct and is not a schedule's health). `final_status` is
// "OK" or "Failed"; `failed_domains` lists the domains that failed.
const (
	virtualminCLI     = "virtualmin"
	virtualminLogDays = 45
)

type vmRecord struct {
	Name   string              `json:"name"`
	Values map[string][]string `json:"values"`
}

func (r vmRecord) get(k string) string {
	if v := r.Values[k]; len(v) > 0 {
		return strings.TrimSpace(v[0])
	}
	return ""
}

type vmEnvelope struct {
	Status string     `json:"status"`
	Data   []vmRecord `json:"data"`
}

func decodeVM(raw []byte) ([]vmRecord, error) {
	var env vmEnvelope
	if err := json.Unmarshal(raw, &env); err != nil {
		return nil, fmt.Errorf("decode: %w", err)
	}
	if env.Status != "" && env.Status != "success" {
		return nil, fmt.Errorf("status %q", env.Status)
	}
	return env.Data, nil
}

// virtualminSchedDir holds one file per schedule (`<id>`, key=value lines,
// cron fields mins/hours/days/months/weekdays or `special`). A var so tests can
// point it elsewhere.
var virtualminSchedDir = "/etc/webmin/virtual-server/backups"

// schedulePeriods reads each schedule's own cron fields: a schedule with a
// single run in the history has no observed period, and gde's weekly push to
// rosso (one run so far) would otherwise be judged as daily.
func schedulePeriods(ids []string) map[string]time.Duration {
	out := map[string]time.Duration{}
	for _, id := range ids {
		if id == "" || strings.ContainsAny(id, "/.") {
			continue
		}
		b, err := os.ReadFile(filepath.Join(virtualminSchedDir, id))
		if err != nil {
			continue
		}
		kv := map[string]string{}
		for _, line := range strings.Split(string(b), "\n") {
			if k, v, ok := strings.Cut(line, "="); ok {
				kv[strings.TrimSpace(k)] = strings.TrimSpace(v)
			}
		}
		if p := cronPeriod(kv); p > 0 {
			out[id] = p
		}
	}
	return out
}

// cronPeriod approximates the longest gap between runs of a webmin cron
// schedule. Good enough for "is the last success too old?"; not a scheduler.
func cronPeriod(kv map[string]string) time.Duration {
	switch strings.ToLower(kv["special"]) {
	case "hourly":
		return time.Hour
	case "daily", "midnight":
		return 24 * time.Hour
	case "weekly":
		return 7 * 24 * time.Hour
	case "monthly":
		return 31 * 24 * time.Hour
	case "yearly", "annually":
		return 366 * 24 * time.Hour
	}
	count := func(field string) int { // entries in "1,3,5" / "1-5"; 0 for "*" or empty
		f := strings.TrimSpace(kv[field])
		if f == "" || f == "*" {
			return 0
		}
		n := 0
		for _, part := range strings.Split(f, ",") {
			if a, b, ok := strings.Cut(part, "-"); ok {
				x, e1 := strconv.Atoi(strings.TrimSpace(a))
				y, e2 := strconv.Atoi(strings.TrimSpace(b))
				if e1 == nil && e2 == nil && y >= x {
					n += y - x + 1
					continue
				}
			}
			n++
		}
		return n
	}
	if _, ok := kv["hours"]; !ok {
		return 0 // not a cron schedule we understand
	}
	if count("months") > 0 || count("days") > 0 {
		return 31 * 24 * time.Hour
	}
	if n := count("weekdays"); n > 0 && n < 7 {
		return 7 * 24 * time.Hour / time.Duration(n)
	}
	if n := count("hours"); n > 0 {
		return 24 * time.Hour / time.Duration(n)
	}
	return time.Hour
}

func checkVirtualmin(run cmdFunc, now time.Time, th Thresholds) AdapterStatus {
	st := AdapterStatus{Name: "virtualmin"}
	sched, err := run(virtualminCLI, "list-scheduled-backups", "--json")
	if err != nil {
		st.Error = "list-scheduled-backups: " + err.Error()
		return st
	}
	since := now.AddDate(0, 0, -virtualminLogDays).Format("2006-01-02")
	logs, err := run(virtualminCLI, "list-backup-logs", "--json", "--start", since)
	if err != nil {
		st.Error = "list-backup-logs: " + err.Error()
		return st
	}
	var ids []string
	if recs, err := decodeVM(sched); err == nil {
		for _, r := range recs {
			ids = append(ids, r.Name)
		}
	}
	st.Jobs, st.Findings, err = evalVirtualmin(sched, logs, schedulePeriods(ids), now, th)
	if err != nil {
		st.Error = err.Error()
	}
	return st
}

type vmRun struct {
	id     string
	start  time.Time
	ok     bool
	failed int // failed domains
}

// evalVirtualmin is the pure evaluation over the two virtualmin responses.
// periods are the schedules' configured intervals (schedulePeriods); a schedule
// missing from it is judged on its observed run gaps, never below a day.
func evalVirtualmin(schedRaw, logsRaw []byte, periods map[string]time.Duration, now time.Time, th Thresholds) ([]Job, []Finding, error) {
	th = th.withDefaults()
	scheds, err := decodeVM(schedRaw)
	if err != nil {
		return nil, nil, fmt.Errorf("list-scheduled-backups %w", err)
	}
	logs, err := decodeVM(logsRaw)
	if err != nil {
		return nil, nil, fmt.Errorf("list-backup-logs %w", err)
	}

	runs := map[string][]vmRun{}
	oldest := now
	for _, l := range logs {
		if l.get("run_from") != "sched" {
			continue
		}
		id := l.get("scheduled_backup_id")
		epoch, err := strconv.ParseInt(strings.SplitN(l.Name, "-", 2)[0], 10, 64)
		if id == "" || err != nil || epoch <= 0 {
			continue
		}
		start := time.Unix(epoch, 0)
		if start.Before(oldest) {
			oldest = start
		}
		runs[id] = append(runs[id], vmRun{
			id: l.Name, start: start,
			ok:     strings.EqualFold(l.get("final_status"), "OK"),
			failed: len(strings.Fields(l.get("failed_domains"))),
		})
	}

	var jobs []Job
	var findings []Finding
	for _, s := range scheds {
		id := s.Name
		enabled := !strings.EqualFold(s.get("enabled"), "No")
		running := strings.EqualFold(s.get("running"), "Yes")
		dest := s.get("destination")
		job := Job{Name: dest, ID: id, Disabled: !enabled, Running: running, Schedule: s.get("cron_schedule"), LastResult: "unknown"}

		rs := runs[id]
		var latest, success *vmRun
		var starts []time.Time
		for i := range rs {
			r := &rs[i]
			starts = append(starts, r.start)
			if latest == nil || r.start.After(latest.start) {
				latest = r
			}
			if r.ok && (success == nil || r.start.After(success.start)) {
				success = r
			}
		}
		if success != nil {
			t := success.start
			job.LastSuccess = &t
		}
		if latest != nil {
			switch {
			case !latest.ok:
				job.LastResult = "failed"
			case latest.failed > 0:
				job.LastResult = "partial"
			default:
				job.LastResult = "ok"
			}
		}
		jobs = append(jobs, job)
		if !enabled {
			continue
		}
		label := fmt.Sprintf("Virtualmin backup to %s", dest)

		if latest != nil {
			at := latest.start.UTC().Format(time.RFC3339)
			switch job.LastResult {
			case "failed":
				msg := fmt.Sprintf("%s: last scheduled run FAILED (started %s)", label, at)
				if latest.failed > 0 {
					msg += fmt.Sprintf(", %d domain(s) failed", latest.failed)
				}
				findings = append(findings, Finding{Type: TypeFailed, Severity: SevCritical, Adapter: "virtualmin", Key: "vm:run:" + latest.id, Message: msg})
			case "partial":
				findings = append(findings, Finding{Type: TypePartial, Severity: SevWarning, Adapter: "virtualmin", Key: "vm:run:" + latest.id,
					Message: fmt.Sprintf("%s: last scheduled run had %d failed domain(s) (started %s)", label, latest.failed, at)})
			}
		}

		if running && latest != nil && now.Sub(latest.start) > th.StuckAfter {
			findings = append(findings, Finding{Type: TypeStuck, Severity: SevCritical, Adapter: "virtualmin", Key: "vm:stuck:" + id,
				Message: fmt.Sprintf("%s: still running %s after its last start", label, ago(now.Sub(latest.start)))})
		}

		// The configured schedule decides the period. Without it, observed run
		// gaps do, floored at a day: a test run minutes after a real one must
		// not make a weekly job look hourly.
		period, ok := periods[id]
		if !ok {
			period = runPeriod(starts)
			if period < 24*time.Hour {
				period = 24 * time.Hour
			}
		}
		limit := time.Duration(float64(period)*th.StaleFactor) + th.StaleGrace
		switch {
		case success != nil:
			if age := now.Sub(success.start); age > limit {
				findings = append(findings, Finding{Type: TypeStale, Severity: SevCritical, Adapter: "virtualmin", Key: "vm:stale:" + id,
					Message: fmt.Sprintf("%s: no successful backup for %s (last success started %s)", label, ago(age), success.start.UTC().Format(time.RFC3339))})
			}
		case len(rs) == 0:
			// Enabled, yet not one scheduled run in the whole window we read: the
			// schedule has stopped firing (or never did).
			findings = append(findings, Finding{Type: TypeStale, Severity: SevCritical, Adapter: "virtualmin", Key: "vm:stale:" + id,
				Message: fmt.Sprintf("%s: enabled but no scheduled run in the last %d days", label, virtualminLogDays)})
		case now.Sub(oldest) > limit:
			findings = append(findings, Finding{Type: TypeStale, Severity: SevCritical, Adapter: "virtualmin", Key: "vm:stale:" + id,
				Message: fmt.Sprintf("%s: no successful scheduled run in the last %s of history", label, ago(now.Sub(oldest)))})
		}
	}
	return jobs, findings, nil
}

package backupcheck

import (
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"
	"sort"
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

// vmSchedInfo is what a schedule's own file says: how long its schedule
// leaves between runs, and since when the file has existed in its current
// form (its mtime — a new or just-edited schedule is not judged early).
type vmSchedInfo struct {
	period time.Duration
	since  time.Time
}

// scheduleInfo reads each schedule's own cron fields: a schedule with a
// single run in the history has no observed period, and gde's weekly push to
// rosso (one run so far) would otherwise be judged as daily.
func scheduleInfo(ids []string) map[string]vmSchedInfo {
	out := map[string]vmSchedInfo{}
	for _, id := range ids {
		if id == "" || strings.ContainsAny(id, "/.") {
			continue
		}
		path := filepath.Join(virtualminSchedDir, id)
		b, err := os.ReadFile(path)
		if err != nil {
			continue
		}
		info := vmSchedInfo{}
		if fi, err := os.Stat(path); err == nil {
			info.since = fi.ModTime()
		}
		kv := map[string]string{}
		for _, line := range strings.Split(string(b), "\n") {
			if k, v, ok := strings.Cut(line, "="); ok {
				kv[strings.TrimSpace(k)] = strings.TrimSpace(v)
			}
		}
		info.period = cronPeriod(kv)
		out[id] = info
	}
	return out
}

// cronPeriod is the LONGEST gap between runs of a webmin cron schedule (a
// Mon–Fri job's Friday→Monday, a 01–05 h job's 05→01), which is what "is the
// last success too old?" must allow for. 0 when the schedule is not one it
// understands. Good enough for staleness; not a scheduler.
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
	if _, ok := kv["hours"]; !ok {
		return 0
	}
	months, days := cronSet(kv["months"], 1, 12), cronSet(kv["days"], 1, 31)
	if len(months) == 12 {
		months = nil
	}
	if len(days) == 31 {
		days = nil
	}
	if months != nil {
		return 31 * 24 * time.Hour
	}
	if days != nil {
		// "every other day" (odd days, */2) is a 2-day gap, not a month; the
		// month end adds at most a day (31 → 1).
		return time.Duration(maxCircularGap(days, 31)+1) * 24 * time.Hour
	}
	if wd := cronSet(kv["weekdays"], 0, 6); wd != nil {
		if len(wd) == 7 {
			wd = nil // every day
		} else {
			return time.Duration(maxCircularGap(wd, 7)) * 24 * time.Hour
		}
	}
	if hs := cronSet(kv["hours"], 0, 23); hs != nil {
		return time.Duration(maxCircularGap(hs, 24)) * time.Hour
	}
	return time.Hour
}

// cronSet expands "1,3,5" / "1-5" / "*/2" into the sorted values within
// [lo,hi]; nil for "*", empty or unparsable (= every value).
func cronSet(field string, lo, hi int) []int {
	f := strings.TrimSpace(field)
	if f == "" || f == "*" {
		return nil
	}
	seen := map[int]bool{}
	for _, part := range strings.Split(f, ",") {
		part = strings.TrimSpace(part)
		step := 1
		if base, st, ok := strings.Cut(part, "/"); ok {
			n, err := strconv.Atoi(st)
			if err != nil || n <= 0 {
				return nil
			}
			step, part = n, base
		}
		a, b := lo, hi
		switch {
		case part == "*":
		case strings.Contains(part, "-"):
			x, y, _ := strings.Cut(part, "-")
			var e1, e2 error
			a, e1 = strconv.Atoi(x)
			b, e2 = strconv.Atoi(y)
			if e1 != nil || e2 != nil {
				return nil
			}
		default:
			n, err := strconv.Atoi(part)
			if err != nil {
				return nil
			}
			a, b = n, n
		}
		for v := a; v <= b; v += step {
			x := v
			if hi == 6 && x == 7 {
				x = 0 // cron allows Sunday as 7
			}
			if x >= lo && x <= hi {
				seen[x] = true
			}
		}
	}
	if len(seen) == 0 {
		return nil
	}
	out := make([]int, 0, len(seen))
	for v := range seen {
		out = append(out, v)
	}
	sort.Ints(out)
	return out
}

// maxCircularGap is the largest distance between consecutive values of a
// sorted set on a ring of size n (e.g. weekdays on 7, hours on 24).
func maxCircularGap(vals []int, n int) int {
	if len(vals) == 0 {
		return n
	}
	gap := vals[0] + n - vals[len(vals)-1]
	for i := 1; i < len(vals); i++ {
		if g := vals[i] - vals[i-1]; g > gap {
			gap = g
		}
	}
	return gap
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
	st.Jobs, st.Findings, err = evalVirtualmin(sched, logs, scheduleInfo(ids), now, th)
	if err != nil {
		st.Error = err.Error()
	}
	return st
}

type vmRun struct {
	id       string
	start    time.Time
	ok       bool
	finished bool // an empty final_status is a run still in progress
	failed   int  // failed domains
}

// evalVirtualmin is the pure evaluation over the two virtualmin responses.
// info is each schedule's own file (scheduleInfo); a schedule missing from it
// is judged on its observed run gaps, never below a day.
func evalVirtualmin(schedRaw, logsRaw []byte, info map[string]vmSchedInfo, now time.Time, th Thresholds) ([]Job, []Finding, error) {
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
		status := l.get("final_status")
		runs[id] = append(runs[id], vmRun{
			id: l.Name, start: start,
			ok:       strings.EqualFold(status, "OK"),
			finished: status != "",
			failed:   len(strings.Fields(l.get("failed_domains"))),
		})
	}

	var jobs []Job
	var findings []Finding
	enabledScheds := 0
	for _, s := range scheds {
		id := s.Name
		enabled := !strings.EqualFold(s.get("enabled"), "No")
		running := strings.EqualFold(s.get("running"), "Yes")
		dest := redactURL(s.get("destination"))
		job := Job{Name: dest, ID: id, Disabled: !enabled, Running: running, Schedule: s.get("cron_schedule"), LastResult: "unknown"}

		rs := runs[id]
		var latest, success, inProgress *vmRun
		var starts []time.Time
		for i := range rs {
			r := &rs[i]
			starts = append(starts, r.start)
			if !r.finished {
				if inProgress == nil || r.start.After(inProgress.start) {
					inProgress = r
				}
				continue
			}
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
		enabledScheds++
		label := fmt.Sprintf("Virtualmin backup to %s", dest)
		si, haveInfo := info[id]
		period := si.period
		if !haveInfo || period <= 0 {
			// The configured schedule decides the period. Without it, observed
			// run gaps do, floored at a day: a test run minutes after a real one
			// must not make a weekly job look hourly.
			period = runPeriod(starts)
			if period < 24*time.Hour {
				period = 24 * time.Hour
			}
		}
		limit := time.Duration(float64(period)*th.StaleFactor) + th.StaleGrace

		if latest != nil {
			at := latest.start.UTC().Format(time.RFC3339)
			switch job.LastResult {
			case "failed":
				msg := fmt.Sprintf("%s: last scheduled run FAILED (started %s)", label, at)
				if latest.failed > 0 {
					msg += fmt.Sprintf(", %d domain(s) failed", latest.failed)
				}
				findings = append(findings, Finding{Type: TypeFailed, Severity: SevCritical, Adapter: "virtualmin", Key: "vm:failed:" + id, Message: msg})
			case "partial":
				findings = append(findings, Finding{Type: TypePartial, Severity: SevWarning, Adapter: "virtualmin", Key: "vm:partial:" + id,
					Message: fmt.Sprintf("%s: last scheduled run had %d failed domain(s) (started %s)", label, latest.failed, at)})
			}
		}

		// Stuck: a logged run still in progress for too long. Without a logged
		// in-progress record, "running" alone says nothing about since when —
		// only a schedule overdue by a whole period AND the stuck limit is.
		if running {
			switch {
			case inProgress != nil && now.Sub(inProgress.start) > th.StuckAfter:
				findings = append(findings, Finding{Type: TypeStuck, Severity: SevCritical, Adapter: "virtualmin", Key: "vm:stuck:" + id,
					Message: fmt.Sprintf("%s: running for %s (started %s)", label, Ago(now.Sub(inProgress.start)), inProgress.start.UTC().Format(time.RFC3339))})
			case inProgress == nil && len(starts) > 0 && now.Sub(latestStart(starts)) > period+th.StuckAfter:
				findings = append(findings, Finding{Type: TypeStuck, Severity: SevCritical, Adapter: "virtualmin", Key: "vm:stuck:" + id,
					Message: fmt.Sprintf("%s: shown as running, but no scheduled run has started for %s", label, Ago(now.Sub(latestStart(starts))))})
			}
		}

		window := time.Duration(virtualminLogDays) * 24 * time.Hour
		switch {
		case success != nil:
			if age := now.Sub(success.start); age > limit {
				findings = append(findings, Finding{Type: TypeStale, Severity: SevCritical, Adapter: "virtualmin", Key: "vm:stale:" + id,
					Message: fmt.Sprintf("%s: no successful backup for %s (last success started %s)", label, Ago(age), success.start.UTC().Format(time.RFC3339))})
			}
		case limit >= window:
			// A schedule rarer than the history we read (yearly): no verdict.
		case len(starts) > 0:
			if first := earliest(starts); now.Sub(first) > limit {
				findings = append(findings, Finding{Type: TypeStale, Severity: SevCritical, Adapter: "virtualmin", Key: "vm:stale:" + id,
					Message: fmt.Sprintf("%s: no successful scheduled run since at least %s", label, first.UTC().Format(time.RFC3339))})
			}
		default:
			// Enabled yet never ran in the window: the schedule stopped firing —
			// but only once it has existed (unchanged) longer than its limit.
			if !si.since.IsZero() && now.Sub(si.since) > limit {
				findings = append(findings, Finding{Type: TypeStale, Severity: SevCritical, Adapter: "virtualmin", Key: "vm:stale:" + id,
					Message: fmt.Sprintf("%s: enabled but no scheduled run in the last %d days", label, virtualminLogDays)})
			}
		}
	}
	if enabledScheds == 0 {
		findings = append(findings, Finding{Type: TypeNoJob, Severity: SevWarning, Adapter: "virtualmin", Key: "vm:nojob",
			Message: fmt.Sprintf("Virtualmin is installed but no scheduled backup is enabled (%d configured)", len(scheds))})
	}
	return jobs, findings, nil
}

func latestStart(ts []time.Time) time.Time {
	l := ts[0]
	for _, t := range ts[1:] {
		if t.After(l) {
			l = t
		}
	}
	return l
}

// redactURL drops the credentials from a destination such as
// "ssh://user:pass@host:/path" or "s3://key:secret@bucket/": the destination
// labels a finding, and findings travel to detection_history and chat.
// Everything between "://" and the last "@" before the path is replaced by the
// part before its first ":" (the user name).
func redactURL(u string) string {
	i := strings.Index(u, "://")
	if i < 0 {
		return u
	}
	rest := u[i+3:]
	at := strings.LastIndex(rest, "@")
	if at < 0 {
		return u
	}
	user := rest[:at]
	if c := strings.IndexByte(user, ':'); c >= 0 {
		user = user[:c] + ":***"
	}
	return u[:i+3] + user + rest[at:]
}

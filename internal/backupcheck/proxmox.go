package backupcheck

import (
	"encoding/json"
	"fmt"
	"sort"
	"strings"
	"time"
)

// Proxmox VE vzdump, read through `pvesh` on the node itself. Four reads:
//   - /cluster/backup                    the backup jobs (schedule, storage, guests)
//   - /cluster/backup-info/not-backed-up guests no job includes
//   - /nodes/<node>/tasks vzdump         this node's vzdump runs (--source all
//     includes the running ones)
//   - /nodes/<node>/storage              whether each backup storage is online
//
// A finished task's status is "OK", "job errors" (some guests failed — vega
// ran three of those in Sep–Oct 2026) or an error text such as "could not
// activate storage 'geros': storage 'geros' is not online".
const (
	pveshCLI       = "pvesh"
	pveTaskLimit   = 50
	pveListMembers = 15 // names in an uncovered message before "…and N more"
)

type pveJob struct {
	ID       string `json:"id"`
	Enabled  jbFlex `json:"enabled"`
	Schedule string `json:"schedule"`
	Storage  string `json:"storage"`
	Node     string `json:"node"`
	Comment  string `json:"comment"`
}

type pveGuest struct {
	Name string `json:"name"`
	Type string `json:"type"`
	VMID jbFlex `json:"vmid"`
}

type pveTask struct {
	UPID      string `json:"upid"`
	Status    string `json:"status"`
	StartTime int64  `json:"starttime"`
	EndTime   int64  `json:"endtime"`
}

type pveStorage struct {
	Storage      string  `json:"storage"`
	Active       jbFlex  `json:"active"`
	Enabled      jbFlex  `json:"enabled"`
	UsedFraction float64 `json:"used_fraction"`
	Avail        float64 `json:"avail"`
}

func checkProxmox(run cmdFunc, node string, now time.Time, th Thresholds) AdapterStatus {
	st := AdapterStatus{Name: "proxmox"}
	if node == "" {
		st.Error = "unknown Proxmox node name"
		return st
	}
	get := func(path string, extra ...string) ([]byte, error) {
		args := append([]string{"get", path}, extra...)
		args = append(args, "--output-format", "json")
		return run(pveshCLI, args...)
	}
	jobs, err := get("/cluster/backup")
	if err != nil {
		st.Error = "/cluster/backup: " + err.Error()
		return st
	}
	uncovered, err := get("/cluster/backup-info/not-backed-up")
	if err != nil {
		st.Error = "/cluster/backup-info/not-backed-up: " + err.Error()
		return st
	}
	tasks, err := get("/nodes/"+node+"/tasks", "--typefilter", "vzdump", "--source", "all", "--limit", fmt.Sprint(pveTaskLimit))
	if err != nil {
		st.Error = "tasks: " + err.Error()
		return st
	}
	storage, err := get("/nodes/" + node + "/storage")
	if err != nil {
		st.Error = "storage: " + err.Error()
		return st
	}
	st.Jobs, st.Findings, err = evalProxmox(node, jobs, uncovered, tasks, storage, now, th)
	if err != nil {
		st.Error = err.Error()
	}
	return st
}

// evalProxmox is the pure evaluation over the four pvesh responses.
func evalProxmox(node string, jobsRaw, uncoveredRaw, tasksRaw, storageRaw []byte, now time.Time, th Thresholds) ([]Job, []Finding, error) {
	th = th.withDefaults()
	var jobs []pveJob
	if err := json.Unmarshal(jobsRaw, &jobs); err != nil {
		return nil, nil, fmt.Errorf("decode /cluster/backup: %w", err)
	}
	var uncovered []pveGuest
	if err := json.Unmarshal(uncoveredRaw, &uncovered); err != nil {
		return nil, nil, fmt.Errorf("decode not-backed-up: %w", err)
	}
	var tasks []pveTask
	if err := json.Unmarshal(tasksRaw, &tasks); err != nil {
		return nil, nil, fmt.Errorf("decode tasks: %w", err)
	}
	var storages []pveStorage
	if err := json.Unmarshal(storageRaw, &storages); err != nil {
		return nil, nil, fmt.Errorf("decode storage: %w", err)
	}

	// Jobs that run on this node: enabled (absent = enabled) and either
	// node-less (every node) or pinned here.
	var out []Job
	active := 0
	wantStorage := map[string]bool{}
	for _, j := range jobs {
		enabled := string(j.Enabled) == "" || j.Enabled.truthy()
		name := j.ID
		if c := strings.TrimSpace(j.Comment); c != "" {
			name = c + " (" + j.ID + ")"
		}
		out = append(out, Job{Name: name, ID: j.ID, Disabled: !enabled, Schedule: j.Schedule})
		if !enabled || (j.Node != "" && j.Node != node) {
			continue
		}
		active++
		if j.Storage != "" {
			wantStorage[j.Storage] = true
		}
	}

	var findings []Finding

	// Runs, newest first by end (running ones last).
	sort.SliceStable(tasks, func(a, b int) bool { return tasks[a].EndTime > tasks[b].EndTime })
	var latest, lastSuccess *pveTask
	oldest := now
	for i := range tasks {
		t := &tasks[i]
		if st := time.Unix(t.StartTime, 0); t.StartTime > 0 && st.Before(oldest) {
			oldest = st
		}
		if t.EndTime == 0 {
			// still running
			if started := time.Unix(t.StartTime, 0); t.StartTime > 0 && now.Sub(started) > th.StuckAfter {
				findings = append(findings, Finding{
					Type: TypeStuck, Severity: SevCritical, Adapter: "proxmox",
					Key:     "pve:stuck:" + t.UPID,
					Message: fmt.Sprintf("vzdump on %s running for %s (started %s)", node, ago(now.Sub(started)), started.UTC().Format(time.RFC3339)),
				})
			}
			continue
		}
		if latest == nil {
			latest = t
		}
		if lastSuccess == nil && (t.Status == "OK" || t.Status == "job errors") {
			lastSuccess = t
		}
	}

	if latest != nil {
		end := time.Unix(latest.EndTime, 0).UTC().Format(time.RFC3339)
		switch latest.Status {
		case "OK":
		case "job errors":
			findings = append(findings, Finding{
				Type: TypePartial, Severity: SevWarning, Adapter: "proxmox",
				Key:     "pve:task:" + latest.UPID,
				Message: fmt.Sprintf("vzdump on %s finished with job errors (some guests failed; ended %s) — see the task log", node, end),
			})
		default:
			findings = append(findings, Finding{
				Type: TypeFailed, Severity: SevCritical, Adapter: "proxmox",
				Key:     "pve:task:" + latest.UPID,
				Message: fmt.Sprintf("vzdump on %s FAILED: %s (ended %s)", node, strings.TrimSpace(latest.Status), end),
			})
		}
	}

	if active > 0 {
		switch {
		case lastSuccess != nil:
			at := time.Unix(lastSuccess.EndTime, 0)
			if age := now.Sub(at); age > th.ProxmoxStaleAfter {
				findings = append(findings, Finding{
					Type: TypeStale, Severity: SevCritical, Adapter: "proxmox",
					Key:     "pve:stale:" + node,
					Message: fmt.Sprintf("no successful vzdump on %s for %s (last %s)", node, ago(age), at.UTC().Format(time.RFC3339)),
				})
			}
		case len(tasks) == 0 || now.Sub(oldest) > th.ProxmoxStaleAfter:
			findings = append(findings, Finding{
				Type: TypeStale, Severity: SevCritical, Adapter: "proxmox",
				Key:     "pve:stale:" + node,
				Message: fmt.Sprintf("%d backup job(s) apply to %s but no successful vzdump task is on record", active, node),
			})
		}
	}

	if len(uncovered) > 0 {
		sort.SliceStable(uncovered, func(a, b int) bool { return string(uncovered[a].VMID) < string(uncovered[b].VMID) })
		members := make([]string, 0, len(uncovered))
		names := make([]string, 0, pveListMembers)
		for i, g := range uncovered {
			members = append(members, string(g.VMID))
			if i < pveListMembers {
				names = append(names, fmt.Sprintf("%s (%s)", g.Name, g.VMID))
			}
		}
		msg := fmt.Sprintf("%d guest(s) in no backup job: %s", len(uncovered), strings.Join(names, ", "))
		if len(uncovered) > pveListMembers {
			msg += fmt.Sprintf(" …and %d more", len(uncovered)-pveListMembers)
		}
		findings = append(findings, Finding{
			Type: TypeUncovered, Severity: SevWarning, Adapter: "proxmox",
			Key: "pve:uncovered", Message: msg, Members: members,
		})
	}

	for _, s := range storages {
		if !wantStorage[s.Storage] {
			continue
		}
		if string(s.Enabled) != "" && !s.Enabled.truthy() {
			continue
		}
		if !s.Active.truthy() {
			findings = append(findings, Finding{
				Type: TypeDest, Severity: SevCritical, Adapter: "proxmox",
				Key:     "pve:dest:" + s.Storage,
				Message: fmt.Sprintf("backup storage %q is offline on %s", s.Storage, node),
			})
			continue
		}
		if free := (1 - s.UsedFraction) * 100; s.UsedFraction > 0 && free < th.DestFreeMinPct {
			findings = append(findings, Finding{
				Type: TypeDest, Severity: SevWarning, Adapter: "proxmox",
				Key:     "pve:dest:" + s.Storage,
				Message: fmt.Sprintf("backup storage %q has %.1f%% free (%.0f GiB)", s.Storage, free, s.Avail/(1<<30)),
			})
		}
	}
	return out, findings, nil
}

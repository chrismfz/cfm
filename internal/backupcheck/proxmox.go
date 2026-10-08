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
	// Which node hosts each guest, so a cluster reports an uncovered guest
	// once (from its own node). Best effort: without it every node reports.
	resources, rerr := get("/cluster/resources", "--type", "vm")
	if rerr != nil {
		resources = nil // evalProxmox: uncovered guests unknown this time
	}
	st.Jobs, st.Findings, st.Unknown, err = evalProxmox(node, jobs, uncovered, tasks, storage, resources, now, th)
	if err != nil {
		st.Error = err.Error()
	}
	// A shared storage (NFS, PBS) is the same for every node: one node reports
	// it, not all of them. Best effort: without the cluster status every node does.
	if cs, cerr := get("/cluster/status"); cerr == nil {
		st.Findings, st.Unknown = dropSharedDestElsewhere(node, storage, cs, st.Findings, st.Unknown)
	}
	return st
}

// dropSharedDestElsewhere keeps a shared storage's finding only on the
// reporting node: the lexically first ONLINE node of the cluster. On the
// others the finding is dropped but its key kept armed (unknown), so an alert
// this node raised before still closes only when the storage is fine again.
func dropSharedDestElsewhere(node string, storageRaw, statusRaw []byte, fs []Finding, unknown []string) ([]Finding, []string) {
	var storages []struct {
		Storage string `json:"storage"`
		Shared  jbFlex `json:"shared"`
	}
	var status []struct {
		Type   string `json:"type"`
		Name   string `json:"name"`
		Online jbFlex `json:"online"`
	}
	if json.Unmarshal(storageRaw, &storages) != nil || json.Unmarshal(statusRaw, &status) != nil {
		return fs, unknown
	}
	reporter := ""
	for _, n := range status {
		if n.Type == "node" && n.Online.truthy() && (reporter == "" || n.Name < reporter) {
			reporter = n.Name
		}
	}
	if reporter == "" || reporter == node {
		return fs, unknown
	}
	shared := map[string]bool{}
	for _, s := range storages {
		if s.Shared.truthy() {
			shared["pve:dest:"+s.Storage] = true
		}
	}
	out := fs[:0]
	for _, f := range fs {
		if shared[f.Key] {
			unknown = append(unknown, f.Key)
			continue
		}
		out = append(out, f)
	}
	return out, unknown
}

// evalProxmox is the pure evaluation over the four pvesh responses.
//
// Limits, by design: runs are judged per NODE, not per job — vzdump task ids
// carry no job id, so a broken weekly job can hide behind a healthy daily one
// on the same node (its guests still show as failed in `job errors` runs).
//
// resourcesRaw (/cluster/resources) says which node hosts each guest; nil
// means it could not be read, and the uncovered finding is then reported as
// unknown rather than widened to every guest of the cluster on every node.
func evalProxmox(node string, jobsRaw, uncoveredRaw, tasksRaw, storageRaw, resourcesRaw []byte, now time.Time, th Thresholds) ([]Job, []Finding, []string, error) {
	th = th.withDefaults()
	var jobs []pveJob
	if err := json.Unmarshal(jobsRaw, &jobs); err != nil {
		return nil, nil, nil, fmt.Errorf("decode /cluster/backup: %w", err)
	}
	var uncovered []pveGuest
	if err := json.Unmarshal(uncoveredRaw, &uncovered); err != nil {
		return nil, nil, nil, fmt.Errorf("decode not-backed-up: %w", err)
	}
	var tasks []pveTask
	if err := json.Unmarshal(tasksRaw, &tasks); err != nil {
		return nil, nil, nil, fmt.Errorf("decode tasks: %w", err)
	}
	var storages []pveStorage
	if err := json.Unmarshal(storageRaw, &storages); err != nil {
		return nil, nil, nil, fmt.Errorf("decode storage: %w", err)
	}
	var resources []struct {
		VMID jbFlex `json:"vmid"`
		Node string `json:"node"`
	}
	var unknown []string
	hostOf := map[string]string{}
	if resourcesRaw == nil || json.Unmarshal(resourcesRaw, &resources) != nil {
		unknown = append(unknown, "pve:uncovered")
		uncovered = nil
	} else {
		for _, r := range resources {
			hostOf[string(r.VMID)] = r.Node
		}
	}
	if len(hostOf) > 0 {
		mine := uncovered[:0]
		for _, g := range uncovered {
			if n, ok := hostOf[string(g.VMID)]; !ok || n == node {
				mine = append(mine, g)
			}
		}
		uncovered = mine
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

	// Guests live here but no enabled job runs here: nothing backs them up.
	// (A node hosting no guest needs no job; without the resource list it is
	// not judged.)
	if active == 0 {
		hosted := 0
		for _, n := range hostOf {
			if n == node {
				hosted++
			}
		}
		if hosted > 0 {
			findings = append(findings, Finding{
				Type: TypeNoJob, Severity: SevWarning, Adapter: "proxmox",
				Key:     "pve:nojob:" + node,
				Message: fmt.Sprintf("no enabled vzdump job runs on %s, which hosts %d guest(s)", node, hosted),
			})
		}
	}

	// Runs, newest first by end (running ones last).
	sort.SliceStable(tasks, func(a, b int) bool { return tasks[a].EndTime > tasks[b].EndTime })
	var latest, lastSuccess *pveTask
	var finished []*pveTask
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
					Message: fmt.Sprintf("vzdump on %s running for %s (started %s)", node, Ago(now.Sub(started)), started.UTC().Format(time.RFC3339)),
				})
			}
			continue
		}
		finished = append(finished, t)
		if latest == nil {
			latest = t
		}
		// Only a clean run is fresh: "job errors" is also what a run where
		// every guest failed reports, so a node that ends that way night after
		// night must still go stale.
		if lastSuccess == nil && pveClean(t.Status) {
			lastSuccess = t
		}
	}

	if latest != nil {
		end := time.Unix(latest.EndTime, 0).UTC().Format(time.RFC3339)
		switch {
		case pveClean(latest.Status):
		case latest.Status == "job errors":
			// "job errors" is also what a run where EVERY guest failed reports;
			// the task list cannot tell the two apart. Three in a row is treated
			// as a failure, not a partial.
			streak := 0
			for _, t := range finished {
				if t.Status != "job errors" {
					break
				}
				streak++
			}
			if streak >= 3 {
				findings = append(findings, Finding{
					Type: TypeFailed, Severity: SevCritical, Adapter: "proxmox",
					Key:     "pve:failed:" + node,
					Message: fmt.Sprintf("vzdump on %s: the last %d runs all finished with job errors (ended %s) — check which guests fail", node, streak, end),
				})
				break
			}
			findings = append(findings, Finding{
				Type: TypePartial, Severity: SevInfo, Adapter: "proxmox",
				Key:     "pve:partial:" + node,
				Message: fmt.Sprintf("vzdump on %s finished with job errors (some guests failed; ended %s) — see the task log", node, end),
			})
		default:
			findings = append(findings, Finding{
				Type: TypeFailed, Severity: SevCritical, Adapter: "proxmox",
				Key:     "pve:failed:" + node,
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
					Message: fmt.Sprintf("no clean vzdump on %s for %s (last OK run %s; later runs failed or ended with job errors)", node, Ago(age), at.UTC().Format(time.RFC3339)),
				})
			}
		case len(tasks) > 0 && now.Sub(oldest) > th.ProxmoxStaleAfter:
			// Tasks on record reaching back past the limit, none successful.
			// (No task at all says nothing: a new node, or one whose guests all
			// live elsewhere, runs no vzdump.)
			findings = append(findings, Finding{
				Type: TypeStale, Severity: SevCritical, Adapter: "proxmox",
				Key:     "pve:stale:" + node,
				Message: fmt.Sprintf("no successful vzdump on %s in the last %s of task history", node, Ago(now.Sub(oldest))),
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
		if free := (1 - s.UsedFraction) * 100; th.DestFreeMinPct >= 0 && s.UsedFraction > 0 && free < th.DestFreeMinPct {
			findings = append(findings, Finding{
				Type: TypeDest, Severity: SevWarning, Adapter: "proxmox",
				Key:     "pve:dest:" + s.Storage,
				Message: fmt.Sprintf("backup storage %q has %.1f%% free (%.0f GiB)", s.Storage, free, s.Avail/(1<<30)),
			})
		}
	}
	return out, findings, unknown, nil
}

// pveClean: the run succeeded. "WARNINGS: <n>" is a SUCCESSFUL task that logged
// warnings (PVE 7+); "job errors" is not (some or all guests failed).
func pveClean(status string) bool {
	return status == "OK" || strings.HasPrefix(status, "WARNINGS")
}

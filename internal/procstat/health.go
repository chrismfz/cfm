package procstat

import (
	"errors"
	"os"
	"path/filepath"
	"sort"
	"strconv"
	"strings"
)

// healthTopN bounds each ranked list in the compact process-health snapshot.
// The full process set is still scanned and aggregated before truncation.
const healthTopN = 20

// FamilySummary aggregates one exact process COMM across the current snapshot.
// RSS is summed process RSS (so shared pages may be counted more than once, just
// like summing per-process RSS in ps/top); it is intended for relative triage,
// not as a replacement for host-level memory accounting.
type FamilySummary struct {
	Comm    string         `json:"comm"`
	Count   int            `json:"count"`
	RSSKB   int64          `json:"rss_kb"`
	Threads int            `json:"threads"`
	States  map[string]int `json:"states"`
}

// StateFamilySummary attributes one process state to one exact COMM family.
// Count is the number of processes in that family observed in the named state.
type StateFamilySummary struct {
	Comm  string `json:"comm"`
	Count int    `json:"count"`
}

// FanoutSummary is one process ranked by its number of direct children in the
// same snapshot. It deliberately reports direct children only; ancestry/tree
// reconstruction belongs in drill-down tooling rather than this compact signal.
type FanoutSummary struct {
	PID      int    `json:"pid"`
	Comm     string `json:"comm"`
	Children int    `json:"children"`
}

// ScanSummary makes snapshot completeness explicit. A small skipped count is
// normal on a busy host because processes can exit between /proc enumeration and
// reading /proc/<pid>/stat; callers can now distinguish that race from a severely
// partial snapshot instead of silently treating every successful Health() call as
// complete.
type ScanSummary struct {
	PIDsEnumerated int `json:"pids_enumerated"`
	PIDsReadable   int `json:"pids_readable"`
	PIDsSkipped    int `json:"pids_skipped"`
}

// HealthSummary is a cheap, read-only process-table summary intended to become
// the foundation for process-health anomaly rules. It does not read cmdline,
// resolve usernames, or take the 150ms CPU sample used by process_list.
type HealthSummary struct {
	TotalProcesses int            `json:"total_processes"`
	TotalThreads   int            `json:"total_threads"`
	States         map[string]int `json:"states"`
	UniqueFamilies int            `json:"unique_families"`
	Scan           ScanSummary    `json:"scan"`

	TopFamiliesByCount []FamilySummary                   `json:"top_families_by_count"`
	TopFamiliesByRSS   []FamilySummary                   `json:"top_families_by_rss"`
	TopFamiliesByState map[string][]StateFamilySummary   `json:"top_families_by_state"`
	TopFanout          []FanoutSummary                   `json:"top_fanout"`
}

// Health scans /proc once and returns a compact process-health snapshot. Unlike
// List/Top it intentionally does not sleep for CPU sampling and never touches
// /proc/<pid>/cmdline. Processes that exit during the scan are counted as skipped
// so consumers can judge snapshot completeness.
func Health() (HealthSummary, error) {
	pids := listPIDs()
	if len(pids) == 0 {
		return HealthSummary{}, errors.New("procstat: cannot enumerate /proc")
	}

	rows := make([]Process, 0, len(pids))
	for _, pid := range pids {
		p, ok := readHealthProcess(pid)
		if !ok {
			continue
		}
		rows = append(rows, p)
	}
	if len(rows) == 0 {
		return HealthSummary{}, errors.New("procstat: no readable processes")
	}

	out := summarizeHealth(rows, healthTopN)
	out.Scan = ScanSummary{
		PIDsEnumerated: len(pids),
		PIDsReadable:   len(rows),
		PIDsSkipped:    len(pids) - len(rows),
	}
	return out, nil
}

// readHealthProcess reads only the /proc/<pid>/stat fields needed by Health.
// Keeping this path separate from readProcess avoids proc-owner/NSS resolution
// and the CPU-sampling work that the interactive process_list endpoint needs.
func readHealthProcess(pid int) (Process, bool) {
	raw, err := os.ReadFile(filepath.Join("/proc", strconv.Itoa(pid), "stat"))
	if err != nil {
		return Process{}, false
	}
	return parseHealthStat(pid, raw)
}

// parseHealthStat decodes the small subset of /proc/<pid>/stat used by Health.
// Numeric parse failures reject the row rather than silently turning malformed
// data into zero-valued PPID/thread/RSS fields that could distort later health
// decisions.
func parseHealthStat(pid int, raw []byte) (Process, bool) {
	s := string(raw)
	lp := strings.IndexByte(s, '(')
	rp := strings.LastIndexByte(s, ')')
	if lp < 0 || rp < 0 || rp < lp {
		return Process{}, false
	}
	f := strings.Fields(s[rp+1:])
	if len(f) < 22 || f[0] == "" {
		return Process{}, false
	}

	ppid, err := strconv.Atoi(f[1]) // field 4 -> f[1]
	if err != nil {
		return Process{}, false
	}
	threads, err := strconv.Atoi(f[17]) // field 20 -> f[17]
	if err != nil {
		return Process{}, false
	}
	rssPages, err := strconv.ParseInt(f[21], 10, 64) // field 24 -> f[21]
	if err != nil {
		return Process{}, false
	}
	pagesKB := int64(os.Getpagesize()) / 1024

	return Process{
		PID:     pid,
		PPID:    ppid,
		State:   f[0],
		Comm:    s[lp+1 : rp],
		Threads: threads,
		RSSKB:   rssPages * pagesKB,
	}, true
}

// summarizeHealth is pure so aggregation, ranking, and truncation can be tested
// deterministically without depending on the live host process table.
func summarizeHealth(rows []Process, limit int) HealthSummary {
	if limit < 1 {
		limit = healthTopN
	}

	out := HealthSummary{
		States:             map[string]int{},
		TopFamiliesByState: map[string][]StateFamilySummary{},
	}
	families := make(map[string]FamilySummary)
	children := make(map[int]int)

	for _, p := range rows {
		out.TotalProcesses++
		out.TotalThreads += p.Threads
		out.States[p.State]++

		f := families[p.Comm]
		f.Comm = p.Comm
		f.Count++
		f.RSSKB += p.RSSKB
		f.Threads += p.Threads
		if f.States == nil {
			f.States = map[string]int{}
		}
		f.States[p.State]++
		families[p.Comm] = f

		if p.PPID >= 0 {
			children[p.PPID]++
		}
	}
	out.UniqueFamilies = len(families)

	allFamilies := make([]FamilySummary, 0, len(families))
	for _, f := range families {
		allFamilies = append(allFamilies, f)
		for state, count := range f.States {
			out.TopFamiliesByState[state] = append(out.TopFamiliesByState[state], StateFamilySummary{
				Comm:  f.Comm,
				Count: count,
			})
		}
	}

	byCount := append([]FamilySummary(nil), allFamilies...)
	sort.Slice(byCount, func(i, j int) bool {
		if byCount[i].Count != byCount[j].Count {
			return byCount[i].Count > byCount[j].Count
		}
		if byCount[i].RSSKB != byCount[j].RSSKB {
			return byCount[i].RSSKB > byCount[j].RSSKB
		}
		return byCount[i].Comm < byCount[j].Comm
	})
	if len(byCount) > limit {
		byCount = byCount[:limit]
	}
	out.TopFamiliesByCount = byCount

	byRSS := append([]FamilySummary(nil), allFamilies...)
	sort.Slice(byRSS, func(i, j int) bool {
		if byRSS[i].RSSKB != byRSS[j].RSSKB {
			return byRSS[i].RSSKB > byRSS[j].RSSKB
		}
		if byRSS[i].Count != byRSS[j].Count {
			return byRSS[i].Count > byRSS[j].Count
		}
		return byRSS[i].Comm < byRSS[j].Comm
	})
	if len(byRSS) > limit {
		byRSS = byRSS[:limit]
	}
	out.TopFamiliesByRSS = byRSS

	for state, ranked := range out.TopFamiliesByState {
		sort.Slice(ranked, func(i, j int) bool {
			if ranked[i].Count != ranked[j].Count {
				return ranked[i].Count > ranked[j].Count
			}
			return ranked[i].Comm < ranked[j].Comm
		})
		if len(ranked) > limit {
			ranked = ranked[:limit]
		}
		out.TopFamiliesByState[state] = ranked
	}

	fanout := make([]FanoutSummary, 0)
	for _, p := range rows {
		if n := children[p.PID]; n > 0 {
			fanout = append(fanout, FanoutSummary{PID: p.PID, Comm: p.Comm, Children: n})
		}
	}
	sort.Slice(fanout, func(i, j int) bool {
		if fanout[i].Children != fanout[j].Children {
			return fanout[i].Children > fanout[j].Children
		}
		if fanout[i].Comm != fanout[j].Comm {
			return fanout[i].Comm < fanout[j].Comm
		}
		return fanout[i].PID < fanout[j].PID
	})
	if len(fanout) > limit {
		fanout = fanout[:limit]
	}
	out.TopFanout = fanout

	return out
}

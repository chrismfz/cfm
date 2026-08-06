// Package procstat produces a top-like snapshot of the busiest processes by
// reading /proc directly (no external tools, no cgo). It backs the read-only
// MCP tool `process_list` / GET /api/v1/system/processes.
//
// SECURITY: this deliberately exposes only the process COMM (the executable
// name, from /proc/<pid>/stat) — never the full cmdline. Command-line args
// routinely carry secrets (`mysql -pXXXX`, `--token=…`, connection strings), so
// /proc/<pid>/cmdline is never read or returned.
package procstat

import (
	"errors"
	"os"
	"os/user"
	"path/filepath"
	"sort"
	"strconv"
	"strings"
	"sync"
	"syscall"
	"time"
)

// Process is one row of the snapshot. CPUPct is normalised so that one fully
// busy core ≈ 100% (like top), computed from a short two-sample delta.
type Process struct {
	PID     int     `json:"pid"`
	User    string  `json:"user"`
	State   string  `json:"state"` // R,S,D,Z,T,I…
	CPUPct  float64 `json:"cpu_pct"`
	MemPct  float64 `json:"mem_pct"`
	RSSKB   int64   `json:"rss_kb"`
	Threads int     `json:"threads"`
	Comm    string  `json:"comm"` // executable name only — NEVER the cmdline
}

// sampleInterval is how long we wait between the two CPU-time samples. Long
// enough for a stable %cpu, short enough to keep the endpoint snappy.
const sampleInterval = 150 * time.Millisecond

// procTimes is one pid's cumulative CPU jiffies (utime+stime) at a sample.
type procTimes struct{ jiffies uint64 }

// Top returns the n busiest processes by CPU, then falls back to RSS to break
// ties / fill when CPU is idle. n is clamped to [1,200].
func Top(n int) ([]Process, error) {
	if n < 1 {
		n = 15
	}
	if n > 200 {
		n = 200
	}

	total1, ok := totalJiffies()
	if !ok {
		return nil, errors.New("procstat: cannot read /proc/stat")
	}
	first := sampleProcJiffies()

	time.Sleep(sampleInterval)

	total2, ok := totalJiffies()
	if !ok {
		return nil, errors.New("procstat: cannot read /proc/stat")
	}
	dTotal := float64(0)
	if total2 > total1 {
		dTotal = float64(total2 - total1)
	}
	numCPU := float64(numCPUs())
	memTotalKB := memTotalKB()

	pids := listPIDs()
	uidCache := map[uint32]string{}
	out := make([]Process, 0, len(pids))
	for _, pid := range pids {
		p, ok := readProcess(pid, uidCache)
		if !ok {
			continue
		}
		// %cpu from the delta of this pid's jiffies over the interval, scaled so
		// a single saturated core reads ~100%.
		if prev, seen := first[pid]; seen && dTotal > 0 {
			now := currentProcJiffies(pid)
			if now > prev.jiffies {
				p.CPUPct = round1(100 * numCPU * float64(now-prev.jiffies) / dTotal)
			}
		}
		if memTotalKB > 0 {
			p.MemPct = round1(100 * float64(p.RSSKB) / float64(memTotalKB))
		}
		out = append(out, p)
	}

	sort.Slice(out, func(i, j int) bool {
		if out[i].CPUPct != out[j].CPUPct {
			return out[i].CPUPct > out[j].CPUPct
		}
		if out[i].RSSKB != out[j].RSSKB {
			return out[i].RSSKB > out[j].RSSKB
		}
		return out[i].PID < out[j].PID
	})
	if len(out) > n {
		out = out[:n]
	}
	return out, nil
}

func listPIDs() []int {
	entries, err := os.ReadDir("/proc")
	if err != nil {
		return nil
	}
	pids := make([]int, 0, len(entries))
	for _, e := range entries {
		if !e.IsDir() {
			continue
		}
		if pid, err := strconv.Atoi(e.Name()); err == nil {
			pids = append(pids, pid)
		}
	}
	return pids
}

// sampleProcJiffies reads every pid's cumulative CPU jiffies once (sample 1).
func sampleProcJiffies() map[int]procTimes {
	m := map[int]procTimes{}
	for _, pid := range listPIDs() {
		if j, ok := procJiffies(pid); ok {
			m[pid] = procTimes{jiffies: j}
		}
	}
	return m
}

func currentProcJiffies(pid int) uint64 {
	if j, ok := procJiffies(pid); ok {
		return j
	}
	return 0
}

// procJiffies returns utime+stime from /proc/<pid>/stat.
func procJiffies(pid int) (uint64, bool) {
	f := statFields(pid)
	if f == nil {
		return 0, false
	}
	// After the comm split, f[0]=state (field 3). utime=field14→f[11],
	// stime=field15→f[12].
	if len(f) < 13 {
		return 0, false
	}
	utime, e1 := strconv.ParseUint(f[11], 10, 64)
	stime, e2 := strconv.ParseUint(f[12], 10, 64)
	if e1 != nil || e2 != nil {
		return 0, false
	}
	return utime + stime, true
}

// readProcess fills the non-CPU fields from /proc/<pid>/stat + dir ownership.
func readProcess(pid int, uidCache map[uint32]string) (Process, bool) {
	raw, err := os.ReadFile(filepath.Join("/proc", strconv.Itoa(pid), "stat"))
	if err != nil {
		return Process{}, false
	}
	s := string(raw)
	lp := strings.IndexByte(s, '(')
	rp := strings.LastIndexByte(s, ')')
	if lp < 0 || rp < 0 || rp < lp {
		return Process{}, false
	}
	comm := s[lp+1 : rp]
	f := strings.Fields(s[rp+1:])
	if len(f) < 22 {
		return Process{}, false
	}
	pagesKB := int64(os.Getpagesize()) / 1024
	rssPages, _ := strconv.ParseInt(f[21], 10, 64) // field 24 → f[21]
	threads, _ := strconv.Atoi(f[17])              // field 20 → f[17]

	p := Process{
		PID:     pid,
		State:   f[0],
		Comm:    comm,
		Threads: threads,
		RSSKB:   rssPages * pagesKB,
		User:    procOwner(pid, uidCache),
	}
	return p, true
}

// statFields returns the whitespace-split fields AFTER the comm parenthesis.
func statFields(pid int) []string {
	raw, err := os.ReadFile(filepath.Join("/proc", strconv.Itoa(pid), "stat"))
	if err != nil {
		return nil
	}
	s := string(raw)
	rp := strings.LastIndexByte(s, ')')
	if rp < 0 || rp+1 >= len(s) {
		return nil
	}
	return strings.Fields(s[rp+1:])
}

// procOwner resolves the owning username from the /proc/<pid> dir ownership.
func procOwner(pid int, cache map[uint32]string) string {
	fi, err := os.Stat(filepath.Join("/proc", strconv.Itoa(pid)))
	if err != nil {
		return ""
	}
	st, ok := fi.Sys().(*syscall.Stat_t)
	if !ok {
		return ""
	}
	if name, seen := cache[st.Uid]; seen {
		return name
	}
	name := strconv.FormatUint(uint64(st.Uid), 10)
	if u, err := user.LookupId(name); err == nil && u.Username != "" {
		name = u.Username
	}
	cache[st.Uid] = name
	return name
}

// totalJiffies sums the aggregate CPU fields from the first line of /proc/stat.
func totalJiffies() (uint64, bool) {
	raw, err := os.ReadFile("/proc/stat")
	if err != nil {
		return 0, false
	}
	line := raw
	if i := strings.IndexByte(string(raw), '\n'); i > 0 {
		line = raw[:i]
	}
	fields := strings.Fields(string(line))
	if len(fields) < 2 || fields[0] != "cpu" {
		return 0, false
	}
	var sum uint64
	for _, f := range fields[1:] {
		v, err := strconv.ParseUint(f, 10, 64)
		if err != nil {
			continue
		}
		sum += v
	}
	return sum, true
}

var numCPUOnce struct {
	sync.Once
	n int
}

func numCPUs() int {
	numCPUOnce.Do(func() {
		raw, err := os.ReadFile("/proc/stat")
		if err != nil {
			numCPUOnce.n = 1
			return
		}
		n := 0
		for _, line := range strings.Split(string(raw), "\n") {
			if strings.HasPrefix(line, "cpu") && len(line) > 3 && line[3] >= '0' && line[3] <= '9' {
				n++
			}
		}
		if n < 1 {
			n = 1
		}
		numCPUOnce.n = n
	})
	return numCPUOnce.n
}

func memTotalKB() int64 {
	raw, err := os.ReadFile("/proc/meminfo")
	if err != nil {
		return 0
	}
	for _, line := range strings.Split(string(raw), "\n") {
		if strings.HasPrefix(line, "MemTotal:") {
			f := strings.Fields(line)
			if len(f) >= 2 {
				if v, err := strconv.ParseInt(f[1], 10, 64); err == nil {
					return v
				}
			}
		}
	}
	return 0
}

func round1(f float64) float64 {
	return float64(int64(f*10+0.5)) / 10
}

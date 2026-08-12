// Package lvestat parses CloudLinux LVE per-tenant resource accounting from
// /proc/lve/list — the LVE kernel-module interface. It is the real per-uid CPU
// source on CloudLinux: the CPU usage is NOT exposed under the cgroup tree
// (the /sys/fs/cgroup/.../lve subtree is empty on CL8 and CL9), and /proc/lve/list
// has the same format on both, independent of cgroup version. So this reader
// needs no cgroup v1/v2 branching and survives a future cgroup-v2 migration.
//
// The file is TAB-separated with a header line of the form
//
//	<version>:LVE  lCPU  lCPUW  nCPU  ...  EP  CPU  MEM  IO  ...  NPROC  ...
//
// Columns are resolved BY NAME from that header (not by fixed position), so a
// future format that adds or reorders columns (the "<version>:" prefix bumps)
// still parses. This package is pure: Parse takes an io.Reader and does no I/O.
package lvestat

import (
	"bufio"
	"io"
	"os"
	"strconv"
	"strings"
)

// ProcLVEListPath is the LVE accounting file exposed by the CloudLinux kernel module.
const ProcLVEListPath = "/proc/lve/list"

// LVE is one row of /proc/lve/list — a single tenant's (reseller,uid) resource
// accounting. Numeric fields are the raw values from the file. CPUUsage is a
// monotonic cumulative counter (delta over an interval gives the tenant's CPU
// rate); LimitCPU is the SPEED limit in hundredths of a percent (10000 = 100%
// of one core-equivalent), 0 meaning unlimited (e.g. the system LVE 0,0).
type LVE struct {
	Reseller int64 `json:"reseller"`
	UID      int64 `json:"uid"`
	LimitCPU int64 `json:"limit_cpu"` // lCPU (hundredths of a %; 0 = unlimited)
	NumCPU   int64 `json:"num_cpu"`   // nCPU (core-count limit)
	EP       int64 `json:"ep"`        // current entry processes
	NProc    int64 `json:"nproc"`     // current processes
	CPUUsage int64 `json:"cpu_usage"` // CPU (cumulative usage counter)
	MemUsage int64 `json:"mem_usage"` // MEM
	IOUsage  int64 `json:"io_usage"`  // IO
}

// Snapshot is a parsed /proc/lve/list plus the header's format version.
type Snapshot struct {
	Version int   `json:"version"` // the "<version>:" header prefix (10 on CL8/CL9 today)
	Entries []LVE `json:"entries"`
}

// Parse reads /proc/lve/list content. Columns are looked up by header name;
// blank numeric fields (the system LVE 0,0 carries no CPU limit) parse as 0;
// rows whose tab-field count doesn't match the header, or whose LVE id isn't
// "reseller,uid", are skipped rather than misparsed.
func Parse(r io.Reader) (Snapshot, error) {
	var snap Snapshot
	sc := bufio.NewScanner(r)
	sc.Buffer(make([]byte, 0, 64*1024), 1024*1024)

	var cols []string
	colIdx := map[string]int{}

	// Header: first non-empty line. Strip the "<version>:" prefix off the first
	// column name and record the version.
	for sc.Scan() {
		line := sc.Text()
		if strings.TrimSpace(line) == "" {
			continue
		}
		cols = strings.Split(line, "\t")
		if len(cols) > 0 {
			first := cols[0]
			if c := strings.IndexByte(first, ':'); c >= 0 {
				if v, err := strconv.Atoi(first[:c]); err == nil {
					snap.Version = v
				}
				cols[0] = first[c+1:]
			}
		}
		for i, name := range cols {
			colIdx[strings.TrimSpace(name)] = i
		}
		break
	}
	if len(cols) == 0 {
		return snap, sc.Err()
	}
	lveCol, ok := colIdx["LVE"]
	if !ok {
		return snap, sc.Err() // no id column → nothing we can key on
	}

	get := func(fields []string, name string) int64 {
		i, ok := colIdx[name]
		if !ok || i >= len(fields) {
			return 0
		}
		s := strings.TrimSpace(fields[i])
		if s == "" {
			return 0
		}
		// Every /proc/lve/list cell is numeric today. A blank cell means 0
		// (e.g. the unlimited lCPU on the system LVE). A non-numeric cell (only
		// possible if a future format adds a text column and we key it here)
		// also yields 0 rather than an error — a consumer deltaing CPUUsage
		// should treat a lone 0 sample as "unknown", not a real counter reset.
		n, _ := strconv.ParseInt(s, 10, 64)
		return n
	}

	for sc.Scan() {
		line := sc.Text()
		if strings.TrimSpace(line) == "" {
			continue
		}
		fields := strings.Split(line, "\t")
		if len(fields) != len(cols) {
			continue
		}
		reseller, uid, ok := parseLVEID(fields[lveCol])
		if !ok {
			continue
		}
		snap.Entries = append(snap.Entries, LVE{
			Reseller: reseller,
			UID:      uid,
			LimitCPU: get(fields, "lCPU"),
			NumCPU:   get(fields, "nCPU"),
			EP:       get(fields, "EP"),
			NProc:    get(fields, "NPROC"),
			CPUUsage: get(fields, "CPU"),
			MemUsage: get(fields, "MEM"),
			IOUsage:  get(fields, "IO"),
		})
	}
	return snap, sc.Err()
}

// parseLVEID parses the "reseller,uid" LVE id (e.g. "0,1004").
func parseLVEID(s string) (reseller, uid int64, ok bool) {
	s = strings.TrimSpace(s)
	c := strings.IndexByte(s, ',')
	if c < 0 {
		return 0, 0, false
	}
	r, err1 := strconv.ParseInt(strings.TrimSpace(s[:c]), 10, 64)
	u, err2 := strconv.ParseInt(strings.TrimSpace(s[c+1:]), 10, 64)
	if err1 != nil || err2 != nil {
		return 0, 0, false
	}
	return r, u, true
}

// Read parses the live /proc/lve/list. It errors if the file is absent (not a
// CloudLinux host, or the LVE kernel module isn't loaded).
func Read() (Snapshot, error) {
	f, err := os.Open(ProcLVEListPath)
	if err != nil {
		return Snapshot{}, err
	}
	defer f.Close()
	return Parse(f)
}

// Available reports whether /proc/lve/list exists (CloudLinux + LVE module).
func Available() bool {
	_, err := os.Stat(ProcLVEListPath)
	return err == nil
}

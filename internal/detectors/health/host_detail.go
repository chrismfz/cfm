package health

import (
	"os"
	"sort"
	"strconv"
	"strings"
)

// Host-detail collectors (Phase 0 of the fleet health work): swap and
// memory breakdown, uptime, CPU identity, real CPU utilization from
// /proc/stat deltas, per-device disk I/O rates, per-NIC throughput and
// OS/kernel identity. Everything lands in Snapshot so the health API
// (/api/v1/health/snapshot), `cfm health`, and later the cfm-web fleet
// UI all see the same values.
//
// Rate collectors follow the same seed-then-delta pattern as
// readThroughput: the first call in a process only seeds counters and
// reports nothing; subsequent calls report the rate since the previous
// call. The daemon's shared snapshotCollector makes this work for API
// consumers; a standalone one-shot process simply lacks rates.

// File readers are variables so tests can stub them (same style as
// openNetDev).
var (
	readProcMeminfo   = func() ([]byte, error) { return os.ReadFile("/proc/meminfo") }
	readProcUptime    = func() ([]byte, error) { return os.ReadFile("/proc/uptime") }
	readProcCPUInfo   = func() ([]byte, error) { return os.ReadFile("/proc/cpuinfo") }
	readProcStat      = func() ([]byte, error) { return os.ReadFile("/proc/stat") }
	readProcDiskstats = func() ([]byte, error) { return os.ReadFile("/proc/diskstats") }
	readOSRelease     = func() ([]byte, error) { return os.ReadFile("/etc/os-release") }
	readKernelRelease = func() ([]byte, error) { return os.ReadFile("/proc/sys/kernel/osrelease") }
	readSysBlockNames = func() ([]string, error) {
		entries, err := os.ReadDir("/sys/block")
		if err != nil {
			return nil, err
		}
		names := make([]string, 0, len(entries))
		for _, e := range entries {
			names = append(names, e.Name())
		}
		return names, nil
	}
)

// MemDetail carries the /proc/meminfo breakdown in bytes.
type MemDetail struct {
	TotalBytes     uint64  `json:"total_bytes"`
	AvailableBytes uint64  `json:"available_bytes"`
	BuffersBytes   uint64  `json:"buffers_bytes"`
	CachedBytes    uint64  `json:"cached_bytes"`
	SwapTotalBytes uint64  `json:"swap_total_bytes"`
	SwapUsedBytes  uint64  `json:"swap_used_bytes"`
	SwapUsedPct    float64 `json:"swap_used_pct"`
}

// CPUIdentity is the static CPU description from /proc/cpuinfo.
type CPUIdentity struct {
	Model   string  `json:"model,omitempty"`
	Threads int     `json:"threads,omitempty"`
	MHz     float64 `json:"mhz,omitempty"`
}

// CPUUtil is real CPU utilization from two /proc/stat reads. Valid is
// false on the seeding call (no previous counters to diff against).
type CPUUtil struct {
	Valid     bool    `json:"valid"`
	BusyPct   float64 `json:"busy_pct"`
	UserPct   float64 `json:"user_pct"`
	SystemPct float64 `json:"system_pct"`
	IOWaitPct float64 `json:"iowait_pct"`
	StealPct  float64 `json:"steal_pct"`
}

// DiskIORate is bytes/sec read/written on one whole block device.
type DiskIORate struct {
	Device   string `json:"device"`
	ReadBps  uint64 `json:"read_bps"`
	WriteBps uint64 `json:"write_bps"`
}

// NICRate is per-interface throughput (loopback excluded).
type NICRate struct {
	Name   string  `json:"name"`
	RxMbps float64 `json:"rx_mbps"`
	TxMbps float64 `json:"tx_mbps"`
}

// maxNICRates bounds the per-NIC list so virtualization hosts with
// dozens of veth/tap interfaces don't bloat the snapshot. Busiest first.
const maxNICRates = 16

// ---------------------------------------------------------------------------
// meminfo / uptime / cpuinfo / os identity (stateless reads)

func (d *Detector) collectHostDetail(s *Snapshot) {
	if b, err := readProcMeminfo(); err == nil {
		s.Mem = parseMemInfoDetail(b)
	}
	if b, err := readProcUptime(); err == nil {
		s.UptimeSeconds = parseUptimeSeconds(b)
	}
	if b, err := readProcCPUInfo(); err == nil {
		s.CPU = parseCPUInfo(b)
	}
	if b, err := readOSRelease(); err == nil {
		s.OSPrettyName = parseOSPrettyName(b)
	}
	if b, err := readKernelRelease(); err == nil {
		s.KernelVersion = strings.TrimSpace(string(b))
	}
	s.CPUUtil = d.readCPUUtil()
	s.DiskIO = d.readDiskIORates()
}

func parseMemInfoDetail(b []byte) MemDetail {
	kb := map[string]uint64{}
	for _, line := range strings.Split(string(b), "\n") {
		f := strings.Fields(line)
		if len(f) < 2 {
			continue
		}
		switch f[0] {
		case "MemTotal:", "MemAvailable:", "Buffers:", "Cached:", "SwapTotal:", "SwapFree:":
			if v, err := strconv.ParseUint(f[1], 10, 64); err == nil {
				kb[f[0]] = v
			}
		}
	}
	out := MemDetail{
		TotalBytes:     kb["MemTotal:"] * 1024,
		AvailableBytes: kb["MemAvailable:"] * 1024,
		BuffersBytes:   kb["Buffers:"] * 1024,
		CachedBytes:    kb["Cached:"] * 1024,
		SwapTotalBytes: kb["SwapTotal:"] * 1024,
	}
	if free, ok := kb["SwapFree:"]; ok && kb["SwapTotal:"] >= free {
		out.SwapUsedBytes = (kb["SwapTotal:"] - free) * 1024
	}
	if out.SwapTotalBytes > 0 {
		out.SwapUsedPct = 100 * float64(out.SwapUsedBytes) / float64(out.SwapTotalBytes)
	}
	return out
}

func parseUptimeSeconds(b []byte) uint64 {
	f := strings.Fields(string(b))
	if len(f) == 0 {
		return 0
	}
	v, err := strconv.ParseFloat(f[0], 64)
	if err != nil || v < 0 {
		return 0
	}
	return uint64(v)
}

func parseCPUInfo(b []byte) CPUIdentity {
	var out CPUIdentity
	for _, line := range strings.Split(string(b), "\n") {
		key, val, found := strings.Cut(line, ":")
		if !found {
			continue
		}
		key = strings.TrimSpace(key)
		val = strings.TrimSpace(val)
		switch key {
		case "processor":
			out.Threads++
		case "model name":
			if out.Model == "" {
				out.Model = val
			}
		case "cpu MHz":
			if out.MHz == 0 {
				out.MHz, _ = strconv.ParseFloat(val, 64)
			}
		}
	}
	return out
}

func parseOSPrettyName(b []byte) string {
	for _, line := range strings.Split(string(b), "\n") {
		if v, ok := strings.CutPrefix(strings.TrimSpace(line), "PRETTY_NAME="); ok {
			return strings.Trim(v, `"`)
		}
	}
	return ""
}

// ---------------------------------------------------------------------------
// CPU utilization from /proc/stat deltas

type cpuTicks struct {
	user, nice, system, idle, iowait, irq, softirq, steal uint64
}

func (t cpuTicks) total() uint64 {
	return t.user + t.nice + t.system + t.idle + t.iowait + t.irq + t.softirq + t.steal
}

func parseCPUStat(b []byte) (cpuTicks, bool) {
	for _, line := range strings.Split(string(b), "\n") {
		if !strings.HasPrefix(line, "cpu ") {
			continue
		}
		f := strings.Fields(line)
		if len(f) < 8 {
			return cpuTicks{}, false
		}
		vals := make([]uint64, 8)
		for i := 0; i < 8; i++ {
			vals[i], _ = strconv.ParseUint(f[i+1], 10, 64)
		}
		return cpuTicks{
			user: vals[0], nice: vals[1], system: vals[2], idle: vals[3],
			iowait: vals[4], irq: vals[5], softirq: vals[6], steal: vals[7],
		}, true
	}
	return cpuTicks{}, false
}

func cpuUtilFromDelta(prev, cur cpuTicks) CPUUtil {
	total := cur.total() - prev.total()
	if cur.total() < prev.total() || total == 0 {
		return CPUUtil{}
	}
	pct := func(v uint64) float64 { return 100 * float64(v) / float64(total) }
	idle := cur.idle - prev.idle
	iowait := cur.iowait - prev.iowait
	return CPUUtil{
		Valid:     true,
		BusyPct:   pct(total - idle - iowait),
		UserPct:   pct((cur.user - prev.user) + (cur.nice - prev.nice)),
		SystemPct: pct((cur.system - prev.system) + (cur.irq - prev.irq) + (cur.softirq - prev.softirq)),
		IOWaitPct: pct(iowait),
		StealPct:  pct(cur.steal - prev.steal),
	}
}

func (d *Detector) readCPUUtil() CPUUtil {
	b, err := readProcStat()
	if err != nil {
		return CPUUtil{}
	}
	cur, ok := parseCPUStat(b)
	if !ok {
		return CPUUtil{}
	}
	if !d.lastCPUValid {
		d.lastCPU, d.lastCPUValid = cur, true
		return CPUUtil{}
	}
	out := cpuUtilFromDelta(d.lastCPU, cur)
	d.lastCPU = cur
	return out
}

// ---------------------------------------------------------------------------
// Disk I/O rates from /proc/diskstats deltas (whole devices only)

type diskIOCounters struct {
	readSectors, writeSectors uint64
}

// parseDiskstats returns per-device sector counters for devices in the
// allowed set (whole block devices from /sys/block; partitions are not
// listed there so they are skipped naturally).
func parseDiskstats(b []byte, allowed map[string]bool) map[string]diskIOCounters {
	out := map[string]diskIOCounters{}
	for _, line := range strings.Split(string(b), "\n") {
		f := strings.Fields(line)
		// major minor name reads _ sectors-read _ writes _ sectors-written ...
		if len(f) < 10 || !allowed[f[2]] {
			continue
		}
		rs, _ := strconv.ParseUint(f[5], 10, 64)
		ws, _ := strconv.ParseUint(f[9], 10, 64)
		out[f[2]] = diskIOCounters{readSectors: rs, writeSectors: ws}
	}
	return out
}

func wholeDiskAllowSet(names []string) map[string]bool {
	allowed := make(map[string]bool, len(names))
	for _, n := range names {
		if strings.HasPrefix(n, "loop") || strings.HasPrefix(n, "ram") || strings.HasPrefix(n, "zram") {
			continue
		}
		allowed[n] = true
	}
	return allowed
}

const diskSectorBytes = 512 // /proc/diskstats sector counters are always 512-byte units

func (d *Detector) readDiskIORates() []DiskIORate {
	names, err := readSysBlockNames()
	if err != nil {
		return nil
	}
	b, err := readProcDiskstats()
	if err != nil {
		return nil
	}
	now := throughputNow()
	cur := parseDiskstats(b, wholeDiskAllowSet(names))
	prev, prevT := d.lastDiskIO, d.lastDiskIOT
	d.lastDiskIO, d.lastDiskIOT = cur, now
	if prev == nil {
		return nil // seeding call
	}
	dt := now.Sub(prevT).Seconds()
	if dt <= 0 {
		return nil
	}
	out := make([]DiskIORate, 0, len(cur))
	for dev, c := range cur {
		p, ok := prev[dev]
		if !ok || c.readSectors < p.readSectors || c.writeSectors < p.writeSectors {
			continue // new device or counter reset
		}
		out = append(out, DiskIORate{
			Device:   dev,
			ReadBps:  uint64(float64((c.readSectors-p.readSectors)*diskSectorBytes) / dt),
			WriteBps: uint64(float64((c.writeSectors-p.writeSectors)*diskSectorBytes) / dt),
		})
	}
	sort.Slice(out, func(i, j int) bool { return out[i].Device < out[j].Device })
	return out
}

// ---------------------------------------------------------------------------
// Per-NIC throughput (shares the /proc/net/dev delta clock with the
// aggregate readThroughput; see health.go)

type nicCounters struct {
	rxBytes, txBytes uint64
}

func perNICRates(prev, cur map[string]nicCounters, dt float64) []NICRate {
	if dt <= 0 || prev == nil {
		return nil
	}
	out := make([]NICRate, 0, len(cur))
	for name, c := range cur {
		p, ok := prev[name]
		if !ok || c.rxBytes < p.rxBytes || c.txBytes < p.txBytes {
			continue
		}
		rx := float64(c.rxBytes-p.rxBytes) * 8.0 / 1e6 / dt
		tx := float64(c.txBytes-p.txBytes) * 8.0 / 1e6 / dt
		if c.rxBytes == 0 && c.txBytes == 0 {
			continue // interface never saw traffic
		}
		out = append(out, NICRate{Name: name, RxMbps: rx, TxMbps: tx})
	}
	sort.Slice(out, func(i, j int) bool {
		ri, rj := out[i].RxMbps+out[i].TxMbps, out[j].RxMbps+out[j].TxMbps
		if ri != rj {
			return ri > rj
		}
		return out[i].Name < out[j].Name
	})
	if len(out) > maxNICRates {
		out = out[:maxNICRates]
	}
	return out
}

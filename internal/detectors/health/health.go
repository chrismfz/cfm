// internal/detectors/health/health.go
package health

import (
	"bufio"
	"bytes"
	"context"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net"
	"os"
	"os/exec"
	"path/filepath"
	"regexp"
	"sort"
	"strconv"
	"strings"
	"sync"
	"syscall"
	"time"

	core "cfm/internal/detectors/core"
	//	"cfm/internal/logging"
	"cfm/internal/enrich"
	"cfm/internal/healthstore"
)

var (
	throughputNow = time.Now
	openNetDev    = func() (io.ReadCloser, error) { return os.Open("/proc/net/dev") }

	snapshotCollectorMu sync.Mutex
	snapshotCollector   *Detector
)

type Config struct {
	Every, Window, Cooldown time.Duration

	CpuLoadPct, RamUsedPct, DiskRootPct int
	TmpUsedPct                          int

	ConnTotalSpikeX, ConnEstSpikeX, ConnSynSpikeX float64
	ConnTotalAbs, EstablishedAbs, SynRecvAbs      int

	ThruSpikeX  float64
	ThruMinMbps float64

	TempWarnC, TempCritC int
	SmartWearWarnPct     int
	SmartWearCritPct     int

	SmartAlert, MdadmAlert, ZfsAlert bool

	// Minimum absolute counts required for spike-style alerts to fire
	ConnTotalMin   int // default 50
	EstablishedMin int // default 30
	SynRecvMin     int // default 50
	// Optional: require a minimum absolute jump vs baseline for spike alerts
	SpikeMinDelta int // default 10

	// --- NEW: enrichment & spike probe ---
	SpikeProbeTopN int      // how many top talkers to include on a spike (default 10; 0 disables)
	UseEnrich      bool     // enable ASN/Country/PTR via enricher
	UsePTR         bool     // fallback PTR when enricher is off/misses
	EnrichDirs     []string // enricher databases (e.g. "/etc/cfm", "/usr/share/GeoIP", ...)

	// tmp filesystem cleanup
	TmpCleanOlder time.Duration // if >0 and /tmp usage exceeds TmpUsedPct, delete files older than this

}

type Detector struct {
	cfg  Config
	name string

	enr *enrich.Enricher

	mu sync.Mutex

	last map[string]time.Time // cooldown per key
	base map[string]float64   // EWMA baselines

	smartProbeCache map[string]string // /dev node -> successful smartctl -d driver ("" for native)

	// throughput deltas
	lastRxBytes uint64
	lastTxBytes uint64
	lastT       time.Time
	lastNIC     map[string]nicCounters

	// cpu utilization deltas (/proc/stat)
	lastCPU      cpuTicks
	lastCPUValid bool

	// disk I/O deltas (/proc/diskstats)
	lastDiskIO  map[string]diskIOCounters
	lastDiskIOT time.Time
}

func New(cfg Config) *Detector {

	// sensible defaults
	if cfg.SpikeProbeTopN == 0 {
		cfg.SpikeProbeTopN = 10
	}
	if !cfg.UseEnrich && !cfg.UsePTR {
		cfg.UsePTR = true
	}
	if cfg.UseEnrich && len(cfg.EnrichDirs) == 0 {
		cfg.EnrichDirs = []string{"/etc/cfm", "/var/lib/cfm/maxmind"}
	}

	if cfg.ConnTotalMin == 0 {
		cfg.ConnTotalMin = 50
	}
	if cfg.EstablishedMin == 0 {
		cfg.EstablishedMin = 30
	}
	if cfg.SynRecvMin == 0 {
		cfg.SynRecvMin = 50
	}
	if cfg.SpikeMinDelta == 0 {
		cfg.SpikeMinDelta = 10
	}
	if cfg.SmartWearWarnPct <= 0 {
		cfg.SmartWearWarnPct = 80
	}
	if cfg.SmartWearCritPct <= 0 {
		cfg.SmartWearCritPct = 95
	}
	if cfg.SmartWearCritPct < cfg.SmartWearWarnPct {
		cfg.SmartWearCritPct = cfg.SmartWearWarnPct
	}

	d := &Detector{
		cfg:             cfg,
		last:            make(map[string]time.Time),
		base:            make(map[string]float64),
		smartProbeCache: make(map[string]string),
	}
	if cfg.UseEnrich {
		if e, _ := enrich.New(cfg.EnrichDirs...); e != nil {
			d.enr = e
		}
	}
	return d

}

func (d *Detector) SetName(n string) { d.name = n }
func (d *Detector) Name() string {
	if d.name != "" {
		return d.name
	}
	return "health"
}
func (d *Detector) Every() time.Duration {
	if d.cfg.Every > 0 {
		return d.cfg.Every
	}
	return 10 * time.Second
}

// decorateIP renders "1.2.3.4 [AS1234 Example | US | ptr.example]" if enrich is available.
func (d *Detector) decorateIP(ip string) string {
	if ip == "" {
		return ip
	}
	meta := d.lookupMeta(ip)
	if meta == "" {
		return ip
	}
	return ip + " [" + meta + "]"
}

// -------- core.PeriodicDetector API (matches your types.go) --------
// Manager calls this once every Every(); we sample + evaluate once.
func (d *Detector) RunOnce(ctx context.Context, out chan<- core.Alert) error {
	// collect
	snap := d.snapshot()
	collectedAt := snap.Time
	if collectedAt.IsZero() {
		collectedAt = time.Now().UTC()
	}
	nodeID := strings.TrimSpace(snap.Host)
	if nodeID == "" {
		nodeID = "local"
	}
	healthstore.Global().Append(nodeID, healthstore.Sample{
		NodeID:      nodeID,
		Hostname:    snap.Host,
		CollectedAt: collectedAt,
		Load1:       snap.Load1,
		CPUPct:      snap.CPUUtil.BusyPct,
		RamUsedPct:  snap.RamUsedPct,
		SwapUsedPct: snap.Mem.SwapUsedPct,
		DiskRootPct: snap.DiskRootPct,
		DiskTmpPct:  snap.DiskTmpPct,
		TempMaxC:    snap.TempMaxC,
		RxMbps:      snap.RxMbps,
		TxMbps:      snap.TxMbps,
	})

	// evaluate & emit
	for _, a := range d.evaluate(snap) {
		select {
		case out <- a:
		case <-ctx.Done():
			return context.Canceled
		}
	}
	return nil
}

// ------------------- snapshot/collectors -------------------

type Snapshot struct {
	Time        time.Time
	Host        string
	CPUCores    int
	Load1       float64
	RamUsedPct  float64
	DiskRootPct float64
	DiskTmpPct  float64
	DiskStats   []DiskStat

	TCP map[string]int // state counts incl total

	RxMbps, TxMbps float64

	TempMaxC float64
	Mdadm    MdstatSummary
	Zfs      map[string]ZpoolStatus
	Smart    map[string]SmartInfo

	// Host detail (see host_detail.go). CPUUtil/DiskIO/NICRates are
	// delta-based: zero/empty on the first (seeding) call in a process.
	Mem           MemDetail
	UptimeSeconds uint64
	CPU           CPUIdentity
	CPUUtil       CPUUtil
	OSPrettyName  string
	KernelVersion string
	DiskIO        []DiskIORate
	NICRates      []NICRate

	RawJSON string // pretty JSON to embed in alert Extra["body"]
}

type MdstatSummary struct {
	Status string        `json:"status"`
	Arrays []MdArrayInfo `json:"arrays,omitempty"`
}

type MdArrayInfo struct {
	Name            string   `json:"name"`
	Level           string   `json:"level,omitempty"`
	ExpectedMembers int      `json:"expected_members"`
	ActiveMembers   int      `json:"active_members"`
	FailedMissing   int      `json:"failed_missing_members"`
	MemberStates    []string `json:"member_states,omitempty"`
	ProgressPct     float64  `json:"progress_pct,omitempty"`
	ProgressPhase   string   `json:"progress_phase,omitempty"`
}

type ZpoolStatus struct {
	Pool            string `json:"pool"`
	State           string `json:"state"`
	UnhealthyVdevs  int    `json:"unhealthy_vdev_count"`
	ScanStatus      string `json:"scan_status,omitempty"`
	Resilvering     bool   `json:"resilvering,omitempty"`
	ResilverPercent string `json:"resilver_progress,omitempty"`
}

type SmartInfo struct {
	Health         string            `json:"health"`
	Wear           string            `json:"wear"`
	WearoutPctUsed *int              `json:"wearout_pct_used,omitempty"`
	WearoutSource  string            `json:"wearout_source,omitempty"`
	WearDebug      map[string]string `json:"wearout_debug,omitempty"`
	TempC          string            `json:"temp_c"`
	Model          string            `json:"model,omitempty"`
	Serial         string            `json:"serial,omitempty"`
	Type           string            `json:"type,omitempty"`
	Error          string            `json:"error,omitempty"`
}

type DiskStat struct {
	MountPath    string  `json:"mount_path"`
	TotalBytes   uint64  `json:"total_bytes"`
	UsedBytes    uint64  `json:"used_bytes"`
	FreeBytes    uint64  `json:"free_bytes"`
	UsedPct      float64 `json:"used_pct"`
	TotalInodes  uint64  `json:"total_inodes"`
	UsedInodes   uint64  `json:"used_inodes"`
	FreeInodes   uint64  `json:"free_inodes"`
	InodeUsedPct float64 `json:"inode_used_pct"`
	FSType       string  `json:"fs_type"`
	Device       string  `json:"device"`
}

func (d *Detector) snapshot() Snapshot {
	s := Snapshot{Time: time.Now()}

	// hostname
	if b, _ := os.ReadFile("/proc/sys/kernel/hostname"); len(b) > 0 {
		s.Host = strings.TrimSpace(string(b))
	}

	// cores (count “processor:” lines; fallback 1)
	if b, err := os.ReadFile("/proc/cpuinfo"); err == nil {
		s.CPUCores = strings.Count(string(b), "\nprocessor\t:")
	}
	if s.CPUCores == 0 {
		s.CPUCores = 1
	}

	// loadavg 1m
	if b, err := os.ReadFile("/proc/loadavg"); err == nil {
		fields := strings.Fields(string(b))
		if len(fields) > 0 {
			s.Load1, _ = strconv.ParseFloat(fields[0], 64)
		}
	}

	// RAM % from /proc/meminfo
	if b, err := os.ReadFile("/proc/meminfo"); err == nil {
		var memTot, memAvail float64
		for _, line := range strings.Split(string(b), "\n") {
			if strings.HasPrefix(line, "MemTotal:") {
				memTot, _ = parseLastFloat(line)
			} else if strings.HasPrefix(line, "MemAvailable:") {
				memAvail, _ = parseLastFloat(line)
			}
		}
		if memTot > 0 {
			s.RamUsedPct = 100.0 * (1.0 - memAvail/memTot)
		}
	}

	// Mount table disk stats (new) + backward-compatible root/tmp summary fields.
	s.DiskStats = collectDiskStats()
	for _, ds := range s.DiskStats {
		switch ds.MountPath {
		case "/":
			s.DiskRootPct = ds.UsedPct
		case "/tmp":
			s.DiskTmpPct = ds.UsedPct
		}
	}
	if s.DiskRootPct == 0 {
		if pct, err := rootUsagePct(); err == nil {
			s.DiskRootPct = pct
		}
	}
	if s.DiskTmpPct == 0 {
		if pct, err := fsUsagePct("/tmp"); err == nil {
			s.DiskTmpPct = pct
		}
	}

	// TCP states
	s.TCP = readTCPStates()

	// Throughput (deltas since previous RunOnce)
	s.RxMbps, s.TxMbps, s.NICRates = d.readThroughput()

	// Host detail: swap/mem breakdown, uptime, CPU identity + real
	// utilization, disk I/O rates, OS identity (host_detail.go).
	d.collectHostDetail(&s)

	// Temperature (lm-sensors, optional)
	s.TempMaxC = readMaxTempSensors()

	// mdadm
	s.Mdadm = readMdstat()

	// zpool (optional)
	s.Zfs = readZpool()

	// smartctl (optional, minimal)
	s.Smart = d.readSmartSummary()

	// pretty JSON for sinks/alert body
	body := map[string]any{
		"hostname": s.Host, "time": s.Time.Format(time.RFC3339),
		"cpu_cores": s.CPUCores, "load1": s.Load1,
		"ram_used_pct": s.RamUsedPct, "disk_root_pct": s.DiskRootPct, "disk_tmp_pct": s.DiskTmpPct,
		"disk_stats": s.DiskStats,
		"tcp":        s.TCP,
		"rx_mbps": s.RxMbps, "tx_mbps": s.TxMbps,
		"temp_max_c": s.TempMaxC, "mdadm": s.Mdadm, "zfs": s.Zfs, "smart": s.Smart,
	}
	if b, _ := json.MarshalIndent(body, "", "  "); b != nil {
		s.RawJSON = string(b)
	}
	return s
}

func parseLastFloat(line string) (float64, error) {
	fs := strings.Fields(line)
	if len(fs) < 2 {
		return 0, errors.New("bad line")
	}
	// value is the penultimate token (before unit)
	val := fs[len(fs)-2]
	return strconv.ParseFloat(val, 64)
}

func fsUsagePct(path string) (float64, error) {
	var st syscall.Statfs_t
	if err := syscall.Statfs(path, &st); err != nil {
		return 0, err
	}
	if st.Blocks == 0 {
		return 0, errors.New("blocks=0")
	}
	used := 1.0 - float64(st.Bavail)/float64(st.Blocks)
	return 100.0 * used, nil
}

func rootUsagePct() (float64, error) {
	return fsUsagePct("/")
}

func collectDiskStats() []DiskStat {
	mounts := parseMountInfo("/proc/self/mountinfo")
	if len(mounts) == 0 {
		mounts = parseProcMounts("/proc/mounts")
	}

	stats := make([]DiskStat, 0, len(mounts))
	seenFS := make(map[string]struct{})
	for _, m := range mounts {
		if m.mountPath == "" || isPseudoFSType(m.fsType) {
			continue
		}
		var st syscall.Statfs_t
		if err := syscall.Statfs(m.mountPath, &st); err != nil || st.Blocks == 0 {
			continue
		}

		totalBytes := uint64(st.Blocks) * uint64(st.Bsize)
		freeBytes := uint64(st.Bavail) * uint64(st.Bsize)
		usedBytes := totalBytes - freeBytes

		var usedPct float64
		if totalBytes > 0 {
			usedPct = 100.0 * float64(usedBytes) / float64(totalBytes)
		}

		totalInodes := uint64(st.Files)
		freeInodes := uint64(st.Ffree)
		usedInodes := uint64(0)
		inodeUsedPct := 0.0
		if totalInodes > 0 {
			usedInodes = totalInodes - freeInodes
			inodeUsedPct = 100.0 * float64(usedInodes) / float64(totalInodes)
		}

		// Dedupe bind-mount noise and repeated views into same filesystem.
		fsKey := strings.Join([]string{
			m.device, m.fsType,
			strconv.FormatUint(totalBytes, 10),
			strconv.FormatUint(totalInodes, 10),
		}, "|")
		if _, ok := seenFS[fsKey]; ok {
			continue
		}
		seenFS[fsKey] = struct{}{}

		stats = append(stats, DiskStat{
			MountPath:    m.mountPath,
			TotalBytes:   totalBytes,
			UsedBytes:    usedBytes,
			FreeBytes:    freeBytes,
			UsedPct:      usedPct,
			TotalInodes:  totalInodes,
			UsedInodes:   usedInodes,
			FreeInodes:   freeInodes,
			InodeUsedPct: inodeUsedPct,
			FSType:       m.fsType,
			Device:       m.device,
		})
	}

	sort.Slice(stats, func(i, j int) bool { return stats[i].MountPath < stats[j].MountPath })
	return stats
}

type mountEntry struct {
	mountPath string
	fsType    string
	device    string
}

func parseMountInfo(path string) []mountEntry {
	f, err := os.Open(path)
	if err != nil {
		return nil
	}
	defer f.Close()

	var out []mountEntry
	sc := bufio.NewScanner(f)
	for sc.Scan() {
		line := sc.Text()
		parts := strings.Split(line, " - ")
		if len(parts) != 2 {
			continue
		}
		left := strings.Fields(parts[0])
		right := strings.Fields(parts[1])
		if len(left) < 5 || len(right) < 2 {
			continue
		}
		out = append(out, mountEntry{
			mountPath: unescapeMountField(left[4]),
			fsType:    right[0],
			device:    right[1],
		})
	}
	return out
}

func parseProcMounts(path string) []mountEntry {
	f, err := os.Open(path)
	if err != nil {
		return nil
	}
	defer f.Close()

	var out []mountEntry
	sc := bufio.NewScanner(f)
	for sc.Scan() {
		fields := strings.Fields(sc.Text())
		if len(fields) < 3 {
			continue
		}
		out = append(out, mountEntry{
			device:    unescapeMountField(fields[0]),
			mountPath: unescapeMountField(fields[1]),
			fsType:    fields[2],
		})
	}
	return out
}

func unescapeMountField(s string) string {
	repl := strings.NewReplacer(`\040`, " ", `\011`, "\t", `\012`, "\n", `\134`, `\`)
	return repl.Replace(s)
}

func isPseudoFSType(fsType string) bool {
	switch fsType {
	case "proc", "sysfs", "devtmpfs", "devpts", "cgroup", "cgroup2", "pstore", "securityfs",
		"autofs", "mqueue", "hugetlbfs", "debugfs", "tracefs", "configfs", "fusectl",
		"rpc_pipefs", "binfmt_misc", "ramfs", "tmpfs", "overlay":
		return true
	default:
		return false
	}
}

// Parse /proc/net/tcp and /proc/net/tcp6
// Return stateCounts (incl "total").
func readTCPStates() map[string]int {
	states := map[string]int{
		"ESTABLISHED": 0, "SYN_SENT": 0, "SYN_RECV": 0, "FIN_WAIT1": 0, "FIN_WAIT2": 0,
		"TIME_WAIT": 0, "CLOSE": 0, "CLOSE_WAIT": 0, "LAST_ACK": 0, "LISTEN": 0, "CLOSING": 0,
	}
	read := func(path string) {
		f, err := os.Open(path)
		if err != nil {
			return
		}
		defer f.Close()
		br := bufio.NewReader(f)
		_, _ = br.ReadString('\n') // header
		for {
			line, err := br.ReadString('\n')
			if err != nil {
				if err == io.EOF {
					break
				}
				return
			}
			fields := strings.Fields(line)
			if len(fields) < 4 {
				continue
			}
			stateHex := fields[3]
			if st := tcpStateName(stateHex); st != "" {
				states[st]++
			}
		}
	}
	read("/proc/net/tcp")
	read("/proc/net/tcp6")
	total := 0
	for _, v := range states {
		total += v
	}
	states["total"] = total
	return states
}

func tcpStateName(hexcode string) string {
	// hexcode like "01" for ESTABLISHED
	switch strings.ToUpper(strings.TrimSpace(hexcode)) {
	case "01":
		return "ESTABLISHED"
	case "02":
		return "SYN_SENT"
	case "03":
		return "SYN_RECV"
	case "04":
		return "FIN_WAIT1"
	case "05":
		return "FIN_WAIT2"
	case "06":
		return "TIME_WAIT"
	case "07":
		return "CLOSE"
	case "08":
		return "CLOSE_WAIT"
	case "09":
		return "LAST_ACK"
	case "0A":
		return "LISTEN"
	case "0B":
		return "CLOSING"
	default:
		return ""
	}
}

// Throughput from /proc/net/dev deltas (excluding "lo"). Also returns
// per-NIC rates computed against the same previous read (host_detail.go),
// busiest interfaces first.
func (d *Detector) readThroughput() (rxMbps, txMbps float64, perNIC []NICRate) {
	now := throughputNow()
	var rx, tx uint64
	nics := map[string]nicCounters{}
	f, err := openNetDev()
	if err != nil {
		return 0, 0, nil
	}
	defer f.Close()
	sc := bufio.NewScanner(f)
	// skip headers
	if sc.Scan() && sc.Scan() {
		for sc.Scan() {
			line := sc.Text()
			iface, rxb, txb, ok := parseNetDevLine(line)
			if !ok || iface == "lo" {
				continue
			}
			rx += rxb
			tx += txb
			nics[iface] = nicCounters{rxBytes: rxb, txBytes: txb}
		}
	}
	if d.lastT.IsZero() {
		// seed for next time
		d.lastRxBytes, d.lastTxBytes, d.lastT = rx, tx, now
		d.lastNIC = nics
		return 0, 0, nil
	}
	dt := now.Sub(d.lastT).Seconds()
	if dt <= 0 {
		return 0, 0, nil
	}
	rxMbps = float64(rx-d.lastRxBytes) * 8.0 / 1e6 / dt
	txMbps = float64(tx-d.lastTxBytes) * 8.0 / 1e6 / dt
	perNIC = perNICRates(d.lastNIC, nics, dt)
	d.lastRxBytes, d.lastTxBytes, d.lastT = rx, tx, now
	d.lastNIC = nics
	return rxMbps, txMbps, perNIC
}

func parseNetDevLine(line string) (iface string, rxBytes, txBytes uint64, ok bool) {
	// iface: <name>: <rx bytes> ... <tx bytes> ...
	col := strings.IndexByte(line, ':')
	if col <= 0 {
		return "", 0, 0, false
	}
	iface = strings.TrimSpace(line[:col])
	fields := strings.Fields(line[col+1:])
	if len(fields) < 16 {
		return "", 0, 0, false
	}
	rxb, _ := strconv.ParseUint(fields[0], 10, 64)
	txb, _ := strconv.ParseUint(fields[8], 10, 64)
	return iface, rxb, txb, true
}

// Temperatures via `sensors` (if present). Returns max °C or 0 if unknown.
func readMaxTempSensors() float64 {
	if _, err := exec.LookPath("sensors"); err != nil {
		return 0
	}
	out, err := exec.Command("sensors").Output()
	if err != nil {
		return 0
	}
	re := regexp.MustCompile(`(?i)(?:temp\d+|Package id \d+):\s*\+?(-?\d+(?:\.\d+)?)°?C`)
	m := re.FindAllStringSubmatch(string(out), -1)
	max := 0.0
	for _, g := range m {
		if v, _ := strconv.ParseFloat(g[1], 64); v > max {
			max = v
		}
	}
	return max
}

// /proc/mdstat parsed into structured array health summary.
func readMdstat() MdstatSummary {
	b, err := os.ReadFile("/proc/mdstat")
	if err != nil {
		return MdstatSummary{Status: "NO RAID"}
	}
	lines := strings.Split(string(b), "\n")
	var out MdstatSummary
	for i := 0; i < len(lines); i++ {
		line := strings.TrimSpace(lines[i])
		if line == "" || strings.HasPrefix(line, "Personalities") || strings.HasPrefix(line, "unused devices") {
			continue
		}
		parts := strings.Fields(line)
		if len(parts) < 4 || parts[1] != ":" || parts[2] != "active" {
			continue
		}
		arr := MdArrayInfo{Name: parts[0]}
		for _, p := range parts[3:] {
			if strings.HasPrefix(p, "raid") {
				arr.Level = p
				break
			}
		}
		for j := i + 1; j < len(lines); j++ {
			l := strings.TrimSpace(lines[j])
			if l == "" {
				break
			}
			if strings.Contains(l, "[") && strings.Contains(l, "/") {
				re := regexp.MustCompile(`\[(\d+)/(\d+)\]`)
				if m := re.FindStringSubmatch(l); len(m) == 3 {
					arr.ExpectedMembers, _ = strconv.Atoi(m[1])
					arr.ActiveMembers, _ = strconv.Atoi(m[2])
				}
				reState := regexp.MustCompile(`\[([U_]+)\]`)
				if m := reState.FindStringSubmatch(l); len(m) == 2 {
					for _, ch := range m[1] {
						if ch == 'U' {
							arr.MemberStates = append(arr.MemberStates, "up")
						} else {
							arr.MemberStates = append(arr.MemberStates, "missing")
						}
					}
				}
			}
			if strings.Contains(l, "recovery =") || strings.Contains(l, "resync =") || strings.Contains(l, "reshape =") || strings.Contains(l, "check =") {
				switch {
				case strings.Contains(l, "recovery ="):
					arr.ProgressPhase = "recovery"
				case strings.Contains(l, "resync ="):
					arr.ProgressPhase = "resync"
				case strings.Contains(l, "reshape ="):
					arr.ProgressPhase = "reshape"
				case strings.Contains(l, "check ="):
					arr.ProgressPhase = "check"
				}
				rePct := regexp.MustCompile(`=\s*([0-9]+(?:\.[0-9]+)?)%`)
				if m := rePct.FindStringSubmatch(l); len(m) == 2 {
					arr.ProgressPct, _ = strconv.ParseFloat(m[1], 64)
				}
			}
		}
		if arr.ExpectedMembers > 0 && arr.ActiveMembers <= arr.ExpectedMembers {
			arr.FailedMissing = arr.ExpectedMembers - arr.ActiveMembers
		}
		out.Arrays = append(out.Arrays, arr)
	}
	if len(out.Arrays) == 0 {
		out.Status = "NO ACTIVE RAID"
		return out
	}
	out.Status = "HEALTHY"
	for _, arr := range out.Arrays {
		if arr.FailedMissing > 0 {
			out.Status = "DEGRADED"
			break
		}
	}
	return out
}

// zpool status parsed into structured per-pool health.
func readZpool() map[string]ZpoolStatus {
	if _, err := exec.LookPath("zpool"); err != nil {
		return map[string]ZpoolStatus{}
	}
	out, err := exec.Command("zpool", "status").Output()
	if err != nil {
		return map[string]ZpoolStatus{}
	}
	res := map[string]ZpoolStatus{}
	sc := bufio.NewScanner(bytes.NewReader(out))
	var cur *ZpoolStatus
	inConfig := false
	for sc.Scan() {
		line := strings.TrimSpace(sc.Text())
		if line == "" && inConfig {
			inConfig = false
			continue
		}
		if strings.HasPrefix(line, "pool:") {
			if cur != nil {
				res[cur.Pool] = *cur
			}
			name := strings.TrimSpace(strings.TrimPrefix(line, "pool:"))
			cur = &ZpoolStatus{Pool: name}
			inConfig = false
			continue
		}
		if cur == nil {
			continue
		}
		if strings.HasPrefix(line, "state:") {
			cur.State = strings.ToUpper(strings.TrimSpace(strings.TrimPrefix(line, "state:")))
			continue
		}
		if strings.HasPrefix(line, "scan:") {
			cur.ScanStatus = strings.TrimSpace(strings.TrimPrefix(line, "scan:"))
			l := strings.ToLower(cur.ScanStatus)
			if strings.Contains(l, "resilver") || strings.Contains(l, "resilvered") {
				cur.Resilvering = !strings.Contains(l, "completed") && !strings.Contains(l, "repaired")
			}
			re := regexp.MustCompile(`([0-9]+(?:\.[0-9]+)?)%`)
			if m := re.FindStringSubmatch(cur.ScanStatus); len(m) == 2 {
				cur.ResilverPercent = m[1] + "%"
			}
			continue
		}
		if strings.HasPrefix(line, "config:") {
			inConfig = true
			continue
		}
		if inConfig {
			parts := strings.Fields(line)
			if len(parts) >= 2 {
				state := strings.ToUpper(parts[1])
				switch state {
				case "ONLINE":
					// healthy
				case "NAME", "STATE", "READ", "WRITE", "CKSUM":
					// header
				default:
					cur.UnhealthyVdevs++
				}
			}
		}
	}
	if cur != nil {
		res[cur.Pool] = *cur
	}
	return res
}

type smartScanEntry struct {
	Device string
	Driver string
}

// SMART summary with adaptive smartctl probe strategies.
func (d *Detector) readSmartSummary() map[string]SmartInfo {
	res := map[string]SmartInfo{}
	if _, err := exec.LookPath("smartctl"); err != nil {
		return res
	}

	devs := d.discoverSmartDevices()
	for _, entry := range devs {
		info, ok := d.probeSmartDevice(entry)
		if !ok && info.Error == "" {
			info.Error = "unable to read SMART"
		}
		res[filepath.Base(entry.Device)] = info
	}
	return res
}

func (d *Detector) discoverSmartDevices() []smartScanEntry {
	if entries := discoverViaSmartctlScanOpen(); len(entries) > 0 {
		return entries
	}
	return discoverViaLsblkAndSysfs()
}

func discoverViaSmartctlScanOpen() []smartScanEntry {
	out, err := exec.Command("smartctl", "--scan-open").CombinedOutput()
	if err != nil && len(out) == 0 {
		return nil
	}
	seen := map[string]bool{}
	var entries []smartScanEntry
	sc := bufio.NewScanner(bytes.NewReader(out))
	for sc.Scan() {
		line := strings.TrimSpace(sc.Text())
		if line == "" || strings.HasPrefix(line, "#") {
			continue
		}
		fields := strings.Fields(line)
		if len(fields) == 0 || !strings.HasPrefix(fields[0], "/dev/") {
			continue
		}
		e := smartScanEntry{Device: fields[0]}
		for i := 1; i < len(fields)-1; i++ {
			if fields[i] == "-d" {
				e.Driver = strings.TrimSpace(fields[i+1])
				break
			}
		}
		key := e.Device + "|" + e.Driver
		if !seen[key] {
			seen[key] = true
			entries = append(entries, e)
		}
	}
	return entries
}

func discoverViaLsblkAndSysfs() []smartScanEntry {
	type lsblkNode struct {
		Name     string      `json:"name"`
		Type     string      `json:"type"`
		Children []lsblkNode `json:"children"`
	}
	type lsblkJSON struct {
		Blockdevices []lsblkNode `json:"blockdevices"`
	}

	out, err := exec.Command("lsblk", "-J", "-o", "NAME,TYPE").Output()
	if err != nil {
		return nil
	}
	var parsed lsblkJSON
	if err := json.Unmarshal(out, &parsed); err != nil {
		return nil
	}

	seen := map[string]bool{}
	var outEntries []smartScanEntry
	var walk func([]lsblkNode)
	walk = func(nodes []lsblkNode) {
		for _, n := range nodes {
			if n.Type == "disk" && n.Name != "" {
				sysPath := filepath.Join("/sys/block", n.Name)
				if fi, err := os.Stat(sysPath); err == nil && fi.IsDir() {
					dev := "/dev/" + n.Name
					if !seen[dev] {
						seen[dev] = true
						outEntries = append(outEntries, smartScanEntry{Device: dev})
					}
				}
			}
			if len(n.Children) > 0 {
				walk(n.Children)
			}
		}
	}
	walk(parsed.Blockdevices)
	return outEntries
}

func (d *Detector) probeSmartDevice(entry smartScanEntry) (SmartInfo, bool) {
	candidates := d.buildProbeCandidates(entry)
	var lastErr string
	for _, driver := range candidates {
		out, err := runSmartctlProbe(entry.Device, driver)
		if !smartProbeSucceeded(out, err) {
			lastErr = smartProbeError(out, err)
			continue
		}
		d.rememberSmartProbe(entry.Device, driver)
		info := parseSmartInfo(entry.Device, out)
		if driver != "" && info.Type == "Unknown" {
			info.Type = strings.ToUpper(driver)
		}
		return info, true
	}
	return SmartInfo{Error: lastErr}, false
}

func (d *Detector) buildProbeCandidates(entry smartScanEntry) []string {
	base := filepath.Base(entry.Device)
	var candidates []string
	seen := map[string]bool{}
	add := func(v string) {
		if !seen[v] {
			seen[v] = true
			candidates = append(candidates, v)
		}
	}

	if entry.Driver != "" {
		add(entry.Driver)
	}
	if cached := d.cachedSmartProbe(entry.Device); cached != "" || (cached == "" && d.hasCachedSmartProbe(entry.Device)) {
		add(cached)
	}
	add("") // native: smartctl -a /dev/...
	if strings.HasPrefix(base, "nvme") {
		add("nvme")
	}
	add("scsi")
	if isUSBBlockDevice(base) {
		add("sat")
		add("sat,12")
		add("usbsunplus")
		add("jmicron")
		add("usbjmicron")
	}
	if looksLikeMegaRaid(base) {
		for i := 0; i < 8; i++ {
			add(fmt.Sprintf("megaraid,%d", i))
		}
	}
	return candidates
}

func runSmartctlProbe(dev, driver string) ([]byte, error) {
	args := []string{"-a"}
	if driver != "" {
		args = append(args, "-d", driver)
	}
	args = append(args, dev)
	return exec.Command("smartctl", args...).CombinedOutput()
}

func smartProbeSucceeded(out []byte, err error) bool {
	l := strings.ToLower(string(out))
	if strings.Contains(l, "unknown usb bridge") ||
		strings.Contains(l, "please specify device type with the -d option") ||
		strings.Contains(l, "unsupported usb bridge") ||
		strings.Contains(l, "unable to detect device type") ||
		strings.Contains(l, "inappropriate ioctl for device") ||
		strings.Contains(l, "device open failed") {
		return false
	}
	if strings.Contains(l, "smart support is: available") ||
		strings.Contains(l, "smart health status") ||
		strings.Contains(l, "nvme smart/health information") ||
		strings.Contains(l, "=== start of information section ===") {
		return true
	}
	return err == nil && len(out) > 0
}

func smartProbeError(out []byte, err error) string {
	msg := strings.TrimSpace(string(out))
	if msg == "" && err != nil {
		msg = err.Error()
	}
	if len(msg) > 180 {
		msg = msg[:180] + "..."
	}
	return msg
}

func parseSmartInfo(dev string, out []byte) SmartInfo {
	info := SmartInfo{}
	l := bytes.ToLower(out)
	switch {
	case bytes.Contains(l, []byte("pass")):
		info.Health = "PASS"
	case bytes.Contains(l, []byte("fail")):
		info.Health = "FAIL"
	}
	// ATA temperature rows: take the RAW_VALUE column (last), not "the first
	// number after the attribute name" — that used to capture the leading 0
	// of the hex FLAG column ("0x0022") and report 0°C on SATA drives.
	// RAW_VALUE may carry a suffix ("35 (Min/Max 20/46)"), so match the
	// leading integer only. NVMe output uses the "Temperature: 37 Celsius"
	// form handled by the fallback.
	if m := regexp.MustCompile(`(?mi)^\s*(?:194\s+Temperature_Celsius|190\s+Airflow_Temperature_Cel)\s+\S+\s+\d{1,3}\s+\d{1,3}\s+\d{1,3}\s+\S+\s+\S+\s+\S+\s+([0-9]{1,3})`).FindSubmatch(out); len(m) == 2 {
		info.TempC = string(m[1])
	} else if m := regexp.MustCompile(`(?mi)^Temperature:\s+([0-9]{1,3})`).FindSubmatch(out); len(m) == 2 {
		info.TempC = string(m[1])
	}
	if m := regexp.MustCompile(`(?mi)(?:Percentage Used:\s+([0-9]{1,3})|Percent_Lifetime_Remain\s+\S+\s+\S+\s+\S+\s+\S+\s+([0-9]{1,3})|Media_Wearout_Indicator\s+\S+\s+\S+\s+\S+\s+\S+\s+([0-9]{1,3}))`).FindSubmatch(out); len(m) >= 2 {
		for i := 1; i < len(m); i++ {
			if len(m[i]) > 0 {
				info.Wear = string(m[i])
				break
			}
		}
	}
	if pctUsed, source, debugRaw, ok := normalizeWear(out); ok {
		info.WearoutPctUsed = &pctUsed
		info.WearoutSource = source
		info.WearDebug = debugRaw
		if info.Wear == "" && debugRaw["source_value"] != "" {
			info.Wear = debugRaw["source_value"]
		}
	}
	info.Model = firstMatch(out, `(?mi)^(?:Device Model|Model Number|Product):\s*(.+)$`)
	info.Serial = firstMatch(out, `(?mi)^Serial Number:\s*(.+)$`)
	info.Type = devType(dev, out)
	return info
}

func normalizeWear(infoRaw []byte) (pctUsed int, source string, raw map[string]string, ok bool) {
	raw = map[string]string{}
	clamp := func(v int) int {
		if v < 0 {
			return 0
		}
		if v > 100 {
			return 100
		}
		return v
	}

	if m := regexp.MustCompile(`(?mi)^Percentage Used:\s*([0-9]{1,3})%?`).FindSubmatch(infoRaw); len(m) == 2 {
		v, _ := strconv.Atoi(string(m[1]))
		v = clamp(v)
		raw["source_value"] = string(m[1])
		raw["nvme_percentage_used"] = string(m[1])
		return v, "nvme.percentage_used", raw, true
	}

	type ataCandidate struct {
		id    string
		name  string
		value int
		raw   int
	}
	attrRe := regexp.MustCompile(`(?mi)^\s*(\d+)\s+([A-Za-z0-9_\-]+)\s+\S+\s+([0-9]{1,3})\s+[0-9]{1,3}\s+[0-9]{1,3}\s+\S+\s+\S+\s+\S+\s+([0-9]+)\s*$`)
	matches := attrRe.FindAllSubmatch(infoRaw, -1)
	cands := make([]ataCandidate, 0, len(matches))
	for _, m := range matches {
		value, _ := strconv.Atoi(string(m[3]))
		rawV, _ := strconv.Atoi(string(m[4]))
		cands = append(cands, ataCandidate{
			id:    string(m[1]),
			name:  strings.ToLower(string(m[2])),
			value: value,
			raw:   rawV,
		})
	}

	remainingStyle := map[string]bool{
		"percent_lifetime_remain": true,
		"ssd_life_left":           true,
		"remaining_life":          true,
		"life_remaining":          true,
		"media_wearout_indicator": true, // common Intel/SATA style, VALUE is usually life remaining
		"wear_leveling_count":     true, // Samsung SATA (attr 177): normalized VALUE declines from 100 (thresh 5)
	}
	usedStyle := map[string]bool{
		"percent_lifetime_used":          true,
		"lifetime_used":                  true,
		"percentage_used":                true,
		"percentage_used_endurance_indi": true,
	}

	for _, c := range cands {
		v := clamp(c.value)
		sourceBase := fmt.Sprintf("ata.attr.%s(%s)", c.id, c.name)
		raw["attr_id"] = c.id
		raw["attr_name"] = c.name
		raw["attr_value"] = strconv.Itoa(c.value)
		raw["attr_raw"] = strconv.Itoa(c.raw)

		if usedStyle[c.name] {
			raw["source_value"] = strconv.Itoa(v)
			return v, sourceBase + ".value_used", raw, true
		}
		if remainingStyle[c.name] {
			raw["source_value"] = strconv.Itoa(v)
			return clamp(100 - v), sourceBase + ".value_remaining", raw, true
		}
	}

	return 0, "", nil, false
}

func isUSBBlockDevice(base string) bool {
	target, err := filepath.EvalSymlinks(filepath.Join("/sys/block", base))
	if err == nil && strings.Contains(strings.ToLower(target), "/usb") {
		return true
	}
	b, err := os.ReadFile(filepath.Join("/sys/block", base, "device", "modalias"))
	return err == nil && strings.HasPrefix(strings.ToLower(strings.TrimSpace(string(b))), "usb:")
}

func looksLikeMegaRaid(base string) bool {
	vendor, _ := os.ReadFile(filepath.Join("/sys/block", base, "device", "vendor"))
	model, _ := os.ReadFile(filepath.Join("/sys/block", base, "device", "model"))
	id := strings.ToUpper(strings.TrimSpace(string(vendor)) + " " + strings.TrimSpace(string(model)))
	return strings.Contains(id, "LSI") ||
		strings.Contains(id, "AVAGO") ||
		strings.Contains(id, "BROADCOM") ||
		strings.Contains(id, "PERC") ||
		strings.Contains(id, "MEGARAID")
}

func (d *Detector) rememberSmartProbe(device, driver string) {
	d.mu.Lock()
	defer d.mu.Unlock()
	d.smartProbeCache[device] = driver
}

func (d *Detector) cachedSmartProbe(device string) string {
	d.mu.Lock()
	defer d.mu.Unlock()
	return d.smartProbeCache[device]
}

func (d *Detector) hasCachedSmartProbe(device string) bool {
	d.mu.Lock()
	defer d.mu.Unlock()
	_, ok := d.smartProbeCache[device]
	return ok
}

func firstMatch(b []byte, pattern string) string {
	re := regexp.MustCompile(pattern)
	m := re.FindSubmatch(b)
	if len(m) == 2 {
		return strings.TrimSpace(string(m[1]))
	}
	return ""
}

func devType(dev string, ident []byte) string {
	if strings.HasPrefix(filepath.Base(dev), "nvme") {
		return "NVMe"
	}
	if bytes.Contains(ident, []byte("Solid State")) || bytes.Contains(bytes.ToUpper(ident), []byte("SSD")) {
		return "SSD"
	}
	// try rotation rate
	if rr := firstMatch(ident, `(?mi)^Rotation Rate:\s*(.+)$`); rr != "" {
		if strings.Contains(strings.ToLower(rr), "rpm") {
			return "HDD"
		}
	}
	return "Unknown"
}

// ------------------- evaluation / alerts -------------------

func (d *Detector) evaluate(s Snapshot) []core.Alert {
	var alerts []core.Alert

	emitExtra := func(kind, key string, extra map[string]string) {
		if d.cool(key, s.Time) {
			merged := map[string]string{
				"window":   d.cfg.Window.String(),
				"cooldown": d.cfg.Cooldown.String(),
				"body":     s.RawJSON,
			}
			for k, v := range extra {
				merged[k] = v
			}
			alerts = append(alerts, core.Alert{
				When:  s.Time,
				Kind:  core.AlertKind(kind),
				Key:   key,
				Count: 1,
				Extra: merged,
			})
		}
	}
	emit := func(kind, key string) {
		emitExtra(kind, key, nil)
	}

	emitS := func(kind, key string, samples []string) {
		if d.cool(key, s.Time) {
			alerts = append(alerts, core.Alert{
				When:    s.Time,
				Kind:    core.AlertKind(kind),
				Key:     key,
				Count:   1,
				Samples: samples,
				Extra: map[string]string{
					"window":   d.cfg.Window.String(),
					"cooldown": d.cfg.Cooldown.String(),
					"body":     s.RawJSON,
				},
			})
		}
	}

	// helper: EWMA baseline
	upd := func(name string, x float64) float64 {
		const alpha = 0.2
		b := d.base[name]
		if b == 0 {
			b = x
		}
		b = alpha*x + (1.0-alpha)*b
		d.base[name] = b
		return b
	}

	// CPU
	if s.CPUCores > 0 {
		pct := (s.Load1 / float64(s.CPUCores)) * 100.0
		if int(pct+0.5) >= d.cfg.CpuLoadPct {
			emit("HEALTH/CPU_HIGH", "cpu")
		}
	}

	// RAM
	if int(s.RamUsedPct+0.5) >= d.cfg.RamUsedPct {
		emit("HEALTH/RAM_HIGH", "ram")
	}

	// Disk /
	if int(s.DiskRootPct+0.5) >= d.cfg.DiskRootPct {
		emit("HEALTH/DISK_ROOT_HIGH", "fs")
	}

	// Disk /tmp
	if d.cfg.TmpUsedPct > 0 && int(s.DiskTmpPct+0.5) >= d.cfg.TmpUsedPct {
		if d.cfg.TmpCleanOlder > 0 {
			removed, freed := cleanupTmp("/tmp", d.cfg.TmpCleanOlder)
			samples := []string{
				fmt.Sprintf("/tmp usage=%.1f%% threshold=%d%% removed_files=%d freed≈%s",
					s.DiskTmpPct, d.cfg.TmpUsedPct, removed, humanBytes(freed)),
			}
			emitS("HEALTH/DISK_TMP_HIGH", "fs.tmp", samples)
		} else {
			emit("HEALTH/DISK_TMP_HIGH", "fs.tmp")
		}
	}

	// --- Total connections spike ---
	bTot := upd("conn.total", float64(s.TCP["total"]))
	tot := s.TCP["total"]
	if tot >= d.cfg.ConnTotalAbs ||
		(tot >= d.cfg.ConnTotalMin &&
			float64(tot) > d.cfg.ConnTotalSpikeX*bTot &&
			tot-int(bTot) >= d.cfg.SpikeMinDelta) {
		emitS("HEALTH/CONN_TOTAL_SPIKE", "net.total",
			[]string{fmt.Sprintf(
				"Total conn spike  cur=%d  baseline≈%.0f  x=%.2f",
				tot, bTot, float64(tot)/maxf(bTot, 1),
			)})
	}

	// --- ESTABLISHED spike ---
	bEst := upd("conn.est", float64(s.TCP["ESTABLISHED"]))
	est := s.TCP["ESTABLISHED"]
	if est >= d.cfg.EstablishedAbs ||
		(est >= d.cfg.EstablishedMin &&
			float64(est) > d.cfg.ConnEstSpikeX*bEst &&
			est-int(bEst) >= d.cfg.SpikeMinDelta) {
		emitS("HEALTH/CONN_EST_SPIKE", "net.est",
			[]string{fmt.Sprintf(
				"ESTABLISHED spike  cur=%d  baseline≈%.0f  x=%.2f",
				est, bEst, float64(est)/maxf(bEst, 1),
			)})
	}

	// --- SYN_RECV spike ---
	bSyn := upd("conn.syn", float64(s.TCP["SYN_RECV"]))
	syn := s.TCP["SYN_RECV"]
	if syn >= d.cfg.SynRecvAbs ||
		(syn >= d.cfg.SynRecvMin &&
			float64(syn) > d.cfg.ConnSynSpikeX*bSyn &&
			syn-int(bSyn) >= d.cfg.SpikeMinDelta) {
		samples := []string{
			fmt.Sprintf("SYN_RECV spike  cur=%d  baseline≈%.0f  x=%.2f",
				syn, bSyn, float64(syn)/maxf(bSyn, 1)),
		}
		if d.cfg.SpikeProbeTopN > 0 {
			top := d.probeSynRecvTalkers(d.cfg.SpikeProbeTopN)
			if len(top) > 0 {
				samples = append(samples, "Top remote IPs (SYN_RECV):")
				samples = append(samples, top...)
			}
		}
		emitS("HEALTH/SYN_RECV_SPIKE", "net.syn", samples)
	}

	// throughput spikes (now with samples)
	bRx := upd("rx", s.RxMbps)
	bTx := upd("tx", s.TxMbps)

	if s.RxMbps >= d.cfg.ThruMinMbps && s.RxMbps > d.cfg.ThruSpikeX*bRx {
		samples := []string{
			fmt.Sprintf("RX spike  rx=%.1f Mbps  baseline≈%.1f  x=%.2f",
				s.RxMbps, bRx, s.RxMbps/maxf(bRx, 1)),
		}
		if d.cfg.SpikeProbeTopN > 0 {
			if top := d.probeTopPIDsByConn(-1, []string{"ESTABLISHED"}, d.cfg.SpikeProbeTopN); len(top) > 0 {
				samples = append(samples, "Top PIDs (ESTABLISHED):")
				samples = append(samples, top...)
			}
			if talk := d.probeTalkersAllPorts([]string{"ESTABLISHED"}, d.cfg.SpikeProbeTopN); len(talk) > 0 {
				samples = append(samples, "Top remote IPs (ESTABLISHED):")
				samples = append(samples, talk...)
			}
		}
		emitS("HEALTH/RX_THRU_SPIKE", "net.rx", samples)
	}

	if s.TxMbps >= d.cfg.ThruMinMbps && s.TxMbps > d.cfg.ThruSpikeX*bTx {
		samples := []string{
			fmt.Sprintf("TX spike  tx=%.1f Mbps  baseline≈%.1f  x=%.2f",
				s.TxMbps, bTx, s.TxMbps/maxf(bTx, 1)),
		}
		if d.cfg.SpikeProbeTopN > 0 {
			if top := d.probeTopPIDsByConn(-1, []string{"ESTABLISHED"}, d.cfg.SpikeProbeTopN); len(top) > 0 {
				samples = append(samples, "Top PIDs (ESTABLISHED):")
				samples = append(samples, top...)
			}
			if talk := d.probeTalkersAllPorts([]string{"ESTABLISHED"}, d.cfg.SpikeProbeTopN); len(talk) > 0 {
				samples = append(samples, "Top remote IPs (ESTABLISHED):")
				samples = append(samples, talk...)
			}
		}
		emitS("HEALTH/TX_THRU_SPIKE", "net.tx", samples)
	}

	// temperature
	if s.TempMaxC >= float64(d.cfg.TempCritC) {
		emit("HEALTH/TEMP_CRITICAL", "hw.temp")
	} else if s.TempMaxC >= float64(d.cfg.TempWarnC) {
		emit("HEALTH/TEMP_WARN", "hw.temp")
	}

	// RAID / ZFS / SMART
	if d.cfg.MdadmAlert && s.Mdadm.Status == "DEGRADED" {
		emit("HEALTH/MDADM_DEGRADED", "disk.raid")
	}
	if d.cfg.ZfsAlert {
		for name, info := range s.Zfs {
			if info.State != "HEALTHY" && info.State != "ONLINE" {
				emit("HEALTH/ZFS_"+info.State, "zfs."+name)
				continue
			}
			if info.UnhealthyVdevs > 0 {
				emit("HEALTH/ZFS_VDEV_DEGRADED", "zfs."+name)
			}
		}
	}
	if d.cfg.SmartAlert {
		for dev, info := range s.Smart {
			health := strings.ToUpper(info.Health)
			if strings.Contains(health, "FAIL") || strings.Contains(health, "CRIT") {
				emit("HEALTH/SMART_FAIL", "smart."+dev)
			}
			if info.WearoutPctUsed != nil {
				extra := map[string]string{
					"smart_device":      dev,
					"wearout_pct_used":  strconv.Itoa(*info.WearoutPctUsed),
					"wearout_source":    info.WearoutSource,
					"wearout_raw_value": info.Wear,
				}
				for k, v := range info.WearDebug {
					extra["wear_debug_"+k] = v
				}
				switch {
				case *info.WearoutPctUsed >= d.cfg.SmartWearCritPct:
					emitExtra("HEALTH/SMART_WEAR_CRIT", "smart.wear."+dev, extra)
				case *info.WearoutPctUsed >= d.cfg.SmartWearWarnPct:
					emitExtra("HEALTH/SMART_WEAR_WARN", "smart.wear."+dev, extra)
				}
			}
		}
	}

	return alerts
}

func (d *Detector) cool(key string, now time.Time) bool {
	cd := d.cfg.Cooldown
	if cd <= 0 {
		cd = 15 * time.Minute
	}
	if t, ok := d.last[key]; ok && now.Sub(t) < cd {
		return false
	}
	d.last[key] = now
	return true
}

func maxf(a, b float64) float64 {
	if a > b {
		return a
	}
	return b
}

// cleanupTmp deletes regular files under root that are older than maxAge.
// It returns number of files removed and total bytes freed.
func cleanupTmp(root string, maxAge time.Duration) (removed int, freedBytes int64) {
	now := time.Now()
	filepath.WalkDir(root, func(path string, d os.DirEntry, err error) error {
		if err != nil {
			return nil
		}
		if d.IsDir() {
			return nil
		}
		info, err := d.Info()
		if err != nil {
			return nil
		}
		// skip sockets/FIFOs/devices just in case
		if !info.Mode().IsRegular() {
			return nil
		}
		if now.Sub(info.ModTime()) < maxAge {
			return nil
		}
		if err := os.Remove(path); err == nil {
			removed++
			freedBytes += info.Size()
		}
		return nil
	})
	return removed, freedBytes
}

// humanBytes renders a rough human-readable size string.
func humanBytes(b int64) string {
	const (
		kb = 1024
		mb = 1024 * kb
		gb = 1024 * mb
	)
	switch {
	case b >= gb:
		return fmt.Sprintf("%.1fGiB", float64(b)/float64(gb))
	case b >= mb:
		return fmt.Sprintf("%.1fMiB", float64(b)/float64(mb))
	case b >= kb:
		return fmt.Sprintf("%.1fKiB", float64(b)/float64(kb))
	default:
		return fmt.Sprintf("%dB", b)
	}
}

// (utility) decode hex-encoded IPv4/IPv6 (debugging aid)
func decodeHexIP(s string) net.IP {
	// s like "0100007F" (IPv4 LE) or 32 hex for IPv6
	b, _ := hex.DecodeString(s)
	switch len(b) {
	case 4:
		// reverse LE
		for i := 0; i < 2; i++ {
			b[i], b[3-i] = b[3-i], b[i]
		}
		return net.IPv4(b[0], b[1], b[2], b[3])
	case 16:
		// Linux /proc/net/tcp6 is BE already
		return net.IP(b)
	default:
		return nil
	}
}

func init() {
	//logging.Logf("[detectors] health loaded")
}

// -------- enrichment helpers (borrowed from exim relays/security style) --------
func (d *Detector) lookupMeta(ip string) string {
	if ip == "" {
		return ""
	}
	var country, city, ptr, asname string
	var asn uint
	if d.enr != nil {
		r := d.enr.Lookup(ip)
		if r.Country != "" {
			country = r.Country
		}
		if r.City != "" {
			city = r.City
		}
		if r.PTR != "" {
			ptr = strings.TrimSuffix(r.PTR, ".")
		}
		if r.ASN > 0 {
			asn = r.ASN
			asname = r.ASNName
		}
	}
	if d.cfg.UsePTR && ptr == "" {
		names, _ := net.LookupAddr(ip)
		if len(names) > 0 {
			ptr = strings.TrimSuffix(names[0], ".")
		}
	}
	geo := ""
	if country != "" || city != "" {
		if country == "" {
			country = "-"
		}
		if city == "" {
			city = "-"
		}
		geo = country + "/" + city
	}
	as := ""
	if asn > 0 && asname != "" {
		as = fmt.Sprintf("[AS%d %s", asn, asname)
	} else if asn > 0 {
		as = fmt.Sprintf("[AS%d", asn)
	}
	if ptr != "" {
		if as != "" {
			as += "; PTR " + ptr + "]"
		} else {
			as = "[PTR " + ptr + "]"
		}
	} else if as != "" {
		as += "]"
	}
	if geo != "" && as != "" {
		return geo + "/" + as
	}
	if geo != "" {
		return geo
	}
	return as
}

// SnapshotNow collects a one-off health snapshot for status CLI.
func SnapshotNow() Snapshot {
	snapshotCollectorMu.Lock()
	defer snapshotCollectorMu.Unlock()
	if snapshotCollector == nil {
		snapshotCollector = New(Config{})
	}
	return snapshotCollector.snapshot()
}

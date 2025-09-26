// internal/detectors/health/health.go
package health

import (
	"bufio"
	"bytes"
	"context"
	"encoding/hex"
	"encoding/json"
	"errors"
	"io"
	"net"
	"os"
	"os/exec"
	"path/filepath"
	"regexp"
	"strconv"
	"strings"
	"sync"
	"syscall"
	"time"
	"fmt"

	core "cfm/internal/detectors/core"
//	"cfm/internal/logging"
	"cfm/internal/enrich"
)

type Config struct {
	Every, Window, Cooldown time.Duration

	CpuLoadPct, RamUsedPct, DiskRootPct int

	ConnTotalSpikeX, ConnEstSpikeX, ConnSynSpikeX float64
	ConnTotalAbs, EstablishedAbs, SynRecvAbs      int

	ThruSpikeX float64

	TempWarnC, TempCritC int

	SmartAlert, MdadmAlert, ZfsAlert bool

	PortWatch  []int
	PortSpikeX float64

	// --- NEW: enrichment & spike probe ---
	SpikeProbeTopN int      // how many top talkers to include on a spike (default 10; 0 disables)
	UseEnrich      bool     // enable ASN/Country/PTR via enricher
	UsePTR         bool     // fallback PTR when enricher is off/misses
	EnrichDirs     []string // enricher databases (e.g. "/etc/cfm", "/usr/share/GeoIP", ...)
}

type Detector struct {
	cfg  Config
	name string

	enr *enrich.Enricher

	mu    sync.Mutex
	last  map[string]time.Time // cooldown per key
	base  map[string]float64   // EWMA baselines

	// throughput deltas
	lastRxBytes uint64
	lastTxBytes uint64
	lastT       time.Time
}

func New(cfg Config) *Detector {

	// sensible defaults
	if cfg.SpikeProbeTopN == 0 { cfg.SpikeProbeTopN = 10 }
	if !cfg.UseEnrich && !cfg.UsePTR { cfg.UsePTR = true }
	if cfg.UseEnrich && len(cfg.EnrichDirs) == 0 {
		cfg.EnrichDirs = []string{"/etc/cfm", "/usr/share/GeoIP", "/usr/local/share/GeoIP", "./configs"}
	}

	d := &Detector{
		cfg:  cfg,
		last: make(map[string]time.Time),
		base: make(map[string]float64),
	}
	if cfg.UseEnrich {
		if e, _ := enrich.New(cfg.EnrichDirs...); e != nil {
			d.enr = e
		}
	}
	return d

}

func (d *Detector) SetName(n string) { d.name = n }
func (d *Detector) Name() string     { if d.name != "" { return d.name } ; return "health" }
func (d *Detector) Every() time.Duration {
	if d.cfg.Every > 0 {
		return d.cfg.Every
	}
	return 10 * time.Second
}

// decorateIP renders "1.2.3.4 [AS1234 Example | US | ptr.example]" if enrich is available.
func (d *Detector) decorateIP(ip string) string {
	if ip == "" { return ip }
	meta := d.lookupMeta(ip)
	if meta == "" { return ip }
	return ip + " [" + meta + "]"
}


// -------- core.PeriodicDetector API (matches your types.go) --------
// Manager calls this once every Every(); we sample + evaluate once.
func (d *Detector) RunOnce(ctx context.Context, out chan<- core.Alert) error {
	// collect
	snap := d.snapshot()

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

	TCP      map[string]int // state counts incl total
	PortConn map[int]int    // approx per-local-port active conns

	RxMbps, TxMbps float64

	TempMaxC float64
	Mdadm    string
	Zfs      map[string]string
	Smart    map[string]SmartInfo

	RawJSON string // pretty JSON to embed in alert Extra["body"]
}

type SmartInfo struct {
	Health string `json:"health"`
	Wear   string `json:"wear"`
	TempC  string `json:"temp_c"`
	Model  string `json:"model,omitempty"`
	Serial string `json:"serial,omitempty"`
	Type   string `json:"type,omitempty"`
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

	// Disk / via syscall.Statfs
	if pct, err := rootUsagePct(); err == nil {
		s.DiskRootPct = pct
	}

	// TCP states + per-port
	s.TCP, s.PortConn = readTCPandPorts()

	// Throughput (deltas since previous RunOnce)
	s.RxMbps, s.TxMbps = d.readThroughput()

	// Temperature (lm-sensors, optional)
	s.TempMaxC = readMaxTempSensors()

	// mdadm
	s.Mdadm = readMdstat()

	// zpool (optional)
	s.Zfs = readZpool()

	// smartctl (optional, minimal)
	s.Smart = readSmartSummary()

	// pretty JSON for sinks/alert body
	body := map[string]any{
		"hostname": s.Host, "time": s.Time.Format(time.RFC3339),
		"cpu_cores": s.CPUCores, "load1": s.Load1,
		"ram_used_pct": s.RamUsedPct, "disk_root_pct": s.DiskRootPct,
		"tcp": s.TCP, "port_conn": s.PortConn,
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

func rootUsagePct() (float64, error) {
	var st syscall.Statfs_t
	if err := syscall.Statfs("/", &st); err != nil {
		return 0, err
	}
	if st.Blocks == 0 {
		return 0, errors.New("blocks=0")
	}
	used := 1.0 - float64(st.Bavail)/float64(st.Blocks)
	return 100.0 * used, nil
}

// Parse /proc/net/tcp and /proc/net/tcp6
// Return (stateCounts, perPortConn)
func readTCPandPorts() (map[string]int, map[int]int) {
	states := map[string]int{
		"ESTABLISHED": 0, "SYN_SENT": 0, "SYN_RECV": 0, "FIN_WAIT1": 0, "FIN_WAIT2": 0,
		"TIME_WAIT": 0, "CLOSE": 0, "CLOSE_WAIT": 0, "LAST_ACK": 0, "LISTEN": 0, "CLOSING": 0,
	}
	perPort := map[int]int{}
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
			// local_address: "HHHHHHHH:PPPP"
			lp := fields[1]
			stateHex := fields[3]
			// state
			if st := tcpStateName(stateHex); st != "" {
				states[st]++
			}
			// per-port (LISTEN/EST/..)
			if p := parseHexPort(lp); p > 0 {
				perPort[p]++
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
	return states, perPort
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

func parseHexPort(local string) int {
	// local like "0100007F:1F90"
	col := strings.IndexByte(local, ':')
	if col < 0 {
		return 0
	}
	phex := local[col+1:]
	p, _ := strconv.ParseInt(phex, 16, 32)
	return int(p)
}

// Throughput from /proc/net/dev deltas (excluding "lo")
func (d *Detector) readThroughput() (rxMbps, txMbps float64) {
	now := time.Now()
	var rx, tx uint64
	f, err := os.Open("/proc/net/dev")
	if err != nil {
		return 0, 0
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
		}
	}
	if d.lastT.IsZero() {
		// seed for next time
		d.lastRxBytes, d.lastTxBytes, d.lastT = rx, tx, now
		return 0, 0
	}
	dt := now.Sub(d.lastT).Seconds()
	if dt <= 0 {
		return 0, 0
	}
	rxMbps = float64(rx-d.lastRxBytes) * 8.0 / 1e6 / dt
	txMbps = float64(tx-d.lastTxBytes) * 8.0 / 1e6 / dt
	d.lastRxBytes, d.lastTxBytes, d.lastT = rx, tx, now
	return rxMbps, txMbps
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

// /proc/mdstat → "HEALTHY", "DEGRADED", "NO ACTIVE RAID"/"NO RAID"
func readMdstat() string {
	b, err := os.ReadFile("/proc/mdstat")
	if err != nil {
		return "NO RAID"
	}
	txt := string(b)
	if !strings.Contains(txt, "active") {
		return "NO ACTIVE RAID"
	}
	if strings.Contains(txt, " DEGRADED") || strings.Contains(txt, "[U_]") || strings.Contains(txt, "[_U]") {
		return "DEGRADED"
	}
	return "HEALTHY"
}

// zpool list -H -o name,health (if zpool exists)
func readZpool() map[string]string {
	if _, err := exec.LookPath("zpool"); err != nil {
		return map[string]string{}
	}
	out, err := exec.Command("zpool", "list", "-H", "-o", "name,health").Output()
	if err != nil {
		return map[string]string{}
	}
	res := map[string]string{}
	sc := bufio.NewScanner(bytes.NewReader(out))
	for sc.Scan() {
		line := strings.TrimSpace(sc.Text())
		if line == "" {
			continue
		}
		parts := strings.Fields(line)
		if len(parts) >= 2 {
			res[parts[0]] = strings.ToUpper(parts[1])
		}
	}
	return res
}

// Minimal SMART summary (per /dev/(sdX|nvmeNn1|vdX|xvdX)). Best-effort, cheap.
func readSmartSummary() map[string]SmartInfo {
	res := map[string]SmartInfo{}
	if _, err := exec.LookPath("smartctl"); err != nil {
		return res
	}
	devs := listBlockDevices()
	for _, dev := range devs {
		info := SmartInfo{}
		// smartctl -H (overall), -A (attributes), -i (model/serial)
		hi, _ := exec.Command("smartctl", "-H", dev).CombinedOutput()
		ai, _ := exec.Command("smartctl", "-A", dev).CombinedOutput()
		ii, _ := exec.Command("smartctl", "-i", dev).CombinedOutput()
		// overall
		if bytes.Contains(bytes.ToLower(hi), []byte("pass")) {
			info.Health = "PASS"
		} else if bytes.Contains(bytes.ToLower(hi), []byte("fail")) {
			info.Health = "FAIL"
		}
		// temp (best-effort)
		reT := regexp.MustCompile(`(?i)(Temperature_Celsius|Temperature:)\s+(\d+)`)
		if m := reT.FindSubmatch(ai); len(m) == 3 {
			info.TempC = string(m[2])
		}
		// wear (for NVMe or SSD attr)
		reWear := regexp.MustCompile(`(?i)(Percent_Lifetime_Remain|Wear_Leveling_Count|Media_Wearout_Indicator)\s+(\d+)`)
		if m := reWear.FindSubmatch(ai); len(m) == 3 {
			info.Wear = string(m[2])
		}
		// id
		info.Model = firstMatch(ii, `(?mi)^(?:Device Model|Model Number):\s*(.+)$`)
		info.Serial = firstMatch(ii, `(?mi)^Serial Number:\s*(.+)$`)
		info.Type = devType(dev, ii)
		res[filepath.Base(dev)] = info
	}
	return res
}

func listBlockDevices() []string {
	// /dev/(nvmeNn1|sdX|vdX|xvdX|hdX)
	var devs []string
	_ = filepath.Walk("/dev", func(path string, info os.FileInfo, err error) error {
		if err == nil && !info.IsDir() {
			base := filepath.Base(path)
			if regexp.MustCompile(`^(sd[a-z]|vd[a-z]|xvd[a-z]|hd[a-z])$`).MatchString(base) ||
				regexp.MustCompile(`^nvme\d+n\d+$`).MatchString(base) {
				devs = append(devs, "/dev/"+base)
			}
		}
		return nil
	})
	return devs
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

	emit := func(kind, key string) {
		if d.cool(key, s.Time) {
			alerts = append(alerts, core.Alert{
				When:  s.Time,
				Kind:  core.AlertKind(kind),
				Key:   key,
				Count: 1,
				Extra: map[string]string{
					"window":   d.cfg.Window.String(),
					"cooldown": d.cfg.Cooldown.String(),
					"body":     s.RawJSON,
				},
			})
		}
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

	// TCP spikes / absolutes
    bTot := upd("conn.total", float64(s.TCP["total"]))
    if s.TCP["total"] >= d.cfg.ConnTotalAbs || float64(s.TCP["total"]) > d.cfg.ConnTotalSpikeX*bTot {
        emitS("HEALTH/CONN_TOTAL_SPIKE", "net.total",
            []string{fmt.Sprintf(
                "Total conn spike  cur=%d  baseline≈%.0f  x=%.2f",
                s.TCP["total"], bTot, float64(s.TCP["total"])/maxf(bTot, 1),
            )})
    }

    bEst := upd("conn.est", float64(s.TCP["ESTABLISHED"]))
    if s.TCP["ESTABLISHED"] >= d.cfg.EstablishedAbs || float64(s.TCP["ESTABLISHED"]) > d.cfg.ConnEstSpikeX*bEst {
        emitS("HEALTH/CONN_EST_SPIKE", "net.est",
            []string{fmt.Sprintf(
                "ESTABLISHED spike  cur=%d  baseline≈%.0f  x=%.2f",
                s.TCP["ESTABLISHED"], bEst, float64(s.TCP["ESTABLISHED"])/maxf(bEst, 1),
            )})
    }

    bSyn := upd("conn.syn", float64(s.TCP["SYN_RECV"]))
    if s.TCP["SYN_RECV"] >= d.cfg.SynRecvAbs || float64(s.TCP["SYN_RECV"]) > d.cfg.ConnSynSpikeX*bSyn {
        samples := []string{
            fmt.Sprintf("SYN_RECV spike  cur=%d  baseline≈%.0f  x=%.2f",
                s.TCP["SYN_RECV"], bSyn, float64(s.TCP["SYN_RECV"])/maxf(bSyn, 1)),
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
	// per-port conn spikes (watchlist)
	for p, c := range s.PortConn {
		if !containsInt(d.cfg.PortWatch, p) {
			continue
		}
		key := "port." + strconv.Itoa(p)
		b := upd(key, float64(c))
		if float64(c) > d.cfg.PortSpikeX*b && c > 50 {
			// include top talkers (if enabled)
			samples := []string{
				fmt.Sprintf("Spike on tcp/%d  conns=%d  baseline≈%.0f  x=%.2f", p, c, b, float64(c)/maxf(b,1)),
			}
			if d.cfg.SpikeProbeTopN > 0 {
				top := d.probeTopTalkers(p, []string{"SYN_RECV", "ESTABLISHED"}, d.cfg.SpikeProbeTopN)
				if len(top) > 0 {
					samples = append(samples, "Top talkers:")
					samples = append(samples, top...)
				}
			}
			emitS("HEALTH/PORT_CONN_SPIKE", key, samples)
		}
	}

	// throughput spikes
	bRx := upd("rx", s.RxMbps)
	bTx := upd("tx", s.TxMbps)
	if s.RxMbps > d.cfg.ThruSpikeX*bRx {
		emit("HEALTH/RX_THRU_SPIKE", "net.rx")
	}
	if s.TxMbps > d.cfg.ThruSpikeX*bTx {
		emit("HEALTH/TX_THRU_SPIKE", "net.tx")
	}

	// temperature
	if s.TempMaxC >= float64(d.cfg.TempCritC) {
		emit("HEALTH/TEMP_CRITICAL", "hw.temp")
	} else if s.TempMaxC >= float64(d.cfg.TempWarnC) {
		emit("HEALTH/TEMP_WARN", "hw.temp")
	}

	// RAID / ZFS / SMART
	if d.cfg.MdadmAlert && strings.Contains(s.Mdadm, "DEGRADED") {
		emit("HEALTH/MDADM_DEGRADED", "disk.raid")
	}
	if d.cfg.ZfsAlert {
		for name, h := range s.Zfs {
			if h != "HEALTHY" && h != "ONLINE" {
				emit("HEALTH/ZFS_"+h, "zfs."+name)
			}
		}
	}
	if d.cfg.SmartAlert {
		for dev, info := range s.Smart {
			health := strings.ToUpper(info.Health)
			if strings.Contains(health, "FAIL") || strings.Contains(health, "CRIT") {
				emit("HEALTH/SMART_FAIL", "smart."+dev)
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

func containsInt(slice []int, v int) bool {
	for _, x := range slice {
		if x == v {
			return true
		}
	}
	return false
}

func maxf(a, b float64) float64 {
	if a > b { return a }
	return b
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
		if r.Country != "" { country = r.Country }
		if r.City != ""    { city = r.City }
		if r.PTR != ""     { ptr = strings.TrimSuffix(r.PTR, ".") }
		if r.ASN > 0       { asn = r.ASN; asname = r.ASNName }
	}
	if d.cfg.UsePTR && ptr == "" {
		names, _ := net.LookupAddr(ip)
		if len(names) > 0 {
			ptr = strings.TrimSuffix(names[0], ".")
		}
	}
	geo := ""
	if country != "" || city != "" {
		if country == "" { country = "-" }
		if city == ""    { city = "-" }
		geo = country + "/" + city
	}
	as := ""
	if asn > 0 && asname != "" {
		as = fmt.Sprintf("[AS%d %s", asn, asname)
	} else if asn > 0 {
		as = fmt.Sprintf("[AS%d", asn)
	}
	if ptr != "" {
		if as != "" { as += "; PTR " + ptr + "]" } else { as = "[PTR " + ptr + "]" }
	} else if as != "" {
		as += "]"
	}
	if geo != "" && as != "" { return geo + "/" + as }
	if geo != "" { return geo }
	return as
}



// SnapshotNow collects a one-off health snapshot for status CLI.
func SnapshotNow() Snapshot {
    d := &Detector{}
    return d.snapshot()
}

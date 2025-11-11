package web

import (
	"context"
	"fmt"
	"io"
	"sort"
	"strconv"
	"strings"
	"time"

	core "cfm/internal/detectors/core"
	"cfm/internal/enrich"
	"cfm/internal/logging"
)

type Kind string
const (
	KindNginx Kind = "nginx"
	KindHTTPD Kind = "httpd"
)

type Config struct {
	Kind     Kind
	Mode     string
	LogPath  string
	Every    time.Duration
	Window   time.Duration
	Cooldown time.Duration

	SampleLimit int

	// thresholds (union: supports both)
	RPSTotalMin    float64
	UniqueIPsMin   int
	ErrRatioMin    float64
	RPS499Min      float64 // nginx typically; httpd often 0
	RPS5xxMin      float64
	MedianIPRPSMax float64

	// optional 401-focused triggers
	RPS401Min       float64
	Auth401RatioMin float64

	// enrichment
	UseEnrich  bool
	UsePTR     bool
	EnrichDirs []string


	// processing time (seconds) – average over window
	// 0 disables the check
	ProcTimeMax float64

}

type Detector struct {
	cfg      Config
	name     string
	src      core.LineSource
	state    *core.State
	stateKey string

	samples *core.SampleRing
	gate    *core.AlertGate

	agg *hostAggregator
	enr *enrich.Enricher
}

type Row struct {
	Host         string  `json:"host"`
	RPSTotal     float64 `json:"rps"`
	R2           float64 `json:"rps_2xx"`
	R3           float64 `json:"rps_3xx"`
	R4           float64 `json:"rps_4xx"`
	R5           float64 `json:"rps_5xx"`
	R499         float64 `json:"rps_499"`
	R401         float64 `json:"rps_401"`
	UniqueIPs    int     `json:"unique_ips"`
	ErrRatio     float64 `json:"err_ratio"`
	Auth401Ratio float64 `json:"auth401_ratio"`
	ProcAvgSec   float64 `json:"proc_avg_sec"`

}

func New(cfg Config) *Detector {
	if cfg.Every <= 0 { cfg.Every = 5 * time.Second }
	if cfg.Window <= 0 { cfg.Window = 60 * time.Second }
	if cfg.Cooldown <= 0 { cfg.Cooldown = 10 * time.Minute }
	if cfg.SampleLimit <= 0 { cfg.SampleLimit = 20 }

	d := &Detector{cfg: cfg}
	d.samples = core.NewSampleRing(cfg.SampleLimit)
	d.gate = core.NewAlertGate(cfg.Cooldown)
	d.agg = NewHostAggregator(cfg.Window, cfg.Every, cfg.SampleLimit)

	if cfg.UseEnrich && len(cfg.EnrichDirs) == 0 {
		cfg.EnrichDirs = []string{"/etc/cfm", "/var/lib/cfm/maxmind"}
	}
	if cfg.UseEnrich {
		if e, _ := enrich.New(cfg.EnrichDirs...); e != nil {
			d.enr = e
			logging.Logf("[detectors][web] enrichment enabled (dirs=%v)", cfg.EnrichDirs)
		}
	}
	return d
}

func (d *Detector) SetName(n string)                    { d.name = n }
func (d *Detector) SetSource(src core.LineSource)       { d.src = src }
func (d *Detector) SetState(st *core.State, key string) { d.state = st; d.stateKey = key }
func (d *Detector) Name() string {
	if d.name != "" { return d.name }
	if d.cfg.Kind == KindHTTPD { return "httpd_access" }
	return "nginx_access"
}
func (d *Detector) Every() time.Duration { return d.cfg.Every }

func (d *Detector) ApplyPosition(p core.Position) {
	if ft, ok := d.src.(*core.FileTailer); ok {
		ft.ApplyResume(p.Inode, p.Offset)
	}
}
func (d *Detector) Position() core.Position {
	if d.src == nil { return core.Position{} }
	off, ino, ts := d.src.Position()
	return core.Position{Offset: off, Inode: ino, TS: ts}
}

func (d *Detector) formatTop(n int) string {
	rows := d.SnapshotTop(n)
	if len(rows) == 0 {
		if d.cfg.Kind == KindHTTPD { return "[httpd-top] (no data)" }
		return "[nginx-top] (no data)"
	}
	b := &strings.Builder{}
	if d.cfg.Kind == KindHTTPD {
		b.WriteString("[httpd-top] host rps 2xx 3xx 4xx 5xx 401 499 err% uniqIP rt_avg\n")
	} else {
		b.WriteString("[nginx-top] host rps 2xx 3xx 4xx 5xx 401 499 err% uniqIP rt_avg\n")
	}
	for _, r := range rows {
		fmt.Fprintf(b, "%s %.2f %.2f %.2f %.2f %.2f %.2f %.2f %.1f%% %d %.3f\n",
			r.Host, r.RPSTotal, r.R2, r.R3, r.R4, r.R5, r.R401, r.R499, r.ErrRatio*100, r.UniqueIPs, r.ProcAvgSec)
	}
	return b.String()
}

func (d *Detector) SnapshotTop(limit int) []Row {
	if d == nil || d.agg == nil { return nil }
	hosts := d.agg.Hosts()
	rows := make([]Row, 0, len(hosts))
	for _, h := range hosts {
		m := d.agg.Metrics(h)
		rows = append(rows, Row{
			Host:         h,
			RPSTotal:     m.RPSTotal,
			R2:           m.RPS2xx,
			R3:           m.RPS3xx,
			R4:           m.RPS4xx,
			R5:           m.RPS5xx,
			R499:         m.RPS499,
			R401:         m.RPS401,
			UniqueIPs:    m.UniqueIPs,
			ErrRatio:     m.ErrRatio,
			Auth401Ratio: m.Auth401Ratio,
	                ProcAvgSec:   m.ProcAvgSec,
		})
	}
	sort.Slice(rows, func(i, j int) bool { return rows[i].RPSTotal > rows[j].RPSTotal })
	if limit > 0 && len(rows) > limit { rows = rows[:limit] }
	return rows
}

func (d *Detector) RunOnce(ctx context.Context, out chan<- core.Alert) error {
	if d.src == nil { return nil }

	// resume pos
	if d.state != nil && d.stateKey != "" {
		if p, ok := d.state.Get(d.stateKey); ok { d.ApplyPosition(p) }
	}

	if err := d.src.Open(); err != nil { return nil }
	defer d.src.Close()

	now := time.Now()
	for {
		line, err := d.src.ReadNext(ctx)
		if err == io.EOF { break }
		if err != nil { break }
		if rec, ok := parseTSV(line); ok {
			d.agg.Add(rec, line)
		}
	}

	// evaluate on rotation
	if d.agg.RotateIfDue(now) {
		for _, host := range d.agg.Hosts() {
			m := d.agg.Metrics(host)

			errBranch := (m.RPS499 >= d.cfg.RPS499Min) || (m.RPS5xx >= d.cfg.RPS5xxMin) || (m.ErrRatio >= d.cfg.ErrRatioMin)
			procBranch := (d.cfg.ProcTimeMax > 0 && m.ProcAvgSec >= d.cfg.ProcTimeMax)
			authBranch := (d.cfg.RPS401Min > 0 && m.RPS401 >= d.cfg.RPS401Min) ||
				(d.cfg.Auth401RatioMin > 0 && m.Auth401Ratio >= d.cfg.Auth401RatioMin)

			trigger := ((m.RPSTotal >= d.cfg.RPSTotalMin) &&
				(m.UniqueIPs >= d.cfg.UniqueIPsMin) &&
				(errBranch || procBranch) &&
				(m.MedianPerIPRPS <= d.cfg.MedianIPRPSMax)) || authBranch

			key := fmt.Sprintf("%s:%s", d.cfg.Kind, host)
			if d.agg.MarkConsecutive(host, trigger) >= 2 &&
				d.gate.Allow(key, now, int(m.RPSTotal), int(d.cfg.RPSTotalMin)) {

				extra := map[string]string{
					"rps_total":     f2(m.RPSTotal),
					"rps_499":       f2(m.RPS499),
					"rps_5xx":       f2(m.RPS5xx),
					"rps_401":       f2(m.RPS401),
					"err_ratio":     f2(m.ErrRatio),
					"auth401_ratio": f2(m.Auth401Ratio),
					"unique_ips":    strconv.Itoa(m.UniqueIPs),
					"median_ip_rps": f2(m.MedianPerIPRPS),
					"rt_avg":        f2(m.ProcAvgSec),
					"rt_max_cfg":    f2(d.cfg.ProcTimeMax),
					"window":        d.cfg.Window.String(),
					"cooldown":      d.cfg.Cooldown.String(),
				}
				topPeek := d.formatTop(5)
				kind := "WEB/ACCESS"
				if d.cfg.Kind == KindNginx { kind = "NGINX/ACCESS_DDOS" }
				if d.cfg.Kind == KindHTTPD { kind = "HTTPD/ACCESS_ANOMALY" }

				out <- core.Alert{
					When:    now,
					Kind:    core.AlertKind(kind),
					Key:     host,
					Count:   int(m.RPSTotal),
					Samples: append([]string{topPeek}, d.agg.SampleLines(host, 20)...),
					Extra:   extra,
				}
			}
		}
	}

	// save pos
	if d.state != nil && d.stateKey != "" {
		d.state.Put(d.stateKey, d.Position())
	}
	return nil
}

func f2(x float64) string { return strconv.FormatFloat(x, 'f', 2, 64) }

// ---- parsing (12-field TSV unified) ----
type LogRec struct {
	TS      float64
	IP      string
	Host    string
	Method  string
	URI     string
	Proto   string
	Status  int
	Bytes   int64
	RT, URT float64
	UA      string
}

func parseTSV(line string) (LogRec, bool) {
	// ts ip host method uri proto status bytes rt urt ref ua
	f := strings.SplitN(line, "\t", 12)
	if len(f) < 12 { return LogRec{}, false }

	ts, _ := strconv.ParseFloat(f[0], 64)
	st, _ := strconv.Atoi(f[6])
	by, _ := strconv.ParseInt(f[7], 10, 64)

    rt, _ := strconv.ParseFloat(zero(f[8]), 64)
    // If Apache wrote microseconds via %D, normalize to seconds.
    if rt > 10000 { // >10ms → likely μs
        rt = rt / 1_000_000.0
    }

	ut, _ := strconv.ParseFloat(zero(f[9]), 64)

	return LogRec{
		TS:     ts,
		IP:     f[1],
		Host:   strings.ToLower(f[2]),
		Method: strings.ToLower(f[3]),
		URI:    strings.ToLower(f[4]),
		Proto:  strings.ToLower(f[5]),
		Status: st,
		Bytes:  by,
		RT:     rt,
		URT:    ut,
		UA:     strings.ToLower(f[11]),
	}, true
}
func zero(s string) string { if s == "" || s == "-" { return "0" }; return s }

// ---- aggregator (same for both kinds) ----
type classCtr struct {
	total, c2xx, c3xx, c4xx, c5xx, c499, c401 int
	ips                                       map[string]int
	sumRT                                     float64
}
type hostAgg struct {
	bkt    [12]classCtr
	idx    int
	last   time.Time
	sample *core.SampleRing
	consec int
}
type hostAggregator struct {
	win, step time.Duration
	hosts     map[string]*hostAgg
}
func NewHostAggregator(win, step time.Duration, sampleCap int) *hostAggregator {
	return &hostAggregator{
		win:   win,
		step:  step,
		hosts: map[string]*hostAgg{},
	}
}
func (a *hostAggregator) get(host string) *hostAgg {
	h := a.hosts[host]
	if h == nil {
		h = &hostAgg{sample: core.NewSampleRing(64), last: time.Now()}
		for i := range h.bkt { h.bkt[i].ips = make(map[string]int) }
		a.hosts[host] = h
	}
	return h
}
func (a *hostAggregator) Add(r LogRec, line string) {
	h := a.get(r.Host)
	b := &h.bkt[h.idx]
	b.total++
	switch r.Status / 100 {
	case 2: b.c2xx++
	case 3: b.c3xx++
	case 4:
		b.c4xx++
		if r.Status == 401 { b.c401++ }
	case 5: b.c5xx++
	}
	if r.Status == 499 { b.c499++ }
	b.ips[r.IP]++
	b.sumRT += r.RT
	h.sample.Add("host:"+r.Host, line)
}
func (a *hostAggregator) RotateIfDue(now time.Time) bool {
	rot := false
	for _, h := range a.hosts {
		if h.last.IsZero() || now.Sub(h.last) >= a.step {
			h.idx = (h.idx + 1) % len(h.bkt)
			h.bkt[h.idx] = classCtr{ips: make(map[string]int)}
			h.last = now
			rot = true
		}
	}
	return rot
}
type Metrics struct {
	RPSTotal, RPS2xx, RPS3xx, RPS4xx, RPS5xx, RPS499, RPS401 float64
	ErrRatio                                                  float64
	UniqueIPs                                                 int
	MedianPerIPRPS                                            float64
	Auth401Ratio                                              float64
	ProcAvgSec                                                float64
}
func (a *hostAggregator) Metrics(host string) Metrics {
	h := a.hosts[host]; if h == nil { return Metrics{} }
	var tot, c2, c3, c4, c5, c499, c401 int
	var sumRT float64
	ipCounts := map[string]int{}
	for i := range h.bkt {
		b := &h.bkt[i]
		tot += b.total; c2 += b.c2xx; c3 += b.c3xx; c4 += b.c4xx; c5 += b.c5xx; c499 += b.c499; c401 += b.c401
		sumRT += b.sumRT
		for ip, n := range b.ips { ipCounts[ip] += n }
	}
	winSec := a.win.Seconds(); if winSec <= 0 { winSec = 1 }
	m := Metrics{
		RPSTotal: float64(tot) / winSec,
		RPS2xx:   float64(c2) / winSec,
		RPS3xx:   float64(c3) / winSec,
		RPS4xx:   float64(c4) / winSec,
		RPS5xx:   float64(c5) / winSec,
		RPS499:   float64(c499) / winSec,
		RPS401:   float64(c401) / winSec,
	}
	if m.RPSTotal > 0 {
		m.ErrRatio = (m.RPS5xx + m.RPS499) / m.RPSTotal
	}
	if m.RPS4xx > 0 {
		m.Auth401Ratio = m.RPS401 / m.RPS4xx
	}
	if tot > 0 {
		m.ProcAvgSec = sumRT / float64(tot)
	}
	// median per-IP RPS (approx)
	m.UniqueIPs = len(ipCounts)
	if m.UniqueIPs > 0 {
		hist := []int{0, 0, 0, 0, 0} // 0-1,1-2,2-5,5-10,10+
		for _, cnt := range ipCounts {
			rps := float64(cnt) / winSec
			switch {
			case rps < 1:
				hist[0]++
			case rps < 2:
				hist[1]++
			case rps < 5:
				hist[2]++
			case rps < 10:
				hist[3]++
			default:
				hist[4]++
			}
		}
		target := (m.UniqueIPs + 1) / 2
		sum := 0
		for i, hcnt := range hist {
			sum += hcnt
			if sum >= target {
				switch i {
				case 0: m.MedianPerIPRPS = 0.5
				case 1: m.MedianPerIPRPS = 1.5
				case 2: m.MedianPerIPRPS = 3.0
				case 3: m.MedianPerIPRPS = 7.0
				default: m.MedianPerIPRPS = 12.0
				}
				break
			}
		}
	}
	return m
}
func (a *hostAggregator) Hosts() []string {
	keys := make([]string, 0, len(a.hosts))
	for k := range a.hosts { keys = append(keys, k) }
	return keys
}
func (a *hostAggregator) MarkConsecutive(host string, ok bool) int {
	h := a.hosts[host]; if h == nil { return 0 }
	if ok { h.consec++ } else { h.consec = 0 }
	return h.consec
}
func (a *hostAggregator) SampleLines(host string, n int) []string {
	h := a.hosts[host]; if h == nil { return nil }
	key := "host:" + host
	all := h.sample.GetAndClear(key)
	if n > 0 && len(all) > n { return all[len(all)-n:] }
	return all
}

// internal/webdetector/engine.go
package webdetector

import (
	"context"
	"encoding/json"
	"io"
	"net"
	"sort"
	"strconv"
	"strings"
	"sync"
	"time"

	core "cfm/internal/detectors/core"
	"cfm/internal/enrich"
	"cfm/internal/logging"
)

// LogRec is one TSV log line parsed.
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
	Ref     string
}

// parseTSV parses the TSV log format used by access_cfm_tsv.log.
// ts ip host method uri proto status bytes rt urt ref ua
func parseTSV(line string) (LogRec, bool) {
	f := strings.SplitN(line, "\t", 12)
	if len(f) < 12 {
		return LogRec{}, false
	}
	ts, _ := strconv.ParseFloat(f[0], 64)
	st, _ := strconv.Atoi(f[6])
	by, _ := strconv.ParseInt(f[7], 10, 64)

	rt, _ := strconv.ParseFloat(zero(f[8]), 64)
	// If Apache wrote microseconds via %D, normalize to seconds.
	if rt > 10000 {
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
		Ref:    strings.ToLower(f[10]),
	}, true
}

func zero(s string) string {
	if s == "" || s == "-" {
		return "0"
	}
	return s
}

type bucketSW struct {
	from, to time.Time
	total    int

	c2xx  int
	c3xx  int
	c4xx  int
	c5xx  int
	c401  int
	c403  int
	c404  int
	c500  int
	c502  int
	c503  int
	c504  int
	c499  int

	sumRT    float64
	sumBytes int64

	ips   map[string]int
	uas   map[string]int
	refs  map[string]int
	paths map[string]int
}

type hostState struct {
	buckets []bucketSW
	samples *core.SampleRing
}

// ShortRow is the short-window row for webtop.
type ShortRow struct {
	Host         string  `json:"host"`
	RPS          float64 `json:"rps"`
	R2xx         float64 `json:"rps_2xx"`
	R3xx         float64 `json:"rps_3xx"`
	R4xx         float64 `json:"rps_4xx"`
	R5xx         float64 `json:"rps_5xx"`
	R401         float64 `json:"rps_401"`
	R403         float64 `json:"rps_403"`
	R404         float64 `json:"rps_404"`
	R499         float64 `json:"rps_499"`
	UniqueIPs    int     `json:"unique_ips"`
	ErrRatio     float64 `json:"err_ratio"`
	Auth401Ratio float64 `json:"auth401_ratio"`
	ProcAvgSec   float64 `json:"proc_avg_sec"`
	Score        float64 `json:"score"`
	Reasons      []string `json:"reasons"`
	BytesRPS float64 `json:"bytes_rps"`
}

// TopKV for drilldown views.
type TopKV struct {
	Key   string `json:"key"`
	Count int    `json:"count"`
}

// HostDetail is the drill-down view for a single host over the short window.
type HostDetail struct {
	Host           string           `json:"host"`
	WindowSec      float64          `json:"window_sec"`
	TotalReq       int              `json:"total_req"`
	DirectPct      float64          `json:"direct_pct"`
	BotPct         float64          `json:"bot_pct"`
	ProcAvgSec     float64          `json:"proc_avg_sec"`
	TopIPs         []TopKV          `json:"top_ips"`
	TopAgents      []TopKV          `json:"top_agents"`
	TopReferrers   []TopKV          `json:"top_referrers"`
	TopPaths       []TopKV          `json:"top_paths"`
	EnrichedTopIPs []map[string]string `json:"enriched_top_ips,omitempty"`
}

// HotIPRow είναι global aggregated view per IP.
type HotIPRow struct {
    IP      string `json:"ip"`
    Req     int    `json:"req"`
    Vhosts  int    `json:"vhosts"`

    PTR     string `json:"ptr,omitempty"`
    ASN     string `json:"asn,omitempty"`
    ASNName string `json:"asn_name,omitempty"`
    Country string `json:"country,omitempty"`
}


// Engine is the main web detector instance.
type Engine struct {
	cfg      Config
	src      core.LineSource
	state    *core.State
	stateKey string

	mu    sync.RWMutex
	hosts map[string]*hostState

	longwin *LongWindow
	scorer  Scorer
	enr     *enrich.Enricher

	lastFeed time.Time // last time we fed long-window
}

// NewEngine creates a webdetector Engine. It does NOT start any goroutines.
func NewEngine(cfg Config) *Engine {
	cfg.FillDefaults()


	e := &Engine{
		cfg:   cfg,
		hosts: make(map[string]*hostState),
		scorer:  DefaultScorer(),
		longwin: NewLongWindow(cfg.LongHorizon(), cfg.Window, DefaultScorer()),
	}

	// Enrichment is optional.
	if cfg.UseEnrich {
		dirs := cfg.EnrichDirs
		if len(dirs) == 0 {
			dirs = []string{"/var/lib/cfm/maxmind", "/etc/cfm"}
		}
		if enr, err := enrich.New(dirs...); err == nil {
			e.enr = enr
			logging.Logf("[webdetector] enrichment enabled (dirs=%v)", dirs)
		} else {
			logging.Logf("[webdetector] enrichment init failed: %v", err)
		}
	}

	return e
}

// --- integration with detectors framework ---

func (e *Engine) SetSource(src core.LineSource)       { e.src = src }
func (e *Engine) SetState(st *core.State, key string) { e.state = st; e.stateKey = key }
func (e *Engine) Every() time.Duration                { return e.cfg.Every }

// Name implements core.PeriodicDetector.
func (e *Engine) Name() string {
    return "webdetector"
}


func (e *Engine) ApplyPosition(p core.Position) {
	if ft, ok := e.src.(*core.FileTailer); ok {
		ft.ApplyResume(p.Inode, p.Offset)
	}
}
func (e *Engine) Position() core.Position {
	if e.src == nil {
		return core.Position{}
	}
	off, ino, ts := e.src.Position()
	return core.Position{Offset: off, Inode: ino, TS: ts}
}

// RunOnce reads new log lines, updates short-window state, and periodically
// feeds the long-window ring. It does NOT currently emit Alerts (L7 autotune),
// only maintains data for webtop/HTTP API.
func (e *Engine) RunOnce(ctx context.Context, out chan<- core.Alert) error {
	if e.src == nil {
		return nil
	}

	// resume pos
	if e.state != nil && e.stateKey != "" {
		if p, ok := e.state.Get(e.stateKey); ok {
			e.ApplyPosition(p)
		}
	}

	if err := e.src.Open(); err != nil {
		return nil
	}
	defer e.src.Close()

	now := time.Now()
	for {
		line, err := e.src.ReadNext(ctx)
		if err == io.EOF {
			break
		}
		if err != nil {
			break
		}
		rec, ok := parseTSV(line)
		if !ok {
			continue
		}
		e.ingest(rec, line)
	}

	// Feed long-window approx once per short-window horizon.
	if e.lastFeed.IsZero() || now.Sub(e.lastFeed) >= e.cfg.Window {
		snap := e.snapshotMini(now)
		e.longwin.Tick(now, snap)
		e.lastFeed = now
	}

	// save pos
	if e.state != nil && e.stateKey != "" {
		e.state.Put(e.stateKey, e.Position())
	}
	return nil
}

// ingest updates per-host buckets with one log record.
func (e *Engine) ingest(rec LogRec, rawLine string) {
	host := rec.Host
	if host == "" {
		return
	}

	t := tsToTime(rec.TS)
	e.mu.Lock()
	defer e.mu.Unlock()

	hs := e.hosts[host]
	if hs == nil {
		hs = &hostState{
			buckets: make([]bucketSW, 0, 16),
			samples: core.NewSampleRing(e.cfg.SampleLimit),
		}
		e.hosts[host] = hs
	}

	// Append sample line (for debugging / future ML).
	hs.samples.Add(host, rawLine)

	bDur := e.cfg.Every
	if bDur <= 0 {
		bDur = 5 * time.Second
	}

	// rotate/prune old buckets
	cutoff := t.Add(-e.cfg.Window)
	i := 0
	for ; i < len(hs.buckets); i++ {
		if hs.buckets[i].to.After(cutoff) {
			break
		}
	}
	if i > 0 {
		hs.buckets = append([]bucketSW(nil), hs.buckets[i:]...)
	}

	// ensure current bucket
	var b *bucketSW
	if len(hs.buckets) == 0 {
		start := t.Truncate(bDur)
		hs.buckets = append(hs.buckets, newBucketSW(start, bDur))
		b = &hs.buckets[0]
	} else {
		last := &hs.buckets[len(hs.buckets)-1]
		if !t.Before(last.to) {
			start := t.Truncate(bDur)
			hs.buckets = append(hs.buckets, newBucketSW(start, bDur))
			b = &hs.buckets[len(hs.buckets)-1]
		} else {
			b = last
		}
	}

	// aggregate stats
b.total++
switch rec.Status / 100 {
case 2:
	b.c2xx++
case 3:
	b.c3xx++
case 4:
	b.c4xx++
	switch rec.Status {
	case 401:
		b.c401++
	case 403:
		b.c403++
	case 404:
		b.c404++
	}
case 5:
	b.c5xx++
	switch rec.Status {
	case 500:
		b.c500++
	case 502:
		b.c502++
	case 503:
		b.c503++
	case 504:
		b.c504++
	}
}

	if rec.Status == 499 {
		b.c499++
	}

	if b.ips == nil {
		b.ips = make(map[string]int)
	}
	if rec.IP != "" {
		b.ips[rec.IP]++
	}

	if b.uas == nil {
		b.uas = make(map[string]int)
	}
	if rec.UA != "" {
		b.uas[rec.UA]++
	}

	if b.refs == nil {
		b.refs = make(map[string]int)
	}
	ref := rec.Ref
	if ref == "" || ref == "-" {
		ref = "(direct)"
	}
	b.refs[ref]++

	if b.paths == nil {
		b.paths = make(map[string]int)
	}
	p := rec.URI
	if p == "" || p == "-" {
		p = "/"
	}
	if i := strings.IndexByte(p, '?'); i >= 0 {
		p = p[:i]
	}
	b.paths[p]++

	b.sumRT += rec.RT
	b.sumBytes += rec.Bytes


}

func newBucketSW(start time.Time, dur time.Duration) bucketSW {
	return bucketSW{
		from:  start,
		to:    start.Add(dur),
		ips:   make(map[string]int),
		uas:   make(map[string]int),
		refs:  make(map[string]int),
		paths: make(map[string]int),
	}
}

func tsToTime(ts float64) time.Time {
	sec := int64(ts)
	nsec := int64((ts - float64(sec)) * float64(time.Second))
	return time.Unix(sec, nsec)
}


// snapshotMiniLocked builds MiniMetrics per host from current short-window buckets.
// Προϋποθέτει ότι ο caller κρατά ήδη e.mu.RLock ή Lock.
func (e *Engine) snapshotMiniLocked(now time.Time) map[string]MiniMetrics {
        out := make(map[string]MiniMetrics, len(e.hosts))
	for host, hs := range e.hosts {
		if len(hs.buckets) == 0 {
			continue
		}

                var tot, c2, c3, c4, c5, c401, c403, c404, c499 int
                var c500, c502, c503, c504 int
                var sumRT float64
                var sumBytes int64
                ipCounts := map[string]int{}

		first := hs.buckets[0].from
		last := hs.buckets[len(hs.buckets)-1].to
		winSec := last.Sub(first).Seconds()
		if winSec <= 0 {
			winSec = e.cfg.Window.Seconds()
		}
		if winSec <= 0 {
			winSec = 1
		}

                for i := range hs.buckets {
                        b := &hs.buckets[i]
                        tot += b.total
                        c2 += b.c2xx
                        c3 += b.c3xx
                        c4 += b.c4xx
                        c5 += b.c5xx
                        c401 += b.c401
                        c403 += b.c403
                        c404 += b.c404
                        c499 += b.c499
                        c500 += b.c500
                        c502 += b.c502
                        c503 += b.c503
                        c504 += b.c504
                        sumRT += b.sumRT
                        sumBytes += b.sumBytes
                        for ip, n := range b.ips {
                                ipCounts[ip] += n
                        }
                }


		if tot == 0 {
			continue
		}

                m := MiniMetrics{}
                m.RPSTotal = float64(tot) / winSec
                m.RPS2xx   = float64(c2)  / winSec
                m.RPS3xx   = float64(c3)  / winSec
                m.RPS4xx   = float64(c4)  / winSec
                m.RPS5xx   = float64(c5)  / winSec
                m.RPS401   = float64(c401)/ winSec
                m.RPS403   = float64(c403)/ winSec
                m.RPS404   = float64(c404)/ winSec
                m.RPS499   = float64(c499)/ winSec

                // 50x breakdown (χωρίς 504, που το κρατάμε ξεχωριστά)
                c50x := c500 + c502 + c503
                m.RPS50x = float64(c50x) / winSec
                m.RPS504 = float64(c504) / winSec


		m.ErrRatio = float64(c4+c5+c499) / float64(tot)
		if m.ErrRatio < 0 {
			m.ErrRatio = 0
		}
		if m.ErrRatio > 1 {
			m.ErrRatio = 1
		}

                m.Auth401Ratio = float64(c401) / float64(tot)

                // bytes/sec
                if winSec > 0 {
                        m.BytesRPS = float64(sumBytes) / winSec
                }


		// median per-IP RPS (approx)
		if len(ipCounts) > 0 {
                        m.UniqueIPs = len(ipCounts)
                        vals := make([]float64, 0, len(ipCounts))

                        // μετράμε και “ζεστές” IPs
                        hotCount := 0
                        const hotRPS = 1.0 // TODO: κάν’ το tunable αν θέλεις

                        for _, cnt := range ipCounts {
                                rps := float64(cnt) / winSec
                                vals = append(vals, rps)
                                if rps >= hotRPS {
                                        hotCount++
                                }
                        }
                        sort.Float64s(vals)
                        m.MedianPerIPRPS = vals[len(vals)/2]
                        m.HotIPs = hotCount
		}

		out[host] = m
	}
	return out
}

// snapshotMini είναι safe wrapper για callers που δεν κρατούν το mutex.
func (e *Engine) snapshotMini(now time.Time) map[string]MiniMetrics {
        e.mu.RLock()
        defer e.mu.RUnlock()
        return e.snapshotMiniLocked(now)
}


// TopShort returns short-window stats + score for all hosts, sorted by RPS.
func (e *Engine) TopShort(limit int) []ShortRow {

	now := time.Now()

        e.mu.RLock()
        defer e.mu.RUnlock()
        snap := e.snapshotMiniLocked(now)

	rows := make([]ShortRow, 0, len(snap))
	for host, m := range snap {
                sig := Signals{
                        RPS:          m.RPSTotal,
                        R3xx:         m.RPS3xx,
                        R4xx:         m.RPS4xx,
                        R5xx:         m.RPS5xx,

                        R401:         m.RPS401,
                        R403:         m.RPS403,
                        R404:         m.RPS404,

                        R50x:         m.RPS50x,
                        R504:         m.RPS504,

                        ErrRatio:     m.ErrRatio,
                        Auth401Ratio: m.Auth401Ratio,
                        UniqueIPs:    m.UniqueIPs,
                        MedianPerIP:  m.MedianPerIPRPS,
                        BytesRPS:     m.BytesRPS,
                        HotIPs:       m.HotIPs,
                }
		res := e.scorer.Score(sig)

		// derive proc avg sec from mini (we stored total RT / total req inside buckets)
		// we don't keep sumRT in MiniMetrics; approximate by using last bucket set:
		procAvg := 0.0
		if hs := e.hosts[host]; hs != nil && len(hs.buckets) > 0 {
			var sumRT float64
			var tot int
			for i := range hs.buckets {
				sumRT += hs.buckets[i].sumRT
				tot += hs.buckets[i].total
			}
			if tot > 0 {
				procAvg = sumRT / float64(tot)
			}
		}

		rows = append(rows, ShortRow{
			Host:         host,
			RPS:          m.RPSTotal,
			R2xx:         m.RPS2xx,
			R3xx:         m.RPS3xx,
			R4xx:         m.RPS4xx,
			R5xx:         m.RPS5xx,

			R401:         m.RPS401,
			R403:         m.RPS403,
			R404:         m.RPS404,
			R499:         m.RPS499,

			UniqueIPs:    m.UniqueIPs,
			ErrRatio:     m.ErrRatio,
			Auth401Ratio: m.Auth401Ratio,
			ProcAvgSec:   procAvg,
			Score:        res.Score,
			Reasons:      res.Reasons,
		})
	}
	sort.Slice(rows, func(i, j int) bool {
		if rows[i].RPS == rows[j].RPS {
			return rows[i].Host < rows[j].Host
		}
		return rows[i].RPS > rows[j].RPS
	})
	if limit > 0 && len(rows) > limit {
		rows = rows[:limit]
	}
	return rows
}

// HostDetail returns top IPs/Agents/Referrers/Paths for a host in the short window.
func (e *Engine) HostDetail(host string, topN int) HostDetail {
	e.mu.RLock()
	defer e.mu.RUnlock()

	hs := e.hosts[host]
	if hs == nil {
		return HostDetail{Host: host, WindowSec: e.cfg.Window.Seconds()}
	}

	if len(hs.buckets) == 0 {
		return HostDetail{Host: host, WindowSec: e.cfg.Window.Seconds()}
	}

	var tot, direct int
	ipc := map[string]int{}
	uac := map[string]int{}
	rfc := map[string]int{}
	ptc := map[string]int{}
	var sumRT float64

	first := hs.buckets[0].from
	last := hs.buckets[len(hs.buckets)-1].to
	winSec := last.Sub(first).Seconds()
	if winSec <= 0 {
		winSec = e.cfg.Window.Seconds()
	}
	if winSec <= 0 {
		winSec = 1
	}

	for i := range hs.buckets {
		b := &hs.buckets[i]
		tot += b.total
		sumRT += b.sumRT
		for k, v := range b.ips {
			ipc[k] += v
		}
		for k, v := range b.uas {
			uac[k] += v
		}
		for k, v := range b.refs {
			rfc[k] += v
			if k == "(direct)" {
				direct += v
			}
		}
		for k, v := range b.paths {
			ptc[k] += v
		}
	}

	top := func(m map[string]int) []TopKV {
		out := make([]TopKV, 0, len(m))
		for k, v := range m {
			out = append(out, TopKV{Key: k, Count: v})
		}
		sort.Slice(out, func(i, j int) bool { return out[i].Count > out[j].Count })
		if topN > 0 && len(out) > topN {
			out = out[:topN]
		}
		return out
	}

	props := HostDetail{
		Host:       host,
		WindowSec:  winSec,
		TotalReq:   tot,
		DirectPct:  pct(direct, tot),
		ProcAvgSec: 0,
		TopIPs:       top(ipc),
		TopAgents:    top(uac),
		TopReferrers: top(rfc),
		TopPaths:     top(ptc),
	}

	if tot > 0 {
		props.ProcAvgSec = sumRT / float64(tot)
	}

	// simplistic bot%: UAs containing common bot substrings.
	botLike := func(ua string) bool {
		sub := []string{"bot", "spider", "crawl", "scanner", "ahrefs", "semrush", "python-requests", "curl", "wget", "headless", "puppeteer"}
		l := strings.ToLower(ua)
		for _, s := range sub {
			if strings.Contains(l, s) {
				return true
			}
		}
		return false
	}
	var botHits int
	for ua, cnt := range uac {
		if botLike(ua) {
			botHits += cnt
		}
	}
	props.BotPct = pct(botHits, tot)

	// Enrich top IPs via MaxMind if enabled.
	if e.enr != nil && len(props.TopIPs) > 0 {
		enriched := make([]map[string]string, 0, len(props.TopIPs))
		for _, kv := range props.TopIPs {
			ipStr := kv.Key
			if net.ParseIP(ipStr) == nil {
				continue
			}
			info := map[string]string{
				"ip":    ipStr,
				"count": strconv.Itoa(kv.Count),
			}
			enriched = append(enriched, info)

                        // Enricher.Lookup returns a value struct (no nil check needed)
                        geo := e.enr.Lookup(ipStr)
                        if geo.PTR != "" {
                                info["ptr"] = geo.PTR
                        }
                        if geo.ASN != 0 {
                                    info["asn"] = strconv.FormatUint(uint64(geo.ASN), 10)
                        }
                        if geo.ASNName != "" {
                                info["asn_name"] = geo.ASNName
                        }
                        if geo.Country != "" {
                                info["country"] = geo.Country


			}
		}
		if len(enriched) > 0 {
			props.EnrichedTopIPs = enriched
		}
	}

	return props
}

func pct(a, b int) float64 {
	if b <= 0 {
		return 0
	}
	return 100 * float64(a) / float64(b)
}

// Marshalable helper for debugging.
func (e *Engine) DebugDump() string {
	e.mu.RLock()
	defer e.mu.RUnlock()
	b, _ := json.MarshalIndent(e.TopShort(0), "", "  ")
	return string(b)
}




// HotIPs υπολογίζει global "ζεστά" IPs από το short-window state.
// Δεν κρατά extra state· περνάει όλα τα hosts και τα buckets και μαζεύει per-IP counters.
func (e *Engine) HotIPs(limit int) []HotIPRow {
    e.mu.RLock()
    defer e.mu.RUnlock()

    type agg struct {
        req   int
        hosts map[string]struct{}
    }

    stats := make(map[string]*agg)

    for host, hs := range e.hosts {
        if hs == nil {
            continue
        }
        for i := range hs.buckets {
            b := &hs.buckets[i]
            for ip, n := range b.ips {
                a := stats[ip]
                if a == nil {
                    a = &agg{
                        hosts: make(map[string]struct{}),
                    }
                    stats[ip] = a
                }
                a.req += n
                a.hosts[host] = struct{}{}
            }
        }
    }

    rows := make([]HotIPRow, 0, len(stats))
    for ip, a := range stats {
        row := HotIPRow{
            IP:     ip,
            Req:    a.req,
            Vhosts: len(a.hosts),
        }

        // enrichment αν είναι ενεργό
        if e.enr != nil && net.ParseIP(ip) != nil {
            geo := e.enr.Lookup(ip)
            if geo.PTR != "" {
                row.PTR = geo.PTR
            }
            if geo.ASN != 0 {
                // κρατάμε το νούμερο σαν string, το "AS" prefix το βάζουμε στο CLI
                row.ASN = strconv.FormatUint(uint64(geo.ASN), 10)
            }
            if geo.ASNName != "" {
                row.ASNName = geo.ASNName
            }
            if geo.Country != "" {
                row.Country = geo.Country
            }
        }

        rows = append(rows, row)
    }

    sort.Slice(rows, func(i, j int) bool {
        if rows[i].Req == rows[j].Req {
            return rows[i].IP < rows[j].IP
        }
        return rows[i].Req > rows[j].Req
    })

    if limit > 0 && len(rows) > limit {
        rows = rows[:limit]
    }
    return rows
}

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
	"math"

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

// isBotUA κάνει ένα απλό substring-based detection για bot-like UAs.
// Το χρησιμοποιούμε και στο short drilldown και στο short snapshot (MiniMetrics).
func isBotUA(ua string) bool {
        sub := []string{
                "bot", "spider", "crawl", "scanner",
                "ahrefs", "semrush",
                "python-requests", "curl", "wget",
                "headless", "puppeteer",
        }
        l := strings.ToLower(ua)
        for _, s := range sub {
            if strings.Contains(l, s) {
                    return true
            }
        }
        return false
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

        // Method mix
        cGET   int
        cPOST  int
        cHEAD  int
        cOTHER int

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

        BotRatio      float64 `json:"bot_ratio"`
        UADiversity   float64 `json:"ua_diversity"`
        PathDiversity float64 `json:"path_diversity"`
        PostRatio     float64 `json:"post_ratio"`
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
        PathDiversity  float64          `json:"path_diversity"`
        UniquePaths    int              `json:"unique_paths"`
        UADiversity    float64          `json:"ua_diversity"`
        UniqueUAs      int              `json:"unique_uas"`
        PostRatio      float64          `json:"post_ratio"`
	ProcAvgSec     float64          `json:"proc_avg_sec"`

        // Short-window scoring for this vhost
        ShortScore     float64          `json:"short_score"`
        ShortReasons   []string         `json:"short_reasons"`

	TopIPs         []TopKV          `json:"top_ips"`
	TopAgents      []TopKV          `json:"top_agents"`
	TopReferrers   []TopKV          `json:"top_referrers"`
	TopPaths       []TopKV          `json:"top_paths"`
	EnrichedTopIPs []map[string]string `json:"enriched_top_ips,omitempty"`

        // Feature dump (για ML / debug)
        MedianPerIPRPS float64          `json:"median_per_ip_rps"`
        BytesRPS       float64          `json:"bytes_rps"`
        HotIPs         int              `json:"hot_ips"`
        FailureIndex   float64          `json:"failure_index"`
        UAEntropy      float64          `json:"ua_entropy"`
        PathEntropy    float64          `json:"path_entropy"`
        IPSkew         float64          `json:"ip_skew"`

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

// IPDetail είναι short-window drilldown για ένα IP.
type IPDetail struct {
    IP        string  `json:"ip"`
    WindowSec float64 `json:"window_sec"`
    Req       int     `json:"req"`
    Vhosts    int     `json:"vhosts"`

    // per-vhost breakdown
    Hosts []TopKV `json:"hosts"`

    // απλό rate
    RPS float64 `json:"rps"`

    // enrichment
    PTR     string `json:"ptr,omitempty"`
    ASN     string `json:"asn,omitempty"`
    ASNName string `json:"asn_name,omitempty"`
    Country string `json:"country,omitempty"`
}

// IPSignals είναι το "full" IP-level row με score & προτάσεις.
type IPSignals struct {
    IP      string   `json:"ip"`
    Req     int      `json:"req"`
    Vhosts  int      `json:"vhosts"`
    RPS     float64  `json:"rps"`
    Score   float64  `json:"score"`
    Reasons []string `json:"reasons,omitempty"`

    PTR     string `json:"ptr,omitempty"`
    ASN     string `json:"asn,omitempty"`
    ASNName string `json:"asn_name,omitempty"`
    Country string `json:"country,omitempty"`

    Proposals []IPActionProposal `json:"proposals,omitempty"`
}

// IPActionProposal είναι απλές firewall / notify προτάσεις για την IP.
type IPActionProposal struct {
    Action     string  `json:"action"`                // "block", "notify", "watch", ...
    Reason     string  `json:"reason"`                // π.χ. "ip_score_high"
    Score      float64 `json:"score"`                 // το score που οδήγησε στην πρόταση
    TTLSeconds int     `json:"ttl_seconds,omitempty"` // π.χ. block για 900s
}


// ipLongAgg κρατά “μαλακά” averages για το long window.
type ipLongAgg struct {
    Req    float64
    Vhosts float64
    RPS    float64
}

// ipLongMem είναι το global IP long-window state.
type ipLongMem struct {
    mu         sync.RWMutex
    stats      map[string]*ipLongAgg
    lastUpdate time.Time
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
	ipLong *ipLongMem  // long-window IP aggregates (EMA)

}

// NewEngine creates a webdetector Engine. It does NOT start any goroutines.
func NewEngine(cfg Config) *Engine {
	cfg.FillDefaults()


	e := &Engine{
		cfg:   cfg,
		hosts: make(map[string]*hostState),
		scorer:  DefaultScorer(),
		longwin: NewLongWindow(cfg.LongHorizon(), cfg.Window, DefaultScorer()),
    ipLong: &ipLongMem{
        stats: make(map[string]*ipLongAgg),
    },
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
		e.updateIPLong(now) //  update EMA-based IP long view
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

        // Method mix
        switch rec.Method {
        case "get":
                b.cGET++
        case "post":
                b.cPOST++
        case "head":
                b.cHEAD++
        default:
                b.cOTHER++
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
                // για diversity / bot signals / methods
                uaCounts := map[string]int{}
                pathsUnion := map[string]struct{}{}
                var cGET, cPOST, cHEAD, cOTHER int

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
                        for ua, n := range b.uas {
                                uaCounts[ua] += n
                        }
                        for p := range b.paths {
                                pathsUnion[p] = struct{}{}
                        }
                        cGET += b.cGET
                        cPOST += b.cPOST
                        cHEAD += b.cHEAD
                        cOTHER += b.cOTHER
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

                // UA diversity + bot ratio
                uniqueUAs := len(uaCounts)
                if uniqueUAs > 0 {
                        m.UADiversity = float64(uniqueUAs) / maxf(float64(tot), 1)
                }
                var botHits int
                for ua, cnt := range uaCounts {
                        if isBotUA(ua) {
                                botHits += cnt
                        }
                }
                if tot > 0 {
                        m.BotRatio = float64(botHits) / float64(tot)
                }

                // Path diversity
                uniquePaths := len(pathsUnion)
                if uniquePaths > 0 {
                        m.PathDiversity = float64(uniquePaths) / maxf(float64(tot), 1)
                }

                // POST ratio (method mix)
                if tot > 0 {
                        m.PostRatio = float64(cPOST) / float64(tot)
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


// updateIPLong ανανεώνει το EMA-based long window για IPs,
// βασισμένο στο τρέχον short-window state.
func (e *Engine) updateIPLong(now time.Time) {
    if e.ipLong == nil {
        return
    }

    // 1) Φτιάχνουμε ένα short snapshot per IP (χωρίς enrichment).
    type aggShort struct {
        req    int
        vhosts map[string]struct{}
    }

    stats := make(map[string]*aggShort)

    e.mu.RLock()
    for host, hs := range e.hosts {
        if hs == nil {
            continue
        }
        for i := range hs.buckets {
            b := &hs.buckets[i]
            for ip, n := range b.ips {
                a := stats[ip]
                if a == nil {
                    a = &aggShort{
                        vhosts: make(map[string]struct{}),
                    }
                    stats[ip] = a
                }
                a.req += n
                a.vhosts[host] = struct{}{}
            }
        }
    }
    e.mu.RUnlock()

    if len(stats) == 0 {
        return
    }

    winSec := e.cfg.Window.Seconds()
    if winSec <= 0 {
        winSec = 60
    }

    // 2) Υπολογίζουμε alpha σε σχέση με το long horizon.
    e.ipLong.mu.Lock()
    defer e.ipLong.mu.Unlock()

    if e.ipLong.stats == nil {
        e.ipLong.stats = make(map[string]*ipLongAgg)
    }

    var alpha float64
    if e.ipLong.lastUpdate.IsZero() {
        alpha = 1.0
    } else {
        horizon := e.cfg.LongHorizon()
        if horizon <= 0 {
            horizon = 10 * e.cfg.Window
        }
        delta := now.Sub(e.ipLong.lastUpdate)
        alpha = delta.Seconds() / horizon.Seconds()
        if alpha > 1 {
            alpha = 1
        } else if alpha < 0 {
            alpha = 0
        }
    }

    for ip, a := range stats {
        rps := float64(a.req) / winSec
        vhosts := float64(len(a.vhosts))
        req := float64(a.req)

        agg := e.ipLong.stats[ip]
        if agg == nil || alpha >= 1.0 || e.ipLong.lastUpdate.IsZero() {
            // πρώτη φορά ή μεγάλο gap → γράψε κατευθείαν
            if agg == nil {
                agg = &ipLongAgg{}
                e.ipLong.stats[ip] = agg
            }
            agg.Req = req
            agg.Vhosts = vhosts
            agg.RPS = rps
            continue
        }

        // EMA: new = (1-alpha)*old + alpha*current
        oneMinus := 1.0 - alpha
        agg.Req = oneMinus*agg.Req + alpha*req
        agg.Vhosts = oneMinus*agg.Vhosts + alpha*vhosts
        agg.RPS = oneMinus*agg.RPS + alpha*rps
    }

    e.ipLong.lastUpdate = now
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
                        BotRatio:     m.BotRatio,
                        PathDiversity: m.PathDiversity,
                        UADiversity:   m.UADiversity,
                        PostRatio:     m.PostRatio,
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
			BytesRPS:     m.BytesRPS,
                        BotRatio:     m.BotRatio,
                        UADiversity:  m.UADiversity,
                        PathDiversity:m.PathDiversity,
                        PostRatio:    m.PostRatio,
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

        // status counters για scoring
        var c2, c3, c4, c5, c401, c403, c404, c499 int
        var sumBytes int64

	ipc := map[string]int{}
	uac := map[string]int{}
	rfc := map[string]int{}
	ptc := map[string]int{}
	var sumRT float64
        var postCount int

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
                sumBytes += b.sumBytes

                c2 += b.c2xx
                c3 += b.c3xx
                c4 += b.c4xx
                c5 += b.c5xx
                c401 += b.c401
                c403 += b.c403
                c404 += b.c404
                c499 += b.c499

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
                postCount += b.cPOST
	}

        // --- Short-window scoring για αυτό το host ---
        // UniqueIPs + median per-IP RPS + hot IPs
        var uniqueIPs int
        var medianPerIP, bytesRPS float64
        var hotIPs int

        if len(ipc) > 0 {
                uniqueIPs = len(ipc)
                vals := make([]float64, 0, len(ipc))
                const hotRPS = 1.0
                for _, cnt := range ipc {
                        rps := float64(cnt) / winSec
                        vals = append(vals, rps)
                        if rps >= hotRPS {
                                hotIPs++
                        }
                }
                sort.Float64s(vals)
                medianPerIP = vals[len(vals)/2]
        }
        if winSec > 0 {
                bytesRPS = float64(sumBytes) / winSec
        }

        // υπολογισμός diversity & ratios
        uniquePaths := len(ptc)
        uniqueUAs := len(uac)
        pathDiv := float64(uniquePaths) / maxf(float64(tot), 1)
        uaDiv := float64(uniqueUAs) / maxf(float64(tot), 1)
        postRatio := float64(postCount) / maxf(float64(tot), 1)

        // bot ratio από UAs (όπως και παραπάνω helper)
        var botHits int
        for ua, cnt := range uac {
                if isBotUA(ua) {
                        botHits += cnt
                }
        }
        botRatio := 0.0
        if tot > 0 {
                botRatio = float64(botHits) / float64(tot)
        }


        // Failure index ~ πόσο “αποτυγχάνει” η κίνηση
        failureIndex := 0.0
        if tot > 0 {
                failureIndex = float64(c4+c5+c401) / float64(tot)
        }

        // UA entropy (0–1, normalized)
        uaEntropy := entropyFromCounts(uac, tot)

        // Path entropy (0–1, normalized)
        pathEntropy := entropyFromCounts(ptc, tot)

        // IP skew = max_per_ip / mean_per_ip (>=1)
        ipSkew := 0.0
        if len(ipc) > 0 {
                maxCnt := 0
                for _, cnt := range ipc {
                        if cnt > maxCnt {
                                maxCnt = cnt
                        }
                }
                mean := float64(tot) / float64(len(ipc))
                if mean > 0 {
                        ipSkew = float64(maxCnt) / mean
                }
        }


        mini := MiniMetrics{
                RPSTotal:       float64(tot) / winSec,
                RPS2xx:         float64(c2) / winSec,
                RPS3xx:         float64(c3) / winSec,
                RPS4xx:         float64(c4) / winSec,
                RPS5xx:         float64(c5) / winSec,
                RPS401:         float64(c401) / winSec,
                RPS403:         float64(c403) / winSec,
                RPS404:         float64(c404) / winSec,
                RPS499:         float64(c499) / winSec,
                ErrRatio:       float64(c4+c5+c499) / maxf(float64(tot), 1),
                Auth401Ratio:   float64(c401) / maxf(float64(tot), 1),
                UniqueIPs:      uniqueIPs,
                MedianPerIPRPS: medianPerIP,
                BytesRPS:       bytesRPS,
                HotIPs:         hotIPs,
                BotRatio:       botRatio,
                PathDiversity:  pathDiv,
                UADiversity:    uaDiv,
                PostRatio:      postRatio,
        }

        sig := Signals{
                RPS:          mini.RPSTotal,
                R3xx:         mini.RPS3xx,
                R4xx:         mini.RPS4xx,
                R5xx:         mini.RPS5xx,
                R401:         mini.RPS401,
                R403:         mini.RPS403,
                R404:         mini.RPS404,
                // R50x / R504 παραμένουν 0 στο short
                ErrRatio:     mini.ErrRatio,
                Auth401Ratio: mini.Auth401Ratio,
                UniqueIPs:    mini.UniqueIPs,
                MedianPerIP:  mini.MedianPerIPRPS,
                BytesRPS:     mini.BytesRPS,
                HotIPs:       mini.HotIPs,
                BotRatio:     mini.BotRatio,
                PathDiversity: mini.PathDiversity,
                UADiversity:   mini.UADiversity,
                PostRatio:     mini.PostRatio,
        }
        res := e.scorer.Score(sig)

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

                PathDiversity: pathDiv,
                UniquePaths:   uniquePaths,
                UADiversity:   uaDiv,
                UniqueUAs:     uniqueUAs,
                PostRatio:     postRatio,

                // Score / reasons
                ShortScore:   res.Score,
                ShortReasons: res.Reasons,

                // Feature dump
                MedianPerIPRPS: medianPerIP,
                BytesRPS:       bytesRPS,
                HotIPs:         hotIPs,
                FailureIndex:   failureIndex,
                UAEntropy:      uaEntropy,
                PathEntropy:    pathEntropy,
                IPSkew:         ipSkew,

                // Top lists
                TopIPs:       top(ipc),
                TopAgents:    top(uac),
                TopReferrers: top(rfc),
                TopPaths:     top(ptc),
        }


	if tot > 0 {
		props.ProcAvgSec = sumRT / float64(tot)
	}


        // Bot% σε μορφή % για CLI
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

// entropyFromCounts υπολογίζει normalized entropy [0,1] πάνω σε counts.
func entropyFromCounts(m map[string]int, total int) float64 {
        if total <= 0 || len(m) == 0 {
            return 0
        }
        var h float64
        t := float64(total)
        for _, c := range m {
                if c <= 0 {
                        continue
                }
                p := float64(c) / t
                h += -p * math.Log2(p)
        }
        maxH := math.Log2(float64(len(m)))
        if maxH <= 0 {
                return 0
        }
        return h / maxH
}

// Marshalable helper for debugging.
func (e *Engine) DebugDump() string {
	e.mu.RLock()
	defer e.mu.RUnlock()
	b, _ := json.MarshalIndent(e.TopShort(0), "", "  ")
	return string(b)
}



// scoreIPSimple: basic heuristic score για IPs.
// Χρησιμοποιεί μόνο RPS, total requests και πόσα vhosts χτυπάει.
func scoreIPSimple(rps float64, req int, vhosts int) (float64, []string) {
        score := 0.0
        reasons := []string{}

        // RPS contribution
        if rps >= 5 {
                score += 0.6
                reasons = append(reasons, "hi_rps")
        } else if rps >= 1 {
                score += 0.4
                reasons = append(reasons, "med_rps")
        } else if rps >= 0.1 {
                score += 0.2
                reasons = append(reasons, "low_rps")
        }

        // Vhost diversity contribution
        if vhosts >= 10 {
            score += 0.3
            reasons = append(reasons, "many_vhosts")
        } else if vhosts >= 3 {
            score += 0.2
            reasons = append(reasons, "multi_vhosts")
        }

        // Slow-but-persistent crawler hint (δεν αυξάνει score, απλά reason)
        if req >= 200 && rps < 0.1 {
            reasons = append(reasons, "slow_crawler_like")
        }

        if score > 1 {
                score = 1
        }
        return score, reasons
}

// proposeIPActions φτιάχνει απλές firewall / notify προτάσεις με βάση το score.
func proposeIPActions(row IPSignals) []IPActionProposal {
        s := row.Score
        out := []IPActionProposal{}

        switch {
        case s >= 0.90:
                out = append(out, IPActionProposal{
                        Action:     "block",
                        Reason:     "ip_score_high",
                        Score:      s,
                        TTLSeconds: 900,
                })
        case s >= 0.70:
                out = append(out, IPActionProposal{
                        Action: "notify",
                        Reason: "ip_score_elevated",
                        Score:  s,
                })
        case s >= 0.50:
                out = append(out, IPActionProposal{
                        Action: "watch",
                        Reason: "ip_score_borderline",
                        Score:  s,
                })
        }
        return out
}

// IPShort παράγει full IP signals (με score & proposals) από το short-window state.
func (e *Engine) IPShort(limit int) []IPSignals {
        e.mu.RLock()
        defer e.mu.RUnlock()

        type agg struct {
                req    int
                vhosts map[string]struct{}
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
                                                vhosts: make(map[string]struct{}),
                                        }
                                        stats[ip] = a
                                }
                                a.req += n
                                a.vhosts[host] = struct{}{}
                        }
                }
        }

        winSec := e.cfg.Window.Seconds()
        if winSec <= 0 {
                winSec = 60
        }

    rows := make([]IPSignals, 0, len(stats))
    for ip, a := range stats {
        rps := float64(a.req) / winSec
        vhosts := len(a.vhosts)

        score, reasons := scoreIPSimple(rps, a.req, vhosts)

        rows = append(rows, IPSignals{
            IP:      ip,
            Req:     a.req,
            Vhosts:  vhosts,
            RPS:     rps,
            Score:   score,
            Reasons: reasons,
        })
    }

        sort.Slice(rows, func(i, j int) bool {
                if rows[i].Score == rows[j].Score {
                        return rows[i].RPS > rows[j].RPS
                }
                return rows[i].Score > rows[j].Score
        })

    if limit > 0 && len(rows) > limit {
        rows = rows[:limit]
    }

    // 🔥 Enrichment + proposals ΜΟΝΟ για τις top-N
    for i := range rows {
        rows[i].Proposals = proposeIPActions(rows[i])

        if e.enr == nil {
            continue
        }

        ip := rows[i].IP
        if net.ParseIP(ip) == nil {
            continue
        }

        geo := e.enr.Lookup(ip)
        if geo.PTR != "" {
            rows[i].PTR = geo.PTR
        }
        if geo.ASN != 0 {
            rows[i].ASN = strconv.FormatUint(uint64(geo.ASN), 10)
        }
        if geo.ASNName != "" {
            rows[i].ASNName = geo.ASNName
        }
        if geo.Country != "" {
            rows[i].Country = geo.Country
        }
    }

    return rows


}

// HotIPs υπολογίζει global "ζεστά" IPs από το short-window state.
// Τώρα βασίζεται πάνω στο IPShort και επιστρέφει μόνο το "παλιό" view για συμβατότητα.
func (e *Engine) HotIPs(limit int) []HotIPRow {
        sigs := e.IPShort(limit)
        rows := make([]HotIPRow, 0, len(sigs))
        for _, s := range sigs {
                rows = append(rows, HotIPRow{
                        IP:      s.IP,
                        Req:     s.Req,
                        Vhosts:  s.Vhosts,
                        PTR:     s.PTR,
                        ASN:     s.ASN,
                        ASNName: s.ASNName,
                        Country: s.Country,
                })
        }
        return rows
}


// IPDetail σκανάρει το short-window state και κάνει drilldown για ένα IP.
func (e *Engine) IPDetail(ip string) IPDetail {
    e.mu.RLock()
    defer e.mu.RUnlock()

    d := IPDetail{
        IP:        ip,
        WindowSec: e.cfg.Window.Seconds(),
    }

    if net.ParseIP(ip) == nil {
        return d
    }

    hostCounts := make(map[string]int)
    var firstSet bool
    var first, last time.Time

    for host, hs := range e.hosts {
        if hs == nil || len(hs.buckets) == 0 {
            continue
        }
        for i := range hs.buckets {
            b := &hs.buckets[i]
            n, ok := b.ips[ip]
            if !ok || n == 0 {
                continue
            }
            hostCounts[host] += n
            d.Req += n

            if !firstSet {
                first = b.from
                last = b.to
                firstSet = true
            } else {
                if b.from.Before(first) {
                    first = b.from
                }
                if b.to.After(last) {
                    last = b.to
                }
            }
        }
    }

    d.Vhosts = len(hostCounts)

    if firstSet {
        winSec := last.Sub(first).Seconds()
        if winSec <= 0 {
            winSec = d.WindowSec
        }
        if winSec <= 0 {
            winSec = 1
        }
        d.RPS = float64(d.Req) / winSec
    }

    if len(hostCounts) > 0 {
        hosts := make([]TopKV, 0, len(hostCounts))
        for h, c := range hostCounts {
            hosts = append(hosts, TopKV{Key: h, Count: c})
        }
        sort.Slice(hosts, func(i, j int) bool {
            return hosts[i].Count > hosts[j].Count
        })
        d.Hosts = hosts
    }

    // enrichment
    if e.enr != nil {
        geo := e.enr.Lookup(ip)
        if geo.PTR != "" {
            d.PTR = geo.PTR
        }
        if geo.ASN != 0 {
            d.ASN = strconv.FormatUint(uint64(geo.ASN), 10)
        }
        if geo.ASNName != "" {
            d.ASNName = geo.ASNName
        }
        if geo.Country != "" {
            d.Country = geo.Country
        }
    }

    return d
}



// IPLong επιστρέφει EMA-based long-window IP view με score & proposals.
func (e *Engine) IPLong(limit int) []IPSignals {
    if e.ipLong == nil {
        return nil
    }

    e.ipLong.mu.RLock()
    defer e.ipLong.mu.RUnlock()

    rows := make([]IPSignals, 0, len(e.ipLong.stats))
    for ip, agg := range e.ipLong.stats {
        req := int(agg.Req + 0.5)
        vhosts := int(agg.Vhosts + 0.5)
        rps := agg.RPS

        if req <= 0 {
            continue
        }

        score, reasons := scoreIPSimple(rps, req, vhosts)

        rows = append(rows, IPSignals{
            IP:      ip,
            Req:     req,
            Vhosts:  vhosts,
            RPS:     rps,
            Score:   score,
            Reasons: reasons,
        })
    }

    sort.Slice(rows, func(i, j int) bool {
        if rows[i].Score == rows[j].Score {
            return rows[i].RPS > rows[j].RPS
        }
        return rows[i].Score > rows[j].Score
    })

    if limit > 0 && len(rows) > limit {
        rows = rows[:limit]
    }

    // Enrichment + proposals για τις top-N
    for i := range rows {
        rows[i].Proposals = proposeIPActions(rows[i])

        if e.enr == nil {
            continue
        }

        ip := rows[i].IP
        if net.ParseIP(ip) == nil {
            continue
        }

        geo := e.enr.Lookup(ip)
        if geo.PTR != "" {
            rows[i].PTR = geo.PTR
        }
        if geo.ASN != 0 {
            rows[i].ASN = strconv.FormatUint(uint64(geo.ASN), 10)
        }
        if geo.ASNName != "" {
            rows[i].ASNName = geo.ASNName
        }
        if geo.Country != "" {
            rows[i].Country = geo.Country
        }
    }

    return rows
}

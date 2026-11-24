package webdetector

// Traffic mix: who the node's web traffic is, and what it costs the origin.
//
// Why (titan, 2026-11-24): the load went from 15 to 75. Meta's crawler was
// ~15% of the requests and a browser-looking scraper (one Chrome/152 UA on
// Greek residential IPs) another ~19%, yet together they took ~61% of the
// origin's response time: they ask for the uncached pages (shop filters,
// listings, add-to-cart). `cfm bots top` showed neither: one was keyed
// "mozilla", the other is a browser UA. Finding them took hours of awk over
// the access log. This keeps that answer in memory, for 24 h.
//
// Every request the engine ingests is counted once, in one of four classes:
//
//   - crawler:    a known search / social crawler by its UA family
//                 (knownCrawlerFamily). By UA only: spoofable, a LABEL.
//   - bot:        any other non-browser UA (curl, python-requests, a
//                 self-declared bot, an empty UA).
//   - automation: a browser UA ("mozilla" family) from an IP that made
//                 >= tmAutomationDynPerMin dynamic requests in its current
//                 minute and showed no human evidence (a static file, a POST or
//                 an XHR endpoint) in the last tmHumanEvidenceTTL. The fleet
//                 read of 2026-11-24 (7 nodes, 1,090 episodes checked against
//                 the access log) found 95%+ of humans fetch static files or
//                 send XHR/POSTs, and the scraper wave neither. The first
//                 requests of an IP's minute count as human until it crosses
//                 the threshold, so the class is a lower bound.
//   - human:      every other browser-UA request ("likely humans").
//
// THE CLASSES ARE LABELS, NEVER AN ACTION: nothing reads them to challenge,
// throttle or block (docs/abuse-defense-master-plan.md D1/D2; the shadow-first
// rule in CLAUDE.md). They feed /api/v1/webdet/traffic-mix (cfm-admin's Web
// Traffic page, the MCP traffic_mix tool, cfm-web's fleet view) so an operator
// decides faster.
//
// Per class: requests, origin seconds (the upstream time of requests the
// site's origin answered; "cfm_apache*", or any upstream on a format without
// the upstream name), bytes, a status mix, and requests the edge answered
// itself (cache hit, block, challenge redirect). Kept in 5-minute buckets for
// 24 h, with per-vhost and per-client splits; requests per class also per
// minute, for the peaks. The client is the UA family for crawler/bot, the raw
// UA for the two browser classes (the scraper's UA is its identity). The top
// IPs of automation and bot clients are kept for the last hour only.
//
// It lives at package level, not on the Engine: a detectors.conf save builds
// a new Engine, and 24 h of history must not reset on every save. Bounded:
// hosts, clients and IPs per bucket are capped (overflow goes to "_other"),
// and the per-IP behaviour state is capped and swept.

import (
	"net/http"
	"sort"
	"strconv"
	"strings"
	"sync"
	"time"

	"cfm/internal/firewall"
)

const (
	tmCrawler = iota
	tmBot
	tmAutomation
	tmHuman
	tmClasses
)

var tmClassKeys = [tmClasses]string{"crawler", "bot", "automation", "human"}
var tmClassLabels = [tmClasses]string{
	"Known crawlers (by UA)",
	"Other bots and tools",
	"Browser UA, no static/XHR (automation)",
	"Browser UA (likely humans)",
}

const (
	tmBucketSec     = 300
	tmBuckets       = 24 * 3600 / tmBucketSec // 288
	tmMinutes       = 24 * 60
	tmIPBuckets     = 3600 / tmBucketSec // top IPs kept for the last hour
	tmMaxHosts      = 4096               // per bucket
	tmMaxClients    = 256                // per bucket
	tmMaxClientIPs  = 512                // per client per bucket
	tmMaxIPState    = 100000
	tmIPStateSweep  = 30 * time.Second
	tmOtherKey      = "_other"
	tmMaxClientLen  = 200
	tmDefaultHosts  = 20
	tmDefaultClient = 20

	tmAutomationDynPerMin = 20
	tmHumanEvidenceTTL    = 10 * time.Minute
)

type tmCounters struct {
	Req, OriginMs, Bytes, Edge         int64
	S2xx, S3xx, S4xx, S403, S429, S5xx int64
}

func (c *tmCounters) add(o tmCounters) {
	c.Req += o.Req
	c.OriginMs += o.OriginMs
	c.Bytes += o.Bytes
	c.Edge += o.Edge
	c.S2xx += o.S2xx
	c.S3xx += o.S3xx
	c.S4xx += o.S4xx
	c.S403 += o.S403
	c.S429 += o.S429
	c.S5xx += o.S5xx
}

type tmSmall struct{ Req, OriginMs, Bytes int64 }

type tmClient struct {
	tmSmall
	ips map[string]int64 // last hour only; nil otherwise
}

type tmBucket struct {
	id      int64 // unix/tmBucketSec; 0 = unused
	c       [tmClasses]tmCounters
	hosts   map[string]*[tmClasses]tmSmall
	clients [tmClasses]map[string]*tmClient
}

type tmMinute struct {
	id  int64 // unix/60
	req [tmClasses]int64
}

type tmIPState struct {
	minute  int64 // unix/60 of dyn's count
	dyn     int
	humanAt time.Time
	seen    time.Time
}

type trafficMixStore struct {
	mu        sync.Mutex
	buckets   [tmBuckets]tmBucket
	minutes   [tmMinutes]tmMinute
	ipState   map[string]*tmIPState
	lastSweep time.Time
}

var trafficMix = newTrafficMixStore()

func newTrafficMixStore() *trafficMixStore {
	return &trafficMixStore{ipState: make(map[string]*tmIPState)}
}

// knownCrawlerFamilies are the UA families (NormalizeUA keys) counted as
// search / social crawlers: Google's (googleVerifiedBots, the --confirm list,
// derived, not copied) plus the others below. A REPORTING label set, not a
// matcher anything enforces with: the traffic-rule bot groups
// (rules-model.js) are glob patterns over raw UAs for rules, and goodbot is
// FCrDNS by PTR; neither yields NormalizeUA keys. A label only: a UA can
// claim any of them. TestTrafficMix_CrawlerFamiliesAreUAKeys pins that every
// entry is a key NormalizeUA can produce.
var knownCrawlerFamilies = func() map[string]bool {
	m := map[string]bool{}
	for _, g := range googleVerifiedBots {
		m[g] = true
	}
	for _, f := range []string{
		"bingbot", "bingpreview", "adidxbot", "applebot", "yandexbot", "yandeximages",
		"duckduckbot", "baiduspider", "baiduspider-render", "petalbot", "seznambot",
		"meta-externalagent", "meta-webindexer", "meta-externalads", "facebookexternalhit",
		"facebookcatalog", "twitterbot", "linkedinbot", "pinterestbot", "slackbot",
		"telegrambot", "whatsapp", "discordbot", "amazonbot", "gptbot", "oai-searchbot",
		"chatgpt-user", "claudebot", "claude-searchbot", "perplexitybot", "ccbot", "bytespider",
	} {
		m[f] = true
	}
	return m
}()

// tmHumanEvidence reports whether a request is something a person's browser
// sends and a page scraper usually does not: a static file, a POST, or an
// XHR endpoint (WooCommerce fragments, admin-ajax, the REST API).
func tmHumanEvidence(method, uri string) bool {
	if strings.EqualFold(method, "POST") {
		return true
	}
	path := uri
	if i := strings.IndexByte(path, '?'); i >= 0 {
		path = path[:i]
	}
	if isStaticAssetPath(path) {
		return true
	}
	return strings.Contains(uri, "wc-ajax=") || strings.Contains(path, "/admin-ajax.php") ||
		strings.Contains(path, "/wp-json/") || strings.Contains(uri, "rest_route=")
}

func tmStatus(c *tmCounters, status int) {
	switch {
	case status == 403:
		c.S403++
	case status == 429:
		c.S429++
	case status >= 500:
		c.S5xx++
	case status >= 400:
		c.S4xx++
	case status >= 300:
		c.S3xx++
	case status >= 200:
		c.S2xx++
	}
}

// originMs is the request's origin time, or -1 when the origin did not answer
// it (the edge did: a cache hit, a block, the challenge server).
func tmOriginMs(rec LogRec) int64 {
	if !rec.Upstream {
		return -1
	}
	if rec.UpstreamName != "" && !strings.HasPrefix(rec.UpstreamName, "cfm_apache") {
		return -1
	}
	// URT only: RT includes the client's transfer. A fast origin logs 0.000
	// and a retried one "0.1, 0.2" (URT parses as 0): both count as 0 here.
	t := rec.URT
	if t < 0 {
		t = 0
	}
	return int64(t * 1000)
}

// observe counts one ingested request. nu is NormalizeUA(rec.UA).
func (s *trafficMixStore) observe(rec LogRec, host, nu string, now time.Time) {
	if host == "" {
		return
	}
	cls := tmHuman
	client := ""
	switch {
	case nu == "" || nu == "-":
		cls, client = tmBot, "(no user-agent)"
	case knownCrawlerFamilies[nu]:
		cls, client = tmCrawler, nu
	case nu != "mozilla":
		cls, client = tmBot, nu
	default:
		client = rec.UA
		if len(client) > tmMaxClientLen {
			client = client[:tmMaxClientLen]
		}
	}
	ipKey := ""
	if rec.IP != "" {
		ipKey = firewall.CountKey(rec.IP)
	}

	// A record dated in the future counts now; one older than the ring, or
	// older than what its slot already holds (a replayed file, clock skew),
	// is dropped: recycling the slot would wipe the newer bucket.
	if wall := time.Now(); now.After(wall) {
		now = wall
	} else if wall.Sub(now) >= 24*time.Hour {
		return
	}

	s.mu.Lock()
	defer s.mu.Unlock()

	sec := now.Unix()
	b := s.bucketLocked(sec / tmBucketSec)
	if b == nil {
		return
	}
	m := &s.minutes[(sec/60)%tmMinutes]
	if m.id > sec/60 {
		return
	}
	if m.id != sec/60 {
		*m = tmMinute{id: sec / 60}
	}

	if cls == tmHuman && ipKey != "" {
		cls = s.browserClassLocked(ipKey, rec, now)
	}
	m.req[cls]++

	var c tmCounters
	c.Req = 1
	c.Bytes = rec.Bytes
	if ms := tmOriginMs(rec); ms >= 0 {
		c.OriginMs = ms
	} else {
		c.Edge = 1
	}
	tmStatus(&c, rec.Status)
	b.c[cls].add(c)

	hk := host
	if _, ok := b.hosts[hk]; !ok && len(b.hosts) >= tmMaxHosts {
		hk = tmOtherKey
	}
	h := b.hosts[hk]
	if h == nil {
		h = &[tmClasses]tmSmall{}
		b.hosts[hk] = h
	}
	h[cls].Req++
	h[cls].OriginMs += c.OriginMs
	h[cls].Bytes += c.Bytes

	cm := b.clients[cls]
	if cm == nil {
		cm = make(map[string]*tmClient)
		b.clients[cls] = cm
	}
	ck := client
	if _, ok := cm[ck]; !ok && len(cm) >= tmMaxClients {
		ck = tmOtherKey
	}
	cl := cm[ck]
	if cl == nil {
		cl = &tmClient{}
		if cls == tmAutomation || cls == tmBot {
			cl.ips = make(map[string]int64)
		}
		cm[ck] = cl
	}
	cl.Req++
	cl.OriginMs += c.OriginMs
	cl.Bytes += c.Bytes
	if cl.ips != nil && rec.IP != "" {
		if _, ok := cl.ips[rec.IP]; ok || len(cl.ips) < tmMaxClientIPs {
			cl.ips[rec.IP]++
		}
	}
}

// browserClassLocked decides automation vs human for a browser-UA request
// from ipKey's behaviour (see the file header). Caller holds s.mu.
func (s *trafficMixStore) browserClassLocked(ipKey string, rec LogRec, now time.Time) int {
	if now.Sub(s.lastSweep) >= tmIPStateSweep {
		s.lastSweep = now
		for k, v := range s.ipState {
			if now.Sub(v.seen) > tmHumanEvidenceTTL {
				delete(s.ipState, k)
			}
		}
	}
	st := s.ipState[ipKey]
	if st == nil {
		if len(s.ipState) >= tmMaxIPState {
			return tmHuman // full: no behaviour state, benefit of the doubt
		}
		st = &tmIPState{}
		s.ipState[ipKey] = st
	}
	st.seen = now
	if tmHumanEvidence(rec.Method, rec.URI) {
		st.humanAt = now
		return tmHuman
	}
	if min := now.Unix() / 60; st.minute != min {
		st.minute, st.dyn = min, 0
	}
	st.dyn++
	if st.dyn >= tmAutomationDynPerMin && (st.humanAt.IsZero() || now.Sub(st.humanAt) > tmHumanEvidenceTTL) {
		return tmAutomation
	}
	return tmHuman
}

// bucketLocked returns the bucket for id, recycling a stale slot, or nil when
// the slot already holds a NEWER bucket (an out-of-order record). A new bucket
// also drops the IP detail of every bucket older than an hour (288 slots, once
// per 5 minutes). Caller holds s.mu.
func (s *trafficMixStore) bucketLocked(id int64) *tmBucket {
	b := &s.buckets[id%tmBuckets]
	if b.id > id {
		return nil
	}
	if b.id != id {
		*b = tmBucket{id: id, hosts: make(map[string]*[tmClasses]tmSmall)}
		for i := range s.buckets {
			old := &s.buckets[i]
			if old.id == 0 || old.id > id-tmIPBuckets {
				continue
			}
			for _, cm := range old.clients {
				for _, cl := range cm {
					cl.ips = nil
				}
			}
		}
	}
	return b
}

// ── Query ──────────────────────────────────────────────────────────────────

type TrafficMixStatus struct {
	S2xx int64 `json:"2xx"`
	S3xx int64 `json:"3xx"`
	S4xx int64 `json:"4xx"`
	S403 int64 `json:"403"`
	S429 int64 `json:"429"`
	S5xx int64 `json:"5xx"`
}

type TrafficMixClass struct {
	Key        string           `json:"key"`
	Label      string           `json:"label"`
	Requests   int64            `json:"requests"`
	OriginSec  float64          `json:"origin_sec"`
	Bytes      int64            `json:"bytes"`
	EdgeServed int64            `json:"edge_served"` // answered by the edge itself (cache, block, challenge)
	Status     TrafficMixStatus `json:"status"`
	RPSAvg     float64          `json:"rps_avg"`
	RPSPeak    float64          `json:"rps_peak"`          // busiest window of peak_window_sec
	PeakAt     int64            `json:"peak_at,omitempty"` // that window's start
	PeakWindow int64            `json:"peak_window_sec,omitempty"`
}

type TrafficMixSplit struct {
	Requests  int64   `json:"requests"`
	OriginSec float64 `json:"origin_sec"`
	Bytes     int64   `json:"bytes"`
}

type TrafficMixHost struct {
	Host    string                     `json:"host"`
	Total   TrafficMixSplit            `json:"total"`
	Classes map[string]TrafficMixSplit `json:"classes"`
}

type TrafficMixIP struct {
	IP       string `json:"ip"`
	Requests int64  `json:"requests"`
}

type TrafficMixClient struct {
	Class     string         `json:"class"`
	Client    string         `json:"client"`
	Requests  int64          `json:"requests"`
	OriginSec float64        `json:"origin_sec"`
	Bytes     int64          `json:"bytes"`
	IPs       int            `json:"ips_last_hour,omitempty"`
	TopIPs    []TrafficMixIP `json:"top_ips_last_hour,omitempty"`
}

type TrafficMixPoint struct {
	T       int64            `json:"t"`
	Classes map[string]int64 `json:"requests"`
}

type TrafficMix struct {
	Schema    string             `json:"schema"`
	WindowSec int64              `json:"window_sec"`
	Since     int64              `json:"since"`
	Until     int64              `json:"until"`
	Host      string             `json:"host,omitempty"`
	Classes   []TrafficMixClass  `json:"classes"`
	Total     TrafficMixClass    `json:"total"`
	Series    []TrafficMixPoint  `json:"series"` // requests per class per series_sec
	SeriesSec int64              `json:"series_sec"`
	Hosts     []TrafficMixHost   `json:"hosts,omitempty"`
	Clients   []TrafficMixClient `json:"clients"`
	Note      string             `json:"note"`
}

const trafficMixNote = "classes are labels by UA and behaviour, never an enforcement decision; automation is a lower bound: an IP's first requests of a minute count as human, so a browser-looking scraper's raw UA also appears, smaller, under human"

// Snapshot aggregates the last window (5m..24h) at now. host != "" limits
// every figure to that vhost (the per-minute peaks and the series then come
// from its 5-minute buckets). hostLimit / clientLimit cap the lists.
func (s *trafficMixStore) Snapshot(now time.Time, window time.Duration, host string, hostLimit, clientLimit int) TrafficMix {
	if window < tmBucketSec*time.Second {
		window = tmBucketSec * time.Second
	}
	if window > 24*time.Hour {
		window = 24 * time.Hour
	}
	if hostLimit <= 0 {
		hostLimit = tmDefaultHosts
	}
	if clientLimit <= 0 {
		clientLimit = tmDefaultClient
	}
	host = strings.ToLower(strings.TrimSpace(host))
	nowSec := now.Unix()
	sinceSec := nowSec - int64(window/time.Second)
	firstB, lastB := sinceSec/tmBucketSec, nowSec/tmBucketSec

	out := TrafficMix{Schema: "webdet.traffic_mix.v1", WindowSec: nowSec - sinceSec, Since: sinceSec, Until: nowSec, Host: host, Note: trafficMixNote}
	var cls [tmClasses]tmCounters
	hosts := map[string]*[tmClasses]tmSmall{}
	type ck struct {
		cls int
		key string
	}
	clients := map[ck]*tmClient{}
	var series []TrafficMixPoint
	var peak [tmClasses]float64
	var peakAt [tmClasses]int64

	// The lock is taken per bucket, not for the whole walk: observe needs it
	// on every request, and a 24h walk over ~1M host entries would stall
	// ingest for its length.
	for id := firstB; id <= lastB; id++ {
		pt := TrafficMixPoint{T: id * tmBucketSec, Classes: map[string]int64{}}
		for i := 0; i < tmClasses; i++ {
			pt.Classes[tmClassKeys[i]] = 0 // every bucket, empty ones too: gaps show as zeros
		}
		s.mu.Lock()
		b := &s.buckets[id%tmBuckets]
		if b.id != id {
			s.mu.Unlock()
			series = append(series, pt)
			continue
		}
		if host == "" {
			for i := 0; i < tmClasses; i++ {
				cls[i].add(b.c[i])
				pt.Classes[tmClassKeys[i]] = b.c[i].Req
			}
			for hk, hv := range b.hosts {
				acc := hosts[hk]
				if acc == nil {
					acc = &[tmClasses]tmSmall{}
					hosts[hk] = acc
				}
				for i := 0; i < tmClasses; i++ {
					acc[i].Req += hv[i].Req
					acc[i].OriginMs += hv[i].OriginMs
					acc[i].Bytes += hv[i].Bytes
				}
			}
		} else if hv := b.hosts[host]; hv != nil {
			for i := 0; i < tmClasses; i++ {
				cls[i].Req += hv[i].Req
				cls[i].OriginMs += hv[i].OriginMs
				cls[i].Bytes += hv[i].Bytes
				pt.Classes[tmClassKeys[i]] = hv[i].Req
				if r := float64(hv[i].Req) / tmBucketSec; r > peak[i] {
					peak[i], peakAt[i] = r, id*tmBucketSec
				}
			}
		}
		if host != "" {
			s.mu.Unlock()
			series = append(series, pt)
			continue // the client split is node-wide only
		}
		for i := 0; i < tmClasses; i++ {
			for key, cl := range b.clients[i] {
				k := ck{i, key}
				acc := clients[k]
				if acc == nil {
					acc = &tmClient{}
					clients[k] = acc
				}
				acc.Req += cl.Req
				acc.OriginMs += cl.OriginMs
				acc.Bytes += cl.Bytes
				if cl.ips != nil && id > lastB-tmIPBuckets {
					if acc.ips == nil {
						acc.ips = map[string]int64{}
					}
					for ip, n := range cl.ips {
						acc.ips[ip] += n
					}
				}
			}
		}
		s.mu.Unlock()
		series = append(series, pt)
	}
	peakWin := int64(tmBucketSec)
	if host == "" {
		peakWin = 60
		s.mu.Lock()
		for m := sinceSec / 60; m <= nowSec/60; m++ {
			mm := &s.minutes[m%tmMinutes]
			if mm.id != m {
				continue
			}
			for i := 0; i < tmClasses; i++ {
				if r := float64(mm.req[i]) / 60; r > peak[i] {
					peak[i], peakAt[i] = r, m*60
				}
			}
		}
		s.mu.Unlock()
	}

	secs := float64(out.WindowSec)
	var tot tmCounters
	for i := 0; i < tmClasses; i++ {
		tot.add(cls[i])
		c := tmClassOut(i, cls[i], secs, peak[i], peakAt[i])
		c.PeakWindow = peakWin
		out.Classes = append(out.Classes, c)
	}
	out.Total = tmClassOut(-1, tot, secs, 0, 0)
	out.Series, out.SeriesSec = series, tmBucketSec

	if host == "" {
		for hk, hv := range hosts {
			h := TrafficMixHost{Host: hk, Classes: map[string]TrafficMixSplit{}}
			for i := 0; i < tmClasses; i++ {
				sp := TrafficMixSplit{Requests: hv[i].Req, OriginSec: msToSec(hv[i].OriginMs), Bytes: hv[i].Bytes}
				h.Classes[tmClassKeys[i]] = sp
				h.Total.Requests += sp.Requests
				h.Total.OriginSec += sp.OriginSec
				h.Total.Bytes += sp.Bytes
			}
			out.Hosts = append(out.Hosts, h)
		}
		sort.Slice(out.Hosts, func(i, j int) bool {
			if out.Hosts[i].Total.OriginSec != out.Hosts[j].Total.OriginSec {
				return out.Hosts[i].Total.OriginSec > out.Hosts[j].Total.OriginSec
			}
			return out.Hosts[i].Host < out.Hosts[j].Host
		})
		if len(out.Hosts) > hostLimit {
			out.Hosts = out.Hosts[:hostLimit]
		}
	}

	for k, cl := range clients {
		c := TrafficMixClient{Class: tmClassKeys[k.cls], Client: k.key, Requests: cl.Req, OriginSec: msToSec(cl.OriginMs), Bytes: cl.Bytes}
		if len(cl.ips) > 0 {
			c.IPs = len(cl.ips)
			for ip, n := range cl.ips {
				c.TopIPs = append(c.TopIPs, TrafficMixIP{IP: ip, Requests: n})
			}
			sort.Slice(c.TopIPs, func(i, j int) bool {
				if c.TopIPs[i].Requests != c.TopIPs[j].Requests {
					return c.TopIPs[i].Requests > c.TopIPs[j].Requests
				}
				return c.TopIPs[i].IP < c.TopIPs[j].IP
			})
			if len(c.TopIPs) > 50 {
				c.TopIPs = c.TopIPs[:50]
			}
		}
		out.Clients = append(out.Clients, c)
	}
	sort.Slice(out.Clients, func(i, j int) bool {
		if out.Clients[i].OriginSec != out.Clients[j].OriginSec {
			return out.Clients[i].OriginSec > out.Clients[j].OriginSec
		}
		if out.Clients[i].Requests != out.Clients[j].Requests {
			return out.Clients[i].Requests > out.Clients[j].Requests
		}
		return out.Clients[i].Client < out.Clients[j].Client
	})
	if len(out.Clients) > clientLimit {
		out.Clients = out.Clients[:clientLimit]
	}
	if out.Clients == nil {
		out.Clients = []TrafficMixClient{}
	}
	return out
}

func msToSec(ms int64) float64 { return float64(ms) / 1000 }

func tmClassOut(i int, c tmCounters, secs, peak float64, peakAt int64) TrafficMixClass {
	o := TrafficMixClass{
		Requests: c.Req, OriginSec: msToSec(c.OriginMs), Bytes: c.Bytes, EdgeServed: c.Edge,
		Status:  TrafficMixStatus{S2xx: c.S2xx, S3xx: c.S3xx, S4xx: c.S4xx, S403: c.S403, S429: c.S429, S5xx: c.S5xx},
		RPSPeak: peak, PeakAt: peakAt,
	}
	if i >= 0 {
		o.Key, o.Label = tmClassKeys[i], tmClassLabels[i]
	} else {
		o.Key, o.Label = "total", "All traffic"
	}
	if secs > 0 {
		o.RPSAvg = float64(c.Req) / secs
	}
	return o
}

// handleTrafficMix serves GET /api/v1/webdet/traffic-mix
// ?window=<5m..24h, default 1h>&host=<vhost>&hosts=<n>&clients=<n>.
// Admin-only (docs/endpoint_scope_inventory.md): the node-wide view names
// other tenants' vhosts, clients and IPs.
func (e *Engine) handleTrafficMix(w http.ResponseWriter, r *http.Request) {
	if !RequireAdmin(w, r) {
		return
	}
	q := r.URL.Query()
	window := time.Hour
	if v := strings.TrimSpace(q.Get("window")); v != "" {
		d, err := time.ParseDuration(v)
		if err != nil || d <= 0 {
			writeJSON(w, http.StatusBadRequest, map[string]string{"error": "window: a duration such as 15m, 1h, 6h or 24h"})
			return
		}
		window = d
	}
	atoi := func(k string) int {
		n, _ := strconv.Atoi(q.Get(k))
		if n > 500 {
			n = 500
		}
		return n
	}
	writeJSON(w, http.StatusOK, trafficMix.Snapshot(time.Now(), window, q.Get("host"), atoi("hosts"), atoi("clients")))
}

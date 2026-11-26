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
	"math"
	"net/http"
	"net/netip"
	"slices"
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
	tmOldMaxHosts   = 256                // per bucket older than an hour (compactBucket)
	tmOldMaxClients = 64                 // per class per bucket older than an hour
	tmMaxClientIPs  = 512                // per client per bucket
	// tmMaxHumanClientIPs bounds a browser-UA ("human") client's IPs per
	// bucket: enough to tell a population spread over hundreds of addresses
	// (the distributed tell) from one visitor's, at an eighth of the memory.
	tmMaxHumanClientIPs = 64
	// tmMaxHumanClientHosts bounds a browser-UA client's vhosts per bucket
	// (the rest count under "_other"): where a distributed population lands
	// is the grain an operator can act on, its addresses are not.
	tmMaxHumanClientHosts = 16
	tmDistTopHosts        = 5 // vhosts listed on a flagged client (then "_other")
	tmMaxIPState          = 100000
	tmIPStateSweep        = 30 * time.Second
	tmOtherKey            = "_other"
	tmMaxClientLen        = 200
	tmDefaultHosts        = 20
	tmDefaultClient       = 20

	tmAutomationDynPerMin = 20
	tmHumanEvidenceTTL    = 10 * time.Minute
)

type tmCounters struct {
	Req, OriginMs, Bytes, Edge         int64
	S2xx, S3xx, S4xx, S403, S429, S5xx int64
	Out                                tmOut // what the edge did (tmOutcome); a file from before it reads zeros
}

func (c *tmCounters) add(o tmCounters) {
	c.Req += o.Req
	c.OriginMs += o.OriginMs
	c.Bytes += o.Bytes
	c.Edge += o.Edge
	c.Out.add(o.Out)
	c.S2xx += o.S2xx
	c.S3xx += o.S3xx
	c.S4xx += o.S4xx
	c.S403 += o.S403
	c.S429 += o.S429
	c.S5xx += o.S5xx
}

type tmSmall struct {
	Req, OriginMs, Bytes int64
	// Out: what the edge did (tmOutcome). nil while every count is zero: most
	// vhost and client entries only ever reach the origin, and this sits in
	// every one of them (and in the saved file). A file from before it reads nil.
	Out *tmOut `json:",omitempty"`
}

// addSmall adds o's counts to a. a's Out is its own: never o's pointer.
func (a *tmSmall) addSmall(o tmSmall) {
	a.Req += o.Req
	a.OriginMs += o.OriginMs
	a.Bytes += o.Bytes
	if o.Out != nil {
		if a.Out == nil {
			a.Out = new(tmOut)
		}
		a.Out.add(*o.Out)
	}
}

// clone copies a with its own Out (a copy read after the lock is dropped).
func (a tmSmall) clone() tmSmall {
	if a.Out != nil {
		o := *a.Out
		a.Out = &o
	}
	return a
}

// out is a's outcomes, zero when it has none.
func (a tmSmall) out() tmOut {
	if a.Out == nil {
		return tmOut{}
	}
	return *a.Out
}

// What the edge did with a request (tmOutcome). A request the origin answered
// is none of them: "reached the origin" is Req minus the edge outcomes. The
// two verify counts and the page count are a SUBSET of tmOutChallenge (the
// challenge's answers, and the page they answer).
const (
	tmOutCached      = iota // a cfm_apache* location answered without its upstream: a static / micro cache hit
	tmOutChallenge          // the challenge: cfm.lua sent the client to it, or the client loaded /__cfm_challenge or posted /__cfm_verify
	tmOutBlocked            // cfm_block: a WAF block, an IP / edge ban, a fingerprint or geo deny, a UA emergency rule
	tmOutRuleBlocked        // cfm_block_rule: a traffic rule's block
	tmOutRateLimited        // a 429 the edge answered itself (no upstream)
	tmOutRedirect           // cfm_redirect
	tmOutOtherEdge          // any other edge answer (the panel proxies)
	tmOutVerifyPass         // a /__cfm_verify answered 303: sent on (solved; or an unsolicited v2 reject sent on without clearance)
	tmOutVerifyFail         // a /__cfm_verify answered 403: refused (wrong, expired, a v2 reject) or asked to confirm
	// tmOutChallengePage: a /__cfm_challenge load, the page itself (also a
	// subset of tmOutChallenge). A challenged visit is up to three challenge
	// requests (the 303 to the page, the page, the verify): the page count is
	// what the answers are a share of. Appended last: a saved file from before
	// it decodes with this count at zero.
	tmOutChallengePage
	tmOutcomes
	tmOutOrigin = -1 // tmOutcome: the origin answered
)

// tmOut counts requests per edge outcome. int32: it sits in every host and
// client entry of the ring, and one 5-minute bucket never nears 2^31.
type tmOut [tmOutcomes]int32

func (o *tmOut) add(x tmOut) {
	for i := range o {
		o[i] += x[i]
	}
}

// tmOutcome classifies what the edge did with a request, from the edge's own
// log fields: the upstream it chose ($cfm_upstream), whether an upstream was
// contacted, the status and the URI. The file tailers' 12-column format has
// no upstream column: there a request cfm.lua sent to the challenge server
// reads as origin (only the /__cfm_* URIs below are caught); the socket
// ingest, the default, carries it. CFM's own /__cfm_* locations bypass
// cfm.lua and keep the server's default $cfm_upstream ("cfm_apache"): read
// by upstream alone, every challenge page and verify counted as origin time
// (titan, 2026-11-25: 15,299 challenge pages in ~45 minutes).
func tmOutcome(rec LogRec) int {
	if strings.HasPrefix(rec.URI, "/__cfm_") {
		if strings.HasPrefix(rec.URI, "/__cfm_challenge") || strings.HasPrefix(rec.URI, "/__cfm_verify") {
			return tmOutChallenge
		}
		return tmOutOtherEdge
	}
	switch rec.UpstreamName {
	case "cfm_challenge":
		return tmOutChallenge
	case "cfm_block":
		if rec.Status == 429 {
			return tmOutRateLimited
		}
		return tmOutBlocked
	case "cfm_block_rule":
		return tmOutRuleBlocked
	case "cfm_redirect":
		return tmOutRedirect
	}
	if rec.UpstreamName != "" && !strings.HasPrefix(rec.UpstreamName, "cfm_apache") {
		return tmOutOtherEdge
	}
	if !rec.Upstream {
		// A cfm_apache* request no upstream answered. The default upstream
		// stays cfm_apache on every edge exit that never set it, so the status
		// decides: only what the cache can serve is a hit (both tiers store
		// 200s only; 206 / 304 are served from them), a 429 is the edge's own
		// limits (limit_req, the crawler limits, a UA emergency throttle), a
		// 403 / 444 a refusal (a UA emergency block closes with 444), and the
		// rest (a challenge_resume 303, a 499 before the upstream answered)
		// is some other edge answer.
		switch rec.Status {
		case 200, 206, 304:
			return tmOutCached
		case 429:
			return tmOutRateLimited
		case 403, 444:
			return tmOutBlocked
		}
		return tmOutOtherEdge
	}
	return tmOutOrigin
}

// tmVerifyOutcome is the challenge's answer to a /__cfm_verify, or -1. The
// status alone is all the log carries: 303 sends the client on (nearly always
// a solve), 403 refuses it or asks it to confirm, which a person then clicks
// through (a second verify, 303). Read them as answers, not exact verdicts.
func tmVerifyOutcome(rec LogRec) int {
	if !strings.HasPrefix(rec.URI, "/__cfm_verify") {
		return -1
	}
	switch rec.Status {
	case 303:
		return tmOutVerifyPass
	case 403:
		return tmOutVerifyFail
	}
	return -1
}

type tmClient struct {
	tmSmall
	ev  int64            // requests a person's browser sends (static, POST, XHR: tmHumanEvidence)
	ips map[string]int64 // last hour only; nil otherwise
	// hosts: a browser-UA client's requests per vhost (tmMaxHumanClientHosts
	// per bucket, the rest under "_other"), last hour only; nil otherwise.
	hosts map[string]int64
}

type tmBucket struct {
	id      int64 // unix/tmBucketSec; 0 = unused
	compact bool  // older than an hour: trimmed to its top hosts and clients
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
// it (the edge did: a cache hit, a block, the challenge server: tmOutcome).
func tmOriginMs(rec LogRec) int64 {
	if tmOutcome(rec) != tmOutOrigin {
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
	if o := tmOutcome(rec); o != tmOutOrigin {
		c.Out[o] = 1
	}
	if v := tmVerifyOutcome(rec); v >= 0 {
		c.Out[v] = 1
	}
	if strings.HasPrefix(rec.URI, "/__cfm_challenge") {
		c.Out[tmOutChallengePage] = 1
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
	one := tmSmall{Req: 1, OriginMs: c.OriginMs, Bytes: c.Bytes}
	if c.Out != (tmOut{}) {
		one.Out = &c.Out
	}
	h[cls].addSmall(one)

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
		if cls == tmAutomation || cls == tmBot || cls == tmHuman {
			cl.ips = make(map[string]int64)
		}
		cm[ck] = cl
	}
	cl.addSmall(one)
	if tmHumanEvidence(rec.Method, rec.URI) {
		cl.ev++
	}
	if cl.ips == nil && (cls == tmAutomation || cls == tmBot || cls == tmHuman) {
		// Lazily too: a client a restored file created without addresses
		// (mergeFileBucket) would otherwise never record one again.
		cl.ips = make(map[string]int64)
	}
	if cl.ips != nil && rec.IP != "" {
		if _, ok := cl.ips[rec.IP]; ok || len(cl.ips) < tmClientIPCap(cls) {
			cl.ips[rec.IP]++
		}
	}
	if cls == tmHuman {
		// Lazily: a client a restored file created (mergeFileBucket) has no
		// map yet. The current bucket is never compact.
		if cl.hosts == nil {
			cl.hosts = make(map[string]int64)
		}
		tmCountHost(cl.hosts, host, 1)
	}
}

// tmCountHost adds n requests on host to a client's per-vhost counts, within
// tmMaxHumanClientHosts (a new vhost past the cap counts under "_other").
func tmCountHost(m map[string]int64, host string, n int64) {
	if _, ok := m[host]; !ok {
		named := len(m)
		if _, ok := m[tmOtherKey]; ok {
			named-- // "_other" is not one of the named vhosts
		}
		if named >= tmMaxHumanClientHosts {
			host = tmOtherKey
		}
	}
	m[host] += n
}

// The distributed tell (a READING, never an enforcement decision): one exact
// browser UA whose last hour came from many addresses, a few requests each,
// with almost nothing a person's browser sends. Measured on titan
// (2026-11-24, the edge access log, one hour): the Mac Chrome 131/133/136
// population was 421-469 IPs at 1.2-2.3 requests per IP with 0-8% static /
// POST / XHR and 2.7-4.7 s of origin per request; real Android / Windows
// Chrome 157-158 populations were 152-319 IPs at 78-101 requests per IP with
// 67-81%. Both conditions are needed: a site behind a CDN serves its visitors'
// static files from the CDN (little evidence at the edge), but its visitors
// still browse many pages each.
const (
	tmDistMinRequests = 200
	tmDistMinIPs      = 50
	tmDistMaxReqPerIP = 3.0
	tmDistMaxEvidence = 0.10
)

// distributedTell reads one browser-UA client's last hour: ips are the
// addresses kept (each bucket keeps its first tmMaxHumanClientIPs, so on a
// population past that cap they are a sample), sampled the requests those
// addresses made, hourReq / hourEv every request and those with evidence.
// Requests per IP come from the sample (all requests over a capped IP count
// would overstate it and hide exactly the biggest populations); the evidence
// share comes from every request. The sample can only UNDERSTATE requests
// per IP (an address kept in one bucket loses its requests in a later bucket
// that was full when it came back), which leans toward flagging a big
// population: what keeps real visitors out there is the evidence share,
// counted over every request (TestTrafficMix_DistributedTellBusyVisitors).
func distributedTell(ips int, sampled, hourReq, hourEv int64) *TrafficMixDistributed {
	if hourReq < tmDistMinRequests || ips < tmDistMinIPs || sampled <= 0 {
		return nil
	}
	perIP := float64(sampled) / float64(ips)
	ev := float64(hourEv) / float64(hourReq)
	if perIP >= tmDistMaxReqPerIP || ev >= tmDistMaxEvidence {
		return nil
	}
	// The population behind the sample: every request of the hour at the
	// sample's requests per IP. Each bucket keeps only its first
	// tmMaxHumanClientIPs addresses, so a pool that rotates through
	// thousands reads ~768 kept (rigel, 2026-11-25: 767 kept, 18,078 in the
	// edge log, an estimate of ~18,300). An UPPER estimate, as ReqPerIP is a
	// lower bound: an address's return in a later bucket that was already
	// full is not counted for it, so a pool whose addresses come back reads
	// fewer requests per IP and more addresses than it has. Never fewer than
	// the addresses kept.
	est := int(math.Round(float64(hourReq) / perIP))
	if est < ips {
		est = ips
	}
	return &TrafficMixDistributed{IPs: ips, EstIPs: est, Requests: hourReq, ReqPerIP: perIP, EvidenceShare: ev}
}

// tmNetCount counts the distinct networks of a client's kept addresses: /16
// for IPv4, /32 for IPv6. For IPv4, a handful means one operator's fleet
// (GeedoShop's 114 addresses on virgo were one /16) and hundreds a
// residential proxy pool (rigel's 18k addresses, 441 /16s). An IPv6 /32 is
// usually one ISP's whole allocation, so there a small count can be one
// ISP's subscribers, not one fleet. Context for the operator, never a
// threshold.
func tmNetCount(ips map[string]int64) int {
	nets := make(map[netip.Prefix]struct{}, len(ips))
	for ip := range ips {
		a, err := netip.ParseAddr(ip)
		if err != nil {
			continue
		}
		bits := 32
		if a = a.Unmap(); a.Is4() {
			bits = 16
		}
		if p, err := a.Prefix(bits); err == nil {
			nets[p] = struct{}{}
		}
	}
	return len(nets)
}

// tmTopHosts lists a client's top n vhosts by requests, then the rest summed
// under "_other" (trailing).
func tmTopHosts(m map[string]int64, n int) []TrafficMixClientHost {
	var out []TrafficMixClientHost
	var other int64
	for h, r := range m {
		if h == tmOtherKey {
			other += r
			continue
		}
		out = append(out, TrafficMixClientHost{Host: h, Requests: r})
	}
	sort.Slice(out, func(i, j int) bool {
		if out[i].Requests != out[j].Requests {
			return out[i].Requests > out[j].Requests
		}
		return out[i].Host < out[j].Host
	})
	if len(out) > n {
		for _, h := range out[n:] {
			other += h.Requests
		}
		out = out[:n]
	}
	if other > 0 {
		out = append(out, TrafficMixClientHost{Host: tmOtherKey, Requests: other})
	}
	return out
}

// tmClientIPCap is how many IPs one client keeps per bucket.
func tmClientIPCap(cls int) int {
	if cls == tmHuman {
		return tmMaxHumanClientIPs
	}
	return tmMaxClientIPs
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
			if old.id == 0 || old.id > id-tmIPBuckets || old.compact {
				continue
			}
			compactBucket(old)
		}
	}
	return b
}

// compactBucket trims a bucket that is older than an hour to its top
// tmOldMaxHosts vhosts and tmOldMaxClients clients per class (by origin time;
// the rest are merged into "_other", so every total stays exact) and drops its
// IPs. It bounds the 24 h ring: full detail for the last hour (12 buckets at
// the per-bucket caps), the top of each older bucket after it. Worst case, all
// caps full: ~12 x (4096 hosts + 1024 clients) + 276 x (256 + 256), on the
// order of tens of MB; a typical node is far below it.
func compactBucket(b *tmBucket) {
	b.compact = true
	if len(b.hosts) > tmOldMaxHosts {
		type hk struct {
			k string
			o int64
		}
		var list []hk
		for k, v := range b.hosts {
			if k == tmOtherKey {
				continue
			}
			var o int64
			for i := 0; i < tmClasses; i++ {
				o += v[i].OriginMs*1000 + v[i].Req // origin time first, requests break ties
			}
			list = append(list, hk{k, o})
		}
		sort.Slice(list, func(i, j int) bool {
			if list[i].o != list[j].o {
				return list[i].o > list[j].o
			}
			return list[i].k < list[j].k
		})
		other := b.hosts[tmOtherKey]
		if other == nil {
			other = &[tmClasses]tmSmall{}
		}
		for _, e := range list[tmOldMaxHosts-1:] {
			v := b.hosts[e.k]
			for i := 0; i < tmClasses; i++ {
				other[i].addSmall(v[i])
			}
			delete(b.hosts, e.k)
		}
		b.hosts[tmOtherKey] = other
	}
	for c, cm := range b.clients {
		for _, cl := range cm {
			cl.ips = nil
			cl.hosts = nil
		}
		if len(cm) <= tmOldMaxClients {
			continue
		}
		type kk struct {
			k string
			o int64
		}
		var list []kk
		for k, v := range cm {
			if k != tmOtherKey {
				list = append(list, kk{k, v.OriginMs*1000 + v.Req})
			}
		}
		sort.Slice(list, func(i, j int) bool {
			if list[i].o != list[j].o {
				return list[i].o > list[j].o
			}
			return list[i].k < list[j].k
		})
		other := cm[tmOtherKey]
		if other == nil {
			other = &tmClient{}
		}
		for _, e := range list[tmOldMaxClients-1:] {
			v := cm[e.k]
			other.addSmall(v.tmSmall)
			other.ev += v.ev
			delete(cm, e.k)
		}
		cm[tmOtherKey] = other
		b.clients[c] = cm
	}
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
	Key        string              `json:"key"`
	Label      string              `json:"label"`
	Requests   int64               `json:"requests"`
	OriginSec  float64             `json:"origin_sec"`
	Bytes      int64               `json:"bytes"`
	EdgeServed *int64              `json:"edge_served,omitempty"` // answered by the edge itself (cache, block, challenge); node-wide view only
	Status     *TrafficMixStatus   `json:"status,omitempty"`      // node-wide view only (not kept per vhost: absent, never a fabricated zero)
	RPSAvg     float64             `json:"rps_avg"`
	RPSPeak    float64             `json:"rps_peak"`          // busiest window of peak_window_sec
	PeakAt     int64               `json:"peak_at,omitempty"` // that window's start
	PeakWindow int64               `json:"peak_window_sec,omitempty"`
	Outcomes   *TrafficMixOutcomes `json:"outcomes,omitempty"`
}

type TrafficMixSplit struct {
	Requests  int64               `json:"requests"`
	OriginSec float64             `json:"origin_sec"`
	Bytes     int64               `json:"bytes"`
	Outcomes  *TrafficMixOutcomes `json:"outcomes,omitempty"`
}

// TrafficMixOutcomes is what the edge did with requests (tmOutcome): origin
// is every request no edge outcome took. verify_sent_on / verify_refused are
// the challenge's answers to a verify (303 / 403: tmVerifyOutcome), a subset
// of challenged; a 403 includes the v2 confirm step's question. A reading of the edge's
// own log, never an enforcement decision. Requests a restored file counted
// before this build kept no outcome and read as origin.
type TrafficMixOutcomes struct {
	Origin        int64 `json:"origin"`
	Cached        int64 `json:"cached"`
	Challenged    int64 `json:"challenged"`
	Blocked       int64 `json:"blocked"`
	RuleBlocked   int64 `json:"rule_blocked"`
	RateLimited   int64 `json:"rate_limited"`
	Redirect      int64 `json:"redirect"`
	OtherEdge     int64 `json:"other_edge"`
	VerifySentOn  int64 `json:"verify_sent_on"`
	VerifyRefused int64 `json:"verify_refused"`
	// ChallengePages: loads of the challenge page (/__cfm_challenge), a subset
	// of challenged; zero for the hours a build before it counted.
	ChallengePages int64 `json:"challenge_pages"`
}

func tmOutcomesOut(req int64, o tmOut) *TrafficMixOutcomes {
	out := &TrafficMixOutcomes{
		Cached: int64(o[tmOutCached]), Challenged: int64(o[tmOutChallenge]), Blocked: int64(o[tmOutBlocked]),
		RuleBlocked: int64(o[tmOutRuleBlocked]), RateLimited: int64(o[tmOutRateLimited]), Redirect: int64(o[tmOutRedirect]),
		OtherEdge: int64(o[tmOutOtherEdge]), VerifySentOn: int64(o[tmOutVerifyPass]), VerifyRefused: int64(o[tmOutVerifyFail]),
		ChallengePages: int64(o[tmOutChallengePage]),
	}
	edge := out.Cached + out.Challenged + out.Blocked + out.RuleBlocked + out.RateLimited + out.Redirect + out.OtherEdge
	if out.Origin = req - edge; out.Origin < 0 {
		out.Origin = 0
	}
	return out
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
	// EvidenceShare (browser-UA clients) is the share of its last hour's
	// requests a person's browser sends: static files, POSTs, XHR.
	EvidenceShare *float64 `json:"evidence_share,omitempty"`
	// Distributed is set on a browser-UA ("human") client whose last hour of
	// the window (all of it when shorter) reads as a scraper spread over many
	// addresses (distributedTell): a LABEL, never an enforcement decision.
	Distributed *TrafficMixDistributed `json:"distributed,omitempty"`
	// Outcomes: what the edge did with this client's requests in the window.
	Outcomes *TrafficMixOutcomes `json:"outcomes,omitempty"`
}

// TrafficMixDistributed is the distributed-population tell's evidence.
type TrafficMixDistributed struct {
	// IPs are the addresses kept (each 5-minute bucket keeps its first
	// tmMaxHumanClientIPs), EstIPs the population they sample
	// (distributedTell): a rotating pool reads ~768 kept of thousands.
	IPs           int     `json:"ips"`
	EstIPs        int     `json:"est_ips"`
	Requests      int64   `json:"requests"`
	ReqPerIP      float64 `json:"req_per_ip"`
	EvidenceShare float64 `json:"evidence_share"`
	// Nets: distinct /16 (IPv4) and /32 (IPv6) networks of the kept
	// addresses (tmNetCount).
	Nets int `json:"nets"`
	// Hosts: where the population lands over the hour, top vhosts by
	// requests, "_other" last: the grain an operator can act on.
	Hosts []TrafficMixClientHost `json:"hosts,omitempty"`
}

// TrafficMixClientHost is one vhost of a client's last hour.
type TrafficMixClientHost struct {
	Host     string `json:"host"`
	Requests int64  `json:"requests"`
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
func (s *trafficMixStore) Snapshot(now time.Time, window time.Duration, host string, mergeWWW bool, hostLimit, clientLimit int) TrafficMix {
	return s.SnapshotSorted(now, window, host, mergeWWW, hostLimit, clientLimit, TrafficMixSortOrigin)
}

// Client orders of the traffic mix: which clients make the top N, and in
// what order (the Web Traffic page's sortable columns; a per-second rate is
// requests over the same window, so it sorts as requests).
const (
	TrafficMixSortOrigin   = "origin"
	TrafficMixSortRequests = "requests"
	TrafficMixSortBytes    = "bytes"
	TrafficMixSortIPs      = "ips"
)

// TrafficMixSorts lists the accepted client orders (the API validates against it).
var TrafficMixSorts = []string{TrafficMixSortOrigin, TrafficMixSortRequests, TrafficMixSortBytes, TrafficMixSortIPs}

// SnapshotSorted is Snapshot with the clients picked and ordered by sortBy
// (one of TrafficMixSorts; anything else is origin time). The selection
// happens before the cap, so "by requests" returns the busiest clients, not
// the costliest ones reordered.
func (s *trafficMixStore) SnapshotSorted(now time.Time, window time.Duration, host string, mergeWWW bool, hostLimit, clientLimit int, sortBy string) TrafficMix {
	return s.snapshot(now.Unix(), false, window, host, mergeWWW, hostLimit, clientLimit, sortBy)
}

// SnapshotUntil is the window that ENDS at until (a bucket boundary, in the
// past): every bucket and minute before until, none after it. It answers
// "what was the hour 09:00-10:00" exactly, as many times as asked (cfm-web's
// hourly history), where Snapshot's window always ends at a "now" inside a
// bucket that is still filling.
func (s *trafficMixStore) SnapshotUntil(until time.Time, window time.Duration, host string, mergeWWW bool, hostLimit, clientLimit int, sortBy string) TrafficMix {
	return s.snapshot(until.Unix(), true, window, host, mergeWWW, hostLimit, clientLimit, sortBy)
}

// snapshot is Snapshot's body: the window ends at nowSec, inclusive (the
// bucket and minute holding it count) or, with closedEnd, exclusive (nowSec
// is a bucket boundary and nothing from it on counts).
func (s *trafficMixStore) snapshot(nowSec int64, closedEnd bool, window time.Duration, host string, mergeWWW bool, hostLimit, clientLimit int, sortBy string) TrafficMix {
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
	var hostKeys []string // the vhost filter: host, plus its www. twin with mergeWWW
	if host != "" {
		hostKeys = []string{host}
		if mergeWWW {
			base := strings.TrimPrefix(host, "www.")
			hostKeys = []string{base, "www." + base}
		}
	}
	// The window starts at the boundary of the bucket holding since (rounded
	// DOWN), and since / window_sec report that span: every figure, the
	// averages included, is exact over what is counted, and a short window
	// asked just after a boundary still covers at least what was asked.
	sinceSec := nowSec - int64(window/time.Second)
	firstB, lastB := sinceSec/tmBucketSec, nowSec/tmBucketSec
	lastMin := nowSec / 60
	if closedEnd {
		lastB, lastMin = nowSec/tmBucketSec-1, nowSec/60-1
	}
	if lastB-firstB >= tmBuckets { // never more buckets than the ring holds
		firstB = lastB - tmBuckets + 1
	}
	sinceSec = firstB * tmBucketSec

	out := TrafficMix{Schema: "webdet.traffic_mix.v1", WindowSec: nowSec - sinceSec, Since: sinceSec, Until: nowSec, Host: host, Note: trafficMixNote}
	var cls [tmClasses]tmCounters
	hosts := map[string]*[tmClasses]tmSmall{}
	type ck struct {
		cls int
		key string
	}
	clients := map[ck]*tmClient{}
	// The last hour of the window, per client: requests and evidence (the
	// distributed tell reads the hour its IPs cover). A window shorter than
	// an hour is read whole: its thresholds (200 requests, 50 IPs) then apply
	// to less time, so a 15-minute view flags fewer populations than the 1 h
	// default, never more.
	hourStat := map[ck]*[2]int64{}
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
					acc[i].addSmall(hv[i])
				}
			}
		} else {
			var bc [tmClasses]int64
			for _, hk := range hostKeys {
				hv := b.hosts[hk]
				if hv == nil {
					continue
				}
				for i := 0; i < tmClasses; i++ {
					cls[i].Req += hv[i].Req
					cls[i].OriginMs += hv[i].OriginMs
					cls[i].Bytes += hv[i].Bytes
					cls[i].Out.add(hv[i].out())
					bc[i] += hv[i].Req
				}
			}
			for i := 0; i < tmClasses; i++ {
				pt.Classes[tmClassKeys[i]] = bc[i]
				if r := float64(bc[i]) / tmBucketSec; r > peak[i] {
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
				acc.addSmall(cl.tmSmall)
				acc.ev += cl.ev
				if id > lastB-tmIPBuckets {
					hs := hourStat[k]
					if hs == nil {
						hs = &[2]int64{}
						hourStat[k] = hs
					}
					hs[0] += cl.Req
					hs[1] += cl.ev
				}
				if cl.ips != nil && id > lastB-tmIPBuckets {
					if acc.ips == nil {
						acc.ips = map[string]int64{}
					}
					for ip, n := range cl.ips {
						acc.ips[ip] += n
					}
				}
				if cl.hosts != nil && id > lastB-tmIPBuckets {
					if acc.hosts == nil {
						acc.hosts = map[string]int64{}
					}
					for h, n := range cl.hosts {
						acc.hosts[h] += n // the hour's sum is not capped: a vhost "_other" in one bucket is named in another
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
		for m := sinceSec / 60; m <= lastMin; m++ {
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
		c := tmClassOut(i, cls[i], secs, peak[i], peakAt[i], len(hostKeys) == 0)
		c.PeakWindow = peakWin
		out.Classes = append(out.Classes, c)
	}
	out.Total = tmClassOut(-1, tot, secs, 0, 0, len(hostKeys) == 0)
	out.Series, out.SeriesSec = series, tmBucketSec

	if host == "" {
		for hk, hv := range hosts {
			h := TrafficMixHost{Host: hk, Classes: map[string]TrafficMixSplit{}}
			var tout tmOut
			for i := 0; i < tmClasses; i++ {
				sp := TrafficMixSplit{Requests: hv[i].Req, OriginSec: msToSec(hv[i].OriginMs), Bytes: hv[i].Bytes, Outcomes: tmOutcomesOut(hv[i].Req, hv[i].out())}
				h.Classes[tmClassKeys[i]] = sp
				h.Total.Requests += sp.Requests
				h.Total.OriginSec += sp.OriginSec
				h.Total.Bytes += sp.Bytes
				tout.add(hv[i].out())
			}
			h.Total.Outcomes = tmOutcomesOut(h.Total.Requests, tout)
			out.Hosts = append(out.Hosts, h)
		}
		// The summed tail (_other) is never ranked against real vhosts nor
		// takes a hosts=N slot: it trails the list.
		var other *TrafficMixHost
		named := out.Hosts[:0]
		for i := range out.Hosts {
			if out.Hosts[i].Host == tmOtherKey {
				o := out.Hosts[i]
				other = &o
				continue
			}
			named = append(named, out.Hosts[i])
		}
		out.Hosts = named
		sort.Slice(out.Hosts, func(i, j int) bool {
			if out.Hosts[i].Total.OriginSec != out.Hosts[j].Total.OriginSec {
				return out.Hosts[i].Total.OriginSec > out.Hosts[j].Total.OriginSec
			}
			return out.Hosts[i].Host < out.Hosts[j].Host
		})
		if len(out.Hosts) > hostLimit {
			out.Hosts = out.Hosts[:hostLimit]
		}
		if other != nil {
			out.Hosts = append(out.Hosts, *other)
		}
	}

	for k, cl := range clients {
		c := TrafficMixClient{Class: tmClassKeys[k.cls], Client: k.key, Requests: cl.Req, OriginSec: msToSec(cl.OriginMs), Bytes: cl.Bytes, Outcomes: tmOutcomesOut(cl.Req, cl.out())}
		var hourReq, hourEv int64
		if hs := hourStat[k]; hs != nil {
			hourReq, hourEv = hs[0], hs[1]
		}
		if (k.cls == tmHuman || k.cls == tmAutomation) && hourReq > 0 {
			e := float64(hourEv) / float64(hourReq)
			c.EvidenceShare = &e
		}
		if k.cls == tmHuman && k.key != tmOtherKey {
			var sampled int64 // requests of the IPs kept (the first tmMaxHumanClientIPs per bucket)
			for _, n := range cl.ips {
				sampled += n
			}
			c.Distributed = distributedTell(len(cl.ips), sampled, hourReq, hourEv)
			if d := c.Distributed; d != nil {
				d.Nets = tmNetCount(cl.ips)
				d.Hosts = tmTopHosts(cl.hosts, tmDistTopHosts)
			}
		}
		// A browser-UA client's addresses are listed only when the tell
		// fires (they are visitors' otherwise): its count is enough.
		listIPs := k.cls != tmHuman || c.Distributed != nil
		ipCap := 50
		if c.Distributed != nil {
			ipCap = manualIPChallengeMax // every address the operator may challenge at once
		}
		if len(cl.ips) > 0 {
			c.IPs = len(cl.ips)
		}
		if len(cl.ips) > 0 && listIPs {
			for ip, n := range cl.ips {
				c.TopIPs = append(c.TopIPs, TrafficMixIP{IP: ip, Requests: n})
			}
			sort.Slice(c.TopIPs, func(i, j int) bool {
				if c.TopIPs[i].Requests != c.TopIPs[j].Requests {
					return c.TopIPs[i].Requests > c.TopIPs[j].Requests
				}
				return c.TopIPs[i].IP < c.TopIPs[j].IP
			})
			if len(c.TopIPs) > ipCap {
				c.TopIPs = c.TopIPs[:ipCap]
			}
		}
		out.Clients = append(out.Clients, c)
	}
	// The chosen key first, then origin time and requests, then the name:
	// a stable order for equal keys.
	key := func(c TrafficMixClient) float64 {
		switch sortBy {
		case TrafficMixSortRequests:
			return float64(c.Requests)
		case TrafficMixSortBytes:
			return float64(c.Bytes)
		case TrafficMixSortIPs:
			// A distributed population by its pool, not the sample its
			// buckets kept (~768 at most an hour): an 18k pool must not
			// rank under an 800-address population.
			if c.Distributed != nil {
				return float64(c.Distributed.EstIPs)
			}
			return float64(c.IPs)
		}
		return c.OriginSec
	}
	sort.Slice(out.Clients, func(i, j int) bool {
		a, b := out.Clients[i], out.Clients[j]
		// A class's summed tail (_other: every client past the bucket cap)
		// is never ranked against named clients: by requests or IPs it
		// would head the list. It trails, as the vhosts' does.
		if ao, bo := a.Client == tmOtherKey, b.Client == tmOtherKey; ao != bo {
			return bo
		}
		if ka, kb := key(a), key(b); ka != kb {
			return ka > kb
		}
		if a.OriginSec != b.OriginSec {
			return a.OriginSec > b.OriginSec
		}
		if a.Requests != b.Requests {
			return a.Requests > b.Requests
		}
		return a.Client < b.Client
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

func tmClassOut(i int, c tmCounters, secs, peak float64, peakAt int64, full bool) TrafficMixClass {
	o := TrafficMixClass{
		Requests: c.Req, OriginSec: msToSec(c.OriginMs), Bytes: c.Bytes,
		RPSPeak: peak, PeakAt: peakAt, Outcomes: tmOutcomesOut(c.Req, c.Out),
	}
	if full {
		edge := c.Edge
		o.EdgeServed = &edge
		o.Status = &TrafficMixStatus{S2xx: c.S2xx, S3xx: c.S3xx, S4xx: c.S4xx, S403: c.S403, S429: c.S429, S5xx: c.S5xx}
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
// ?window=<5m..24h, default 1h>&host=<vhost>&merge_www=1&hosts=<n>&clients=<n>
// &sort=<origin|requests|bytes|ips> (which clients make the top n, and their
// order; default origin time; anything else is a 400)
// &until=<unix seconds> (the window ENDS there instead of now: a 5-minute
// boundary within the last 24 h, so a finished hour reads the same every
// time; anything else is a 400).
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
	mergeWWW := q.Get("merge_www") == "1" || strings.EqualFold(q.Get("merge_www"), "true")
	sortBy := strings.ToLower(strings.TrimSpace(q.Get("sort")))
	if sortBy == "" {
		sortBy = TrafficMixSortOrigin
	}
	if !slices.Contains(TrafficMixSorts, sortBy) {
		writeJSON(w, http.StatusBadRequest, map[string]string{"error": "sort: one of " + strings.Join(TrafficMixSorts, ", ")})
		return
	}
	if v := strings.TrimSpace(q.Get("until")); v != "" {
		until, err := strconv.ParseInt(v, 10, 64)
		now := time.Now().Unix()
		if err != nil || until%tmBucketSec != 0 || until > now || until <= now-24*3600 {
			writeJSON(w, http.StatusBadRequest, map[string]string{"error": "until: unix seconds on a 5-minute boundary, in the past, within the last 24 h"})
			return
		}
		writeJSON(w, http.StatusOK, trafficMix.SnapshotUntil(time.Unix(until, 0), window, q.Get("host"), mergeWWW, atoi("hosts"), atoi("clients"), sortBy))
		return
	}
	writeJSON(w, http.StatusOK, trafficMix.SnapshotSorted(time.Now(), window, q.Get("host"), mergeWWW, atoi("hosts"), atoi("clients"), sortBy))
}

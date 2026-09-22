package enrich

import (
	"context"
	"errors"
	"net"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"sync/atomic"
	"time"

	lruexp "github.com/hashicorp/golang-lru/v2/expirable"
	"github.com/oschwald/geoip2-golang"
	"golang.org/x/sync/singleflight"
)

const (
	// 24-hour TTL. PTR reverse-DNS is the expensive field (up to dnsTimeout per
	// cold IP) and changes very rarely, so a long cache means we resolve a given
	// IP roughly once a day instead of every few hours — the bulk of the WAF/
	// challenge/drilldown enrich cost is repeat lookups of the same IPs. The TTL
	// is shared with the (cheap) mmdb country/ASN fields, which bounds their
	// staleness to ~1 day after a weekly mmdb update — acceptable for country/ASN
	// rules (an IP's geo/ASN almost never changes). PTR-using consumers (FCrDNS
	// for crawlers) re-verify the PTR back-resolves, so stale PTR fails closed.
	// A longer, PTR-only cache (week+) would need PTR split from the geo TTL.
	cacheTTL   = 24 * time.Hour
	dnsTimeout = 1 * time.Second // 1s timeout για PTR lookups

	// ptrCacheTTL keeps resolved PTRs far longer than the 24h geo TTL. PTR is
	// the ONLY expensive field (a blocking reverse-DNS, up to dnsTimeout each)
	// and it changes very rarely (an IP's rDNS is stable for months), so it lives
	// in its own long-lived cache: geo (country/ASN) still refreshes daily from
	// mmdb while a given IP's PTR is resolved roughly once a month regardless of
	// how many times it is seen. Negative results (no PTR / DNS timeout) are NOT
	// cached, so a transient failure doesn't suppress a real PTR for 30 days.
	// In-memory only (lost on restart); a persistent (SQLite) PTR store is a
	// possible follow-up, low-value now that no hot path blocks on PTR.
	ptrCacheTTL = 30 * 24 * time.Hour
	// ptrRetryInterval: a cached Result whose PTR resolution FAILED (timeout /
	// SERVFAIL → PTR "", ptrFailed=true) is retried this often instead of
	// sitting empty for the whole 24h geo TTL. Matters since verified_bot
	// traffic rules and the good-bot challenge exemption key on the PTR: one
	// resolver blip must not make a crawler IP unverifiable for a day. A
	// definitive "no PTR" (NXDOMAIN) is NOT retried — it is the common case and
	// would otherwise cost every synchronous Lookup caller a reverse lookup
	// per IP every few minutes.
	ptrRetryInterval = 5 * time.Minute
	statEvery        = 300 * time.Second // πόσο συχνά θα ελέγχουμε για αλλαγές στα mmdb αρχεία

	// cacheCap is the maximum number of distinct IPs held in the geoip
	// result cache. The previous map[string]Result had no eviction and
	// grew with every unique IP seen since worker start (~250 bytes per
	// entry). At 400 000 entries the worst-case footprint is ~100 MB per
	// worker; the LRU evicts the coldest entry once the cap is reached,
	// so memory plateaus regardless of how many unique IPs the worker
	// has seen over its lifetime. Raised from 200k alongside the 24h TTL so
	// a busy node's active IP set stays resident for the full day rather than
	// being evicted and re-resolved (PTR rDNS) under churn.
	cacheCap = 400_000

	// asyncWorkerCap caps the number of concurrent in-flight async PTR/mmdb
	// lookups dispatched by LookupCachedOrAsync. Past this, fresh-IP misses
	// quietly return an empty Result rather than spawning more goroutines —
	// the next request for that IP will retry. Tuned to comfortably absorb a
	// burst from a few hundred unique IPs without unbounded goroutine growth.
	asyncWorkerCap = 32
)

type Result struct {
	PTR        string
	ASN        uint
	ASNName    string
	Country    string
	CountryISO string // ISO-2 "GR" (rule matching)
	City       string
	ts         time.Time
	// ptrFailed: the reverse lookup did NOT complete (timeout / SERVFAIL /
	// network), as opposed to a definitive "this IP has no PTR" (NXDOMAIN).
	// Only a failed lookup is retried before the geo TTL (ptrRetryDue); an IP
	// that simply has no PTR — the common case — stays cached for the full TTL
	// so the many synchronous Lookup callers (detectors, notify, ipquery) do
	// not pay a reverse lookup every few minutes for it.
	ptrFailed bool
}

type Enricher struct {
	// mu protects the geoip DB pointers and hot-reload bookkeeping below.
	// It is NOT held around cache reads/writes — the LRU has its own
	// internal locking, so the hot path takes only one mutex (the LRU's)
	// instead of two.
	//
	// READERS HOLD mu.RLock FOR THE WHOLE READ, not just to load the pointer
	// (readGeo). The readers are mmap'd: Close() munmaps them, and the swap
	// in refreshIfChanged used to close the old reader while a lookup that
	// had already copied its pointer was still decoding from it — a read of
	// unmapped memory, i.e. SIGSEGV, which Go cannot recover from. That
	// crashed the daemon when a lookup overlapped a database refresh (CFM's
	// own maxmindupdater, as often as every ~3 days; each Enricher swaps on
	// its own). Reproduced: TestHotSwapNeverReadsAClosedReader. A writer now
	// takes mu.Lock, which waits for every in-flight read, so a reader is
	// closed only once nothing can still be reading it. Never call back into the
	// Enricher while holding mu, and never do network I/O under it.
	mu sync.RWMutex
	// cache is a size-bounded TTL-expiring LRU. Eviction policy:
	//   - entry expires after cacheTTL → auto-removed on next Get/Add
	//   - cache full → coldest entry evicted on Add
	// This bounds memory at cacheCap entries (~50 MB worst case per worker)
	// regardless of how many unique IPs have been seen since worker start.
	cache *lruexp.LRU[string, Result]
	// ptrCache holds resolved PTRs alone, on the much longer ptrCacheTTL, so a
	// given IP's reverse-DNS is done ~once a month while geo stays daily-fresh.
	ptrCache *lruexp.LRU[string, string]
	asnDB    *geoip2.Reader
	cityDB   *geoip2.Reader
	// hot-reload state
	asnPath    string
	cityPath   string
	searchDirs []string
	asnMTime   time.Time
	cityMTime  time.Time
	// closed is set by Close; a refresh then installs nothing (under mu).
	closed bool
	// statChk is when the last on-disk change check ran, in monotonic
	// nanoseconds since monoStart (0 = never). Atomic, NOT under mu:
	// refreshIfChanged runs on every Lookup cache miss, and when
	// its rate-limit test took mu.Lock, that write lock — now that readers
	// hold mu.RLock for a whole decode — waited on in-flight reads and, with
	// Go's writer preference, stalled every new reader behind it, on every
	// miss (BenchmarkLookupGeoFastUnderMisses). Now mu.Lock is taken only
	// for an actual swap. CompareAndSwap lets one caller per statEvery check.
	statChk atomic.Int64
	// options
	enablePTR bool
	// Async-dispatch primitives for LookupCachedOrAsync.
	// sf coalesces concurrent fresh-IP misses for the same address into a
	// single underlying Lookup call. asyncSem bounds total concurrent async
	// lookups so a flood of unique IPs cannot spawn unbounded goroutines.
	sf       singleflight.Group
	asyncSem chan struct{}
}

// New ενεργοποιεί enrichment αν βρει mmdb αρχεία σε dirs (π.χ. /etc/cfm, ./configs).
// Αν δεν βρει κανένα, θα δίνει μόνο PTR (reverse DNS) με caching.

func New(dirs ...string) (*Enricher, error) {
	e := &Enricher{
		cache:     lruexp.NewLRU[string, Result](cacheCap, nil, cacheTTL),
		ptrCache:  lruexp.NewLRU[string, string](cacheCap, nil, ptrCacheTTL),
		enablePTR: true,
		asyncSem:  make(chan struct{}, asyncWorkerCap),
	}
	var asnPath, cityPath string

	// default search dirs now include maxmind updater location
	if len(dirs) == 0 {
		dirs = []string{
			"/var/lib/cfm/maxmind",
			"/etc/cfm",
			"./configs",
		}
	}
	e.searchDirs = append([]string(nil), dirs...)
	for _, d := range dirs {
		if asnPath == "" {
			p := filepath.Join(d, "GeoLite2-ASN.mmdb")
			if _, err := os.Stat(p); err == nil {
				asnPath = p
			}
		}
		if cityPath == "" {
			p := filepath.Join(d, "GeoLite2-City.mmdb")
			if _, err := os.Stat(p); err == nil {
				cityPath = p
			}
		}
	}

	// Φόρτωσε τις DBs αν βρέθηκαν (δεν είναι σφάλμα αν δεν υπάρχουν).
	if asnPath != "" {
		if db, err := geoip2.Open(asnPath); err == nil {
			e.asnDB = db
			e.asnPath = asnPath
			if fi, err2 := os.Stat(asnPath); err2 == nil {
				e.asnMTime = fi.ModTime()
			}
		}
	}
	if cityPath != "" {
		if db, err := geoip2.Open(cityPath); err == nil {
			e.cityDB = db
			e.cityPath = cityPath
			if fi, err2 := os.Stat(cityPath); err2 == nil {
				e.cityMTime = fi.ModTime()
			}
		}
	}

	return e, nil
}

func (e *Enricher) Close() {
	// Detach under the write lock — which waits for every in-flight read —
	// then close outside it. A lookup running concurrently with Close used to
	// be able to read the unmapped reader; now it finishes first, and a
	// lookup after Close sees no reader (empty geo). Close is final: closed
	// stops a later refresh from reopening the files, and a refresh already
	// past its stat when Close runs discards what it opened (see the swap).
	// Callers: the nflog SMTP snoop and outbound collector workers on
	// shutdown, and the status / ipquery CLI paths.
	e.mu.Lock()
	asn, city := e.asnDB, e.cityDB
	e.asnDB, e.cityDB = nil, nil
	e.closed = true
	e.mu.Unlock()
	if asn != nil {
		_ = asn.Close()
	}
	if city != nil {
		_ = city.Close()
	}
}

// readGeo fills r's ASN / country / city from the open databases. It is the
// ONE place the mmdb readers are read, and it holds mu.RLock for the whole
// read — see the note on mu for why copying the pointer and unlocking first
// is not enough. Only mmdb decoding here — no network or file I/O — though a
// read of a cold page of the mmap'd file can page-fault. Readers share the
// RLock, so a slow read holds up no other lookup — except while a swap is
// waiting: a pending mu.Lock queues every new RLock behind it (Go's writer
// preference), so for that one swap, lookups wait on the slowest read.
func (e *Enricher) readGeo(ip net.IP, r *Result) {
	e.mu.RLock()
	defer e.mu.RUnlock()
	if e.asnDB != nil {
		if rec, err := e.asnDB.ASN(ip); err == nil && rec != nil {
			r.ASN = rec.AutonomousSystemNumber
			r.ASNName = rec.AutonomousSystemOrganization
		}
	}
	if e.cityDB != nil {
		if rec, err := e.cityDB.City(ip); err == nil && rec != nil {
			r.CountryISO = rec.Country.IsoCode
			if name, ok := rec.Country.Names["en"]; ok && name != "" {
				r.Country = name
			} else {
				r.Country = rec.Country.IsoCode
			}
			if c, ok := rec.City.Names["en"]; ok {
				r.City = c
			}
		}
	}
}

// Lookup: κάνει PTR + (προαιρετικά) ASN/City και χρησιμοποιεί cache με TTL.
func (e *Enricher) Lookup(ipStr string) Result {
	now := time.Now()

	// cache hit — TTL/LRU eviction is handled internally by the LRU. A hit
	// whose PTR fetch failed earlier is re-resolved once ptrRetryInterval has
	// passed (the fresh Result then replaces it with a new ts).
	if r, ok := e.cache.Get(ipStr); ok && !e.ptrRetryDue(r, ipStr, now) {
		return r
	}

	// hot-reload if underlying files changed (rate-limited stat calls)
	e.refreshIfChanged()

	r := Result{ts: now}
	ip := net.ParseIP(ipStr)
	if ip == nil {
		return r
	}

	// PTR (reverse DNS) με timeout

	if e.enablePTR && isRoutable(ip) {
		// L1: this Enricher's own in-memory PTR cache.
		if p, ok := e.ptrCache.Get(ipStr); ok {
			r.PTR = p
		} else if sp := sharedPTRStore(); sp != nil {
			// L2: the process-wide persistent store, warmed by every Enricher
			// and surviving restarts. A hit here still skips reverse-DNS; warm
			// L1 so subsequent lookups on this instance don't touch SQLite.
			if p, ok := sp.get(ipStr); ok {
				r.PTR = p
				e.ptrCache.Add(ipStr, p)
			}
		}
		if r.PTR == "" {
			// Cold in both layers → resolve, then populate L1 and (async) L2.
			ctx, cancel := context.WithTimeout(context.Background(), dnsTimeout)
			names, err := net.DefaultResolver.LookupAddr(ctx, ipStr)
			cancel()
			if len(names) > 0 {
				// καθάρισε τυχόν τελεία στο τέλος
				r.PTR = strings.TrimSuffix(names[0], ".")
			} else if err != nil {
				// NXDOMAIN is a definitive "no PTR"; anything else (timeout,
				// SERVFAIL, network) did not complete → eligible for retry.
				var dnsErr *net.DNSError
				r.ptrFailed = !(errors.As(err, &dnsErr) && dnsErr.IsNotFound)
			}
			// Cache only a real PTR; a miss/timeout is left uncached so it is
			// retried next time rather than pinned empty for ptrCacheTTL.
			if r.PTR != "" {
				e.ptrCache.Add(ipStr, r.PTR)
				sharedPTRStore().put(ipStr, r.PTR) // nil-safe when persistence is off
			}
		}
	}

	// ASN + Country/City (under mu.RLock for the whole read — readGeo).
	e.readGeo(ip, &r)

	// store in cache (LRU handles its own locking + eviction)
	e.cache.Add(ipStr, r)

	return r
}

// LookupGeoFast performs ONLY the synchronous mmdb (country + ASN + city)
// lookups, deliberately skipping the slow reverse-DNS PTR resolution that
// makes Lookup() unsafe on a request hot path. Typical cost is 1–10 μs
// (memory-mapped DB reads); never blocks on the network.
//
// Used by LookupCachedOrAsync below so cache misses still return real
// country / ASN data immediately — only PTR is deferred. This matters
// because cfm-admin country-block rules consume Country directly from
// the bridge's TrafficRuleEvalInput; if we returned an empty Result on
// cache miss, the *first* request from a fresh IP from a blocked country
// would slip through.
func (e *Enricher) LookupGeoFast(ipStr string) Result {
	if e == nil || ipStr == "" {
		return Result{}
	}
	ip := net.ParseIP(ipStr)
	if ip == nil {
		return Result{}
	}

	r := Result{ts: time.Now()}
	e.readGeo(ip, &r)
	return r
}

// LookupCachedOrAsync returns the cached Result for ipStr if one is fresh in
// memory. On a cache miss it returns the *fast* mmdb-only data (country +
// ASN — microseconds, no DNS) immediately and dispatches the *full* Lookup
// (which includes PTR reverse-DNS) on a background goroutine, so the next
// request for the same IP can serve the complete record from cache.
//
// Why: Lookup() does up to 1s of reverse-DNS plus mmdb reads on a cold IP.
// On the bridge decision hot path (one call per HTTP request from nginx),
// that latency can exhaust the Lua-side cosocket timeout under load even
// though the bridge handler itself is otherwise sub-millisecond.
//
// Trade-off: only PTR is deferred. Country and ASN remain inline-accurate
// on every request — country-block rules in cfm-admin still fire on the
// FIRST request from a fresh IP. PTR-dependent paths (challenge_exclude
// FCrDNS for Googlebot etc.) live in autoblock_sink and call Lookup()
// synchronously on their own pipeline; they're unaffected by this method.
//
// Concurrent misses for the same IP are coalesced via singleflight, and
// the total number of in-flight async lookups is bounded by asyncSem so
// a flood of unique IPs can't spawn unbounded goroutines. If asyncSem is
// saturated we just skip the dispatch — the next request retries.
func (e *Enricher) LookupCachedOrAsync(ipStr string) Result {
	if e == nil || ipStr == "" {
		return Result{}
	}

	// Fast path: cache hit. LRU handles TTL expiry + recency tracking. A hit
	// with a failed PTR is served as-is but, once ptrRetryDue, also kicks the
	// async full Lookup below so the PTR gets another chance.
	if r, ok := e.cache.Get(ipStr); ok {
		if !e.ptrRetryDue(r, ipStr, time.Now()) {
			return r
		}
		e.dispatchAsyncLookup(ipStr)
		return r
	}

	// Inline mmdb call: country + ASN in microseconds, no DNS.
	// Returned to the caller right away so country-block / ASN-block rules
	// have real data even on the *first* request from a fresh IP. We do
	// NOT cache this partial result — the async dispatch below will
	// overwrite cache with the full PTR-included Result shortly.
	partial := e.LookupGeoFast(ipStr)
	e.dispatchAsyncLookup(ipStr)
	return partial
}

// dispatchAsyncLookup runs the full Lookup for ip on a background goroutine,
// best-effort: non-blocking on asyncSem saturation (the next request retries),
// singleflight-coalesced per IP.
func (e *Enricher) dispatchAsyncLookup(ipStr string) {
	select {
	case e.asyncSem <- struct{}{}:
		go func(ip string) {
			defer func() { <-e.asyncSem }()
			// singleflight guarantees only one Lookup runs per IP at a
			// time even if many requests miss simultaneously.
			_, _, _ = e.sf.Do(ip, func() (interface{}, error) {
				return e.Lookup(ip), nil
			})
		}(ipStr)
	default:
		// asyncSem full; intentionally drop. Next request retries.
	}
}

// ptrRetryDue reports whether a cached Result should have its PTR re-resolved:
// PTR resolution is enabled, the IP is routable, the earlier reverse lookup
// FAILED (ptrFailed — not a definitive NXDOMAIN) and ptrRetryInterval has
// passed since it was cached.
func (e *Enricher) ptrRetryDue(r Result, ipStr string, now time.Time) bool {
	if e == nil || !e.enablePTR || r.PTR != "" || !r.ptrFailed {
		return false
	}
	if now.Sub(r.ts) < ptrRetryInterval {
		return false
	}
	ip := net.ParseIP(ipStr)
	return ip != nil && isRoutable(ip)
}

// PTREnabled reports whether this Enricher resolves reverse DNS at all (the
// ENRICH PTR switch). Callers that need a PTR for a verdict (verified_bot)
// must treat false as "cannot be verified here", not as "no PTR".
func (e *Enricher) PTREnabled() bool {
	return e != nil && e.enablePTR
}

// Enabled επιστρέφει true αν έχουμε τουλάχιστον μία GeoIP DB ανοιχτή.
func (e *Enricher) Enabled() bool {
	if e == nil {
		return false
	}
	e.mu.RLock()
	defer e.mu.RUnlock()
	return e.asnDB != nil || e.cityDB != nil
}

// HasASN / HasCountry report whether the ASN / City database is loaded right
// now. Either can change after New: a database installed later (the MaxMind
// updater) is picked up by the hot reload on a later lookup, and Close drops
// both. Cheap (one RLock); never calls out.
func (e *Enricher) HasASN() bool {
	if e == nil {
		return false
	}
	e.mu.RLock()
	defer e.mu.RUnlock()
	return e.asnDB != nil
}

func (e *Enricher) HasCountry() bool {
	if e == nil {
		return false
	}
	e.mu.RLock()
	defer e.mu.RUnlock()
	return e.cityDB != nil
}

// monoStart anchors statChk to the monotonic clock (see refreshIfChanged).
var monoStart = time.Now()

// refreshIfChanged checks if files changed and safely reopens them.
// CRITICAL: Does file I/O OUTSIDE the mutex to avoid blocking all Lookup() calls.
func (e *Enricher) refreshIfChanged() {
	// Monotonic, like the time.Time.Sub this replaced: a wall-clock step
	// (NTP) must neither stall nor hasten the check. +1 keeps a real reading
	// from ever colliding with 0, which means "never checked".
	now := int64(time.Since(monoStart)) + 1

	// Rate limit WITHOUT a lock (see statChk): the common case — checked
	// recently — returns here having touched only an atomic. One caller per
	// statEvery wins the CompareAndSwap and does the check.
	last := e.statChk.Load()
	if (last != 0 && now-last < int64(statEvery)) || !e.statChk.CompareAndSwap(last, now) {
		return
	}

	// Snapshot under the read lock; these are written only by the swap below.
	e.mu.RLock()
	if e.closed {
		e.mu.RUnlock()
		return
	}
	asnPath := e.asnPath
	cityPath := e.cityPath
	searchDirs := append([]string(nil), e.searchDirs...)
	asnMTime := e.asnMTime
	cityMTime := e.cityMTime
	e.mu.RUnlock()

	// Do ALL file I/O outside lock (CRITICAL FIX)
	var newASN, newCity *geoip2.Reader
	var newASNTime, newCityTime time.Time
	var newASNPath, newCityPath string

	// If ASN path is unknown, discover it first from configured search dirs.
	if asnPath == "" {
		for _, d := range searchDirs {
			p := filepath.Join(d, "GeoLite2-ASN.mmdb")
			if fi, err := os.Stat(p); err == nil {
				if db, err := geoip2.Open(p); err == nil {
					newASN = db
					newASNTime = fi.ModTime()
					newASNPath = p
				}
				break
			}
		}
	} else {
		// Check and load ASN DB (outside lock)
		if fi, err := os.Stat(asnPath); err == nil {
			if fi.ModTime().After(asnMTime) {
				if db, err := geoip2.Open(asnPath); err == nil {
					newASN = db
					newASNTime = fi.ModTime()
					newASNPath = asnPath
				}
			}
		}
	}

	// If City path is unknown, discover it first from configured search dirs.
	if cityPath == "" {
		for _, d := range searchDirs {
			p := filepath.Join(d, "GeoLite2-City.mmdb")
			if fi, err := os.Stat(p); err == nil {
				if db, err := geoip2.Open(p); err == nil {
					newCity = db
					newCityTime = fi.ModTime()
					newCityPath = p
				}
				break
			}
		}
	} else {
		// Check and load City DB (outside lock)
		if fi, err := os.Stat(cityPath); err == nil {
			if fi.ModTime().After(cityMTime) {
				if db, err := geoip2.Open(cityPath); err == nil {
					newCity = db
					newCityTime = fi.ModTime()
					newCityPath = cityPath
				}
			}
		}
	}

	// Swap under the write lock. Taking it waits for every in-flight read
	// (readers hold mu.RLock for the whole read), and once the pointers are
	// swapped no new read can reach the old readers — so they are closed
	// (munmap'd) only after the unlock, when nothing can still be reading
	// them. Closing them while a read was in flight is what used to fault.
	//
	// The snapshot above may be stale by now: Close may have run, or an
	// overlapping check (one whose stat outlasted statEvery) may already have
	// installed this file or a newer one. A reader opened here that is not
	// newer than the installed one — or any, after Close — is closed instead
	// of installed, so a swap never goes backwards and Close stays final.
	var oldASN, oldCity *geoip2.Reader
	e.mu.Lock()
	if newASN != nil {
		if e.closed || !newASNTime.After(e.asnMTime) {
			oldASN = newASN
		} else {
			oldASN = e.asnDB
			e.asnDB = newASN
			if newASNPath != "" {
				e.asnPath = newASNPath
			}
			e.asnMTime = newASNTime
		}
	}
	if newCity != nil {
		if e.closed || !newCityTime.After(e.cityMTime) {
			oldCity = newCity
		} else {
			oldCity = e.cityDB
			e.cityDB = newCity
			if newCityPath != "" {
				e.cityPath = newCityPath
			}
			e.cityMTime = newCityTime
		}
	}
	e.mu.Unlock()
	if oldASN != nil {
		_ = oldASN.Close()
	}
	if oldCity != nil {
		_ = oldCity.Close()
	}

}

// isRoutable: αποφυγή PTR για private/loopback/link-local/multicast/unspecified
func isRoutable(ip net.IP) bool {
	// Go 1.20+ έχει helpers:
	if ip.IsLoopback() || ip.IsMulticast() || ip.IsUnspecified() {
		return false
	}
	// Private & link-local
	if ip.IsPrivate() || ip.IsLinkLocalUnicast() || ip.IsLinkLocalMulticast() {
		return false
	}
	return true
}

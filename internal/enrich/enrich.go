package enrich

import (
	"context"
	"net"
	"os"
	"path/filepath"
	"strings"
	"sync"
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
	// SERVFAIL → PTR "") is retried this often instead of sitting empty for the
	// whole 24h geo TTL. Matters since verified_bot traffic rules and the
	// good-bot challenge exemption key on the PTR: one resolver blip must not
	// make a crawler IP unverifiable for a day.
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
}

type Enricher struct {
	// mu protects the geoip DB pointers and hot-reload bookkeeping below.
	// It is NOT held around cache reads/writes — the LRU has its own
	// internal locking, so the hot path takes only one mutex (the LRU's)
	// instead of two.
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
	asnPath     string
	cityPath    string
	searchDirs  []string
	asnMTime    time.Time
	cityMTime   time.Time
	lastStatChk time.Time
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
	if e.asnDB != nil {
		_ = e.asnDB.Close()
	}
	if e.cityDB != nil {
		_ = e.cityDB.Close()
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
			names, _ := net.DefaultResolver.LookupAddr(ctx, ipStr)
			cancel()
			if len(names) > 0 {
				// καθάρισε τυχόν τελεία στο τέλος
				r.PTR = strings.TrimSuffix(names[0], ".")
			}
			// Cache only a real PTR; a miss/timeout is left uncached so it is
			// retried next time rather than pinned empty for ptrCacheTTL.
			if r.PTR != "" {
				e.ptrCache.Add(ipStr, r.PTR)
				sharedPTRStore().put(ipStr, r.PTR) // nil-safe when persistence is off
			}
		}
	}

	// ASN
	e.mu.RLock()
	localASN := e.asnDB
	localCity := e.cityDB
	e.mu.RUnlock()

	if localASN != nil {
		if rec, err := localASN.ASN(ip); err == nil && rec != nil {
			r.ASN = rec.AutonomousSystemNumber
			r.ASNName = rec.AutonomousSystemOrganization
		}
	}

	// Country/City
	if localCity != nil {
		if rec, err := localCity.City(ip); err == nil && rec != nil {
			r.CountryISO = rec.Country.IsoCode // ← add this line
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

	e.mu.RLock()
	localASN := e.asnDB
	localCity := e.cityDB
	e.mu.RUnlock()

	r := Result{ts: time.Now()}

	if localASN != nil {
		if rec, err := localASN.ASN(ip); err == nil && rec != nil {
			r.ASN = rec.AutonomousSystemNumber
			r.ASNName = rec.AutonomousSystemOrganization
		}
	}
	if localCity != nil {
		if rec, err := localCity.City(ip); err == nil && rec != nil {
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
// PTR resolution is enabled, the IP is routable, the cached PTR is empty
// (earlier miss/timeout) and ptrRetryInterval has passed since it was cached.
func (e *Enricher) ptrRetryDue(r Result, ipStr string, now time.Time) bool {
	if e == nil || !e.enablePTR || r.PTR != "" {
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
	return e != nil && (e.asnDB != nil || e.cityDB != nil)
}

// refreshIfChanged checks if files changed and safely reopens them.
// CRITICAL: Does file I/O OUTSIDE the mutex to avoid blocking all Lookup() calls.
func (e *Enricher) refreshIfChanged() {
	now := time.Now()

	// Quick check + snapshot under lock
	e.mu.Lock()
	if now.Sub(e.lastStatChk) < statEvery {
		e.mu.Unlock()
		return
	}
	e.lastStatChk = now

	asnPath := e.asnPath
	cityPath := e.cityPath
	searchDirs := append([]string(nil), e.searchDirs...)
	asnMTime := e.asnMTime
	cityMTime := e.cityMTime
	e.mu.Unlock()

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

	// Quick lock to swap pointers
	e.mu.Lock()
	defer e.mu.Unlock()

	if newASN != nil {
		old := e.asnDB
		e.asnDB = newASN
		if newASNPath != "" {
			e.asnPath = newASNPath
		}
		e.asnMTime = newASNTime
		if old != nil {
			_ = old.Close()
		}
	}
	if newCity != nil {
		old := e.cityDB
		e.cityDB = newCity
		if newCityPath != "" {
			e.cityPath = newCityPath
		}
		e.cityMTime = newCityTime
		if old != nil {
			_ = old.Close()
		}
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

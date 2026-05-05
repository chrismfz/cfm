package enrich

import (
	"context"
	"net"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"time"

	"github.com/oschwald/geoip2-golang"
	"golang.org/x/sync/singleflight"
)

const (
	cacheTTL   = 3600 * time.Second // 1h cache για αποτελέσματα
	dnsTimeout = 1 * time.Second    // 1s timeout για PTR lookups
	statEvery  = 300 * time.Second  // πόσο συχνά θα ελέγχουμε για αλλαγές στα mmdb αρχεία

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
	mu     sync.RWMutex
	cache  map[string]Result
	asnDB  *geoip2.Reader
	cityDB *geoip2.Reader
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
		cache:     make(map[string]Result),
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

	// cache hit
	e.mu.RLock()
	if r, ok := e.cache[ipStr]; ok && now.Sub(r.ts) < cacheTTL {
		e.mu.RUnlock()
		return r
	}
	e.mu.RUnlock()

	// hot-reload if underlying files changed (rate-limited stat calls)
	e.refreshIfChanged()

	r := Result{ts: now}
	ip := net.ParseIP(ipStr)
	if ip == nil {
		return r
	}

	// PTR (reverse DNS) με timeout

	if e.enablePTR && isRoutable(ip) {
		ctx, cancel := context.WithTimeout(context.Background(), dnsTimeout)
		names, _ := net.DefaultResolver.LookupAddr(ctx, ipStr)
		cancel()
		if len(names) > 0 {
			// καθάρισε τυχόν τελεία στο τέλος
			r.PTR = strings.TrimSuffix(names[0], ".")
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

	// store in cache
	e.mu.Lock()
	e.cache[ipStr] = r
	e.mu.Unlock()

	return r
}

// LookupCachedOrAsync returns the cached Result for ipStr if one is fresh in
// memory. On a cache miss it returns an empty Result *immediately* and
// dispatches the full Lookup (PTR + ASN + City) on a background goroutine,
// so the next request for the same IP can serve from cache.
//
// Why: Lookup() does up to 1s of reverse-DNS plus mmdb reads on a cold IP.
// On the bridge decision hot path (one call per HTTP request from nginx),
// that latency can exhaust the Lua-side cosocket timeout under load even
// though the bridge handler itself is otherwise sub-millisecond. Deferring
// it costs us geo data on the *first* request from a fresh IP only —
// always-acceptable because rules that depend on country still apply on
// the second request (~tens of ms later under load) once the cache is warm.
//
// Concurrent misses for the same IP are coalesced via singleflight, and
// the total number of in-flight async lookups is bounded by asyncSem so
// a flood of unique IPs can't spawn unbounded goroutines. If asyncSem is
// saturated we just skip the dispatch — the next request retries.
func (e *Enricher) LookupCachedOrAsync(ipStr string) Result {
	if e == nil || ipStr == "" {
		return Result{}
	}
	now := time.Now()

	// Fast path: identical to Lookup()'s cache check.
	e.mu.RLock()
	if r, ok := e.cache[ipStr]; ok && now.Sub(r.ts) < cacheTTL {
		e.mu.RUnlock()
		return r
	}
	e.mu.RUnlock()

	// Cache miss. Best-effort async dispatch — non-blocking on saturation.
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

	return Result{ts: now}
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

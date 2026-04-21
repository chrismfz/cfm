package enrich

import (
	"context"
	"fmt"
	"github.com/oschwald/geoip2-golang"
	"net"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"time"
)

const (
	cacheTTL   = 3600 * time.Second // 1h cache για αποτελέσματα
	dnsTimeout = 1 * time.Second    // 1s timeout για PTR lookups
	statEvery  = 300 * time.Second  // πόσο συχνά θα ελέγχουμε για αλλαγές στα mmdb αρχεία
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
	asnMTime    time.Time
	cityMTime   time.Time
	lastStatChk time.Time
	// options
	enablePTR bool
}

// New ενεργοποιεί enrichment αν βρει mmdb αρχεία σε dirs (π.χ. /etc/cfm, ./configs).
// Αν δεν βρει κανένα, θα δίνει μόνο PTR (reverse DNS) με caching.

func New(dirs ...string) (*Enricher, error) {
	e := &Enricher{
		cache:     make(map[string]Result),
		enablePTR: true,
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

	r = e.LookupLocal(ipStr)
	r.ts = now
	if e.enablePTR {
		ctx, cancel := context.WithTimeout(context.Background(), dnsTimeout)
		if ptr, err := e.LookupPTR(ctx, ipStr, false); err == nil {
			r.PTR = ptr
		}
		cancel()
	}

	// store in cache
	e.mu.Lock()
	e.cache[ipStr] = r
	e.mu.Unlock()

	return r
}

// LookupLocal returns only local DB enrichment (ASN/Country/City) without DNS PTR.
func (e *Enricher) LookupLocal(ipStr string) Result {
	r := Result{ts: time.Now()}
	ip := net.ParseIP(ipStr)
	if ip == nil {
		return r
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

// LookupPTR resolves reverse DNS with optional forward-confirm verification.
func (e *Enricher) LookupPTR(ctx context.Context, ipStr string, verifyForward bool) (string, error) {
	ip := net.ParseIP(ipStr)
	if ip == nil {
		return "", fmt.Errorf("invalid ip")
	}
	if !isRoutable(ip) {
		return "", nil
	}
	names, err := net.DefaultResolver.LookupAddr(ctx, ipStr)
	if err != nil {
		return "", err
	}
	if len(names) == 0 {
		return "", nil
	}
	ptr := strings.TrimSuffix(strings.TrimSpace(names[0]), ".")
	if ptr == "" || !verifyForward {
		return ptr, nil
	}
	fwd, err := net.DefaultResolver.LookupIPAddr(ctx, ptr)
	if err != nil {
		return "", err
	}
	for _, a := range fwd {
		if a.IP.Equal(ip) {
			return ptr, nil
		}
	}
	return "", fmt.Errorf("forward verify mismatch")
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
	asnMTime := e.asnMTime
	cityMTime := e.cityMTime
	e.mu.Unlock()

	// Do ALL file I/O outside lock (CRITICAL FIX)
	var newASN, newCity *geoip2.Reader
	var newASNTime, newCityTime time.Time

	// Check and load ASN DB (outside lock)
	if asnPath != "" {
		if fi, err := os.Stat(asnPath); err == nil {
			if fi.ModTime().After(asnMTime) {
				if db, err := geoip2.Open(asnPath); err == nil {
					newASN = db
					newASNTime = fi.ModTime()
				}
			}
		}

	}

	// Check and load City DB (outside lock)
	if cityPath != "" {
		if fi, err := os.Stat(cityPath); err == nil {
			if fi.ModTime().After(cityMTime) {
				if db, err := geoip2.Open(cityPath); err == nil {
					newCity = db
					newCityTime = fi.ModTime()
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
		e.asnMTime = newASNTime
		if old != nil {
			_ = old.Close()
		}
	}
	if newCity != nil {
		old := e.cityDB
		e.cityDB = newCity
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

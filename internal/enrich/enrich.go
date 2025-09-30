package enrich

import (
	"context"
	"net"
	"os"
	"path/filepath"
	"sync"
	"time"
	"strings"
	"github.com/oschwald/geoip2-golang"
)

const (
	cacheTTL   = 3600 * time.Second // 1h cache για αποτελέσματα
	dnsTimeout = 1 * time.Second    // 1s timeout για PTR lookups
	statEvery  = 300 * time.Second   // πόσο συχνά θα ελέγχουμε για αλλαγές στα mmdb αρχεία
)

type Result struct {
	PTR     string
	ASN     uint
	ASNName string
	Country string
	City    string
	ts      time.Time
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
			if fi, err2 := os.Stat(asnPath); err2 == nil { e.asnMTime = fi.ModTime() }
		}
	}
	if cityPath != "" {
		if db, err := geoip2.Open(cityPath); err == nil {
			e.cityDB = db
			e.cityPath = cityPath
			if fi, err2 := os.Stat(cityPath); err2 == nil { e.cityMTime = fi.ModTime() }
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

// Enabled επιστρέφει true αν έχουμε τουλάχιστον μία GeoIP DB ανοιχτή.
func (e *Enricher) Enabled() bool {
	return e != nil && (e.asnDB != nil || e.cityDB != nil)
}


// refreshIfChanged ελέγχει αν άλλαξαν τα αρχεία και κάνει ασφαλές reopen.
func (e *Enricher) refreshIfChanged() {
	now := time.Now()
	e.mu.Lock()
	if now.Sub(e.lastStatChk) < statEvery {
		e.mu.Unlock()
		return
	}
	e.lastStatChk = now

	// ASN
	if e.asnPath != "" {
		if fi, err := os.Stat(e.asnPath); err == nil {
			if fi.ModTime().After(e.asnMTime) {
				if db, err := geoip2.Open(e.asnPath); err == nil {
					old := e.asnDB
					e.asnDB = db
					e.asnMTime = fi.ModTime()
					if old != nil { _ = old.Close() }
				}
			}
		}
	}
	// City
	if e.cityPath != "" {
		if fi, err := os.Stat(e.cityPath); err == nil {
			if fi.ModTime().After(e.cityMTime) {
				if db, err := geoip2.Open(e.cityPath); err == nil {
					old := e.cityDB
					e.cityDB = db
					e.cityMTime = fi.ModTime()
					if old != nil { _ = old.Close() }
				}
			}
		}
	}
	e.mu.Unlock()
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

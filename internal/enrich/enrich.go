package enrich

import (
	"context"
	"net"
	"os"
	"path/filepath"
	"sync"
	"time"

	"github.com/oschwald/geoip2-golang"
)

const (
	cacheTTL   = 3600 * time.Second // 1h cache για αποτελέσματα
	dnsTimeout = 1 * time.Second    // 1s timeout για PTR lookups
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
}

// New ενεργοποιεί enrichment αν βρει mmdb αρχεία σε dirs (π.χ. /etc/cfm, ./configs).
// Αν δεν βρει κανένα, θα δίνει μόνο PTR (reverse DNS) με caching.
func New(dirs ...string) (*Enricher, error) {
	e := &Enricher{cache: make(map[string]Result)}
	var asnPath, cityPath string

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
		}
	}
	if cityPath != "" {
		if db, err := geoip2.Open(cityPath); err == nil {
			e.cityDB = db
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

	r := Result{ts: now}
	ip := net.ParseIP(ipStr)
	if ip == nil {
		return r
	}

	// PTR (reverse DNS) με timeout
	ctx, cancel := context.WithTimeout(context.Background(), dnsTimeout)
	names, _ := net.DefaultResolver.LookupAddr(ctx, ipStr)
	cancel()
	if len(names) > 0 {
		r.PTR = names[0]
	}

	// ASN
	if e.asnDB != nil {
		if rec, err := e.asnDB.ASN(ip); err == nil && rec != nil {
			r.ASN = rec.AutonomousSystemNumber
			r.ASNName = rec.AutonomousSystemOrganization
		}
	}

	// Country/City
	if e.cityDB != nil {
		if rec, err := e.cityDB.City(ip); err == nil && rec != nil {
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

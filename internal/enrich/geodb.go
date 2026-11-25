package enrich

import (
	"errors"
	"net"
	"strconv"
	"strings"
	"sync"

	"github.com/oschwald/geoip2-golang"
	"github.com/oschwald/maxminddb-golang"

	"cfm/internal/logging"
)

// geoDB is one open geo database, whichever schema it carries. The enricher
// holds two (the files named GeoLite2-ASN.mmdb and GeoLite2-City.mmdb) and
// reads them only under its mu.RLock (see readGeo) — both implementations are
// memory-mapped, so the lock-covers-the-read rule applies to either.
type geoDB interface {
	// asn returns the autonomous system number and organisation; ok is false
	// when the address has no ASN record.
	asn(ip net.IP) (num uint, org string, ok bool)
	// country returns the ISO-2 code, the English country name and the city
	// ("" when the database has none); ok is false when the address has no
	// country record.
	country(ip net.IP) (iso, name, city string, ok bool)
	Close() error
}

// openGeoDB opens a geo database in either schema CFM installs:
//   - MaxMind's (GeoLite2 / GeoIP2 and the compatible DB-IP editions): geoip2
//     recognises the type, and the records are read into lean structs that
//     name only the fields CFM uses (maxmindDB);
//   - IPLocate's, which the MaxMind updater installs under the same file names
//     when no MaxMind account is configured (maxmindupdater: source=auto
//     without a licence key, or source=iplocate). Its records are FLAT —
//     {asn, org, name, country_code} for ip-to-asn, {country_code,
//     country_name, continent_code} for ip-to-country — not MaxMind's nested
//     schema, and geoip2 refuses its database type outright. Before this
//     adapter such a node loaded neither file: every ASN and country lookup
//     came back empty, silently.
//
// Any other database type geoip2 rejects is still an error: a schema this
// adapter doesn't know must not be half-read. Every open failure is logged once
// per (path, error) — a database that silently fails to load is exactly how
// the IPLocate gap went unseen.
func openGeoDB(path string) (geoDB, error) {
	db, err := openGeoDBQuiet(path)
	if err != nil {
		warnOpenOnce(path, err)
	}
	return db, err
}

// openFailWarned de-dups the open-failure warning: the hot reload retries a
// file it could not load on every stat interval, and must not log each time.
var openFailWarned sync.Map // "path\x00error" -> struct{}

func warnOpenOnce(path string, err error) {
	if _, seen := openFailWarned.LoadOrStore(path+"\x00"+err.Error(), struct{}{}); seen {
		return
	}
	logging.Logf("[enrich] WARNING: cannot load geo database %s: %v — its lookups (ASN or country) stay empty until it is replaced", path, err)
}

func openGeoDBQuiet(path string) (geoDB, error) {
	r, err := geoip2.Open(path)
	if err == nil {
		// geoip2 only vouches for the type: the reads go through maxminddb
		// into lean structs (maxmindDB). The second open is once per file
		// load; deciding the type ourselves would copy geoip2's type list.
		_ = r.Close()
		raw, err := maxminddb.Open(path)
		if err != nil {
			return nil, err
		}
		return maxmindDB{raw}, nil
	}
	var unknown geoip2.UnknownDatabaseTypeError
	if !errors.As(err, &unknown) {
		return nil, err
	}
	// geoip2.Open returns the mapped reader alongside this error; close it
	// rather than leave the mapping to a finalizer.
	if r != nil {
		_ = r.Close()
	}
	if !isIPLocateType(unknown.DatabaseType) {
		return nil, err
	}
	raw, err := maxminddb.Open(path)
	if err != nil {
		return nil, err
	}
	return iplocateDB{raw}, nil
}

// isIPLocateType matches IPLocate's database_type metadata, e.g.
// "iplocate ip-to-asn-20260922.mmdb" / "iplocate ip-to-country-20260922.mmdb".
func isIPLocateType(t string) bool {
	return strings.HasPrefix(strings.ToLower(strings.TrimSpace(t)), "iplocate ")
}

// maxmindDB reads MaxMind's nested schema into lean structs that name only
// the fields CFM uses. geoip2's City() decoded the whole record for them:
// every language's country and city name (maps), the subdivisions, the
// location, the postal code, the continent and the registered country. On the
// bridge's per-request path (the challenge excludes' ASN, the traffic rules'
// country) that was the top consumer of a busy node's CPU profile
// (qualityweb, 2026-11-25); the maxminddb decoder skips what a struct does
// not name, without allocating it.
type maxmindDB struct{ r *maxminddb.Reader }

type maxmindASNFields struct {
	ASN uint   `maxminddb:"autonomous_system_number"`
	Org string `maxminddb:"autonomous_system_organization"`
}

type maxmindName struct {
	EN string `maxminddb:"en"`
}

type maxmindCountryFields struct {
	Country struct {
		IsoCode string      `maxminddb:"iso_code"`
		Names   maxmindName `maxminddb:"names"`
	} `maxminddb:"country"`
	City struct {
		Names maxmindName `maxminddb:"names"`
	} `maxminddb:"city"`
}

func (d maxmindDB) asn(ip net.IP) (uint, string, bool) {
	var rec maxmindASNFields
	if err := d.r.Lookup(ip, &rec); err != nil || rec.ASN == 0 {
		return 0, "", false
	}
	return rec.ASN, rec.Org, true
}

func (d maxmindDB) country(ip net.IP) (string, string, string, bool) {
	var rec maxmindCountryFields
	if err := d.r.Lookup(ip, &rec); err != nil {
		return "", "", "", false
	}
	name := rec.Country.IsoCode
	if rec.Country.Names.EN != "" {
		name = rec.Country.Names.EN
	}
	// As geoip2's City() read: a record with a city but no country still
	// answers its city.
	if rec.Country.IsoCode == "" && name == "" && rec.City.Names.EN == "" {
		return "", "", "", false
	}
	return rec.Country.IsoCode, name, rec.City.Names.EN, true
}

func (d maxmindDB) Close() error { return d.r.Close() }

// iplocateDB reads IPLocate's flat schema. One record type covers both files:
// ip-to-asn carries asn/org/name (plus the ASN's registration country, which
// is NOT the address's location and is ignored), ip-to-country carries
// country_code/country_name. It has no city.
type iplocateDB struct{ r *maxminddb.Reader }

// iplocateASNFields: asn is stored as a STRING ("6799" — measured on the
// 2026-09-22 file, all 1.68M networks), so it is decoded as interface{} and
// parsed by asnNumber, which also takes a number in case a later file
// switches. A typed uint field made the whole record fail to decode. The two
// record types are separate so each lookup decodes only the fields it uses: a
// malformed country field can't fail an ASN lookup, or the reverse.
type iplocateASNFields struct {
	ASN  interface{} `maxminddb:"asn"`
	Org  string      `maxminddb:"org"`
	Name string      `maxminddb:"name"`
}

type iplocateCountryFields struct {
	CountryCode string `maxminddb:"country_code"`
	CountryName string `maxminddb:"country_name"`
}

// asnNumber reads an AS number stored as a string ("6799", "AS6799") or as an
// unsigned integer; anything else, or out of the 32-bit AS range, is 0.
func asnNumber(v interface{}) uint {
	switch x := v.(type) {
	case string:
		s := strings.TrimSpace(x)
		if len(s) > 2 && strings.EqualFold(s[:2], "AS") {
			s = s[2:]
		}
		n, err := strconv.ParseUint(s, 10, 32)
		if err != nil {
			return 0
		}
		return uint(n)
	case uint64:
		if x > 1<<32-1 {
			return 0
		}
		return uint(x)
	}
	return 0
}

func (d iplocateDB) asn(ip net.IP) (uint, string, bool) {
	var rec iplocateASNFields
	if err := d.r.Lookup(ip, &rec); err != nil {
		return 0, "", false
	}
	n := asnNumber(rec.ASN)
	if n == 0 {
		return 0, "", false
	}
	org := rec.Org
	if org == "" {
		org = rec.Name
	}
	return n, org, true
}

func (d iplocateDB) country(ip net.IP) (string, string, string, bool) {
	var rec iplocateCountryFields
	if err := d.r.Lookup(ip, &rec); err != nil || rec.CountryCode == "" {
		return "", "", "", false
	}
	iso := strings.ToUpper(rec.CountryCode)
	name := rec.CountryName
	if name == "" {
		name = iso
	}
	return iso, name, "", true
}

func (d iplocateDB) Close() error { return d.r.Close() }

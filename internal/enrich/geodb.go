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
//   - MaxMind's (GeoLite2 / GeoIP2 and the compatible DB-IP editions), read
//     through geoip2 exactly as before;
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
		return maxmindDB{r}, nil
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

// maxmindDB reads MaxMind's nested schema through geoip2.
type maxmindDB struct{ r *geoip2.Reader }

func (d maxmindDB) asn(ip net.IP) (uint, string, bool) {
	rec, err := d.r.ASN(ip)
	if err != nil || rec == nil {
		return 0, "", false
	}
	return rec.AutonomousSystemNumber, rec.AutonomousSystemOrganization, true
}

func (d maxmindDB) country(ip net.IP) (string, string, string, bool) {
	rec, err := d.r.City(ip)
	if err != nil || rec == nil {
		return "", "", "", false
	}
	name := rec.Country.IsoCode
	if n, ok := rec.Country.Names["en"]; ok && n != "" {
		name = n
	}
	return rec.Country.IsoCode, name, rec.City.Names["en"], true
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

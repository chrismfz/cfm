package enrich

import (
	"net"
	"path/filepath"
	"testing"
	"time"

	"github.com/oschwald/geoip2-golang"

	"cfm/internal/enrich/mmdbtest"
)

// names is a "names" map in the eight languages GeoLite2 carries.
func names(en string) mmdbMap {
	m := mmdbMap{{"en", en}}
	for _, l := range []string{"de", "es", "fr", "ja", "pt-BR", "ru", "zh-CN"} {
		m = append(m, [2]mmdbValue{l, en + " (" + l + ")"})
	}
	return m
}

// fullCityRecord is a GeoLite2-City record with what the real one carries
// besides the fields CFM reads: every language's names, the continent, the
// registered country, the location, the postal code.
func fullCityRecord(iso, country, city string) mmdbMap {
	return mmdbMap{
		{"city", mmdbMap{{"geoname_id", mmdbtest.Uint32(264371)}, {"names", names(city)}}},
		{"continent", mmdbMap{{"code", "EU"}, {"geoname_id", mmdbtest.Uint32(6255148)}, {"names", names("Europe")}}},
		{"country", mmdbMap{{"geoname_id", mmdbtest.Uint32(390903)}, {"iso_code", iso}, {"names", names(country)}}},
		{"location", mmdbMap{{"accuracy_radius", mmdbtest.Uint16(20)}, {"time_zone", "Europe/Athens"}}},
		{"postal", mmdbMap{{"code", "104 31"}}},
		{"registered_country", mmdbMap{{"geoname_id", mmdbtest.Uint32(390903)}, {"iso_code", iso}, {"names", names(country)}}},
	}
}

// The lean read answers what geoip2's City() / ASN() read answered, on full
// records and on a record without a city or a country name.
func TestLeanReadMatchesGeoip2(t *testing.T) {
	dir := t.TempDir()
	ip := net.ParseIP("94.68.42.127")
	for name, rec := range map[string]mmdbMap{
		"full":       fullCityRecord("GR", "Greece", "Athens"),
		"no city":    mmdbMap{{"country", mmdbMap{{"iso_code", "CY"}, {"names", names("Cyprus")}}}},
		"no en name": mmdbMap{{"country", mmdbMap{{"iso_code", "DE"}, {"names", mmdbMap{{"de", "Deutschland"}}}}}},
	} {
		path := filepath.Join(dir, name+".mmdb")
		writeMMDB(t, dir, name+".mmdb", buildMMDB("GeoLite2-City", rec), time.Now())
		ref, err := geoip2.Open(path)
		if err != nil {
			t.Fatal(err)
		}
		want, err := ref.City(ip)
		_ = ref.Close()
		if err != nil {
			t.Fatal(err)
		}
		db, err := openGeoDB(path)
		if err != nil {
			t.Fatal(err)
		}
		iso, cname, city, ok := db.country(ip)
		_ = db.Close()
		wname := want.Country.IsoCode
		if n := want.Country.Names["en"]; n != "" {
			wname = n
		}
		if !ok || iso != want.Country.IsoCode || cname != wname || city != want.City.Names["en"] {
			t.Errorf("%s: lean %q %q %q %v, geoip2 %q %q %q", name, iso, cname, city, ok, want.Country.IsoCode, wname, want.City.Names["en"])
		}
	}
	path := filepath.Join(dir, "asn.mmdb")
	writeMMDB(t, dir, "asn.mmdb", buildMMDB("GeoLite2-ASN", asnRecord(6799, "Ote SA")), time.Now())
	db, err := openGeoDB(path)
	if err != nil {
		t.Fatal(err)
	}
	defer db.Close()
	if n, org, ok := db.asn(ip); !ok || n != 6799 || org != "Ote SA" {
		t.Errorf("lean ASN: %d %q %v", n, org, ok)
	}
}

// LookupASNFast reads the ASN database alone, in either schema, and answers
// 0 without one.
func TestLookupASNFast(t *testing.T) {
	for name, db := range map[string][]byte{
		"maxmind":  buildMMDB("GeoLite2-ASN", asnRecord(3329, "Vodafone-Panafon")),
		"iplocate": buildMMDB("iplocate ip-to-asn-20260922.mmdb", iplocateASNRecord("3329", "Vodafone-Panafon", "VODAFONE-GR", "GR")),
	} {
		dir := t.TempDir()
		writeMMDB(t, dir, "GeoLite2-ASN.mmdb", db, time.Now())
		e, _ := New(dir)
		if n, org := e.LookupASNFast("94.68.42.127"); n != 3329 || org != "Vodafone-Panafon" {
			t.Errorf("%s: %d %q, want 3329 Vodafone-Panafon", name, n, org)
		}
		if n, _ := e.LookupASNFast("not an ip"); n != 0 {
			t.Errorf("%s: a bad address answered %d", name, n)
		}
		e.Close()
	}
	e, _ := New(t.TempDir())
	defer e.Close()
	if n, _ := e.LookupASNFast("94.68.42.127"); n != 0 {
		t.Errorf("no ASN database: %d", n)
	}
	var nilE *Enricher
	if n, _ := nilE.LookupASNFast("94.68.42.127"); n != 0 {
		t.Error("nil enricher answered")
	}
}

// The country read of a full GeoLite2-City record: geoip2's City() (what
// readGeo did) against the lean struct.
func BenchmarkCountryRead(b *testing.B) {
	dir := b.TempDir()
	path := filepath.Join(dir, "city.mmdb")
	writeMMDB(b, dir, "city.mmdb", buildMMDB("GeoLite2-City", fullCityRecord("GR", "Greece", "Athens")), time.Now())
	ip := net.ParseIP("94.68.42.127")
	b.Run("geoip2.City", func(b *testing.B) {
		r, _ := geoip2.Open(path)
		defer r.Close()
		b.ReportAllocs()
		for i := 0; i < b.N; i++ {
			rec, _ := r.City(ip)
			_ = rec.Country.Names["en"]
		}
	})
	b.Run("lean", func(b *testing.B) {
		db, _ := openGeoDB(path)
		defer db.Close()
		b.ReportAllocs()
		for i := 0; i < b.N; i++ {
			db.country(ip)
		}
	})
}

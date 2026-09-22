// Package mmdbtest writes small, spec-valid MaxMind DB (.mmdb) files for
// tests. Import it from _test files only.
//
// The real GeoLite2 databases cannot be committed (licensing), so without this
// nothing in the repo would exercise a real, mmap'd reader — which is exactly
// where the reader-lifetime bugs live (see the enrich package's hot-swap
// tests). It builds an IPv4 database (https://maxmind.github.io/MaxMind-DB/)
// whose one search-tree node sends every address to a single data record, and
// Write installs it the way geoipupdate does: to a temp file, then an atomic
// rename, so an already-open reader keeps its old mapping until it is closed.
package mmdbtest

import (
	"encoding/binary"
	"os"
	"path/filepath"
	"testing"
	"time"
)

// Value is anything Build can serialise: string, Uint16/32/64, Map, []string.
type Value interface{}

// Map is an ordered list of key/value pairs; keys are strings.
type Map [][2]Value

type (
	Uint16 uint16
	Uint32 uint32
	Uint64 uint64
)

// ctrl encodes a control byte, then the extended-type byte (types > 7), then
// any size-extension bytes — the order the spec lays them out in.
func ctrl(typ int, size int) []byte {
	var sizeField byte
	var ext []byte
	switch {
	case size < 29:
		sizeField = byte(size)
	case size < 29+256:
		sizeField, ext = 29, []byte{byte(size - 29)}
	case size < 285+65536:
		n := size - 285
		sizeField, ext = 30, []byte{byte(n >> 8), byte(n)}
	default:
		panic("mmdbtest: value too large")
	}
	var out []byte
	if typ <= 7 {
		out = []byte{byte(typ<<5) | sizeField}
	} else {
		out = []byte{sizeField, byte(typ - 7)} // extended type
	}
	return append(out, ext...)
}

func uintBytes(v uint64, max int) []byte {
	b := make([]byte, 8)
	binary.BigEndian.PutUint64(b, v)
	b = b[8-max:]
	for len(b) > 0 && b[0] == 0 {
		b = b[1:]
	}
	return b
}

func encode(v Value) []byte {
	switch x := v.(type) {
	case string:
		return append(ctrl(2, len(x)), x...)
	case Uint16:
		b := uintBytes(uint64(x), 2)
		return append(ctrl(5, len(b)), b...)
	case Uint32:
		b := uintBytes(uint64(x), 4)
		return append(ctrl(6, len(b)), b...)
	case Uint64:
		b := uintBytes(uint64(x), 8)
		return append(ctrl(9, len(b)), b...)
	case Map:
		out := ctrl(7, len(x))
		for _, kv := range x {
			out = append(out, encode(kv[0])...)
			out = append(out, encode(kv[1])...)
		}
		return out
	case []string:
		out := ctrl(11, len(x))
		for _, s := range x {
			out = append(out, encode(s)...)
		}
		return out
	}
	panic("mmdbtest: unsupported value type")
}

// Build returns a complete IPv4 database of the given database_type whose
// every address resolves to record.
func Build(dbType string, record Map) []byte {
	const nodeCount = 1
	// One node, 24-bit records; both point at data-section offset 0.
	// A record value > node_count is a data pointer: offset = value - node_count - 16.
	ptr := uint32(nodeCount + 16)
	tree := []byte{
		byte(ptr >> 16), byte(ptr >> 8), byte(ptr),
		byte(ptr >> 16), byte(ptr >> 8), byte(ptr),
	}
	out := append([]byte{}, tree...)
	out = append(out, make([]byte, 16)...) // data section separator
	out = append(out, encode(record)...)
	out = append(out, "\xab\xcd\xefMaxMind.com"...)
	out = append(out, encode(Map{
		{"binary_format_major_version", Uint16(2)},
		{"binary_format_minor_version", Uint16(0)},
		{"build_epoch", Uint64(uint64(time.Now().Unix()))},
		{"database_type", dbType},
		{"description", Map{{"en", "cfm test database"}}},
		{"ip_version", Uint16(4)},
		{"languages", []string{"en"}},
		{"node_count", Uint32(nodeCount)},
		{"record_size", Uint16(24)},
	})...)
	return out
}

// ASNRecord is a MaxMind GeoLite2-ASN record.
func ASNRecord(asn uint32, org string) Map {
	return Map{
		{"autonomous_system_number", Uint32(asn)},
		{"autonomous_system_organization", org},
	}
}

// CityRecord is a MaxMind GeoLite2-City record (country + city names).
func CityRecord(iso, country, city string) Map {
	return Map{
		{"city", Map{{"names", Map{{"en", city}}}}},
		{"country", Map{{"iso_code", iso}, {"names", Map{{"en", country}}}}},
	}
}

// IPLocateASNRecord / IPLocateCountryRecord mirror IPLocate's FLAT records as
// measured on the real 2026-09-22 files — note asn is a string there.
func IPLocateASNRecord(asn Value, org, name, cc string) Map {
	return Map{
		{"asn", asn},
		{"country_code", cc},
		{"domain", "example.net"},
		{"name", name},
		{"network", "0.0.0.0/0"},
		{"org", org},
	}
}

func IPLocateCountryRecord(cc, name string) Map {
	return Map{
		{"continent_code", "EU"},
		{"country_code", cc},
		{"country_name", name},
	}
}

// Write installs db at dir/name atomically (temp file + rename, like
// geoipupdate) and stamps it with mtime, so a hot reload sees a change.
func Write(t testing.TB, dir, name string, db []byte, mtime time.Time) {
	t.Helper()
	tmp, err := os.CreateTemp(dir, name+".tmp*")
	if err != nil {
		t.Fatal(err)
	}
	if _, err := tmp.Write(db); err != nil {
		t.Fatal(err)
	}
	if err := tmp.Close(); err != nil {
		t.Fatal(err)
	}
	if err := os.Chtimes(tmp.Name(), mtime, mtime); err != nil {
		t.Fatal(err)
	}
	if err := os.Rename(tmp.Name(), filepath.Join(dir, name)); err != nil {
		t.Fatal(err)
	}
}

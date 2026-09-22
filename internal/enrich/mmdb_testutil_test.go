package enrich

import (
	"encoding/binary"
	"os"
	"path/filepath"
	"testing"
	"time"
)

// A minimal MaxMind DB writer, test-only.
//
// The real GeoLite2 databases cannot be committed (licensing), so without this
// nothing in the repo exercises a real, mmap'd geoip2.Reader — which is exactly
// where the reader-lifetime bugs live. It builds a spec-valid IPv4 database
// (https://maxmind.github.io/MaxMind-DB/) whose one search-tree node sends
// every address to a single data record, and writes it the way geoipupdate
// does: to a temp file, then an atomic rename, so an already-open reader keeps
// its old mapping until it is closed.

// mmdbValue is anything encodeMMDB can serialise.
type mmdbValue interface{}

type mmdbMap [][2]mmdbValue // ordered key/value pairs; keys are strings

type mmdbUint16 uint16
type mmdbUint32 uint32
type mmdbUint64 uint64

// mmdbCtrl encodes a control byte, then the extended-type byte (types > 7),
// then any size-extension bytes — the order the spec lays them out in.
func mmdbCtrl(typ int, size int) []byte {
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
		panic("mmdb test writer: value too large")
	}
	var out []byte
	if typ <= 7 {
		out = []byte{byte(typ<<5) | sizeField}
	} else {
		out = []byte{sizeField, byte(typ - 7)} // extended type
	}
	return append(out, ext...)
}

func mmdbUintBytes(v uint64, max int) []byte {
	b := make([]byte, 8)
	binary.BigEndian.PutUint64(b, v)
	b = b[8-max:]
	for len(b) > 0 && b[0] == 0 {
		b = b[1:]
	}
	return b
}

func encodeMMDB(v mmdbValue) []byte {
	switch x := v.(type) {
	case string:
		return append(mmdbCtrl(2, len(x)), x...)
	case mmdbUint16:
		b := mmdbUintBytes(uint64(x), 2)
		return append(mmdbCtrl(5, len(b)), b...)
	case mmdbUint32:
		b := mmdbUintBytes(uint64(x), 4)
		return append(mmdbCtrl(6, len(b)), b...)
	case mmdbUint64:
		b := mmdbUintBytes(uint64(x), 8)
		return append(mmdbCtrl(9, len(b)), b...)
	case mmdbMap:
		out := mmdbCtrl(7, len(x))
		for _, kv := range x {
			out = append(out, encodeMMDB(kv[0])...)
			out = append(out, encodeMMDB(kv[1])...)
		}
		return out
	case []string:
		out := mmdbCtrl(11, len(x))
		for _, s := range x {
			out = append(out, encodeMMDB(s)...)
		}
		return out
	}
	panic("mmdb test writer: unsupported value type")
}

// buildMMDB returns a complete IPv4 database of the given type whose every
// address resolves to record.
func buildMMDB(dbType string, record mmdbMap) []byte {
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
	out = append(out, encodeMMDB(record)...)
	out = append(out, "\xab\xcd\xefMaxMind.com"...)
	out = append(out, encodeMMDB(mmdbMap{
		{"binary_format_major_version", mmdbUint16(2)},
		{"binary_format_minor_version", mmdbUint16(0)},
		{"build_epoch", mmdbUint64(uint64(time.Now().Unix()))},
		{"database_type", dbType},
		{"description", mmdbMap{{"en", "cfm test database"}}},
		{"ip_version", mmdbUint16(4)},
		{"languages", []string{"en"}},
		{"node_count", mmdbUint32(nodeCount)},
		{"record_size", mmdbUint16(24)},
	})...)
	return out
}

func asnRecord(asn uint32, org string) mmdbMap {
	return mmdbMap{
		{"autonomous_system_number", mmdbUint32(asn)},
		{"autonomous_system_organization", org},
	}
}

func cityRecord(iso, country, city string) mmdbMap {
	return mmdbMap{
		{"city", mmdbMap{{"names", mmdbMap{{"en", city}}}}},
		{"country", mmdbMap{{"iso_code", iso}, {"names", mmdbMap{{"en", country}}}}},
	}
}

// writeMMDB installs db at dir/name atomically (temp file + rename, like
// geoipupdate) and stamps it with mtime, so refreshIfChanged sees a change.
func writeMMDB(t testing.TB, dir, name string, db []byte, mtime time.Time) {
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

// iplocateASNRecord / iplocateCountryRecord mirror IPLocate's FLAT records as
// measured on the real 2026-09-22 files — note asn is a string there.
func iplocateASNRecord(asn mmdbValue, org, name, cc string) mmdbMap {
	return mmdbMap{
		{"asn", asn},
		{"country_code", cc},
		{"domain", "example.net"},
		{"name", name},
		{"network", "0.0.0.0/0"},
		{"org", org},
	}
}

func iplocateCountryRecord(cc, name string) mmdbMap {
	return mmdbMap{
		{"continent_code", "EU"},
		{"country_code", cc},
		{"country_name", name},
	}
}

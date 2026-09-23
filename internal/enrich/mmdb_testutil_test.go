package enrich

import (
	"testing"
	"time"

	"cfm/internal/enrich/mmdbtest"
)

// Short local names for the mmdbtest writer (internal/enrich/mmdbtest), which
// other packages' tests use too.

type (
	mmdbValue  = mmdbtest.Value
	mmdbMap    = mmdbtest.Map
	mmdbUint32 = mmdbtest.Uint32
)

func buildMMDB(dbType string, record mmdbMap) []byte { return mmdbtest.Build(dbType, record) }

func asnRecord(asn uint32, org string) mmdbMap { return mmdbtest.ASNRecord(asn, org) }

func cityRecord(iso, country, city string) mmdbMap { return mmdbtest.CityRecord(iso, country, city) }

func iplocateASNRecord(asn mmdbValue, org, name, cc string) mmdbMap {
	return mmdbtest.IPLocateASNRecord(asn, org, name, cc)
}

func iplocateCountryRecord(cc, name string) mmdbMap { return mmdbtest.IPLocateCountryRecord(cc, name) }

func writeMMDB(t testing.TB, dir, name string, db []byte, mtime time.Time) {
	t.Helper()
	mmdbtest.Write(t, dir, name, db, mtime)
}

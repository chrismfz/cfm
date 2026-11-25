package webdetector

import (
	"testing"
	"time"

	"cfm/internal/enrich"
)

// countingEnricher answers every lookup the bridge may ask, and counts them.
type countingEnricher struct{ asnFast, geoFast int }

func (c *countingEnricher) Lookup(string) enrich.Result              { return enrich.Result{} }
func (c *countingEnricher) LookupCachedOrAsync(string) enrich.Result { return enrich.Result{} }
func (c *countingEnricher) LookupGeoFast(string) enrich.Result {
	c.geoFast++
	return enrich.Result{ASN: 1}
}
func (c *countingEnricher) LookupASNFast(string) (uint, string) {
	c.asnFast++
	return 6799, "Ote SA"
}

// The challenge excludes' ASN check reads the ASN database alone: the
// country LookupGeoFast also read was never used there, on every request an
// ASN exclude asks about (the top of qualityweb's profile, 2026-11-25).
func TestChalExcludeASNReadsTheASNOnly(t *testing.T) {
	b := NewNginxBridge("/tmp/cfm-test.sock", "tok", time.Minute, time.Minute)
	c := &countingEnricher{}
	b.enr = c
	if got := b.chalExcludeASN("94.68.42.127"); got != 6799 || c.asnFast != 1 || c.geoFast != 0 {
		t.Fatalf("asn %d, LookupASNFast %d, LookupGeoFast %d; want 6799 from LookupASNFast alone", got, c.asnFast, c.geoFast)
	}
}

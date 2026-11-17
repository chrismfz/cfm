package webdetector

import (
	"testing"
	"time"

	"cfm/internal/enrich"
	"cfm/internal/proxyipfilter"
)

// The bridge's enricher is what fills the proxied IP filter's cc= / asn=
// fields; an engine with no enricher clears the previous one.
func TestBridgeEnricherFeedsProxiedIPFilterGeo(t *testing.T) {
	t.Cleanup(func() { proxyipfilter.SetGeo(nil) })
	proxyipfilter.SetGeo(nil)

	enr, err := enrich.New(t.TempDir()) // no database: fields read "-", but wired
	if err != nil {
		t.Skipf("enrich.New: %v", err)
	}
	b := &NginxBridge{}
	b.SetEnricher(enr)
	if proxyipfilter.Stats()["geo"] != true {
		t.Fatal("SetEnricher must give the proxied IP filter its geo resolver")
	}

	e := NewEngine(Config{Every: time.Second, Window: time.Minute})
	if e.nginxBridge == nil || proxyipfilter.Stats()["geo"] != false {
		t.Fatal("an engine without an enricher must clear the previous resolver")
	}
}

package detectors

import (
	"net"
	"testing"
	"time"

	"cfm/internal/detectors/core"
	"cfm/internal/edgeban"
)

// A trusted proxy's own address (a Cloudflare edge) is never banned, reported
// or challenged: it stands for every visitor behind that edge. earth's
// ModSecurity log named the edge while the edge proxy was bypassed, and 345
// permanent Cloudflare bans reached the fleet blacklist.
func TestSectionSinkNeverBansATrustedProxy(t *testing.T) {
	_, cf, _ := net.ParseCIDR("172.64.0.0/13")
	edgeban.SetTrustedProxies([]*net.IPNet{cf})
	t.Cleanup(func() { edgeban.SetTrustedProxies(nil) })

	for _, extra := range []map[string]string{nil, {"action": "challenge"}} {
		fw := &sinkSetFake{left: map[string]time.Duration{}}
		in := &capturingSink{}
		s := &sectionSink{section: "modsec", pol: blockPolicy{Mode: "permanent"}, fw: fw, inner: in, last: map[string]time.Time{}}
		s.Publish(core.Alert{When: time.Now(), Kind: "MODSEC/403", Key: "172.71.172.97", Extra: extra})
		if len(fw.left) != 0 || len(fw.reports) != 0 {
			t.Fatalf("extra=%v: banned %v, reported %v", extra, fw.left, fw.reports)
		}
		if len(in.got) != 1 || in.got[0].Extra["reason"] != "ignored_trusted_proxy" || in.got[0].Extra["blocked"] != "no" {
			t.Fatalf("extra=%v: outcome %+v", extra, in.got)
		}
	}

	// Any other address is banned as before.
	fw := &sinkSetFake{left: map[string]time.Duration{}}
	s := &sectionSink{section: "modsec", pol: blockPolicy{Mode: "permanent"}, fw: fw, inner: &capturingSink{}, last: map[string]time.Time{}}
	s.Publish(core.Alert{When: time.Now(), Kind: "MODSEC/403", Key: "198.51.100.9"})
	if _, ok := fw.left["198.51.100.9"]; !ok {
		t.Fatalf("an ordinary address was not banned: %v", fw.left)
	}
}

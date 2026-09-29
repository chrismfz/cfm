package detectors

import (
	"strings"
	"testing"

	webdet "cfm/internal/webdetector"
)

// The hook-written result=solved line: every field older tooling reads keeps
// its place, src= and scope= follow the geo fields, and the legacy free-text
// " - (AS…, Country)" tail stays last.
func TestChallengeSolvedLine_FieldOrder(t *testing.T) {
	s := webdet.ChallengeSolve{
		IP: "203.0.113.40", Host: "shop.example.com", URI: "/", Diff: 16, UA: "Mozilla/5.0",
		Country: "Greece", CountryISO: "GR", ASN: 6799, ASNName: "OTEnet S.A.", PTR: "ppp.otenet.gr",
		SrcResolved: true, Scope: "panel:2083",
	}
	line := challengeSolvedLine(s, "WAF_IP_HOST", 602)
	if !strings.HasPrefix(line, "[challenge] ip=203.0.113.40 host=shop.example.com uri=/ result=solved ") {
		t.Fatalf("head moved: %q", line)
	}
	const tail = ` reason=WAF_IP_HOST waf_rule_id=602 cc=GR asn=6799 asn_name="OTEnet S.A." ptr=ppp.otenet.gr src=- scope=panel:2083 - (AS6799 OTEnet S.A., Greece)`
	if !strings.HasSuffix(line, tail) {
		t.Fatalf("tail:\n got %q\nwant suffix %q", line, tail)
	}
	// Unset (a literal that never went through verify): no scope= at all.
	s.Scope = ""
	if got := challengeSolvedLine(s, "", 0); strings.Contains(got, "scope=") {
		t.Fatalf("unset scope rendered: %q", got)
	}
}

package detectors

import (
	"testing"

	"cfm/internal/enrich"
)

// MATCH_COUNTRY is matched against the record's ISO code first. By name alone
// it missed any ISO code outside countryNameToISO (e.g. "EE") and, on an
// IPLocate node, the Netherlands ("The Netherlands" there, "Netherlands" at
// MaxMind).
func TestLeniencyMatchGeoCountry(t *testing.T) {
	maxmindGR := enrich.Result{CountryISO: "GR", Country: "Greece"}
	maxmindEE := enrich.Result{CountryISO: "EE", Country: "Estonia"}
	iplocateNL := enrich.Result{CountryISO: "NL", Country: "The Netherlands"}
	maxmindNL := enrich.Result{CountryISO: "NL", Country: "Netherlands"}
	nameOnly := enrich.Result{Country: "Greece"}

	for _, c := range []struct {
		name      string
		countries string
		r         enrich.Result
		want      bool
		reason    string
	}{
		{"iso", "GR,CY", maxmindGR, true, "country=GR"},
		{"iso outside the name table", "EE", maxmindEE, true, "country=EE"},
		{"iso vs IPLocate name", "NL", iplocateNL, true, "country=NL"},
		{"iso vs MaxMind name", "NL", maxmindNL, true, "country=NL"},
		{"name vs IPLocate name", "NETHERLANDS", iplocateNL, true, "country=NETHERLANDS"},
		{"name", "GREECE", maxmindGR, true, "country=GREECE"},
		{"lower-case config", "gr", maxmindGR, true, "country=GR"},
		{"record with a name but no ISO", "GR", nameOnly, true, "country=GR"},
		{"other country", "DE,FR", maxmindGR, false, ""},
		{"unknown name", "ATLANTIS", maxmindGR, false, ""},
		{"no geo resolved", "GR", enrich.Result{}, false, ""},
	} {
		lp := parseLeniencyPolicy(KV{"MATCH_COUNTRY": c.countries})
		if lp == nil {
			t.Fatalf("%s: policy not parsed", c.name)
		}
		got, reason := lp.matchGeo(c.r)
		if got != c.want || reason != c.reason {
			t.Errorf("%s: MATCH_COUNTRY=%q on %+v = (%v, %q), want (%v, %q)",
				c.name, c.countries, c.r, got, reason, c.want, c.reason)
		}
	}
}

func TestLeniencyMatchGeoASN(t *testing.T) {
	lp := parseLeniencyPolicy(KV{"MATCH_ASN": "AS6799, 6866"})
	if got, reason := lp.matchGeo(enrich.Result{ASN: 6866}); !got || reason != "asn=AS6866" {
		t.Fatalf("ASN without AS prefix in config: (%v, %q)", got, reason)
	}
	if got, _ := lp.matchGeo(enrich.Result{ASN: 3329, CountryISO: "GR"}); got {
		t.Fatal("an unlisted ASN matched (and there is no MATCH_COUNTRY)")
	}
	var nilPolicy *leniencyPolicy
	if got, _ := nilPolicy.matchGeo(enrich.Result{ASN: 6799}); got {
		t.Fatal("a nil policy matched")
	}
}

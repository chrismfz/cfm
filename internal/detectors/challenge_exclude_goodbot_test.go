package detectors

import "testing"

func TestRegistrableDomain(t *testing.T) {
	cases := map[string]string{
		"crawl.ahrefs.com":   "ahrefs.com",
		"x.y.googlebot.com":  "googlebot.com",
		"spider.semrush.com": "semrush.com",
		"ahrefs.com":         "ahrefs.com",
		"localhost":          "localhost",
		"CRAWL.Ahrefs.COM.":  "ahrefs.com", // case + trailing dot normalized
		"":                   "",
	}
	for in, want := range cases {
		if got := registrableDomain(in); got != want {
			t.Errorf("registrableDomain(%q) = %q, want %q", in, got, want)
		}
	}
}

// The forward-confirm=true path is DNS-bound and covered at the wiring layer (with a
// fake matcher). Here we assert the NON-DNS decisions are hermetic and correct: only
// verify_fcrdns PTR rules are considered, a non-candidate PTR spends no DNS, and the
// budget guard short-circuits BEFORE any forward-confirm.
func TestVerifiedGoodBotName_NoDNSPaths(t *testing.T) {
	ce := &ChallengeExclude{rules: []challengeExcludeRule{
		{ptr: "*.ahrefs.com", verifyFcrdns: true, action: "skip"},
		{ua: "*googlebot*", verifyFcrdns: true, action: "skip"}, // no ptr → never a good-bot source
		{ptr: "*.semrush.com", action: "skip"},                  // ptr but NOT verify_fcrdns → ignored (spoofable)
	}}

	// A PTR matching no verify_fcrdns ptr rule → false, and no DNS is attempted
	// (the ua rule has no ptr; the semrush rule isn't fcrdns).
	if name, ok := ce.VerifiedGoodBotName("1.2.3.4", "spider.semrush.com", nil); ok || name != "" {
		t.Fatalf("a non-fcrdns ptr rule must not confirm a good bot: %q %v", name, ok)
	}
	if name, ok := ce.VerifiedGoodBotName("1.2.3.4", "host.example.net", nil); ok || name != "" {
		t.Fatalf("a ptr matching no rule must not confirm: %q %v", name, ok)
	}

	// The ptr glob matches a verify_fcrdns rule, but a zero budget short-circuits
	// BEFORE the (blocking) forward-confirm — proving the guard bounds DNS.
	zero := 0
	if name, ok := ce.VerifiedGoodBotName("1.2.3.4", "crawl.ahrefs.com", &zero); ok || name != "" {
		t.Fatalf("zero budget must short-circuit before DNS: %q %v", name, ok)
	}
	if zero != 0 {
		t.Fatalf("zero budget must not be decremented, got %d", zero)
	}

	// Guards.
	var nilCE *ChallengeExclude
	if _, ok := nilCE.VerifiedGoodBotName("1.2.3.4", "crawl.ahrefs.com", nil); ok {
		t.Fatal("nil receiver → false")
	}
	if _, ok := ce.VerifiedGoodBotName("1.2.3.4", "", nil); ok {
		t.Fatal("empty ptr → false")
	}
}

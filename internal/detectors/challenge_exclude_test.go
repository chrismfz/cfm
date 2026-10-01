package detectors

import "testing"

// Real UAs contain '/', so '*' in a pattern must NOT treat '/' as a separator.
// This was previously broken because globMatch used filepath.Match.
func TestGlobMatch_UAWithSlash(t *testing.T) {
	cases := []struct {
		pattern, value string
		want           bool
	}{
		{"*ahrefs*", "mozilla/5.0 (compatible; ahrefsbot/7.0; +http://ahrefs.com/robot/)", true},
		{"*semrush*", "mozilla/5.0 (compatible; semrushbot/7~bl; +http://www.semrush.com/bot.html)", true},
		{"*", "mozilla/5.0 (compatible; whatever)", true},
		{"*.googlebot.com", "crawl-66-249-66-1.googlebot.com", true},
		{"*.ahrefs.com", "crawl-1-2-3-4.ahrefs.com", true},

		{"*ahrefs*", "mozilla/5.0 (compatible; bingbot/2.0)", false},
		{"*.googlebot.com", "fake.example.com", false},
		{"", "anything", false},

		// '?' matches exactly one char.
		{"a?c", "abc", true},
		{"a?c", "ac", false},

		// Substring fallback when no wildcards.
		{"ahrefsbot", "mozilla/5.0 (compatible; ahrefsbot/7.0)", true},
	}
	for _, c := range cases {
		got := globMatch(c.pattern, c.value)
		if got != c.want {
			t.Errorf("globMatch(%q, %q) = %v, want %v", c.pattern, c.value, got, c.want)
		}
	}
}

func TestChallengeExclude_Match_AhrefsUARule(t *testing.T) {
	// Simulate the file rule: ua=*ahrefs*; ptr=*.ahrefs.com; action=skip
	// (verify_fcrdns intentionally off — Match() doesn't do real DNS in this unit.)
	ce := &ChallengeExclude{
		rules: []challengeExcludeRule{{
			raw:    "ua=*ahrefs*; ptr=*.ahrefs.com; action=skip",
			ua:     "*ahrefs*",
			ptr:    "*.ahrefs.com",
			action: "skip",
		}},
	}
	ua := "Mozilla/5.0 (compatible; AhrefsBot/7.0; +http://ahrefs.com/robot/)"
	ptr := "crawl-1-2-3-4.ahrefs.com"

	act, _, ok := ce.Match("1.2.3.4", "example.com", ua, "as12345", ptr, "CHALLENGE_IP")
	if !ok || act != "skip" {
		t.Fatalf("expected skip match, got ok=%v action=%q", ok, act)
	}

	// Spoofed UA from unrelated PTR must not match (ptr glob fails).
	_, _, ok = ce.Match("9.9.9.9", "example.com", ua, "as12345", "unrelated.host.example", "CHALLENGE_IP")
	if ok {
		t.Fatal("spoofed PTR should not match")
	}
}

// MatchNoDNS (the edge decision hot path) honours ua/asn rules — the shipped
// Meta rules must exempt Meta's link-preview crawlers, which come from IPv6 with
// no PTR — and skips every verify_fcrdns rule (no DNS on the hot path).
func TestChallengeExclude_MatchNoDNS(t *testing.T) {
	ce := &ChallengeExclude{}
	for _, line := range []string{
		"ptr=*.googlebot.com; verify_fcrdns=1; action=skip",
		"ua=*googlebot*; ptr=*.googlebot.com; verify_fcrdns=1; mode=any; action=skip",
		"asn=as32934; ua=*facebookexternalhit*; action=skip",
		"asn=as32934; ua=*meta*;                action=skip",
		"asn=as714; action=skip",
		"asn=as64500; action=skip_vhost_only",
		"ptr=*.crawl.example; action=skip",
		"host=status.shop.gr; action=skip",
	} {
		ce.rules = append(ce.rules, parseChallengeExcludeRule(line))
	}
	str := func(v string) func() string { return func() string { return v } }
	cases := []struct {
		name, host, ua, asn, ptr, rule string
		want                           bool
		act                            string
	}{
		{"meta-externalads", "shop.gr", "meta-externalads/1.1 (+https://developers.facebook.com/docs/sharing/webmasters/crawler)", "AS32934", "", "CHALLENGE_VHOST", true, "skip"},
		{"meta-webindexer chrome", "shop.gr", "Mozilla/5.0 (Macintosh) Chrome/145.0.0.0 Safari/537.36 (compatible; meta-webindexer/1.1)", "AS32934", "", "CHALLENGE_VHOST", true, "skip"},
		{"facebookexternalhit", "shop.gr", "facebookexternalhit/1.1 (+http://www.facebook.com/externalhit_uatext.php)", "AS32934", "", "CHALLENGE_VHOST", true, "skip"},
		{"meta UA off Meta ASN", "shop.gr", "meta-externalads/1.1", "AS16509", "", "CHALLENGE_VHOST", false, ""},
		{"meta UA, ASN unknown", "shop.gr", "meta-externalads/1.1", "", "", "CHALLENGE_VHOST", false, ""},
		{"fcrdns rule skipped", "shop.gr", "x", "AS15169", "crawl-66-249-66-1.googlebot.com", "CHALLENGE_VHOST", false, ""},
		{"fcrdns mode=any rule skipped (spoofed UA)", "shop.gr", "Googlebot/2.1", "AS9009", "", "CHALLENGE_VHOST", false, ""},
		{"asn exact", "shop.gr", "x", "AS714", "", "CHALLENGE_VHOST", true, "skip"},
		{"asn no substring (AS7145)", "shop.gr", "x", "AS7145", "", "CHALLENGE_VHOST", false, ""},
		{"asn no substring (AS71400)", "shop.gr", "x", "AS71400", "", "CHALLENGE_VHOST", false, ""},
		{"bare ptr against cached ptr", "shop.gr", "x", "", "a.crawl.example", "CHALLENGE_VHOST", true, "skip"},
		{"host exact", "status.shop.gr", "x", "", "", "CHALLENGE_VHOST", true, "skip"},
		{"host subdomain", "www.status.shop.gr", "x", "", "", "CHALLENGE_VHOST", true, "skip"},
		{"host no substring", "mystatus.shop.gr", "x", "", "", "CHALLENGE_VHOST", false, ""},
		{"skip_vhost_only on vhost rule", "shop.gr", "x", "AS64500", "", "CHALLENGE_VHOST", true, "skip_vhost_only"},
		{"skip_vhost_only not on per-IP", "shop.gr", "x", "AS64500", "", "", false, ""},
	}
	for _, c := range cases {
		act, ok := ce.MatchNoDNS(c.host, c.ua, str(c.asn), str(c.ptr), c.rule)
		if ok != c.want || act != c.act {
			t.Errorf("%s: MatchNoDNS = (%q, %v), want (%q, %v)", c.name, act, ok, c.act, c.want)
		}
	}
	var nilCE *ChallengeExclude
	if _, ok := nilCE.MatchNoDNS("h", "meta", str("AS32934"), nil, ""); ok {
		t.Error("nil ChallengeExclude must not match")
	}
}

// The ASN / PTR lookups are lazy: a request whose UA fails every ua-gated rule
// never resolves its ASN, and the ASN is resolved at most once per call.
func TestChallengeExclude_MatchNoDNSLazy(t *testing.T) {
	ce := &ChallengeExclude{}
	for _, line := range []string{
		"asn=as32934; ua=*facebookexternalhit*; action=skip",
		"ua=*meta*; asn=as32934; action=skip",
	} {
		ce.rules = append(ce.rules, parseChallengeExcludeRule(line))
	}
	asnCalls, ptrCalls := 0, 0
	asnFn := func() string { asnCalls++; return "AS32934" }
	ptrFn := func() string { ptrCalls++; return "" }
	if _, ok := ce.MatchNoDNS("shop.gr", "Mozilla/5.0 Chrome/150", asnFn, ptrFn, "CHALLENGE_VHOST"); ok {
		t.Fatal("browser UA must not match")
	}
	if asnCalls != 0 || ptrCalls != 0 {
		t.Fatalf("lookups ran for a UA no rule accepts: asn=%d ptr=%d", asnCalls, ptrCalls)
	}
	if _, ok := ce.MatchNoDNS("shop.gr", "meta-externalads/1.1", asnFn, ptrFn, "CHALLENGE_VHOST"); !ok {
		t.Fatal("meta UA from AS32934 must match")
	}
	if asnCalls != 1 {
		t.Fatalf("ASN resolved %d times, want 1", asnCalls)
	}
}

// Match (the log-driven path) gets the same exact-ASN / host-boundary fix: an
// `asn=as714` rule must not exempt AS7145.
func TestChallengeExclude_MatchASNAndHostBoundaries(t *testing.T) {
	ce := &ChallengeExclude{rules: []challengeExcludeRule{
		parseChallengeExcludeRule("asn=as714; action=skip"),
		parseChallengeExcludeRule("host=shop.gr; action=skip"),
		parseChallengeExcludeRule("asn=as1516?; action=skip"),
	}}
	for _, c := range []struct {
		host, asn string
		want      bool
	}{
		{"x.gr", "AS714", true},
		{"x.gr", "AS7145", false},
		{"x.gr", "AS15169", true},
		{"x.gr", "AS151690", false},
		{"shop.gr", "", true},
		{"www.shop.gr", "", true},
		{"myshop.gr", "", false},
		{"shop.gr.evil.example", "", false},
	} {
		if _, _, ok := ce.Match("192.0.2.1", c.host, "", c.asn, "", "CHALLENGE_IP"); ok != c.want {
			t.Errorf("Match(host=%q asn=%q) = %v, want %v", c.host, c.asn, ok, c.want)
		}
	}
}

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
// no PTR — and treats a verify_fcrdns ptr condition as a non-match (no DNS).
func TestChallengeExclude_MatchNoDNS(t *testing.T) {
	ce := &ChallengeExclude{}
	for _, line := range []string{
		"ptr=*.googlebot.com; verify_fcrdns=1; action=skip",
		"asn=as32934; ua=*facebookexternalhit*; action=skip",
		"asn=as32934; ua=*meta*;                action=skip",
		"asn=as64500; action=skip_vhost_only",
		"ptr=*.crawl.example; action=skip",
	} {
		ce.rules = append(ce.rules, parseChallengeExcludeRule(line))
	}
	cases := []struct {
		name, ua, asn, ptr, rule string
		want                     bool
		act                      string
	}{
		{"meta-externalads", "meta-externalads/1.1 (+https://developers.facebook.com/docs/sharing/webmasters/crawler)", "AS32934", "", "CHALLENGE_VHOST", true, "skip"},
		{"meta-webindexer chrome", "Mozilla/5.0 (Macintosh) Chrome/145.0.0.0 Safari/537.36 (compatible; meta-webindexer/1.1)", "AS32934", "", "", true, "skip"},
		{"facebookexternalhit", "facebookexternalhit/1.1 (+http://www.facebook.com/externalhit_uatext.php)", "AS32934", "", "", true, "skip"},
		{"meta UA off Meta ASN", "meta-externalads/1.1", "AS16509", "", "CHALLENGE_VHOST", false, ""},
		{"meta UA, ASN unknown", "meta-externalads/1.1", "", "", "CHALLENGE_VHOST", false, ""},
		{"fcrdns ptr never confirms without DNS", "Googlebot/2.1", "AS15169", "crawl-66-249-66-1.googlebot.com", "CHALLENGE_VHOST", false, ""},
		{"bare ptr against cached ptr", "x", "", "a.crawl.example", "", true, "skip"},
		{"skip_vhost_only on vhost rule", "x", "AS64500", "", "CHALLENGE_VHOST", true, "skip_vhost_only"},
		{"skip_vhost_only not on per-IP", "x", "AS64500", "", "", false, ""},
	}
	for _, c := range cases {
		act, ok := ce.MatchNoDNS("shop.gr", c.ua, c.asn, c.ptr, c.rule)
		if ok != c.want || act != c.act {
			t.Errorf("%s: MatchNoDNS = (%q, %v), want (%q, %v)", c.name, act, ok, c.act, c.want)
		}
	}
	var nilCE *ChallengeExclude
	if _, ok := nilCE.MatchNoDNS("h", "meta", "AS32934", "", ""); ok {
		t.Error("nil ChallengeExclude must not match")
	}
}

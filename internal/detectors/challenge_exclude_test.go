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
		"asn=as32935; ua=*meta*; verify_fcrdns=1; action=skip",
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
		{"verify_fcrdns without ptr= still applies", "shop.gr", "meta-externalagent/1.1", "AS32935", "", "CHALLENGE_VHOST", true, "skip"},
	}
	for _, c := range cases {
		act, _, ok := ce.MatchNoDNS(c.host, c.ua, str(c.asn), str(c.ptr), c.rule)
		if ok != c.want || act != c.act {
			t.Errorf("%s: MatchNoDNS = (%q, %v), want (%q, %v)", c.name, act, ok, c.act, c.want)
		}
	}
	var nilCE *ChallengeExclude
	if _, _, ok := nilCE.MatchNoDNS("h", "meta", str("AS32934"), nil, ""); ok {
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
	if _, _, ok := ce.MatchNoDNS("shop.gr", "Mozilla/5.0 Chrome/150", asnFn, ptrFn, "CHALLENGE_VHOST"); ok {
		t.Fatal("browser UA must not match")
	}
	if asnCalls != 0 || ptrCalls != 0 {
		t.Fatalf("lookups ran for a UA no rule accepts: asn=%d ptr=%d", asnCalls, ptrCalls)
	}
	if _, rule, ok := ce.MatchNoDNS("shop.gr", "meta-externalads/1.1", asnFn, ptrFn, "CHALLENGE_VHOST"); !ok || rule != "ua=*meta*; asn=as32934; action=skip" {
		t.Fatalf("meta UA from AS32934 must match and name its rule, got ok=%v rule=%q", ok, rule)
	}
	if false {
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
		{"shop.gr:443", "", true},
		{"www.shop.gr.", "", true},
		{"myshop.gr:443", "", false},
	} {
		if _, _, ok := ce.Match("192.0.2.1", c.host, "", c.asn, "", "CHALLENGE_IP"); ok != c.want {
			t.Errorf("Match(host=%q asn=%q) = %v, want %v", c.host, c.asn, ok, c.want)
		}
	}
}

// Match and MatchNoDNS are one evaluator: the same rule, fed the same resolved
// request, decides the same way on both paths (verify_fcrdns ptr rules aside,
// which MatchNoDNS skips by design).
func TestChallengeExclude_MatchAndMatchNoDNSAgree(t *testing.T) {
	ce := &ChallengeExclude{}
	for _, line := range []string{
		"asn=as32934; ua=*meta*; action=skip",
		"asn=as32934; ua=*meta*; verify_fcrdns=1; action=skip",
		"ua=*crawler*; host=*.shop.gr; mode=any; action=skip",
		"asn=as15169; ptr=*.googlezip.net; action=skip",
		"asn=as64500; action=skip_vhost_only",
	} {
		ce.rules = append(ce.rules, parseChallengeExcludeRule(line))
	}
	for _, c := range []struct{ host, ua, asn, ptr, rule string }{
		{"shop.gr", "meta-externalads/1.1", "AS32934", "", "CHALLENGE_VHOST"},
		{"shop.gr", "meta-externalads/1.1", "AS16509", "", "CHALLENGE_VHOST"},
		{"a.shop.gr", "Mozilla/5.0", "", "", ""},
		{"x.gr", "SomeCrawler/1", "", "", ""},
		{"x.gr", "Mozilla/5.0", "AS15169", "a.fetch.tunnel.googlezip.net", ""},
		{"x.gr", "Mozilla/5.0", "AS15169", "", ""},
		{"x.gr", "x", "AS64500", "", "CHALLENGE_VHOST"},
		{"x.gr", "x", "AS64500", "", "CHALLENGE_IP"},
	} {
		a1, _, ok1 := ce.Match("192.0.2.1", c.host, c.ua, c.asn, c.ptr, c.rule)
		a2, _, ok2 := ce.MatchNoDNS(c.host, c.ua, func() string { return c.asn }, func() string { return c.ptr }, c.rule)
		if ok1 != ok2 || a1 != a2 {
			t.Errorf("%+v: Match=(%q,%v) MatchNoDNS=(%q,%v)", c, a1, ok1, a2, ok2)
		}
	}
}

// The hot-path matcher must not allocate per rule (it runs for every uncached
// decision on a vhost under a vhost-wide challenge — a flood). The one
// allowance is normalising the request's ASN ("AS16509" → "as16509"), done
// once per call however many asn= rules the file has.
func TestChallengeExclude_MatchNoDNSNoAllocs(t *testing.T) {
	ce := &ChallengeExclude{}
	for _, line := range []string{
		"ptr=*.googlebot.com; verify_fcrdns=1; action=skip",
		"asn=as32934; ua=*facebookexternalhit*; action=skip",
		"asn=as32934; ua=*meta*; action=skip",
		"asn=as202042; action=skip",
		"asn=as714; action=skip",
		"asn=as15169; ptr=*.googlezip.net; action=skip",
	} {
		ce.rules = append(ce.rules, parseChallengeExcludeRule(line))
	}
	asnFn := func() string { return "AS16509" }
	ptrFn := func() string { return "" }
	ua := "mozilla/5.0 (windows nt 10.0; win64; x64) chrome/150.0.0.0 safari/537.36"
	if n := testing.AllocsPerRun(200, func() {
		_, _, _ = ce.MatchNoDNS("shop.gr", ua, asnFn, ptrFn, "CHALLENGE_VHOST")
	}); n > 1 {
		t.Fatalf("MatchNoDNS allocates %.1f times per call, want <= 1", n)
	}
	// A request no rule gets as far as the ASN for: zero.
	ce2 := &ChallengeExclude{rules: []challengeExcludeRule{parseChallengeExcludeRule("asn=as32934; ua=*meta*; action=skip")}}
	if n := testing.AllocsPerRun(200, func() {
		_, _, _ = ce2.MatchNoDNS("shop.gr", ua, asnFn, ptrFn, "CHALLENGE_VHOST")
	}); n != 0 {
		t.Fatalf("MatchNoDNS allocates %.1f times for a UA-rejected request, want 0", n)
	}
}

func BenchmarkMatchNoDNSShippedRules(b *testing.B) {
	ce, err := LoadChallengeExclude("../../configs/webdetector_challenge_exclude.txt")
	if err != nil || ce == nil {
		b.Fatalf("load shipped file: %v", err)
	}
	asnFn := func() string { return "AS16509" }
	ptrFn := func() string { return "" }
	ua := "Mozilla/5.0 (Windows NT 10.0; Win64; x64) Chrome/150.0.0.0 Safari/537.36"
	b.ReportAllocs()
	for b.Loop() {
		_, _, _ = ce.MatchNoDNS("shop.gr", ua, asnFn, ptrFn, "CHALLENGE_VHOST")
	}
}

// The SHIPPED exclude file exempts every Meta crawler UA seen challenged across
// the fleet (2026-10-01) — only from Meta's own ASN. facebookcatalog (the
// Commerce Manager product-catalog fetcher) matched neither *meta* nor
// *facebookexternalhit*; the *facebook* rule covers it. The same UAs from the
// Google Cloud spoofing farm (AS396982) or a residential ASN stay challenged.
func TestShippedExcludeFile_MetaCrawlers(t *testing.T) {
	ce, err := LoadChallengeExclude("../../configs/webdetector_challenge_exclude.txt")
	if err != nil || ce == nil {
		t.Fatalf("load shipped file: %v", err)
	}
	str := func(v string) func() string { return func() string { return v } }
	uas := []string{
		"facebookexternalhit/1.1 (+http://www.facebook.com/externalhit_uatext.php)",
		"facebookcatalog/1.0",
		"meta-externalads/1.1 (+https://developers.facebook.com/docs/sharing/webmasters/crawler)",
		"Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/145.0.0.0 Safari/537.36 (compatible; meta-webindexer/1.1 (+https://developers.facebook.com/docs/sharing/webmasters/crawler))",
		"Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/145.0.0.0 Safari/537.36 (compatible; meta-externalagent/1.1 (+https://developers.facebook.com/docs/sharing/webmasters/crawler))",
	}
	for _, ua := range uas {
		if act, _, ok := ce.MatchNoDNS("shop.gr", ua, str("AS32934"), nil, "CHALLENGE_VHOST"); !ok || act != "skip" {
			t.Errorf("Meta crawler from AS32934 not exempt: %q (ok=%v act=%q)", ua, ok, act)
		}
		for _, asn := range []string{"AS396982", "AS6799", ""} {
			if _, _, ok := ce.MatchNoDNS("shop.gr", ua, str(asn), nil, "CHALLENGE_VHOST"); ok {
				t.Errorf("Meta UA %q exempt from non-Meta ASN %q", ua, asn)
			}
		}
	}
	// A browser on a Meta-owned network is not a crawler: still challenged.
	browser := "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/150.0.0.0 Safari/537.36"
	if _, _, ok := ce.MatchNoDNS("shop.gr", browser, str("AS32934"), nil, "CHALLENGE_VHOST"); ok {
		t.Error("plain browser UA from AS32934 must not be exempt")
	}
}

// The SHIPPED file exempts two user-triggered preview / fetch bots, each only
// from its operator's own ASN (UAs and ASNs as observed on titan, 2026-10-02):
// X's Twitterbot (AS13414) and Google-Read-Aloud (AS15169, Google's own network
// — not Google Cloud AS396982). The same UAs from a spoofing host stay
// challenged, and so does the on-device preview UA iMessage / Google Messages
// send from residential networks (it also contains "Twitterbot/1.0").
func TestShippedExcludeFile_PreviewFetchers(t *testing.T) {
	ce, err := LoadChallengeExclude("../../configs/webdetector_challenge_exclude.txt")
	if err != nil || ce == nil {
		t.Fatalf("load shipped file: %v", err)
	}
	str := func(v string) func() string { return func() string { return v } }
	const (
		twitterbot = "Twitterbot/1.0"
		readAloud  = "Mozilla/5.0 (Linux; Android 10; K) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/138.0.0.0 Mobile Safari/537.36 (compatible; Google-Read-Aloud; +https://support.google.com/webmasters/answer/1061943)"
		onDevice   = "Mozilla/5.0 (Macintosh; Intel Mac OS X 10_11_1) AppleWebKit/601.2.4 (KHTML, like Gecko) Version/9.0.1 Safari/601.2.4 facebookexternalhit/1.1 Facebot Twitterbot/1.0"
	)
	for _, c := range []struct {
		name, ua, asn string
		want          bool
	}{
		{"twitterbot from X", twitterbot, "AS13414", true},
		{"twitterbot from Google Cloud", twitterbot, "AS396982", false},
		{"twitterbot from Hetzner", twitterbot, "AS24940", false},
		{"read-aloud from Google", readAloud, "AS15169", true},
		{"read-aloud from Google Cloud", readAloud, "AS396982", false},
		{"read-aloud spoof from Hetzner", readAloud, "AS24940", false},
		{"read-aloud, ASN unknown", readAloud, "", false},
		{"iMessage/Messages on-device preview, residential", onDevice, "AS6799", false},
		{"plain Google UA on AS15169 is not read-aloud", "Mozilla/5.0 (compatible; Google-Something/1.0)", "AS15169", false},
	} {
		_, _, ok := ce.MatchNoDNS("shop.gr", c.ua, str(c.asn), nil, "CHALLENGE_VHOST")
		if ok != c.want {
			t.Errorf("%s: exempt=%v, want %v", c.name, ok, c.want)
		}
	}
}

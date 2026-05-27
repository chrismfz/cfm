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

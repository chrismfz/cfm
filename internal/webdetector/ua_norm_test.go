package webdetector

import "testing"

func TestNormalizeUA(t *testing.T) {
	cases := []struct {
		in   string
		want string
	}{
		{"", "-"},
		{"-", "-"},
		{"   ", "-"},

		// Direct bot UAs (no Mozilla envelope).
		{"facebookexternalhit/1.1", "facebookexternalhit"},
		{"facebookexternalhit/1.1 (+http://www.facebook.com/externalhit_uatext.php)", "facebookexternalhit"},
		{"curl/7.88.1", "curl"},
		{"python-requests/2.31.0", "python-requests"},
		{"AhrefsBot/7.0", "ahrefsbot"},
		{"Wget/1.21.3", "wget"},

		// Mozilla envelope cases.
		{"Mozilla/5.0 (compatible; Googlebot/2.1; +http://www.google.com/bot.html)", "googlebot"},
		{"Mozilla/5.0 (compatible; bingbot/2.0; +http://www.bing.com/bingbot.htm)", "bingbot"},
		{"Mozilla/5.0 (compatible; SemrushBot/7~bl; +http://www.semrush.com/bot.html)", "semrushbot"},
		{"Mozilla/5.0 (compatible; AhrefsBot/7.0; +http://ahrefs.com/robot/)", "ahrefsbot"},
		{"Mozilla/5.0 (compatible; MJ12bot/v1.4.8; http://mj12bot.com/)", "mj12bot"},
		{"Mozilla/5.0 (compatible; DotBot/1.2; +https://opensiteexplorer.org/dotbot)", "dotbot"},
		{"Mozilla/5.0 (compatible; Amazonbot/0.1; +https://developer.amazon.com/support/amazonbot)", "amazonbot"},
		{"Mozilla/5.0 (compatible; meta-externalagent/1.1; +https://developers.facebook.com)", "meta-externalagent"},

		// Bot declared in a LATER "(...)" group (Meta Chrome-145 crawler,
		// Googlebot smartphone); an unclosed group stays "mozilla".
		{"Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/145.0.0.0 Safari/537.36 (compatible; meta-externalagent/1.1 (+https://developers.facebook.com/docs/sharing/webmasters/crawler))", "meta-externalagent"},
		{"Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/145.0.0.0 Safari/537.36 (compatible; meta-webindexer/1.1 (+https://developers.facebook.com/docs/sharing/webmasters/crawler))", "meta-webindexer"},
		{"Mozilla/5.0 (Linux; Android 6.0.1; Nexus 5X Build/MMB29P) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/141.0.0.0 Mobile Safari/537.36 (compatible; Googlebot/2.1; +http://www.google.com/bot.html)", "googlebot"},
		{"Mozilla/5.0 (Windows NT 10.0) AppleWebKit/537.36 (compatible; FooBot/1.0", "mozilla"},

		// Real browsers — keep generic "mozilla" identifier.
		{"Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/120 Safari/537.36", "mozilla"},
		{"Mozilla/5.0 (iPhone; CPU iPhone OS 17_0 like Mac OS X) AppleWebKit/605", "mozilla"},

		// FB in-app browser — should not collapse to facebookexternalhit.
		{"Mozilla/5.0 (Linux; Android 12; SM-G991B) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/120 Mobile Safari/537.36 [FB_IAB/FB4A;FBAV/444]", "mozilla"},

		// Whitespace parity with Lua: firstUAToken must NOT treat \n \r
		// \v \f as token separators (Lua's %s would; Go's must not).
		// These cases lock the parity in.
		{"FooBot\nextra/1.0", "foobot\nextra"},
		{"SemBot\v/1.0", "sembot\v"},
		{"DotBot\f/2.0", "dotbot\f"},
		{"GooBot\r/3.0", "goobot\r"},
	}

	for _, c := range cases {
		got := NormalizeUA(c.in)
		if got != c.want {
			t.Errorf("NormalizeUA(%q) = %q, want %q", c.in, got, c.want)
		}
	}
}

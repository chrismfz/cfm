package uaplausible

import (
	"fmt"
	"strings"
	"testing"
)

// Every string below is taken verbatim from a 314,877-request production
// capture, so these are regressions against real traffic, not invented shapes.

func TestImpossibleUAs(t *testing.T) {
	tests := []struct {
		name   string
		ua     string
		reason string
	}{
		{
			// iOS is required to use the system WebKit (AppleWebKit/60x); the
			// 537.36 token belongs to Blink. 1,664 requests / 738 distinct
			// strings in the capture, all of this shape.
			name:   "iPhone claiming Blink WebKit",
			ua:     "Mozilla/5.0 (iPhone; CPU iPhone OS 11_0 like Mac OS X) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/60.0.5721.1352 Mobile Safari/537.36",
			reason: "ios_with_blink_webkit",
		},
		{
			name:   "iPhone with desktop Chrome token instead of CriOS",
			ua:     "Mozilla/5.0 (iPhone; CPU iPhone OS 11_0 like Mac OS X) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/53.0.9885.1352 Mobile Safari/537.36",
			reason: "ios_with_desktop_chrome_token",
		},
		{
			name:   "CriOS off an Apple platform",
			ua:     "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/605.1.15 (KHTML, like Gecko) CriOS/150.0.7871.113 Safari/604.1",
			reason: "crios_without_ios_platform",
		},
		{
			// Firefox is Gecko; it never carries the Blink WebKit token.
			name:   "Firefox claiming Blink WebKit",
			ua:     "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Firefox/115.0",
			reason: "firefox_with_blink_webkit",
		},
		{
			name:   "Chrome without the KHTML compatibility token",
			ua:     "Mozilla/5.0 (X11; Linux x86_64) AppleWebKit/537.36 Chrome/120 Safari/537.36",
			reason: "chrome_missing_khtml_token",
		},
		{
			name:   "Chrome with a hand-written short version",
			ua:     "Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/120.0 Safari/537.36",
			reason: "chrome_truncated_version",
		},
		{
			// The generator's signature: Chrome's fourth component drawn from
			// 1000-1999. Every non-generated Chrome string in the capture has it
			// below 300, with a few outliers to 819.
			name:   "Chrome patch number no release has ever had",
			ua:     "Mozilla/5.0 (Linux; Android 8.0; Pixel 2 Build/OPD3.170816.012) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/39.0.8475.1801 Mobile Safari/537.36",
			reason: "chrome_impossible_patch",
		},
		{
			// Chrome's minor has been 0 for its entire history — 4,149 of the
			// 4,151 Chrome version strings in the capture, majors 15 to 150.
			name:   "Chrome with a non-zero minor",
			ua:     "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/99.101.4951.54 Safari/537.36",
			reason: "chrome_nonzero_minor",
		},
		{
			// A reduced UA freezes the last three components together
			// ("145.0.0.0"). A zero build with a live patch is that shape with
			// its last field overwritten.
			name:   "Chrome reduced build with a live patch",
			ua:     "Mozilla/5.0 (Windows NT 6.1; WOW64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/69.0.0.3016 Safari/537.36",
			reason: "chrome_reduced_build_with_patch",
		},
		{
			name:   "two platforms at once",
			ua:     "Mozilla/5.0 (Windows NT 10.0; Macintosh; Intel Mac OS X 10_15_7) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/145.0.0.0 Safari/537.36",
			reason: "multiple_platform_tokens",
		},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			v := Check(tc.ua)
			if !v.Impossible {
				t.Fatalf("Check(%q).Impossible = false, want true", tc.ua)
			}
			found := false
			for _, r := range v.Reasons {
				if r == tc.reason {
					found = true
				}
			}
			if !found {
				t.Errorf("reasons = %v, want to include %q", v.Reasons, tc.reason)
			}
		})
	}
}

func TestPlausibleUAsAreNotFlagged(t *testing.T) {
	// The crawler entries are the important ones: an earlier version of the
	// KHTML rule tested for the literal "(KHTML, like Gecko)" and flagged all
	// three, because well-behaved crawlers append their identity inside the
	// same parentheses.
	uas := []string{
		"Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/145.0.0.0 Safari/537.36",
		"Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/118.0.0.0 Safari/537.36",
		"Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/131.0.0.0 Safari/537.36",
		"Mozilla/5.0 (X11; Linux x86_64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/150.0.0.0 Safari/537.36",
		"Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/78.0.3904.108 Safari/537.36",
		// The highest patch numbers in the capture that are NOT generator
		// output. The version rules must clear all of them — 280 is the top of
		// the dense population and 819 the highest outlier, so these are what
		// stands between the 1000 bound and a false positive.
		"Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/120.0.6099.280 Safari/537.36",
		"Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/119.0.6045.214 Safari/537.36",
		"Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/66.0.3359.819 Safari/537.36",
		"Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/145.0.0.0 Safari/537.36 Edg/145.0.0.0",
		"Mozilla/5.0 (Windows NT 10.0; Win64; x64; rv:153.0) Gecko/20100101 Firefox/153.0",
		"Mozilla/5.0 (iPhone; CPU iPhone OS 26_5_2 like Mac OS X) AppleWebKit/605.1.15 (KHTML, like Gecko) CriOS/150.0.7871.113 Mobile/15E148 Safari/604.1",
		"Mozilla/5.0 (iPhone; CPU iPhone OS 17_0 like Mac OS X) AppleWebKit/605.1.15 (KHTML, like Gecko) Version/17.0 Mobile/15E148 Safari/604.1",
		"Mozilla/5.0 (Linux; Android 10; K) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/145.0.0.0 Mobile Safari/537.36",
		// Legitimate crawlers — must stay clean.
		"Mozilla/5.0 AppleWebKit/537.36 (KHTML, like Gecko; compatible; ClaudeBot/1.0; +claudebot@anthropic.com)",
		"Mozilla/5.0 (X11; Linux x86_64) AppleWebKit/537.36 (KHTML, like Gecko; GeedoShopProductFinder) Chrome/142.0.0.0 Safari/537.36",
		"Mozilla/5.0 AppleWebKit/537.36 (KHTML, like Gecko; compatible; Amazonbot/0.1; +https://developer.amazon.com/support/amazonbot)",
		"Mozilla/5.0 AppleWebKit/537.36 (KHTML, like Gecko; compatible; YouBot/1.0; +https://docs.you.com/youbot)",
		"Mozilla/5.0 (compatible; AhrefsBot/7.0; +http://ahrefs.com/robot/)",
		"Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7) AppleWebKit/605.1.15 (KHTML, like Gecko) Version/17.4 Safari/605.1.15 (Applebot/0.1; +http://www.apple.com/go/applebot)",
		"Uptime-Kuma/1.23.16",
		"Mozilla/5.0 (compatible; crawler)",

		// Chromium derivatives — all carry a Chrome/ token.
		"Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/119.0.0.0 Safari/537.36 OPR/105.0.0.0",
		"Mozilla/5.0 (Linux; Android 13; SAMSUNG SM-S918B) AppleWebKit/537.36 (KHTML, like Gecko) SamsungBrowser/23.0 Chrome/115.0.0.0 Mobile Safari/537.36",
		"Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/102.0.5005.167 Electron/19.0.11 Safari/537.36",
		"Mozilla/5.0 (X11; Linux x86_64) AppleWebKit/537.36 (KHTML, like Gecko) Ubuntu Chromium/120.0.6099.109 Chrome/120.0.6099.109 Safari/537.36",
		"Mozilla/5.0 (Linux; Android 10; K) AppleWebKit/537.36 (KHTML, like Gecko) Version/4.0 Chrome/145.0.0.0 Mobile Safari/537.36",
		"Mozilla/5.0 (X11; CrOS x86_64 14541.0.0) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/145.0.0.0 Safari/537.36",
		"Mozilla/5.0 (X11; Linux x86_64) AppleWebKit/537.36 (KHTML, like Gecko) HeadlessChrome/119.0.6045.105 Safari/537.36",

		// Alternative browsers on iOS keep the system WebKit and their own token.
		"Mozilla/5.0 (iPhone; CPU iPhone OS 17_0 like Mac OS X) AppleWebKit/605.1.15 (KHTML, like Gecko) FxiOS/119.0 Mobile/15E148 Safari/605.1.15",
		"Mozilla/5.0 (iPhone; CPU iPhone OS 17_0 like Mac OS X) AppleWebKit/605.1.15 (KHTML, like Gecko) EdgiOS/119.0.0.0 Mobile/15E148 Safari/605.1.15",

		// iPadOS in desktop-content mode reports Macintosh as its platform while
		// apps keep their own device/product tokens after the parenthetical. Both
		// of these tripped an earlier draft of the platform-conflict rule.
		"Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7) AppleWebKit/605.1.15 (KHTML, like Gecko) CriOS/125.0.6422.80 Version/17.4 Safari/605.1.15",
		"Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7) AppleWebKit/605.1.15 (KHTML, like Gecko) Version/17.0 Safari/605.1.15 [FBAN/FBIOS;FBDV/iPad11,3;FBMD/iPad;FBSN/iOS;FBSV/17.0]",

		// In-app browsers that append device tokens after the platform group.
		"Mozilla/5.0 (iPhone; CPU iPhone OS 17_0 like Mac OS X) AppleWebKit/605.1.15 (KHTML, like Gecko) Mobile/15E148 Instagram 302.0.0.23.113",
		"Mozilla/5.0 (Linux; Android 13; V2309A Build/TP1A.220905.001) AppleWebKit/537.36 (KHTML, like Gecko) Version/4.0 Chrome/116.0.0.0 Mobile Safari/537.36 MicroMessenger/8.0.42",
	}
	for _, ua := range uas {
		if v := Check(ua); v.Impossible {
			t.Errorf("false positive on %q: %v", ua, v.Reasons)
		}
	}
}

// The version digits come from a client-controlled header via an unbounded
// (\d+) capture. A wrapping accumulator would let a caller choose the sign of
// Major, which becomes a live bug the moment anything compares against it.
func TestVersionOverflowSaturates(t *testing.T) {
	for _, ua := range []string{
		"Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/9999999999999999999.0.0.0 Safari/537.36",
		"Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/99999999999999999999999999999999.0.0.0 Safari/537.36",
	} {
		if got := Check(ua).Major; got < 0 {
			t.Errorf("Major = %d for an overflowing version; want a saturated non-negative value", got)
		}
	}
}

// The version-shape rules read the Chrome token, which every Chromium
// derivative carries — so the question is whether any of them writes something
// other than the upstream Chromium version there. Measured over the capture:
// 69 distinct derivative UA strings across 12 families (Edge, Opera, Vivaldi,
// Brave, Samsung, Yandex-style, Electron, Chromium, WebView, MIUI, Sputnik,
// EdgeAndroid), 1,497 requests, and NONE is flagged. Their highest patch is 280
// — Opera's Chrome/120.0.6099.280, which is also the highest legitimate patch
// anywhere in the capture.
//
// That is what the rules rest on: derivatives carry the Chrome token precisely
// for compatibility, so they advertise the Chromium build they are made from,
// using Chromium's own version string. A fork that invented its own numbers
// there would break UA sniffing everywhere, which is the opposite of why the
// token exists.
func TestChromiumDerivativesAreNotFlagged(t *testing.T) {
	// Each of these carries the highest patch number its family reached in the
	// capture, so they sit as close to the bound as real traffic gets.
	for _, ua := range []string{
		"Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/120.0.6099.280 Safari/537.36 OPR/106.0.0.0",
		"Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/132.0.6834.210 Electron/34.0.0 Safari/537.36",
		"Mozilla/5.0 (Linux; Android 14; K) AppleWebKit/537.36 (KHTML, like Gecko) Version/4.0 Chrome/150.0.7871.181 Mobile Safari/537.36",
		"Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/112.0.5615.136 Mobile Safari/537.36 MiuiBrowser/17.2.11",
		"Mozilla/5.0 (Linux; Android 14; SM-S928B) AppleWebKit/537.36 (KHTML, like Gecko) SamsungBrowser/25.0 Chrome/123.0.6312.120 Mobile Safari/537.36",
		"Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/125.0.6422.112 Safari/537.36 Brave/125",
		"Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/126.0.6478.70 Safari/537.36 Vivaldi/6.8",
		"Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/86.0.4240.111 Safari/537.36 Edg/86.0.622.51",
		"Mozilla/5.0 (Linux; Android 13; K) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/109.0.5414.117 Mobile Safari/537.36 EdgA/109.0.1518.80",
		"Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/118.0.5993.117 YaBrowser/23.11.0.0 Safari/537.36",
		// Forks with no product token of their own, which is the case the rules
		// cannot distinguish from plain Chrome even in principle — they must
		// pass on the strength of the upstream version alone.
		"Mozilla/5.0 (Linux; Android 14; K) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/130.0.6723.107 Mobile Safari/537.36",
		"Mozilla/5.0 (X11; Linux x86_64) AppleWebKit/537.36 (KHTML, like Gecko) Ubuntu Chromium/120.0.6099.109 Chrome/120.0.6099.109 Safari/537.36",
	} {
		if v := Check(ua); v.Impossible {
			t.Errorf("false positive on a Chromium derivative %q: %v", ua, v.Reasons)
		}
	}
}

// The patch bound is the one number in this package chosen from a distribution
// rather than from a structural fact, so pin both sides of it.
func TestChromePatchBound(t *testing.T) {
	const tmpl = "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/120.0.6099.%d Safari/537.36"
	for _, patch := range []int{0, 108, 280, 819, 999} {
		if v := Check(fmt.Sprintf(tmpl, patch)); v.Impossible {
			t.Errorf("patch %d flagged (%v), want plausible", patch, v.Reasons)
		}
	}
	for _, patch := range []int{1000, 1801, 9999} {
		v := Check(fmt.Sprintf(tmpl, patch))
		if !v.Impossible {
			t.Errorf("patch %d not flagged, want chrome_impossible_patch", patch)
		}
	}
}

// The version rules read a regexp submatch, so they must not run when the UA
// carries no Chrome token at all — reading chrome[2] off a nil match panics, and
// a panic here takes down the verify path this package is called from.
func TestNonChromeUAsDoNotReachTheVersionRules(t *testing.T) {
	for _, ua := range []string{
		"Uptime-Kuma/1.23.16",
		"Mozilla/5.0 (compatible; crawler)",
		"Mozilla/5.0 (Windows NT 10.0; Win64; x64; rv:153.0) Gecko/20100101 Firefox/153.0",
		"curl/8.5.0",
		"-",
		"Chrome",
		"Chrome/",
	} {
		if v := Check(ua); v.Impossible {
			t.Errorf("false positive on %q: %v", ua, v.Reasons)
		}
	}
}

// A rule that becomes over-broad must be caught, so assert the exact reason set
// rather than mere membership.
func TestReasonsAreExact(t *testing.T) {
	v := Check("Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 Chrome/120 Safari/537.36")
	want := map[string]bool{"chrome_missing_khtml_token": true, "chrome_truncated_version": true}
	if len(v.Reasons) != len(want) {
		t.Fatalf("reasons = %v, want exactly %d", v.Reasons, len(want))
	}
	for _, r := range v.Reasons {
		if !want[r] {
			t.Errorf("unexpected reason %q in %v", r, v.Reasons)
		}
	}
}

// Absent is not the same as impossible; an empty UA is a separate signal and
// must not be laundered into a high-confidence "this UA is a lie" verdict.
func TestEmptyUAIsNotImpossible(t *testing.T) {
	for _, ua := range []string{"", "   ", "-"} {
		if v := Check(ua); v.Impossible {
			t.Errorf("Check(%q).Impossible = true, want false (%v)", ua, v.Reasons)
		}
	}
}

func TestIdentityParsing(t *testing.T) {
	tests := []struct {
		ua     string
		family string
		major  int
	}{
		{"Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/118.0.0.0 Safari/537.36", "Chrome", 118},
		{"Mozilla/5.0 (Windows NT 10.0; Win64; x64; rv:153.0) Gecko/20100101 Firefox/153.0", "Firefox", 153},
		{"Mozilla/5.0 (iPhone; CPU iPhone OS 26_5_2 like Mac OS X) AppleWebKit/605.1.15 (KHTML, like Gecko) CriOS/150.0.7871.113 Mobile/15E148 Safari/604.1", "CriOS", 150},
		{"Mozilla/5.0 (iPhone; CPU iPhone OS 17_0 like Mac OS X) AppleWebKit/605.1.15 (KHTML, like Gecko) Version/17.0 Mobile/15E148 Safari/604.1", "Safari", 17},
		{"Uptime-Kuma/1.23.16", "", 0},
	}
	for _, tc := range tests {
		v := Check(tc.ua)
		if v.Family != tc.family || v.Major != tc.major {
			t.Errorf("Check(%.60q) identity = %s/%d, want %s/%d", tc.ua, v.Family, v.Major, tc.family, tc.major)
		}
	}
}

func TestReasonJoinsStably(t *testing.T) {
	v := Check("Mozilla/5.0 (iPhone; CPU iPhone OS 11_0 like Mac OS X) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/60.0.5721.1352 Mobile Safari/537.36")
	got := v.Reason()
	if !strings.Contains(got, "ios_with_blink_webkit") || !strings.Contains(got, "ios_with_desktop_chrome_token") {
		t.Errorf("Reason() = %q, want both iOS contradictions", got)
	}
	if Check("Mozilla/5.0 (compatible; crawler)").Reason() != "" {
		t.Error("Reason() must be empty for a plausible UA")
	}
}

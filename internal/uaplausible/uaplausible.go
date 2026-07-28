// Package uaplausible reports whether a User-Agent string is internally
// self-contradictory — a browser identity that no real build could emit.
//
// It answers "is this UA a lie?", NOT "is this UA old". A stale-but-coherent UA
// belongs to a real person on an old browser; a UA claiming an iPhone running
// desktop Blink belongs to nobody. Only the second is reported here.
//
// Every rule below was derived from, and validated against, 314,877 real
// requests (4,889 distinct UA strings) captured on a production edge. The rules
// flag 0.55% of that traffic, and every flagged string was inspected. That
// validation matters more than it sounds: an earlier version of the KHTML rule
// tested for the literal "(KHTML, like Gecko)" and wrongly flagged legitimate
// crawlers — Amazonbot, YouBot, GeedoShopProductFinder — which place their own
// token inside the same parentheses ("(KHTML, like Gecko; Amazonbot/0.1)").
// Never add a rule here from memory; check it against a real corpus first.
//
// Deliberately NOT implemented: version-staleness scoring. It is tempting to
// call a UA suspicious when its version is far behind the fleet, but on the very
// data these rules came from, Chrome 118 was 72.5% of all Chrome requests
// BECAUSE the farm dominated the traffic. Calibrating "current" by request
// volume lets the attacker define normal, and calibrating any other way still
// only measures age — which legitimately old browsers share. Freshness is a
// different question from coherence and needs its own design.
package uaplausible

import (
	"errors"
	"math"
	"regexp"
	"strconv"
	"strings"
)

// Verdict is the result of checking one User-Agent.
type Verdict struct {
	// Impossible is true when the UA contradicts itself. It is high-confidence
	// by construction: each rule describes a combination no shipping browser
	// emits, not a combination that is merely unusual.
	Impossible bool
	// Reasons lists every rule that matched, in a stable order.
	Reasons []string
	// Family and Major carry the claimed browser identity when parseable, for
	// callers that want to group or report on it. They are descriptive only —
	// nothing here treats an old version as suspicious.
	Family string
	Major  int
}

// Reason returns the reasons joined for logging. Empty when plausible.
func (v Verdict) Reason() string { return strings.Join(v.Reasons, ",") }

var (
	reIOSPlatform = regexp.MustCompile(`\b(?:iPhone|iPad|iPod)\b`)
	reChromeTok   = regexp.MustCompile(`\bChrome/(\d+)((?:\.\d+)*)`)
	reFirefoxTok  = regexp.MustCompile(`\bFirefox/(\d+)`)
	reCriOSTok    = regexp.MustCompile(`\bCriOS/(\d+)`)
	reSafariVer   = regexp.MustCompile(`\bVersion/(\d+)[\d.]*\s+(?:Mobile/\S+\s+)?Safari\b`)

	rePlatformTokens = []*regexp.Regexp{
		regexp.MustCompile(`\bWindows NT\b`),
		regexp.MustCompile(`\bMacintosh\b`),
		regexp.MustCompile(`\bAndroid\b`),
		regexp.MustCompile(`\bX11;`),
		reIOSPlatform,
	}
	// rePlatformGroup captures the leading parenthetical, which is where a UA
	// declares its platform. Everything after it is product and device tokens —
	// an in-app browser appends `FBDV/iPad11,3;FBMD/iPad`, IE Mobile shipped
	// `like iPhone OS 7_0_3 Mac OS X`, the Kindle browser said `Linux armv7l like
	// Android`. Counting platform words across the whole string flags all of
	// those, so the platform-conflict rule looks only inside this group.
	rePlatformGroup = regexp.MustCompile(`^[^(]*\(([^)]*)\)`)
)

// blinkWebKit is the AppleWebKit build token frozen into every Blink-engine UA
// (Chrome and derivatives). Apple's own WebKit reports 60x.x.xx, so seeing this
// exact token on an Apple platform is a contradiction, not a coincidence.
const blinkWebKit = "AppleWebKit/537.36"

// Check reports whether ua is self-contradictory. An empty UA is NOT flagged:
// absent is not the same as impossible, and it is a separate signal.
func Check(ua string) Verdict {
	ua = strings.TrimSpace(ua)
	v := Verdict{}
	if ua == "" || ua == "-" {
		return v
	}

	isIOS := reIOSPlatform.MatchString(ua)
	hasBlinkWK := strings.Contains(ua, blinkWebKit)
	hasCriOS := reCriOSTok.MatchString(ua)
	chrome := reChromeTok.FindStringSubmatch(ua)

	// Identity, for reporting only.
	switch {
	case hasCriOS:
		v.Family, v.Major = "CriOS", atoi(reCriOSTok.FindStringSubmatch(ua)[1])
	case chrome != nil:
		// "Chrome" here means the Blink engine identity, not the Chrome browser:
		// Edge, Opera, Samsung Internet, Brave, Vivaldi, Yandex and Electron apps
		// all carry a Chrome/ token and are reported as Chrome. Note also that
		// HeadlessChrome/ does NOT match (no word boundary before "Chrome"), so
		// headless Chrome is classified as "" and is invisible to both Chrome
		// rules — a deliberate gap, since a headless UA is honest, not impossible.
		v.Family, v.Major = "Chrome", atoi(chrome[1])
	case reFirefoxTok.MatchString(ua):
		v.Family, v.Major = "Firefox", atoi(reFirefoxTok.FindStringSubmatch(ua)[1])
	case reSafariVer.MatchString(ua):
		v.Family, v.Major = "Safari", atoi(reSafariVer.FindStringSubmatch(ua)[1])
	}

	// iOS has historically been required to use the system WebKit, which reports
	// AppleWebKit/60x, so the Blink token on an Apple platform is a contradiction.
	// Watch this one: the EU DMA has obliged Apple to allow alternative engines
	// since iOS 17.4, so a genuinely Blink-based iOS browser would land here. It
	// would arrive as a version-coherent UA from a wide, ordinary population —
	// recheck against a corpus if this rule's share starts climbing.
	if isIOS && hasBlinkWK {
		v.Reasons = append(v.Reasons, "ios_with_blink_webkit")
	}
	// Chrome on iOS identifies as CriOS. A bare "Chrome/" token on an iOS
	// platform is a desktop string with the platform swapped in.
	if isIOS && chrome != nil && !hasCriOS {
		v.Reasons = append(v.Reasons, "ios_with_desktop_chrome_token")
	}
	// ...and the converse: CriOS only exists on iOS. Skip the check when the
	// platform is Macintosh — iPadOS in desktop-content mode reports `Macintosh`
	// while apps keep their own product token, so `Macintosh` + `CriOS` is a real
	// shape, not a contradiction.
	if hasCriOS && !isIOS && !strings.Contains(ua, "Macintosh") {
		v.Reasons = append(v.Reasons, "crios_without_ios_platform")
	}
	// Firefox is Gecko. It never carries the Blink WebKit token.
	if reFirefoxTok.MatchString(ua) && hasBlinkWK {
		v.Reasons = append(v.Reasons, "firefox_with_blink_webkit")
	}
	// Every real Chrome UA carries the "KHTML, like Gecko" compatibility token.
	// Match the phrase, NOT "(KHTML, like Gecko)" — well-behaved crawlers append
	// their own identity inside the same parentheses.
	if chrome != nil && strings.Contains(ua, "AppleWebKit/") && !strings.Contains(ua, "KHTML, like Gecko") {
		v.Reasons = append(v.Reasons, "chrome_missing_khtml_token")
	}
	// Chrome always reports four version components (145.0.0.0 today,
	// 78.0.3904.108 before the reduced-UA change), and so do the Chromium
	// derivatives checked against a real corpus: Edge, Opera, Samsung Internet,
	// Brave, Vivaldi, Yandex, Electron apps and Android WebView. Fewer means the
	// string was hand-written — which includes benign tooling (uptime monitors,
	// link previewers, corporate proxies), not only bots.
	if chrome != nil && strings.Count(chrome[2], ".") < 3 {
		v.Reasons = append(v.Reasons, "chrome_truncated_version")
	}
	// A UA declares exactly one platform. Counted inside the leading
	// parenthetical only — see rePlatformGroup.
	if countPlatformTokens(platformGroup(ua)) > 1 {
		v.Reasons = append(v.Reasons, "multiple_platform_tokens")
	}

	v.Impossible = len(v.Reasons) > 0
	return v
}

// platformGroup returns the leading parenthetical, or "" when the UA has none
// (many crawlers do not), in which case there is no platform claim to check.
func platformGroup(ua string) string {
	if m := rePlatformGroup.FindStringSubmatch(ua); m != nil {
		return m[1]
	}
	return ""
}

func countPlatformTokens(ua string) int {
	n := 0
	for _, re := range rePlatformTokens {
		if re.MatchString(ua) {
			n++
		}
	}
	return n
}

// atoi parses a leading run of digits, saturating instead of wrapping. The digit
// run comes from a client-controlled header via an unbounded (\d+) capture, so a
// hand-rolled accumulator would let a caller pick the sign of Major.
func atoi(s string) int {
	n, err := strconv.Atoi(s)
	if err != nil {
		if errors.Is(err, strconv.ErrRange) {
			return math.MaxInt
		}
		return 0
	}
	return n
}

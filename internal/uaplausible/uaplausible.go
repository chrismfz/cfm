// Package uaplausible reports whether a User-Agent string is internally
// self-contradictory — a browser identity that no real build could emit.
//
// It answers "is this UA a lie?", NOT "is this UA old". A stale-but-coherent UA
// belongs to a real person on an old browser; a UA claiming an iPhone running
// desktop Blink belongs to nobody. Only the second is reported here.
//
// Every rule below was derived from, and validated against, 314,877 real
// requests (4,889 distinct UA strings) captured on a production edge. The rules
// flag ~0.54% of that traffic, and every flagged string was inspected. That
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
	"regexp"
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
		v.Family, v.Major = "Chrome", atoi(chrome[1])
	case reFirefoxTok.MatchString(ua):
		v.Family, v.Major = "Firefox", atoi(reFirefoxTok.FindStringSubmatch(ua)[1])
	case reSafariVer.MatchString(ua):
		v.Family, v.Major = "Safari", atoi(reSafariVer.FindStringSubmatch(ua)[1])
	}

	// iOS never ships the Blink WebKit build token — every browser on iOS is
	// required to use the system WebKit, which reports AppleWebKit/60x.
	if isIOS && hasBlinkWK {
		v.Reasons = append(v.Reasons, "ios_with_blink_webkit")
	}
	// Chrome on iOS identifies as CriOS. A bare "Chrome/" token on an iOS
	// platform is a desktop string with the platform swapped in.
	if isIOS && chrome != nil && !hasCriOS {
		v.Reasons = append(v.Reasons, "ios_with_desktop_chrome_token")
	}
	// ...and the converse: CriOS only exists on iOS.
	if hasCriOS && !isIOS {
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
	// 78.0.3904.108 before the reduced-UA change). Fewer means hand-written.
	if chrome != nil && strings.Count(chrome[2], ".") < 3 {
		v.Reasons = append(v.Reasons, "chrome_truncated_version")
	}
	// A UA claims exactly one platform.
	if countPlatformTokens(ua) > 1 {
		v.Reasons = append(v.Reasons, "multiple_platform_tokens")
	}

	v.Impossible = len(v.Reasons) > 0
	return v
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

func atoi(s string) int {
	n := 0
	for _, c := range s {
		if c < '0' || c > '9' {
			return n
		}
		n = n*10 + int(c-'0')
	}
	return n
}

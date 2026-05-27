package detectors

import (
	"strings"
	"testing"
)

// matchNoFCrDNS is a copy of Match() that skips real DNS resolution — it
// pretends verify_fcrdns=1 succeeds when the PTR glob matches. Used only
// for end-to-end verification of rule patterns against the real rule file.
func (ce *ChallengeExclude) matchNoFCrDNS(host, ua, asn, ptr, ruleName string) (string, string, bool) {
	hostL := strings.ToLower(strings.TrimSpace(host))
	uaL := strings.ToLower(strings.TrimSpace(ua))
	asnL := strings.ToLower(strings.TrimSpace(asn))
	ptrL := strings.ToLower(strings.TrimSpace(ptr))
	rn := strings.ToUpper(strings.TrimSpace(ruleName))
	isVHostWide := rn == "CHALLENGE_VHOST" || rn == "CHALLENGE_SUSPICIOUS_VHOST_SCORE"

	for _, r := range ce.rules {
		if r.action == "skip_vhost_only" && !isVHostWide {
			continue
		}
		checks, matches := 0, 0
		if r.host != "" {
			checks++
			if globMatch(r.host, hostL) {
				matches++
			}
		}
		if r.ua != "" {
			checks++
			if globMatch(r.ua, uaL) {
				matches++
			}
		}
		if r.asn != "" {
			checks++
			if globMatch(r.asn, asnL) {
				matches++
			}
		}
		if r.ptr != "" {
			checks++
			if globMatch(r.ptr, ptrL) {
				matches++ // pretend FCrDNS passes
			}
		}
		if checks == 0 {
			continue
		}
		ok := matches == checks
		if r.modeAny {
			ok = matches >= 1
		}
		if ok {
			return r.action, r.raw, true
		}
	}
	return "", "", false
}

// TestVerify_RealRuleFile loads the actual production rule file and verifies
// each realistic scenario lands on the rule we expect (or no rule at all).
// Skipped if the rule file isn't reachable from the test working dir.
func TestVerify_RealRuleFile(t *testing.T) {
	const path = "../../configs/webdetector_challenge_exclude.txt"
	ce, err := LoadChallengeExclude(path)
	if err != nil {
		t.Skipf("rule file not found at %s: %v", path, err)
	}
	if ce == nil {
		t.Skipf("rule file at %s has no rules", path)
	}
	t.Logf("loaded %d rules", len(ce.rules))

	type tc struct {
		name                            string
		host, ua, asn, ptr              string
		wantMatch                       bool
		mustContainRule                 string // substring expected in matched rule.raw
	}
	cases := []tc{
		{"Googlebot", "ex.com",
			"Mozilla/5.0 (compatible; Googlebot/2.1; +http://www.google.com/bot.html)",
			"as15169", "crawl-66-249-66-1.googlebot.com", true, "*.googlebot.com"},
		{"Bingbot", "ex.com",
			"Mozilla/5.0 (compatible; bingbot/2.0; +http://www.bing.com/bingbot.htm)",
			"as8075", "msnbot-207-46-13-10.search.msn.com", true, "*.search.msn.com"},
		{"AhrefsBot", "ex.com",
			"Mozilla/5.0 (compatible; AhrefsBot/7.0; +http://ahrefs.com/robot/)",
			"as16276", "crawl-54-36-148-1.ahrefs.com", true, "*.ahrefs.com"},
		{"SemrushBot", "ex.com",
			"Mozilla/5.0 (compatible; SemrushBot/7~bl; +http://www.semrush.com/bot.html)",
			"as209366", "bot-85-208-96-10.semrush.com", true, "*.semrush.com"},
		{"facebookexternalhit", "ex.com",
			"facebookexternalhit/1.1 (+http://www.facebook.com/externalhit_uatext.php)",
			"as32934", "edge.facebook.com", true, "facebookexternalhit"},
		{"Skroutz ASN", "ex.com", "anything/1.0", "as202042", "", true, "as202042"},
		{"Apple ASN", "ex.com", "Mozilla/5.0", "as714", "", true, "as714"},

		{"Regular visitor — must NOT match", "ex.com",
			"Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36",
			"as7922", "c-73-0-0-1.hsd1.ca.comcast.net", false, ""},
		{"Spoofed AhrefsBot UA, wrong PTR — must NOT match", "ex.com",
			"Mozilla/5.0 (compatible; AhrefsBot/7.0; +http://ahrefs.com/robot/)",
			"as1", "evil.example.com", false, ""},
		{"Spoofed Googlebot UA, wrong PTR — must NOT match", "ex.com",
			"Mozilla/5.0 (compatible; Googlebot/2.1)",
			"as99999", "host.attacker.com", false, ""},
	}

	for _, c := range cases {
		act, rule, ok := ce.matchNoFCrDNS(c.host, c.ua, c.asn, c.ptr, "CHALLENGE_IP")
		if ok != c.wantMatch {
			t.Errorf("[%s] matched=%v action=%q rule=%q  want match=%v",
				c.name, ok, act, rule, c.wantMatch)
			continue
		}
		if ok {
			if !strings.Contains(rule, c.mustContainRule) {
				t.Errorf("[%s] matched rule %q does not contain expected %q",
					c.name, rule, c.mustContainRule)
			} else {
				t.Logf("[%s] OK  action=%s  rule=%s", c.name, act, rule)
			}
		} else {
			t.Logf("[%s] OK  (no match, as expected)", c.name)
		}
	}
}

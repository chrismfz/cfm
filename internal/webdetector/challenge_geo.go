package webdetector

import (
	"fmt"
	"strconv"
	"strings"
	"sync/atomic"

	"cfm/internal/enrich"
)

// Network identity of a solving client — country, ASN and PTR — resolved ONCE
// at verify and carried on the ChallengeSolve, so the result=solved line, the
// result=v2_reject line and both history rows (challenge_solved,
// challenge_v2_reject) all render the same answer.
//
// It exists for false-positive hunting on the ChallengeV2 rung. Before it, a
// v2_reject line carried only the IP, so judging whether a rejected client was
// a farm or a person took a separate manual lookup per address — and the
// rejects were the one population with no durable row at all. Log/corpus
// only: nothing scores or gates on these fields.

// challengeSolveEnricher maps a solving client's IP to its enrichment. Wired on
// every engine build (SetChallengeSolveEnricher, engine.go) and cleared when
// that engine has no enricher; nil leaves every geo field empty — fail-open,
// the solve itself is never affected.
//
// It must never block: verify is on the request path, and a cold reverse
// lookup can take up to a second. So the engine wires it as two non-blocking
// halves — country/ASN from a live mmdb read (microseconds, no DNS; the cached
// record could be up to a day stale), PTR from the cached-or-async path
// (served when warm, resolved in the background otherwise). The page load that
// served this challenge already went through the bridge, so by verify the PTR
// is usually warm. "Once" is per record: when a country/ASN policy is armed,
// the verify-side arm check (GeoPolicyActionForIP) does its own lookup too.
var challengeSolveEnricher atomic.Pointer[func(ip string) enrich.Result]

// SetChallengeSolveEnricher installs the resolver behind the solve's network
// identity; nil disables it (all geo fields stay empty).
func SetChallengeSolveEnricher(fn func(ip string) enrich.Result) {
	if fn == nil {
		challengeSolveEnricher.Store(nil)
		return
	}
	challengeSolveEnricher.Store(&fn)
}

// resolveGeo fills the solve's network-identity fields from the wired
// enricher. Called once per verify, before the v2 gate, so a rejected solve
// carries them too.
func (s *ChallengeSolve) resolveGeo() {
	p := challengeSolveEnricher.Load()
	if p == nil || s.IP == "" {
		return
	}
	r := (*p)(s.IP)
	s.Country = r.Country
	s.CountryISO = r.CountryISO
	s.ASN = r.ASN
	s.ASNName = r.ASNName
	s.PTR = r.PTR
}

// GeoSuffix renders the network identity for a [challenge] line:
//
//	cc=GR asn=6799 asn_name="OTEnet S.A." ptr=ppp-1-2.example.gr
//
// Every key is emitted only when resolved. Absent means "not resolved at
// verify" — and for ptr also "the address has none" — never a fabricated
// value: the same absent-never-zero rule sig= follows (D5b).
//
// asn_name is always quoted (organisation names carry spaces). cc and ptr go
// through logToken, because a PTR is chosen by whoever controls the address's
// reverse zone and may be read back from the persistent PTR store: the line
// must stay parseable whatever arrives.
func (s ChallengeSolve) GeoSuffix() string {
	var b strings.Builder
	if s.CountryISO != "" {
		b.WriteString(" cc=")
		b.WriteString(logToken(s.CountryISO))
	}
	if s.ASN != 0 {
		fmt.Fprintf(&b, " asn=%d", s.ASN)
	}
	if s.ASNName != "" {
		fmt.Fprintf(&b, " asn_name=%q", s.ASNName)
	}
	if s.PTR != "" {
		b.WriteString(" ptr=")
		b.WriteString(logToken(s.PTR))
	}
	return b.String()
}

// LegacyGeoTail renders the free-text " - (AS6799 OTEnet S.A., Greece)" tail
// the solved-hook line has always ended with. Kept byte-for-byte so tooling
// that reads it keeps working; it now renders from the fields resolved once at
// verify instead of from a second lookup of its own, so it can no longer
// disagree with GeoSuffix or the history row. "" when nothing resolved.
func (s ChallengeSolve) LegacyGeoTail() string {
	parts := make([]string, 0, 2)
	if s.ASN > 0 {
		if s.ASNName != "" {
			parts = append(parts, fmt.Sprintf("AS%d %s", s.ASN, s.ASNName))
		} else {
			parts = append(parts, fmt.Sprintf("AS%d", s.ASN))
		}
	}
	if s.Country != "" {
		parts = append(parts, s.Country)
	}
	if len(parts) == 0 {
		return ""
	}
	return " - (" + strings.Join(parts, ", ") + ")"
}

// addGeoPayload writes the resolved network identity into a history payload.
// Key names match the waf_trigger row (country / country_iso / asn / asn_name)
// so one query shape reads both. Unlike waf_trigger, an unresolved field is
// OMITTED rather than written as a zero: "asn": 0 would read as a resolved
// answer. ptr is admin-only on the scoped surface — see
// redactScopedHistoryRows.
func (s ChallengeSolve) addGeoPayload(p map[string]interface{}) {
	if s.Country != "" {
		p["country"] = s.Country
	}
	if s.CountryISO != "" {
		p["country_iso"] = s.CountryISO
	}
	if s.ASN != 0 {
		p["asn"] = s.ASN
	}
	if s.ASNName != "" {
		p["asn_name"] = s.ASNName
	}
	if s.PTR != "" {
		p["ptr"] = s.PTR
	}
}

// logToken returns s bare when it is a plain token, quoted otherwise, so a
// value on a key=value line can never smuggle in a space, a quote or a newline.
func logToken(s string) string {
	for _, c := range s {
		switch {
		case c >= 'a' && c <= 'z', c >= 'A' && c <= 'Z', c >= '0' && c <= '9':
		case c == '.', c == '-', c == '_', c == ':':
		default:
			return strconv.Quote(s)
		}
	}
	return s
}

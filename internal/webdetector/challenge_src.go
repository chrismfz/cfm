package webdetector

// Challenge-solve provenance: "WHY was this client challenged?" on every
// solve, reject and would_v2 line (src=) and on the challenge_solved /
// challenge_v2_reject history rows (payload.src).
//
// Why it exists: the verify handler never knew what served the challenge it
// is verifying, so a would_v2 line could not say whether the client met an
// auto vhost challenge, a per-IP detector challenge, a WAF rule or a
// fingerprint/geo policy — exactly the split needed to size a v2 arm on any
// one of those sources before turning it on (e.g. arming the auto vhost
// challenge at v2).
//
// What it is: a SNAPSHOT, taken at verify, of every challenge source that
// covers (ip, host) at that moment. It is not a record of the one decision
// that served the page — several sources can cover the same client (all are
// listed), and the snapshot runs seconds to minutes after the serve:
//
//	waf:<id>        per-IP bridge entry written by a WAF rule's ip_push
//	ip:<reason>     per-IP bridge entry from a detector (ChallengeIPWithReason;
//	                "ip" alone when the writer gave no reason)
//	vhost:<reason>  vhost-wide entry: manual | vhost_config | suspicious_vhost |
//	                uniqpaths_short ("vhost" alone for an edge-pushed entry)
//	rule:<id>       a traffic rule answered challenge/challenge_v2 for this
//	                (ip, host) recently (noteRuleChallenge, below)
//	fp              the client's TLS fingerprint has a challenge-tier policy
//	geo             a country/ASN challenge-tier policy covers the client IP
//
// src=- means the snapshot found none: a challenge that is purely edge-local
// by then (an entry that expired between serve and verify, or a stale page).
// The field is absent when provenance could not be read at all (no bridge
// wired). It is LOG-ONLY: nothing decides on it, so it can never move a
// solve's outcome. The v2= grain stays the one answer to "did the teeth
// cover this solve".

import (
	"strconv"
	"strings"
	"sync"
	"time"
)

// Source tokens (a grep surface — keep them short and stable).
const (
	srcWAF   = "waf"
	srcIP    = "ip"
	srcVhost = "vhost"
	srcRule  = "rule"
	srcFP    = "fp"
	srcGeo   = "geo"
)

// srcTokenMax bounds one reason inside a token. Reasons are operator/config
// strings (rule ids, detector names); the bound only keeps a line sane.
const srcTokenMax = 64

// srcReasonToken makes a reason safe inside a comma-joined, space-free src=
// value (the abuse-shadow parser splits on spaces): anything outside
// [A-Za-z0-9._:/-] becomes '_', and it is truncated to srcTokenMax.
func srcReasonToken(s string) string {
	s = strings.TrimSpace(s)
	if len(s) > srcTokenMax {
		s = s[:srcTokenMax]
	}
	b := []byte(s)
	for i, c := range b {
		switch {
		case c >= 'a' && c <= 'z', c >= 'A' && c <= 'Z', c >= '0' && c <= '9':
		case c == '.', c == '-', c == '_', c == ':', c == '/':
		default:
			b[i] = '_'
		}
	}
	return string(b)
}

// ── Traffic-rule challenge notes ────────────────────────────────────────────
//
// A traffic rule's challenge is decided per request and leaves no bridge
// state behind (the edge acts on the decision answer), so without a note the
// verify could never see it. handleDecision records the rule id per
// (ip, host) whenever a rule answers challenge or challenge_v2 on the web
// scope. Same key, TTL and cap as the v2 marks — but a SEPARATE store: the
// marks are gate teeth, these notes are telemetry only, and a note must
// never be able to arm anything. Bounded and fail-open: over the cap a new
// note is dropped (the solve then simply lacks rule:<id>).
type challengeRuleNoteStore struct {
	mu sync.RWMutex
	m  map[string]challengeRuleNote
}

type challengeRuleNote struct {
	ruleID  string
	expires time.Time
}

var challengeRuleNotes = challengeRuleNoteStore{m: map[string]challengeRuleNote{}}

// noteRuleChallenge records that traffic rule ruleID challenged (ip, host).
func noteRuleChallenge(ip, host, ruleID string) {
	key := challengeV2MarkKey(ip, host)
	if key == "" || strings.TrimSpace(ruleID) == "" {
		return
	}
	now := time.Now()
	s := &challengeRuleNotes
	s.mu.Lock()
	defer s.mu.Unlock()
	if _, exists := s.m[key]; !exists && len(s.m) >= challengeV2MarkMaxKeys {
		for k, n := range s.m { // expiry sweep, only on pressure
			if now.After(n.expires) {
				delete(s.m, k)
			}
		}
		if len(s.m) >= challengeV2MarkMaxKeys {
			return
		}
	}
	s.m[key] = challengeRuleNote{ruleID: ruleID, expires: now.Add(challengeV2MarkTTL)}
}

// ruleChallengeNote returns the traffic rule that recently challenged
// (ip, host), or "".
func ruleChallengeNote(ip, host string) string {
	key := challengeV2MarkKey(ip, host)
	if key == "" {
		return ""
	}
	s := &challengeRuleNotes
	s.mu.RLock()
	n, ok := s.m[key]
	s.mu.RUnlock()
	if !ok || time.Now().After(n.expires) {
		return ""
	}
	return n.ruleID
}

// ── The snapshot ────────────────────────────────────────────────────────────

// challengeSources lists the challenge sources covering (ip, host) right now,
// in a fixed order (per-IP, vhost, rule, fp, geo) so equal situations always
// render the same string. See the file header for the vocabulary. Read-only:
// it takes the bridge's RLock once and never mutates any store.
func (b *NginxBridge) challengeSources(fpID, ip, host string) []string {
	var out []string
	now := time.Now()
	if b != nil {
		b.mu.RLock()
		if e, ok := b.ipState[ip]; ok && e.Expires.After(now) && e.Action == "challenge" {
			switch {
			case e.WAFRuleID > 0:
				out = append(out, srcWAF+":"+strconv.Itoa(e.WAFRuleID))
			case strings.TrimSpace(e.Reason) != "":
				out = append(out, srcIP+":"+srcReasonToken(e.Reason))
			default:
				out = append(out, srcIP)
			}
		}
		if h, ok := b.vhostEntryLocked(host, now); ok && h.Action == "challenge" {
			if r := strings.TrimSpace(h.Reason); r != "" {
				out = append(out, srcVhost+":"+srcReasonToken(r))
			} else {
				out = append(out, srcVhost)
			}
		}
		b.mu.RUnlock()
	}
	if id := ruleChallengeNote(ip, host); id != "" {
		out = append(out, srcRule+":"+srcReasonToken(id))
	}
	if a := FingerprintPolicyForID(fpID); a == "challenge" || a == "challenge_v2" {
		out = append(out, srcFP)
	}
	if GeoPolicyActionForIP(ip) != "" {
		out = append(out, srcGeo)
	}
	return out
}

// SrcValue renders the provenance as the src= value: the comma-joined
// sources, "-" when resolved and none covered the client, "" when provenance
// was never resolved (the field is then omitted everywhere).
func (s ChallengeSolve) SrcValue() string {
	if !s.SrcResolved {
		return ""
	}
	if len(s.Src) == 0 {
		return "-"
	}
	return strings.Join(s.Src, ",")
}

// SrcSuffix renders " src=<value>" for a [challenge] / [abuse-shadow] line,
// or "" when unresolved. Every writer appends it at the END of its line, so
// no field an existing parser reads moves.
func (s ChallengeSolve) SrcSuffix() string {
	v := s.SrcValue()
	if v == "" {
		return ""
	}
	return " src=" + v
}

// ShadowContextSuffix is the tail of the would_v2 [abuse-shadow] line: who
// the client is and what challenged it, so a would-reject can be judged
// (a Google fetcher, a self-declared AI crawler, a farm exit, an auto vhost
// challenge vs a WAF rule) without joining against cfm.challenges.log:
//
//	cc=GR asn=16509 provider=amazon-aws ptr=x.example ua_family=Chrome ua_bot=1 src=vhost:suspicious_vhost
//
// The abuse-shadow parser splits on spaces (abuseshadow.Parse, "every value
// is space-free"), so only space-free values ride here: no asn_name, no raw
// UA. provider is DatacenterClass (canonicalised space-free at the source);
// a PTR that is not a plain token renders as ptr=invalid rather than
// quoted. ua_bot=1 means the UA SELF-DECLARES a bot (isBotUA) — unverified,
// the same substring test the vhost bot_ratio uses. Each key is emitted only
// when known (absent never zero, as on the solve line); src is last.
func (s ChallengeSolve) ShadowContextSuffix() string {
	var b strings.Builder
	if s.CountryISO != "" {
		b.WriteString(" cc=")
		b.WriteString(shadowToken(s.CountryISO))
	}
	if s.ASN != 0 {
		b.WriteString(" asn=")
		b.WriteString(strconv.FormatUint(uint64(s.ASN), 10))
		if p := DatacenterClass(s.ASN, s.ASNName); p != "" {
			b.WriteString(" provider=")
			b.WriteString(shadowToken(p))
		}
	}
	if s.PTR != "" {
		b.WriteString(" ptr=")
		b.WriteString(shadowToken(s.PTR))
	}
	b.WriteString(" ua_family=")
	b.WriteString(s.UAFamilyOrDash())
	if isBotUA(s.UA) {
		b.WriteString(" ua_bot=1")
	}
	b.WriteString(s.SrcSuffix())
	return b.String()
}

// shadowToken returns s when it is a plain log token (the logToken charset),
// else "invalid": an [abuse-shadow] value must never carry a space or quote.
func shadowToken(s string) string {
	if logToken(s) != s {
		return "invalid"
	}
	return s
}

package webdetector

import (
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"

	"cfm/internal/abuseshadow"
)

// Challenge-solve provenance (challenge_src.go): the src= snapshot of what
// covered (ip, host) at verify. Log-only — these tests pin the vocabulary and
// the "never reads two ways" matcher reuse, not any decision.

func resetChallengeRuleNotes(t *testing.T) {
	t.Helper()
	reset := func() {
		challengeRuleNotes.mu.Lock()
		challengeRuleNotes.m = map[string]time.Time{}
		challengeRuleNotes.vals = map[string]string{}
		challengeRuleNotes.fullWarn = false
		challengeRuleNotes.lastSweep = time.Time{}
		challengeRuleNotes.mu.Unlock()
	}
	reset()
	t.Cleanup(reset)
}

func TestChallengeSourcesVocabulary(t *testing.T) {
	resetFPPolicies(t)
	resetChallengeRuleNotes(t)
	b := NewNginxBridge("/tmp/cfm-test-src.sock", "tok", time.Minute, time.Minute)
	ip, host := "203.0.113.40", "shop.gr"
	future := time.Now().Add(time.Hour)

	if got := b.challengeSources("", ip, host, "", 0); len(got) != 0 {
		t.Fatalf("nothing covers the client: got %v", got)
	}

	// Per-IP: a WAF push names the rule id, a detector entry its reason, a
	// reason-less entry is bare "ip". A block is not a challenge source.
	b.mu.Lock()
	b.ipState[ip] = bridgeIPEntry{Action: "challenge", Expires: future, Reason: "WAF_XSS", WAFRuleID: 302}
	b.mu.Unlock()
	if got := b.challengeSources("", ip, host, "", 0); strings.Join(got, ",") != "waf:302" {
		t.Fatalf("waf entry: got %v", got)
	}
	b.mu.Lock()
	b.ipState[ip] = bridgeIPEntry{Action: "challenge", Expires: future, Reason: "CHALLENGE_ERR_RATIO"}
	b.mu.Unlock()
	if got := b.challengeSources("", ip, host, "", 0); strings.Join(got, ",") != "ip:CHALLENGE_ERR_RATIO" {
		t.Fatalf("detector entry: got %v", got)
	}
	b.mu.Lock()
	b.ipState[ip] = bridgeIPEntry{Action: "challenge", Expires: future}
	b.mu.Unlock()
	if got := b.challengeSources("", ip, host, "", 0); strings.Join(got, ",") != "ip" {
		t.Fatalf("reason-less entry: got %v", got)
	}
	b.mu.Lock()
	b.ipState[ip] = bridgeIPEntry{Action: "block", Expires: future, Reason: "x"}
	b.mu.Unlock()
	if got := b.challengeSources("", ip, host, "", 0); len(got) != 0 {
		t.Fatalf("a block is not a challenge source: got %v", got)
	}
	b.mu.Lock()
	b.ipState[ip] = bridgeIPEntry{Action: "challenge", Expires: time.Now().Add(-time.Second), Reason: "stale"}
	b.mu.Unlock()
	if got := b.challengeSources("", ip, host, "", 0); len(got) != 0 {
		t.Fatalf("an expired entry is not a source: got %v", got)
	}

	// Vhost-wide: exact and wildcard both resolve through the ONE matcher.
	b.mu.Lock()
	b.vhState["shop.gr"] = bridgeVhostEntry{Action: "challenge", Expires: future, Reason: "suspicious_vhost"}
	b.vhState["*.farm.gr"] = bridgeVhostEntry{Action: "challenge", Expires: future, Reason: "manual"}
	b.vhState["edge.gr"] = bridgeVhostEntry{Action: "challenge", Expires: future}
	b.mu.Unlock()
	if got := b.challengeSources("", ip, host, "", 0); strings.Join(got, ",") != "vhost:suspicious_vhost" {
		t.Fatalf("exact vhost: got %v", got)
	}
	if got := b.challengeSources("", ip, "www.farm.gr", "", 0); strings.Join(got, ",") != "vhost:manual" {
		t.Fatalf("wildcard vhost: got %v", got)
	}
	if got := b.challengeSources("", ip, "edge.gr", "", 0); strings.Join(got, ",") != "vhost" {
		t.Fatalf("reason-less vhost entry: got %v", got)
	}

	// Traffic-rule note, fingerprint and geo policies, in the fixed order.
	noteRuleChallenge(ip, host, "r_checkout")
	id := fpTestID(t)
	SetFingerprintPolicies([]FingerprintPolicy{
		{ID: id, Action: "challenge"},
		{ID: "CN", Kind: "country", Action: "challenge_v2"},
	})
	SetFingerprintPolicyGeoResolver(func(string) (string, uint64) { return "CN", 4134 })
	t.Cleanup(func() { SetFingerprintPolicyGeoResolver(nil) })
	b.mu.Lock()
	b.ipState[ip] = bridgeIPEntry{Action: "challenge", Expires: future, WAFRuleID: 201}
	b.mu.Unlock()
	want := "waf:201,vhost:suspicious_vhost,rule:r_checkout,fp,geo"
	if got := strings.Join(b.challengeSources(id, ip, host, "", 0), ","); got != want {
		t.Fatalf("all sources (resolver fallback): got %q, want %q", got, want)
	}
	// With the solve's own resolved identity the geo token follows IT, not a
	// second lookup: a GR solve is not geo-covered even though the resolver
	// (a later, hot-swapped database, say) would now answer CN.
	if got := strings.Join(b.challengeSources(id, ip, host, "GR", 6799), ","); strings.Contains(got, "geo") {
		t.Fatalf("geo must follow the resolved identity: %q", got)
	}
	if got := strings.Join(b.challengeSources(id, ip, host, "CN", 4134), ","); got != want {
		t.Fatalf("resolved CN: got %q, want %q", got, want)
	}

	// A deny fingerprint is not a CHALLENGE source (it never reaches verify).
	SetFingerprintPolicies([]FingerprintPolicy{{ID: id, Action: "deny"}})
	if got := strings.Join(b.challengeSources(id, ip, host, "", 0), ","); strings.Contains(got, "fp") {
		t.Fatalf("deny fp listed as a challenge source: %q", got)
	}
}

func TestChallengeSourcesNilBridgeStillReadsPolicies(t *testing.T) {
	resetFPPolicies(t)
	resetChallengeRuleNotes(t)
	var b *NginxBridge
	noteRuleChallenge("203.0.113.41", "shop.gr", "r1")
	if got := strings.Join(b.challengeSources("", "203.0.113.41", "shop.gr", "", 0), ","); got != "rule:r1" {
		t.Fatalf("nil bridge: got %q", got)
	}
}

func TestSrcReasonTokenIsSpaceAndCommaFree(t *testing.T) {
	got := srcReasonToken("  WEB/abuse 404 flood,x=y\"z  ")
	if got != "WEB/abuse_404_flood_x_y_z" {
		t.Fatalf("got %q", got)
	}
	long := srcReasonToken(strings.Repeat("a", 200))
	if len(long) != srcTokenMax {
		t.Fatalf("not bounded: %d", len(long))
	}
}

func TestSrcValueAbsentVersusNone(t *testing.T) {
	if v := (ChallengeSolve{}).SrcValue(); v != "" {
		t.Fatalf("unresolved must render nothing, got %q", v)
	}
	if s := (ChallengeSolve{}).SrcSuffix(); s != "" {
		t.Fatalf("unresolved suffix: %q", s)
	}
	if v := (ChallengeSolve{SrcResolved: true}).SrcValue(); v != "-" {
		t.Fatalf("resolved-and-empty must render -, got %q", v)
	}
	s := ChallengeSolve{SrcResolved: true, Src: []string{"ip:X", "vhost:manual"}}
	if s.SrcSuffix() != " src=ip:X,vhost:manual" {
		t.Fatalf("got %q", s.SrcSuffix())
	}
	if s.historyPayload()["src"] != "ip:X,vhost:manual" {
		t.Fatalf("history payload src: %v", s.historyPayload()["src"])
	}
	if _, ok := (ChallengeSolve{}).historyPayload()["src"]; ok {
		t.Fatalf("unresolved solve must not persist src")
	}
	// The reject line carries it at the END.
	rej := ChallengeSolve{IP: "1.2.3.4", Host: "h", HumanityScored: true, HumanityScore: 100, V2Grain: "vhost", SrcResolved: true, Src: []string{"vhost:manual"}}
	if !strings.HasSuffix(rej.RejectLine(), " src=vhost:manual") {
		t.Fatalf("reject line: %q", rej.RejectLine())
	}
}

// The would_v2 shadow line's tail must round-trip through the abuse-shadow
// parser, whose contract is "every value is space-free": a hostile PTR, an
// ASN org name with spaces or a UA must never split a field.
func TestShadowContextSuffixParses(t *testing.T) {
	s := ChallengeSolve{
		IP: "216.73.217.117", Host: "shop.gr",
		UA:         "Mozilla/5.0 (Macintosh) Chrome/131.0.0.0 Safari/537.36; ClaudeBot/1.0; +claudebot@anthropic.com) verdict=pwned",
		UAFamily:   "Chrome",
		CountryISO: "US", ASN: 16509, ASNName: "Amazon.com, Inc.",
		PTR:         "evil host.example",
		SrcResolved: true, Src: []string{"vhost:suspicious_vhost", "ip:CHALLENGE_ERR_RATIO"},
	}
	line := "2026-09-23 10:00:00 [abuse-shadow] signal=humanity host=shop.gr ip=216.73.217.117 hs=160 tells=webdriver,sw_renderer fp=c28caa00 verdict=would_v2" + s.ShadowContextSuffix()
	e, ok := abuseshadow.Parse(line)
	if !ok {
		t.Fatalf("line did not parse: %q", line)
	}
	if e.Verdict != "would_v2" || e.Signal != "humanity" {
		t.Fatalf("core fields clobbered: %+v", e)
	}
	if e.CC != "US" || e.ASN != 16509 || e.Provider != "amazon-aws" {
		t.Fatalf("network fields: %+v", e)
	}
	if e.PTR != "invalid" {
		t.Fatalf("a non-token PTR must render invalid, got %q", e.PTR)
	}
	if e.UAFamily != "Chrome" || !e.UABot {
		t.Fatalf("ua fields: %+v", e)
	}
	if e.Src != "vhost:suspicious_vhost,ip:CHALLENGE_ERR_RATIO" {
		t.Fatalf("src: %q", e.Src)
	}
	if strings.Contains(s.ShadowContextSuffix(), "Amazon.com") || strings.Contains(s.ShadowContextSuffix(), "Mozilla") {
		t.Fatalf("free text leaked into the shadow line: %q", s.ShadowContextSuffix())
	}
	// Unknown fields are omitted, never zero; ua_family falls back to "-".
	if got := (ChallengeSolve{}).ShadowContextSuffix(); got != " ua_family=-" {
		t.Fatalf("empty solve: %q", got)
	}
}

// A traffic rule that answers challenge (either tier) on the web scope leaves
// a note the verify reads back as rule:<id>; the panel probe and non-challenge
// actions leave none.
func TestDecisionNotesRuleChallenge(t *testing.T) {
	resetChallengeV2Marks(t)
	resetChallengeRuleNotes(t)
	b := NewNginxBridge("/tmp/cfm-test-src-rule.sock", "tok", time.Minute, time.Minute)
	decide := func(ip, action, scope string) {
		t.Helper()
		b.RuleDecision = func(TrafficRuleEvalInput) TrafficRuleEvalResult {
			return TrafficRuleEvalResult{Matched: true, Rule: TrafficRule{ID: "r_" + action}, Action: action}
		}
		q := "/nginx/decision?ip=" + ip + "&host=shop.gr&uri=%2F&method=GET&ua=x"
		if scope != "" {
			q += "&scope=" + scope
		}
		rr := httptest.NewRecorder()
		req := httptest.NewRequest(http.MethodGet, q, nil)
		req.Header.Set("X-CFM-Token", "tok")
		b.handleDecision(rr, req)
		if rr.Code != http.StatusOK {
			t.Fatalf("status=%d", rr.Code)
		}
	}
	decide("203.0.113.50", TrafficActionChallenge, "")
	decide("203.0.113.51", TrafficActionChallengeV2, "")
	decide("203.0.113.52", TrafficActionChallenge, "panel%3A2083")
	decide("203.0.113.53", "block", "")

	if got := ruleChallengeNote("203.0.113.50", "shop.gr"); got != "r_challenge" {
		t.Fatalf("v1 rule note: %q", got)
	}
	if got := ruleChallengeNote("203.0.113.51", "shop.gr"); got != "r_challenge_v2" {
		t.Fatalf("v2 rule note: %q", got)
	}
	if got := ruleChallengeNote("203.0.113.52", "shop.gr"); got != "" {
		t.Fatalf("panel scope must not note: %q", got)
	}
	if got := ruleChallengeNote("203.0.113.53", "shop.gr"); got != "" {
		t.Fatalf("a block rule is not a challenge: %q", got)
	}
	// The note is telemetry only: a plain challenge rule must still not arm v2.
	if challengeV2Marked("203.0.113.50", "shop.gr") {
		t.Fatalf("a rule note armed v2")
	}
}

func TestRuleChallengeNoteExpiryAndCap(t *testing.T) {
	resetChallengeRuleNotes(t)
	noteRuleChallenge("203.0.113.60", "shop.gr", "r1")
	challengeRuleNotes.mu.Lock()
	challengeRuleNotes.m["203.0.113.60|shop.gr"] = time.Now().Add(-time.Second)
	challengeRuleNotes.mu.Unlock()
	if got := ruleChallengeNote("203.0.113.60", "shop.gr"); got != "" {
		t.Fatalf("expired note answered %q", got)
	}

	challengeRuleNotes.mu.Lock()
	for i := 0; i < challengeV2MarkMaxKeys; i++ {
		k := time.Duration(i).String() + "|h"
		challengeRuleNotes.m[k] = time.Now().Add(time.Hour)
		challengeRuleNotes.vals[k] = "x"
	}
	challengeRuleNotes.mu.Unlock()
	noteRuleChallenge("203.0.113.61", "shop.gr", "r2")
	if got := ruleChallengeNote("203.0.113.61", "shop.gr"); got != "" {
		t.Fatalf("over the cap a new note must be dropped, got %q", got)
	}
	challengeRuleNotes.mu.RLock()
	n, warned := len(challengeRuleNotes.m), challengeRuleNotes.fullWarn
	challengeRuleNotes.mu.RUnlock()
	if n > challengeV2MarkMaxKeys {
		t.Fatalf("store grew past the cap: %d", n)
	}
	if !warned {
		t.Fatalf("saturation must be logged once, like the mark store")
	}
}

// Under cap pressure the note store sweeps at most once per sweepEvery: a
// store full of LIVE notes frees nothing on a sweep, so a per-new-pair O(n)
// pass under the write lock would only stall the decision path.
func TestRuleChallengeNoteSweepIsThrottled(t *testing.T) {
	resetChallengeRuleNotes(t)
	now := time.Now()
	challengeRuleNotes.mu.Lock()
	for i := 0; i < challengeV2MarkMaxKeys; i++ {
		k := time.Duration(i).String() + "|h"
		challengeRuleNotes.m[k] = now.Add(-time.Second) // all expired
		challengeRuleNotes.vals[k] = "x"
	}
	challengeRuleNotes.lastSweep = now // a sweep "just ran"
	challengeRuleNotes.mu.Unlock()

	challengeRuleNotes.put("a|h", "r", now)
	if _, ok := challengeRuleNotes.get("a|h", now); ok {
		t.Fatalf("within sweepEvery the newcomer must be dropped without a sweep")
	}
	challengeRuleNotes.put("a|h", "r", now.Add(2*time.Second))
	if id, ok := challengeRuleNotes.get("a|h", now.Add(2*time.Second)); !ok || id != "r" {
		t.Fatalf("after sweepEvery the sweep must free the expired entries: %q %v", id, ok)
	}
	challengeRuleNotes.mu.RLock()
	n, nv := len(challengeRuleNotes.m), len(challengeRuleNotes.vals)
	challengeRuleNotes.mu.RUnlock()
	if n != 1 || nv != 1 {
		t.Fatalf("sweep must clear both maps: m=%d vals=%d", n, nv)
	}
}

// A same-rule refresh with most of its TTL left is skipped (RLock only); a
// DIFFERENT rule, or a note near expiry, is written.
func TestRuleChallengeNoteRefreshSkip(t *testing.T) {
	resetChallengeRuleNotes(t)
	now := time.Now()
	challengeRuleNotes.put("b|h", "r1", now)
	exp1 := challengeRuleNotes.m["b|h"]
	challengeRuleNotes.put("b|h", "r1", now.Add(10*time.Second))
	if !challengeRuleNotes.m["b|h"].Equal(exp1) {
		t.Fatalf("a fresh same-rule note must not be rewritten")
	}
	challengeRuleNotes.put("b|h", "r2", now.Add(10*time.Second))
	if id, _ := challengeRuleNotes.get("b|h", now.Add(11*time.Second)); id != "r2" {
		t.Fatalf("a different rule must replace the note, got %q", id)
	}
	later := now.Add(challengeV2MarkTTL - 30*time.Second)
	challengeRuleNotes.put("b|h", "r2", later)
	if !challengeRuleNotes.m["b|h"].After(later.Add(challengeV2MarkTTL - time.Second)) {
		t.Fatalf("a note near expiry must be refreshed")
	}
}

func TestChallengeIPWithReasonRecordsReason(t *testing.T) {
	b := NewNginxBridge("/tmp/cfm-test-src-reason.sock", "tok", time.Minute, time.Minute)
	b.ChallengeIPWithReason("203.0.113.70", time.Minute, " CHALLENGE_ERR_RATIO ")
	if got := b.GetReason("203.0.113.70"); got != "CHALLENGE_ERR_RATIO" {
		t.Fatalf("reason: %q", got)
	}
	b.ChallengeIP("203.0.113.71", time.Minute)
	if got := b.GetReason("203.0.113.71"); got != "" {
		t.Fatalf("plain ChallengeIP must stay reason-less, got %q", got)
	}
	// A reason-less refresh of an active challenge keeps the reason it has
	// (the section sink re-challenging an IP the webdetector just challenged).
	b.ChallengeIP("203.0.113.70", time.Minute)
	if got := b.GetReason("203.0.113.70"); got != "CHALLENGE_ERR_RATIO" {
		t.Fatalf("reason-less refresh erased the reason: %q", got)
	}
	// A new reason replaces it.
	b.ChallengeIPWithReason("203.0.113.70", time.Minute, "web_404_flood")
	if got := b.GetReason("203.0.113.70"); got != "web_404_flood" {
		t.Fatalf("new reason: %q", got)
	}
}

// payload.src carries operator fleet policy (fp / geo coverage, traffic-rule
// ids): it must not cross the scoped boundary, while admin keeps it.
func TestHistoryEventsRedactsSrcForScopedCallers(t *testing.T) {
	row := func() []HistoryEvent {
		return []HistoryEvent{{
			Type: "challenge_solved", Host: "shop.example.com", IP: "203.0.113.31",
			Payload: map[string]interface{}{"src": "vhost:suspicious_vhost,fp", "hs": 0},
		}}
	}
	scoped := row()
	redactScopedHistoryRows(httptest.NewRequest(http.MethodGet, "/x", nil).WithContext(scopedCtx("shop.example.com")), scoped)
	if _, present := scoped[0].Payload["src"]; present {
		t.Errorf("src must not cross the scoped boundary")
	}
	if _, present := scoped[0].Payload["hs"]; !present {
		t.Errorf("scoped caller lost hs")
	}
	admin := row()
	redactScopedHistoryRows(httptest.NewRequest(http.MethodGet, "/x", nil).WithContext(adminCtx()), admin)
	if admin[0].Payload["src"] != "vhost:suspicious_vhost,fp" {
		t.Errorf("admin must still receive src")
	}
}

// End to end through the real verify handler: the provenance snapshot must be
// taken BEFORE the solve releases the per-IP entry it reads (releaseSolvedIP →
// ClearIP), or every per-IP source would read as src=-.
func TestVerify_SolveCarriesProvenanceBeforeRelease(t *testing.T) {
	resetFPPolicies(t)
	resetChallengeRuleNotes(t)
	const (
		ip   = "203.0.113.90"
		host = "shop.example.com"
		ua   = "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/131.0.0.0 Safari/537.36"
	)
	// ENABLED (so the solve's ClearIP really deletes the per-IP entry) but
	// pointed at a socket that does not exist: the edge notifications fail
	// silently, the in-process state behaves exactly as in production.
	b := NewNginxBridge(t.TempDir()+"/no-edge.sock", "tok", time.Minute, time.Minute)
	b.ipState[ip] = bridgeIPEntry{Action: "challenge", Expires: time.Now().Add(time.Hour), Reason: "CHALLENGE_ERR_RATIO"}
	b.vhState[host] = bridgeVhostEntry{Action: "challenge", Expires: time.Now().Add(time.Hour), Reason: "suspicious_vhost"}
	base, capt := startVerifyServerWithBridge(t, b)

	// Unarmed + failing: shadow only, so it takes the solved path.
	resp := postVerify(t, base, ip, host, ua, `{"v":1,"wd":true,"ptr":0,"tch":0,"key":0}`)
	if resp.StatusCode == http.StatusForbidden {
		t.Fatalf("an unarmed solve was refused")
	}
	solved, _ := capt.counts()
	if solved != 1 {
		t.Fatalf("solved=%d, want 1", solved)
	}
	s := capt.solved[0]
	if got := s.SrcValue(); got != "ip:CHALLENGE_ERR_RATIO,vhost:suspicious_vhost" {
		t.Fatalf("src=%q — the snapshot must run before the per-IP entry is released", got)
	}
	if s.V2Grain != "" {
		t.Fatalf("provenance must never arm: grain=%q", s.V2Grain)
	}
	// And the release really happened after it (the snapshot did not just
	// read a bridge that never clears).
	if action, _ := b.GetIPDecision(ip); action != "" {
		t.Fatalf("per-IP entry still active after the solve: %q", action)
	}
}

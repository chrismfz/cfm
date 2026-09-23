package webdetector

import (
	"encoding/json"
	"fmt"
	"net/http/httptest"
	"net/url"
	"strings"
	"testing"
	"time"

	"cfm/internal/enrich/mmdbtest"
	"cfm/internal/tlsfp"
)

const fpTestTuple = "1|TLSv1.3|TLS_AES_128_GCM_SHA256:TLS_AES_256_GCM_SHA384:TLS_CHACHA20_POLY1305_SHA256:ECDHE-ECDSA-AES128-GCM-SHA256:ECDHE-RSA-AES128-GCM-SHA256|X25519:prime256v1:secp384r1|h2|HTTP/2.0|"

// resetFPPolicies restores the package-level store so tests don't leak into
// each other (the store is deliberately package-level, like the solverfarm
// marks).
func resetFPPolicies(t *testing.T) {
	t.Helper()
	t.Cleanup(func() {
		SetFingerprintPolicies(nil)
		ConfigureFingerprintPolicyEnforcement(true, nil)
	})
	SetFingerprintPolicies(nil)
	ConfigureFingerprintPolicyEnforcement(true, nil)
}

func fpTestID(t *testing.T) string {
	t.Helper()
	fp, ok := tlsfp.Parse(fpTestTuple)
	if !ok || fp.ID == "" {
		t.Fatalf("test tuple did not parse")
	}
	return fp.ID
}

func TestFingerprintPolicyStore(t *testing.T) {
	resetFPPolicies(t)
	id := fpTestID(t)

	// Nothing armed.
	if got := FingerprintPolicyForID(id); got != "" {
		t.Fatalf("empty store returned %q", got)
	}

	SetFingerprintPolicies([]FingerprintPolicy{
		{ID: id, Action: "deny"},
		{ID: "AABBCCDD", Action: "challenge"},                                       // stored lowercased
		{ID: "11223344", Action: "observe"},                                         // unknown action → dropped
		{ID: "55667788", Action: "challenge_v2", ExpiresAt: time.Now().Add(-time.Hour)}, // expired
	})

	if got := FingerprintPolicyForID(id); got != "deny" {
		t.Fatalf("deny policy: got %q", got)
	}
	if got := FingerprintPolicyForID("aabbccdd"); got != "challenge" {
		t.Fatalf("case-insensitive lookup: got %q", got)
	}
	if got := FingerprintPolicyForID("11223344"); got != "" {
		t.Fatalf("unknown action must be dropped at set time, got %q", got)
	}
	if got := FingerprintPolicyForID("55667788"); got != "" {
		t.Fatalf("expired policy must not bite, got %q", got)
	}

	// Operator escape hatch.
	ConfigureFingerprintPolicyEnforcement(true, []string{" " + id + " "})
	if got := FingerprintPolicyForID(id); got != "" {
		t.Fatalf("ALLOW_FPS-exempt id must not be enforced, got %q", got)
	}

	// Master kill switch.
	ConfigureFingerprintPolicyEnforcement(false, nil)
	if got := FingerprintPolicyForID("aabbccdd"); got != "" {
		t.Fatalf("FP_POLICY=0 must disarm every lookup, got %q", got)
	}

	// Replace-all semantics: a disarmed policy vanishes on the next snapshot.
	ConfigureFingerprintPolicyEnforcement(true, nil)
	SetFingerprintPolicies([]FingerprintPolicy{{ID: "aabbccdd", Action: "challenge_v2"}})
	if got := FingerprintPolicyForID(id); got != "" {
		t.Fatalf("policy missing from the new snapshot must stop, got %q", got)
	}
	if got := FingerprintPolicyForID("aabbccdd"); got != "challenge_v2" {
		t.Fatalf("challenge_v2 lookup: got %q", got)
	}
}

func TestHandleFpPolicy(t *testing.T) {
	resetFPPolicies(t)
	id := fpTestID(t)
	SetFingerprintPolicies([]FingerprintPolicy{{ID: id, Action: "deny"}})

	b := NewNginxBridge("/tmp/fppolicy-test.sock", "tok", time.Minute, time.Minute)

	call := func(token, fp string) (int, map[string]any) {
		req := httptest.NewRequest("GET", "/nginx/fppolicy?fp="+url.QueryEscape(fp), nil)
		if token != "" {
			req.Header.Set("X-CFM-Token", token)
		}
		rec := httptest.NewRecorder()
		b.handleFpPolicy(rec, req)
		var out map[string]any
		_ = json.Unmarshal(rec.Body.Bytes(), &out)
		return rec.Code, out
	}

	if code, _ := call("", fpTestTuple); code != 403 {
		t.Fatalf("missing token: code=%d, want 403", code)
	}
	if code, _ := call("wrong", fpTestTuple); code != 403 {
		t.Fatalf("wrong token: code=%d, want 403", code)
	}

	code, out := call("tok", fpTestTuple)
	if code != 200 || out["action"] != "deny" || out["id"] != id {
		t.Fatalf("armed lookup: code=%d out=%v", code, out)
	}
	if ttl, _ := out["ttl"].(float64); ttl <= 0 {
		t.Fatalf("ttl missing: %v", out)
	}

	// No / unparseable fingerprint → empty action, still 200 (fail-open).
	if code, out := call("tok", ""); code != 200 || out["action"] != "" {
		t.Fatalf("empty fp: code=%d out=%v", code, out)
	}
	if code, out := call("tok", "garbage"); code != 200 || out["action"] != "" {
		t.Fatalf("garbage fp: code=%d out=%v", code, out)
	}
}

// ── Geo kinds (policy-kinds slice): country/ASN challenge floors ─────────────

func TestGeoPolicyStoreAndLookup(t *testing.T) {
	resetFPPolicies(t)
	t.Cleanup(func() { SetFingerprintPolicyGeoResolver(nil) })

	asnCalls := 0
	asnFn := func() uint64 { asnCalls++; return 6799 }

	// Empty store: no lookup work at all (asnFn never consulted).
	if got := GeoPolicyAction("GR", asnFn); got != "" || asnCalls != 0 {
		t.Fatalf("empty store: got %q asnCalls=%d", got, asnCalls)
	}

	SetFingerprintPolicies([]FingerprintPolicy{
		{ID: "gr", Kind: "country", Action: "challenge_v2"},
		{ID: "6799", Kind: "asn", Action: "challenge"},
		{ID: "US", Kind: "country", Action: "deny"},         // geo deny → dropped (doctrine)
		{ID: "DE", Kind: "country", Action: "challenge", ExpiresAt: time.Now().Add(-time.Minute)}, // expired
		{ID: "notanasn", Kind: "asn", Action: "challenge"},  // unparseable → dropped
		{ID: "FR", Kind: "wat", Action: "challenge"},        // unknown kind → dropped
	})

	// Country match (case-insensitive), before any ASN work.
	asnCalls = 0
	if got := GeoPolicyAction("gr", asnFn); got != "challenge_v2" {
		t.Fatalf("country lookup got %q", got)
	}
	if asnCalls != 0 {
		t.Fatalf("asnFn consulted despite country hit")
	}

	// Country miss → ASN match.
	if got := GeoPolicyAction("IT", asnFn); got != "challenge" {
		t.Fatalf("asn lookup got %q", got)
	}

	// Geo deny was dropped, expired country answers nothing.
	if got := GeoPolicyAction("US", func() uint64 { return 0 }); got != "" {
		t.Fatalf("geo deny must never be enforceable, got %q", got)
	}
	if got := GeoPolicyAction("DE", func() uint64 { return 0 }); got != "" {
		t.Fatalf("expired country policy answered %q", got)
	}

	// FP_POLICY master knob gates geo kinds too.
	ConfigureFingerprintPolicyEnforcement(false, nil)
	if got := GeoPolicyAction("GR", asnFn); got != "" {
		t.Fatalf("disabled enforcement still answered %q", got)
	}
	ConfigureFingerprintPolicyEnforcement(true, nil)

	// Verify-side helper: resolver-driven; nil resolver fails open.
	if got := GeoPolicyActionForIP("203.0.113.9"); got != "" {
		t.Fatalf("nil resolver must fail open, got %q", got)
	}
	SetFingerprintPolicyGeoResolver(func(ip string) (string, uint64) { return "", 6799 })
	if got := GeoPolicyActionForIP("203.0.113.9"); got != "challenge" {
		t.Fatalf("resolver-driven asn lookup got %q", got)
	}
	SetFingerprintPolicyGeoResolver(func(ip string) (string, uint64) { return "GR", 0 })
	if got := GeoPolicyActionForIP("203.0.113.9"); got != "challenge_v2" {
		t.Fatalf("resolver-driven country lookup got %q", got)
	}
}

// The detectors factory rebuilds the engine on every reload, and NewEngine is
// what wires the verify-side geo resolver. An engine built WITHOUT an enricher
// (ENRICH = 0; enrich.New itself never fails) must clear it: it used to be set
// only when an enricher existed, so the previous engine's resolver stayed
// wired — an armed country/ASN challenge_v2 kept biting at verify through an
// enricher the current config no longer has, and kept that enricher alive.
func TestNewEngineRewiresTheGeoResolverOnEveryBuild(t *testing.T) {
	resetFPPolicies(t)
	// NewEngine also rewires the other verify-path globals; put all three
	// back so a later test never inherits this one's engine or its real,
	// PTR-resolving enricher.
	prevSolve := challengeSolveEnricher.Load()
	challengeV2.mu.RLock()
	prevHostArmed := challengeV2.hostArmed
	challengeV2.mu.RUnlock()
	t.Cleanup(func() {
		SetFingerprintPolicyGeoResolver(nil)
		challengeSolveEnricher.Store(prevSolve)
		SetChallengeV2HostArmed(prevHostArmed)
	})
	SetFingerprintPolicies([]FingerprintPolicy{{ID: "GR", Kind: "country", Action: "challenge_v2"}})

	// The previous engine's resolver.
	SetFingerprintPolicyGeoResolver(func(string) (string, uint64) { return "GR", 0 })
	if got := GeoPolicyActionForIP("203.0.113.9"); got != "challenge_v2" {
		t.Fatalf("precondition: the armed GR policy should bite via the wired resolver, got %q", got)
	}

	_ = NewEngine(Config{Every: time.Second, Window: time.Minute}) // UseEnrich unset
	if got := GeoPolicyActionForIP("203.0.113.9"); got != "" {
		t.Fatalf("an engine built without an enricher left the previous resolver enforcing %q", got)
	}

	// And an engine WITH an enricher wires its own (no mmdb in the dir: the
	// enricher still builds, it just resolves no geo).
	_ = NewEngine(Config{Every: time.Second, Window: time.Minute, UseEnrich: true, EnrichDirs: []string{t.TempDir()}})
	fpPolicies.mu.RLock()
	wired := fpPolicies.geoResolver != nil
	fpPolicies.mu.RUnlock()
	if !wired {
		t.Fatal("an engine built with an enricher did not wire the geo resolver")
	}
}

// captureGeoWarnings isolates the store's geo-warning state and captures what
// it logs. Restores everything it touches.
func captureGeoWarnings(t *testing.T) *[]string {
	t.Helper()
	resetFPPolicies(t)
	fpPolicies.mu.Lock()
	prevResolver, prevSources := fpPolicies.geoResolver, fpPolicies.geoSources
	prevKnown, prevWarn := fpPolicies.resolverKnown, fpPolicies.geoWarn
	fpPolicies.geoResolver, fpPolicies.geoSources = nil, nil
	fpPolicies.resolverKnown, fpPolicies.geoWarn = false, ""
	fpPolicies.mu.Unlock()
	prevLogf := fpPolicyLogf
	lines := &[]string{}
	fpPolicyLogf = func(format string, args ...interface{}) { *lines = append(*lines, fmt.Sprintf(format, args...)) }
	t.Cleanup(func() {
		fpPolicyLogf = prevLogf
		fpPolicies.mu.Lock()
		fpPolicies.geoResolver, fpPolicies.geoSources = prevResolver, prevSources
		fpPolicies.resolverKnown, fpPolicies.geoWarn = prevKnown, prevWarn
		fpPolicies.mu.Unlock()
	})
	return lines
}

// expectLines asserts the lines logged since the last call, one substring per
// line, and resets the capture.
func expectLines(t *testing.T, lines *[]string, name string, want ...string) {
	t.Helper()
	got := *lines
	*lines = nil
	if len(got) != len(want) {
		t.Fatalf("%s: logged %d lines %q, want %d", name, len(got), got, len(want))
	}
	for i, w := range want {
		if !strings.Contains(got[i], w) {
			t.Fatalf("%s: line %q does not contain %q", name, got[i], w)
		}
	}
}

var geoWarnTestPolicies = []FingerprintPolicy{
	{ID: "GR", Kind: "country", Action: "challenge_v2"},
	{ID: "CN", Kind: "country", Action: "challenge"}, // works from edge country: not counted
	{ID: "6799", Kind: "asn", Action: "challenge"},
	{ID: "3329", Kind: "asn", Action: "challenge_v2"},
	{ID: "1241", Kind: "asn", Action: "challenge", ExpiresAt: time.Now().Add(-time.Minute)}, // expired: not counted
	{ID: "aabbccdd", Action: "deny"}, // tls: unaffected by enrichment
}

func noopResolver(string) (string, uint64) { return "", 0 }

// With enrichment off (ENRICH = 0) an armed ASN policy can never match and a
// country challenge_v2 policy acts as plain challenge — the designed
// fail-open, but silent. The store says so in the log, once per change: the
// policy pull runs every 60s and must not repeat it every minute. A cleared
// warning says WHY it cleared, so it is never a false "all good".
func TestGeoDegradationIsWarnedOncePerChange(t *testing.T) {
	lines := captureGeoWarnings(t)
	armed := geoWarnTestPolicies

	SetFingerprintPolicies(armed)
	expectLines(t, lines, "pull before any engine build") // a nil resolver means "not built yet"

	SetFingerprintPolicyGeo(nil, nil) // engine built with ENRICH = 0
	expectLines(t, lines, "engine without enrichment",
		"WARNING: web-detector enrichment is off ([webdetector] ENRICH = 0): 2 armed ASN policies cannot match")
	fpPolicies.mu.RLock()
	warn := fpPolicies.geoWarn
	fpPolicies.mu.RUnlock()
	if !strings.Contains(warn, "1 armed country challenge_v2 policy acts as plain challenge") ||
		!strings.Contains(warn, "Set ENRICH = 1 in [webdetector]") {
		t.Fatalf("warning misses the country challenge_v2 count or the remedy: %q", warn)
	}

	SetFingerprintPolicies(armed)
	expectLines(t, lines, "next pull, same set") // no repeat every 60s

	SetFingerprintPolicies(armed[:2])
	expectLines(t, lines, "ASN policies disarmed",
		"WARNING: web-detector enrichment is off ([webdetector] ENRICH = 0): 1 armed country challenge_v2 policy acts")

	ConfigureFingerprintPolicyEnforcement(false, nil)
	expectLines(t, lines, "FP_POLICY = 0", "no longer degraded (FP_POLICY = 0: no policy is enforced)")
	ConfigureFingerprintPolicyEnforcement(true, nil)
	expectLines(t, lines, "FP_POLICY back on", "WARNING:")

	SetFingerprintPolicyGeo(noopResolver, func() (bool, bool) { return true, true }) // ENRICH = 1, both databases
	expectLines(t, lines, "enrichment back", "no longer degraded (the geo lookups they need are available again)")

	SetFingerprintPolicyGeo(nil, nil)
	expectLines(t, lines, "ENRICH = 0 again", "WARNING:")
	SetFingerprintPolicies([]FingerprintPolicy{
		{ID: "CN", Kind: "country", Action: "challenge"},
		{ID: "aabbccdd", Action: "challenge_v2"},
	})
	expectLines(t, lines, "only country-challenge and tls armed",
		"no longer degraded (the degraded policies were disarmed or expired)")
}

// Enrichment ON is the default, and enrich.New never fails: with no GeoLite2
// download yet it just answers no ASN / no country. That is the likelier
// degraded node, and it must be warned too — naming the missing database —
// not reported as fine.
func TestGeoDegradationNamesTheMissingDatabase(t *testing.T) {
	lines := captureGeoWarnings(t)
	SetFingerprintPolicies(geoWarnTestPolicies)
	hasASN, hasCountry := false, false
	SetFingerprintPolicyGeo(noopResolver, func() (bool, bool) { return hasASN, hasCountry })
	expectLines(t, lines, "no database",
		"WARNING: no GeoLite2 database is loaded (GeoLite2-ASN.mmdb, GeoLite2-City.mmdb): 2 armed ASN policies cannot match")

	hasCountry = true // City arrives; the pull re-evaluates
	SetFingerprintPolicies(geoWarnTestPolicies)
	expectLines(t, lines, "ASN still missing",
		"WARNING: the GeoLite2-ASN database is not loaded: 2 armed ASN policies cannot match")
	fpPolicies.mu.RLock()
	warn := fpPolicies.geoWarn
	fpPolicies.mu.RUnlock()
	if strings.Contains(warn, "challenge_v2 polic") || !strings.Contains(warn, "Install the missing database") {
		t.Fatalf("with the City database loaded, country v2 policies are not degraded: %q", warn)
	}

	hasASN, hasCountry = true, false
	SetFingerprintPolicies(geoWarnTestPolicies)
	expectLines(t, lines, "City missing",
		"WARNING: the GeoLite2-City database is not loaded: 1 armed country challenge_v2 policy acts as plain challenge")

	hasCountry = true
	SetFingerprintPolicies(geoWarnTestPolicies)
	expectLines(t, lines, "both loaded", "no longer degraded (the geo lookups they need are available again)")

	// A resolver whose databases are not reported is assumed complete.
	SetFingerprintPolicyGeoResolver(noopResolver)
	expectLines(t, lines, "sources unknown")
}

// End to end through NewEngine: ENRICH on (the default) with no GeoLite2 files
// is warned, not silently accepted.
func TestNewEngineWithoutGeoLiteDatabasesWarns(t *testing.T) {
	lines := captureGeoWarnings(t)
	prevSolve := challengeSolveEnricher.Load()
	challengeV2.mu.RLock()
	prevHostArmed := challengeV2.hostArmed
	challengeV2.mu.RUnlock()
	t.Cleanup(func() {
		challengeSolveEnricher.Store(prevSolve)
		SetChallengeV2HostArmed(prevHostArmed)
	})
	SetFingerprintPolicies([]FingerprintPolicy{{ID: "6799", Kind: "asn", Action: "challenge"}})
	_ = NewEngine(Config{Every: time.Second, Window: time.Minute, UseEnrich: true, EnrichDirs: []string{t.TempDir()}})
	expectLines(t, lines, "enricher with an empty database dir",
		"WARNING: no GeoLite2 database is loaded (GeoLite2-ASN.mmdb, GeoLite2-City.mmdb): 1 armed ASN policy cannot match")
}

// The verify-side geo gate reads the node's database LIVE — the same source as
// the solve line's cc=/asn= — not through the enricher's cache. A cache HIT
// survives an mmdb update (up to 24h) and holds an empty record when cached
// before the mmdb loaded, so the gate acted on the old answer: here, a client
// the updated database moved from GR to DE stayed un-armed under a DE policy.
func TestVerifyGeoGateReadsTheDatabaseLive(t *testing.T) {
	captureGeoWarnings(t) // isolates the resolver + policy state
	prevSolve := challengeSolveEnricher.Load()
	challengeV2.mu.RLock()
	prevHostArmed := challengeV2.hostArmed
	challengeV2.mu.RUnlock()
	t.Cleanup(func() {
		challengeSolveEnricher.Store(prevSolve)
		SetChallengeV2HostArmed(prevHostArmed)
	})

	const ip = "10.20.30.40" // non-routable: the enricher does no reverse DNS
	base := time.Now().Add(-time.Hour)
	dir := t.TempDir()
	install := func(iso, country string, mt time.Time) {
		mmdbtest.Write(t, dir, "GeoLite2-City.mmdb",
			mmdbtest.Build("GeoLite2-City", mmdbtest.CityRecord(iso, country, "")), mt)
	}

	install("GR", "Greece", base)
	e := NewEngine(Config{Every: time.Second, Window: time.Minute, UseEnrich: true, EnrichDirs: []string{dir}})
	if e.enr == nil {
		t.Fatal("engine built without its enricher")
	}
	t.Cleanup(e.enr.Close)
	if got := e.enr.Lookup(ip).CountryISO; got != "GR" { // warms the 24h cache
		t.Fatalf("setup: Lookup = %q, want GR", got)
	}
	SetFingerprintPolicies([]FingerprintPolicy{{ID: "DE", Kind: "country", Action: "challenge_v2"}})
	if got := GeoPolicyActionForIP(ip); got != "" {
		t.Fatalf("a GR client under a DE policy = %q, want none", got)
	}

	// The database is updated: the address is German now.
	install("DE", "Germany", base.Add(time.Minute))
	e.enr.RefreshNow()
	if got := e.enr.LookupCachedOrAsync(ip).CountryISO; got != "GR" {
		t.Fatalf("setup: the cache should still hold the old answer, got %q", got)
	}
	if got := GeoPolicyActionForIP(ip); got != "challenge_v2" {
		t.Fatalf("after the update the gate = %q, want challenge_v2 (it must read the live database, not the cached GR)", got)
	}
}

func TestGeoPoliciesDoNotLeakIntoFingerprintLookup(t *testing.T) {
	resetFPPolicies(t)
	SetFingerprintPolicies([]FingerprintPolicy{
		{ID: "gr", Kind: "country", Action: "challenge"},
	})
	// A country target must never answer a fingerprint-id lookup (separate maps).
	if got := FingerprintPolicyForID("gr"); got != "" {
		t.Fatalf("country policy leaked into fp lookup: %q", got)
	}
}

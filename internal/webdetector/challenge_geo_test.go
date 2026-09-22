package webdetector

import (
	"context"
	"crypto/rand"
	"fmt"
	"net/http"
	"net/http/httptest"
	"strconv"
	"strings"
	"sync"
	"testing"
	"time"

	"cfm/internal/enrich"
)

func TestGeoSuffix(t *testing.T) {
	cases := []struct {
		name string
		s    ChallengeSolve
		want string
	}{
		{"fully resolved",
			ChallengeSolve{CountryISO: "GR", ASN: 6799, ASNName: "OTEnet S.A.", PTR: "ppp-1-2.otenet.gr"},
			` cc=GR asn=6799 asn_name="OTEnet S.A." ptr=ppp-1-2.otenet.gr`},
		// A cold cache: country/ASN come from the mmdb inline, PTR is deferred.
		{"cache miss has no ptr",
			ChallengeSolve{CountryISO: "US", ASN: 14618, ASNName: "Amazon.com, Inc."},
			` cc=US asn=14618 asn_name="Amazon.com, Inc."`},
		// Unresolved is ABSENT, never a zero that reads as an answer.
		{"nothing resolved", ChallengeSolve{}, ""},
	}
	for _, c := range cases {
		if got := c.s.GeoSuffix(); got != c.want {
			t.Errorf("%s: GeoSuffix() = %q, want %q", c.name, got, c.want)
		}
	}
}

// A PTR is chosen by whoever controls the address's reverse zone and can be
// read back off disk from the persistent store: it must never be able to add a
// field or a line to a key=value log line.
func TestGeoSuffixQuotesAHostilePTR(t *testing.T) {
	hostile := "evil host\" asn=1\nfake=2"
	got := ChallengeSolve{PTR: hostile}.GeoSuffix()
	if strings.ContainsAny(got, "\n\r") {
		t.Fatalf("a PTR smuggled a line break into the log line: %q", got)
	}
	if want := " ptr=" + strconv.Quote(hostile); got != want {
		t.Fatalf("GeoSuffix() = %q, want %q", got, want)
	}
	if n := strings.Count(got, "asn="); n != 1 {
		// Exactly one, and it is inside the quoted value, not a new field.
		t.Fatalf("hostile PTR produced %d asn= occurrences", n)
	}
}

func TestLogToken(t *testing.T) {
	for _, plain := range []string{"GR", "ppp-1-2.otenet.gr", "2a02:587::1", "a_b"} {
		if got := logToken(plain); got != plain {
			t.Errorf("logToken(%q) = %q, want it bare", plain, got)
		}
	}
	for _, odd := range []string{"a b", `a"b`, "a\nb", "a=b", ""} {
		if odd == "" {
			continue // empty never reaches logToken: GeoSuffix omits the key
		}
		if got := logToken(odd); got != strconv.Quote(odd) {
			t.Errorf("logToken(%q) = %q, want it quoted", odd, got)
		}
	}
}

// oldHookTail is the solved hook's former rendering, copied verbatim from
// before it was moved onto ChallengeSolve. LegacyGeoTail must match it byte
// for byte — that is the only reason the tail is kept at all.
func oldHookTail(asn uint, asnName, country string) string {
	parts := []string{}
	if asn > 0 {
		if asnName != "" {
			parts = append(parts, fmt.Sprintf("AS%d %s", asn, asnName))
		} else {
			parts = append(parts, fmt.Sprintf("AS%d", asn))
		}
	}
	if country != "" {
		parts = append(parts, country)
	}
	if len(parts) > 0 {
		return " - (" + strings.Join(parts, ", ") + ")"
	}
	return ""
}

func TestLegacyGeoTailMatchesTheOldHookByteForByte(t *testing.T) {
	cases := []struct {
		asn              uint
		asnName, country string
	}{
		{6799, "OTEnet S.A.", "Greece"},
		{6799, "", "Greece"},
		{0, "", "Greece"},
		{6799, "OTEnet S.A.", ""},
		{0, "orphan name, no number", "Greece"}, // name without a number is dropped, as before
		{0, "", ""},
	}
	for _, c := range cases {
		s := ChallengeSolve{ASN: c.asn, ASNName: c.asnName, Country: c.country}
		if got, want := s.LegacyGeoTail(), oldHookTail(c.asn, c.asnName, c.country); got != want {
			t.Errorf("LegacyGeoTail(%d, %q, %q) = %q, old hook rendered %q", c.asn, c.asnName, c.country, got, want)
		}
	}
}

func setSolveEnricher(t *testing.T, fn func(ip string) enrich.Result) {
	t.Helper()
	prev := challengeSolveEnricher.Load()
	SetChallengeSolveEnricher(fn)
	t.Cleanup(func() { challengeSolveEnricher.Store(prev) })
}

func TestResolveGeo(t *testing.T) {
	var calls []string
	setSolveEnricher(t, func(ip string) enrich.Result {
		calls = append(calls, ip)
		return enrich.Result{Country: "Greece", CountryISO: "GR", ASN: 6799, ASNName: "OTEnet S.A.", PTR: "ppp.otenet.gr"}
	})

	s := ChallengeSolve{IP: "203.0.113.9"}
	s.resolveGeo()
	if s.Country != "Greece" || s.CountryISO != "GR" || s.ASN != 6799 || s.ASNName != "OTEnet S.A." || s.PTR != "ppp.otenet.gr" {
		t.Fatalf("resolveGeo did not copy the enrichment: %+v", s)
	}

	var noIP ChallengeSolve
	noIP.resolveGeo()
	if len(calls) != 1 {
		t.Fatalf("an empty IP must not be looked up; calls=%v", calls)
	}

	SetChallengeSolveEnricher(nil)
	var unwired ChallengeSolve
	unwired.IP = "203.0.113.9"
	unwired.resolveGeo()
	if unwired.GeoSuffix() != "" {
		t.Fatalf("an unwired enricher must leave every geo field empty, got %q", unwired.GeoSuffix())
	}
}

// The detectors factory rebuilds the engine on every reload. A rebuild with
// enrichment OFF must clear the resolver, or the previous engine's enricher
// keeps stamping geo onto every solve after the operator turned it off.
func TestNewEngineWithoutEnrichClearsTheSolveEnricher(t *testing.T) {
	setSolveEnricher(t, func(string) enrich.Result { return enrich.Result{PTR: "stale.example"} })
	_ = NewEngine(Config{Every: time.Second, Window: time.Minute}) // UseEnrich unset
	if challengeSolveEnricher.Load() != nil {
		t.Fatal("an engine built without an enricher left the previous one wired")
	}
}

func TestRecordChallengeSolved_PersistsGeoOnlyWhenResolved(t *testing.T) {
	e := newSolveTestEngine(t)
	e.RecordChallengeSolved(ChallengeSolve{
		IP: "203.0.113.9", Host: "shop.example.com", URI: "/",
		Country: "Greece", CountryISO: "GR", ASN: 6799, ASNName: "OTEnet S.A.", PTR: "ppp.otenet.gr",
	})
	p := latestSolveEvent(t, e).Payload
	for k, want := range map[string]interface{}{
		"country": "Greece", "country_iso": "GR", "asn": float64(6799), "asn_name": "OTEnet S.A.", "ptr": "ppp.otenet.gr",
	} {
		if p[k] != want {
			t.Errorf("payload[%q] = %#v, want %#v", k, p[k], want)
		}
	}

	e2 := newSolveTestEngine(t)
	e2.RecordChallengeSolved(ChallengeSolve{IP: "203.0.113.9", Host: "shop.example.com", URI: "/"})
	p2 := latestSolveEvent(t, e2).Payload
	for _, k := range []string{"country", "country_iso", "asn", "asn_name", "ptr"} {
		if v, present := p2[k]; present {
			// "asn": 0 especially would read as a resolved answer.
			t.Errorf("unresolved %q must be absent, got %#v", k, v)
		}
	}
}

// A reject gets its own row type, never challenge_solved (it cleared nothing),
// and the SAME payload builder, so rejected and passing solves compare
// field for field.
func TestRecordChallengeV2Reject(t *testing.T) {
	s := ChallengeSolve{
		IP: "203.0.113.9", Host: "shop.example.com", URI: "/cart", Diff: 16, UA: "Mozilla/5.0",
		TLSFP: "c28caa00", HumanityScored: true, HumanityScore: 130, HumanityTells: "webdriver,no_input",
		V2Grain: "mark", CountryISO: "GR", ASN: 6799, PTR: "ppp.otenet.gr",
	}

	rej := newSolveTestEngine(t)
	rej.RecordChallengeV2Reject(s)
	rows, err := rej.history.QueryEvents("", "", "challenge_v2_reject", 10)
	if err != nil || len(rows) != 1 {
		t.Fatalf("want exactly one challenge_v2_reject row, got %d (err %v)", len(rows), err)
	}
	if solved, _ := rej.history.QueryEvents("", "", "challenge_solved", 10); len(solved) != 0 {
		t.Fatalf("a reject must not write a challenge_solved row, got %d", len(solved))
	}
	if rows[0].IP != s.IP || rows[0].Host != s.Host {
		t.Fatalf("row keyed wrong: ip=%q host=%q", rows[0].IP, rows[0].Host)
	}

	sol := newSolveTestEngine(t)
	sol.RecordChallengeSolved(s)
	want := latestSolveEvent(t, sol).Payload
	got := rows[0].Payload
	if fmt.Sprint(got) != fmt.Sprint(want) {
		t.Fatalf("reject and solved payloads diverged:\nreject: %v\nsolved: %v", got, want)
	}
	for _, k := range []string{"hs", "tells", "v2", "tls_fp", "ua", "ptr", "country_iso", "asn"} {
		if _, present := got[k]; !present {
			t.Errorf("reject row is missing %q — it would not be judgeable without the log", k)
		}
	}
}

func TestHistoryEventsRedactsPTRForScopedCallers(t *testing.T) {
	row := func() []HistoryEvent {
		return []HistoryEvent{{
			Type: "challenge_v2_reject", Host: "shop.example.com", IP: "203.0.113.30",
			Payload: map[string]interface{}{
				"ptr": "ppp.otenet.gr", "country": "Greece", "country_iso": "GR",
				"asn": 6799, "asn_name": "OTEnet S.A.", "hs": 130,
			},
		}}
	}

	scoped := row()
	redactScopedHistoryRows(httptest.NewRequest(http.MethodGet, "/x", nil).WithContext(scopedCtx("shop.example.com")), scoped)
	if _, present := scoped[0].Payload["ptr"]; present {
		t.Errorf("ptr must not cross the scoped boundary")
	}
	// enrich=1 already hands country/ASN to scoped callers: not a new category.
	for _, k := range []string{"country", "country_iso", "asn", "asn_name", "hs"} {
		if _, present := scoped[0].Payload[k]; !present {
			t.Errorf("scoped caller lost %q", k)
		}
	}

	admin := row()
	redactScopedHistoryRows(httptest.NewRequest(http.MethodGet, "/x", nil).WithContext(adminCtx()), admin)
	if admin[0].Payload["ptr"] != "ppp.otenet.gr" {
		t.Errorf("admin must still receive ptr")
	}
}

// ── End to end through the real verify handler ─────────────────────────────
//
// The reject path had no HTTP-level test at all. This drives a real verify —
// cookie, HMAC token, a PoW actually solved — against a live listener, with
// the rung armed by a per-(ip,host) mark, and checks the wiring the whole
// feature rests on: geo is resolved BEFORE the gate, a reject reaches the
// reject hook and never the solved one, and a passing solve is the mirror.

type verifyCapture struct {
	mu      sync.Mutex
	solved  []ChallengeSolve
	rejects []ChallengeSolve
}

func (c *verifyCapture) counts() (int, int) {
	c.mu.Lock()
	defer c.mu.Unlock()
	return len(c.solved), len(c.rejects)
}

func startVerifyServer(t *testing.T) (string, *verifyCapture) {
	t.Helper()
	t.Setenv("CFM_CHALLENGE_SECRET", "challenge-geo-e2e-secret")
	resetChallengeV2Marks(t)

	on, fail, debug, shadow := challengeV2Settings()
	ConfigureChallengeV2(true, defaultV2FailScore, false, false)
	t.Cleanup(func() { ConfigureChallengeV2(on, fail, debug, shadow) })

	setSolveEnricher(t, func(ip string) enrich.Result {
		return enrich.Result{Country: "Greece", CountryISO: "GR", ASN: 6799, ASNName: "OTEnet S.A.", PTR: "ppp.otenet.gr"}
	})

	capt := &verifyCapture{}
	prevSolved, prevReject := challengeSolvedHook, challengeV2RejectHook
	SetChallengeSolvedHook(func(s ChallengeSolve) { capt.mu.Lock(); capt.solved = append(capt.solved, s); capt.mu.Unlock() })
	SetChallengeV2RejectHook(func(s ChallengeSolve) { capt.mu.Lock(); capt.rejects = append(capt.rejects, s); capt.mu.Unlock() })
	t.Cleanup(func() { SetChallengeSolvedHook(prevSolved); SetChallengeV2RejectHook(prevReject) })

	srv := NewChallengeServer(nil)
	if err := srv.Start(context.Background(), "127.0.0.1:0"); err != nil {
		t.Fatalf("Start: %v", err)
	}
	t.Cleanup(func() {
		ctx, cancel := context.WithTimeout(context.Background(), 2*time.Second)
		defer cancel()
		_ = srv.Stop(ctx)
	})
	return "http://" + srv.httpLn.Addr().String(), capt
}

// postVerify performs one genuine verify: fresh cookie, the HMAC token bound to
// (ip, ua, cookie), and a PoW solved at the configured difficulty.
func postVerify(t *testing.T, base, clientIP, host, ua, body string) *http.Response {
	t.Helper()
	cookie := randomCookieValue()
	nonce := make([]byte, 16)
	if _, err := rand.Read(nonce); err != nil {
		t.Fatal(err)
	}
	bind := powBind(ua, cookie)
	cfg := defaultPowConfig()
	powTok, err := issuePowChallenge(powSecretKey(), time.Now().UTC(), cfg.Difficulty, nonce, bind)
	if err != nil {
		t.Fatalf("issuePowChallenge: %v", err)
	}
	sol := ""
	for i := 0; i < 1<<26; i++ {
		if cand := strconv.Itoa(i); verifyPowSolution(nonce, bind, cand, cfg.Difficulty) {
			sol = cand
			break
		}
	}
	if sol == "" {
		t.Fatal("could not solve the PoW")
	}

	req, _ := http.NewRequest(http.MethodPost, base+verifyPath+"?next=/", strings.NewReader(body))
	req.Header.Set("User-Agent", ua)
	req.Header.Set("X-Real-IP", clientIP)
	req.Header.Set("X-Forwarded-Host", host)
	req.Header.Set("X-CFM-Token", issueToken(clientIP, ua, cookie))
	req.Header.Set("X-CFM-Pow", powTok)
	req.Header.Set("X-CFM-Sol", sol)
	req.AddCookie(&http.Cookie{Name: "cfm_chal", Value: cookie})

	client := &http.Client{
		Timeout:       10 * time.Second,
		CheckRedirect: func(*http.Request, []*http.Request) error { return http.ErrUseLastResponse },
	}
	resp, err := client.Do(req)
	if err != nil {
		t.Fatalf("verify POST: %v", err)
	}
	t.Cleanup(func() { resp.Body.Close() })
	return resp
}

func TestVerify_V2RejectCarriesGeoAndNeverReachesTheSolvedPath(t *testing.T) {
	base, capt := startVerifyServer(t)
	const (
		ip   = "203.0.113.9"
		host = "shop.example.com"
		ua   = "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/131.0.0.0 Safari/537.36"
	)
	MarkChallengeV2(ip, host) // arm the rung for this (ip, host), as a v2 WAF/traffic rule would

	// navigator.webdriver === true is certain evidence (100); zero input amplifies.
	resp := postVerify(t, base, ip, host, ua, `{"v":1,"wd":true,"ptr":0,"tch":0,"key":0}`)
	if resp.StatusCode != http.StatusForbidden || resp.Header.Get("X-CFM-V2") != "reject" {
		t.Fatalf("armed failing solve: status=%d X-CFM-V2=%q, want 403 + reject", resp.StatusCode, resp.Header.Get("X-CFM-V2"))
	}
	solved, rejects := capt.counts()
	if rejects != 1 || solved != 0 {
		t.Fatalf("reject reached rejects=%d solved=%d; want 1/0 — a reject cleared nothing", rejects, solved)
	}
	r := capt.rejects[0]
	if r.V2Grain != v2GrainMark || r.HumanityScore < defaultV2FailScore {
		t.Errorf("reject not attributed: grain=%q hs=%d", r.V2Grain, r.HumanityScore)
	}
	if r.CountryISO != "GR" || r.ASN != 6799 || r.PTR != "ppp.otenet.gr" {
		t.Errorf("geo was not resolved before the gate: %+v", r)
	}

	// Positive control, same (ip, host), same arm: a clean report passes and
	// takes the solved path — with the same geo.
	resp = postVerify(t, base, ip, host, ua, `{"v":1,"wd":false,"ptr":7,"tch":0,"key":2}`)
	if resp.StatusCode == http.StatusForbidden {
		t.Fatalf("clean solve under the same arm was refused: X-CFM-V2=%q", resp.Header.Get("X-CFM-V2"))
	}
	solved, rejects = capt.counts()
	if solved != 1 || rejects != 1 {
		t.Fatalf("after a clean solve: solved=%d rejects=%d, want 1/1", solved, rejects)
	}
	if s := capt.solved[0]; s.PTR != "ppp.otenet.gr" || s.CountryISO != "GR" {
		t.Errorf("solved path lost the geo: %+v", s)
	}
}

package webdetector

import (
	"context"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"net/url"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"
)

// Vhost LOCKDOWN (vhost_lockdown.go): an attribute of a manual vhost
// challenge that withdraws every client exemption while it holds.

func lockdownTestEngine(t *testing.T) (*Engine, *HistoryStore) {
	t.Helper()
	hs, err := NewHistoryStore(filepath.Join(t.TempDir(), "history.sqlite"), 30, time.Hour, 0)
	if err != nil {
		t.Fatalf("NewHistoryStore: %v", err)
	}
	t.Cleanup(hs.Close)
	e := &Engine{history: hs}
	e.manualChal.init("")
	e.nginxBridge = NewNginxBridge("/tmp/cfm-test.sock", "tok", time.Minute, time.Minute)
	return e, hs
}

func TestManualChalLockdown_StoreSemantics(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "manual.json")
	var s manualChalState
	s.init(path)

	if _, _, ok := s.setLockdown("none.gr", time.Now().Add(time.Hour)); ok {
		t.Fatal("a lockdown must not create an arm")
	}
	s.set("shop.gr", time.Hour, "manual", "")
	_, stored, ok := s.setLockdown("shop.gr", time.Now().Add(3*time.Hour))
	if !ok || stored.After(time.Now().Add(time.Hour+time.Second)) {
		t.Fatalf("lockdown must be clamped to the arm's expiry: ok=%v stored=%v", ok, stored)
	}

	// A re-arm keeps the lockdown, clamped to the new (shorter) expiry.
	s.set("shop.gr", 10*time.Minute, "manual", "v2")
	lu := s.lockdownUntil("shop.gr")
	if lu.IsZero() || lu.After(time.Now().Add(10*time.Minute+time.Second)) {
		t.Fatalf("re-arm lost or did not clamp the lockdown: %v", lu)
	}

	// Persisted and reloaded; an older snapshot (no key) has none.
	var s2 manualChalState
	s2.init(path)
	if got := s2.lockdownUntil("shop.gr"); got.IsZero() {
		t.Fatal("lockdown not restored from the snapshot")
	}
	old := `[{"host":"old.gr","expires_at":"` + time.Now().Add(time.Hour).Format(time.RFC3339Nano) + `","ttl_sec":3600}]`
	oldPath := filepath.Join(dir, "old.json")
	if err := os.WriteFile(oldPath, []byte(old), 0o600); err != nil {
		t.Fatal(err)
	}
	var s3 manualChalState
	s3.init(oldPath)
	if got := s3.lockdownUntil("old.gr"); !got.IsZero() {
		t.Fatalf("an old snapshot must load with no lockdown, got %v", got)
	}

	// Lifting clears it; clear() takes it with the arm.
	if _, stored, _ := s.setLockdown("shop.gr", time.Time{}); !stored.IsZero() || !s.lockdownUntil("shop.gr").IsZero() {
		t.Fatal("lift did not clear the lockdown")
	}
}

func TestSetManualChallengeLockdownAs(t *testing.T) {
	e, hs := lockdownTestEngine(t)
	if _, _, _, ok := e.SetManualChallengeLockdownAs("shop.gr", time.Hour, "admin"); ok {
		t.Fatal("no arm: ok must be false")
	}
	e.ManualChallengeVhost("shop.gr", 24*time.Hour, "manual", "")

	until, capped, changed, ok := e.SetManualChallengeLockdownAs("shop.gr", 10*time.Hour, "scoped")
	if !ok || !changed || !capped || until.After(time.Now().Add(maxLockdownTTL+time.Second)) {
		t.Fatalf("10h must cap at 6h: until=%v capped=%v changed=%v ok=%v", until, capped, changed, ok)
	}
	if !e.nginxBridge.vhostLockedDown("shop.gr", time.Now()) || !e.nginxBridge.vhostLockedDown("www.shop.gr", time.Now()) {
		t.Fatal("the bridge must hold the lockdown for the apex and its www. variant")
	}
	evs, _ := hs.QueryEvents("shop.gr", "", "challenge_vhost_lockdown", 5)
	if len(evs) != 1 || evs[0].Payload["lockdown"] != true || evs[0].Payload["actor"] != "scoped" {
		t.Fatalf("audit row: %+v", evs)
	}

	// Lifting: changed, audited, gone from the bridge; lifting again is a no-op.
	if _, _, changed, _ := e.SetManualChallengeLockdownAs("shop.gr", 0, "admin"); !changed {
		t.Fatal("lift must report changed")
	}
	if e.nginxBridge.vhostLockedDown("shop.gr", time.Now()) {
		t.Fatal("lifted lockdown still at the bridge")
	}
	if _, _, changed, ok := e.SetManualChallengeLockdownAs("shop.gr", 0, "admin"); !ok || changed {
		t.Fatal("lifting an absent lockdown must be a no-op")
	}
	if evs, _ := hs.QueryEvents("shop.gr", "", "challenge_vhost_lockdown", 5); len(evs) != 2 {
		t.Fatalf("no-op wrote an audit row: %d rows", len(evs))
	}

	// The arm ending first caps the lockdown too.
	e.ManualChallengeVhost("short.gr", 5*time.Minute, "manual", "")
	if _, capped, _, _ := e.SetManualChallengeLockdownAs("short.gr", time.Hour, ""); !capped {
		t.Fatal("a lockdown past the arm must report capped")
	}

	// Clearing the arm takes the lockdown off the bridge.
	e.ClearManualChallengeVhost("short.gr")
	if e.nginxBridge.vhostLockedDown("short.gr", time.Now()) {
		t.Fatal("cleared arm left its lockdown at the bridge")
	}
}

// A www. host with an arm of its own is governed by that arm, not the apex's
// lockdown (manualRungTarget prefers it, and so must the edge).
func TestSyncVhostLockdowns_WWWOwnArmWins(t *testing.T) {
	e, _ := lockdownTestEngine(t)
	e.ManualChallengeVhost("shop.gr", time.Hour, "manual", "")
	e.ManualChallengeVhost("www.shop.gr", time.Hour, "manual", "")
	e.SetManualChallengeLockdownAs("shop.gr", time.Hour, "")
	now := time.Now()
	if !e.nginxBridge.vhostLockedDown("shop.gr", now) {
		t.Fatal("apex not locked")
	}
	if e.nginxBridge.vhostLockedDown("www.shop.gr", now) {
		t.Fatal("www. has its own (unlocked) arm and must not inherit the apex lockdown")
	}
	if !e.vhostLockdownUntil("www.shop.gr").IsZero() {
		t.Fatal("vhostLockdownUntil must resolve www. to its own arm")
	}
}

func TestLockdownFeed(t *testing.T) {
	e, _ := lockdownTestEngine(t)
	e.ManualChallengeVhost("shop.gr", time.Hour, "manual", "")
	until, _, _, _ := e.SetManualChallengeLockdownAs("shop.gr", 30*time.Minute, "")

	rr := httptest.NewRecorder()
	req := httptest.NewRequest(http.MethodGet, "/nginx/lockdown", nil)
	e.nginxBridge.handleLockdownFeed(rr, req)
	if rr.Code != http.StatusForbidden {
		t.Fatalf("no token must be refused, got %d", rr.Code)
	}
	rr = httptest.NewRecorder()
	req.Header.Set("X-CFM-Token", "tok")
	e.nginxBridge.handleLockdownFeed(rr, req)
	if rr.Code != http.StatusOK || rr.Header().Get("Content-Length") == "" {
		t.Fatalf("feed: code=%d content-length=%q", rr.Code, rr.Header().Get("Content-Length"))
	}
	var body struct {
		Hosts map[string]int64 `json:"hosts"`
	}
	if err := json.Unmarshal(rr.Body.Bytes(), &body); err != nil {
		t.Fatal(err)
	}
	if body.Hosts["shop.gr"] != until.Unix() || body.Hosts["www.shop.gr"] != until.Unix() || len(body.Hosts) != 2 {
		t.Fatalf("feed hosts = %v, want shop.gr + www.shop.gr at %d", body.Hosts, until.Unix())
	}
}

// handleDecision: under a lockdown the exclude-file lift stands down (the
// good-bot and Access-Control lifts share the same gate).
func TestHandleDecision_LockdownWithdrawsLifts(t *testing.T) {
	b := NewNginxBridge("/tmp/cfm-test.sock", "tok", time.Minute, time.Minute)
	b.chalExcludeASNFn = func(string) uint32 { return 714 }
	b.ChalExcludeHot = func(host, ua string, asn, ptr func() string, rule string) (string, string, bool) {
		return "skip", "asn=as714; action=skip", asn() == "AS714"
	}
	accessCalls := 0
	b.ChallengeAccessExempt = func(ChallengeAccessInput, func() uint32) bool { accessCalls++; return true }
	decide := func() map[string]any {
		b.mu.Lock()
		b.vhState["shop.gr"] = bridgeVhostEntry{Action: "challenge", Expires: time.Now().Add(time.Minute)}
		b.mu.Unlock()
		q := url.Values{"ip": {"17.166.20.62"}, "host": {"shop.gr"}, "uri": {"/"}, "method": {"GET"}, "ua": {"Applebot/0.1"}}
		rr := httptest.NewRecorder()
		req := httptest.NewRequest(http.MethodGet, "/nginx/decision?"+q.Encode(), nil)
		req.Header.Set("X-CFM-Token", "tok")
		b.handleDecision(rr, req)
		var m map[string]any
		_ = json.Unmarshal(rr.Body.Bytes(), &m)
		return m
	}
	if got := decide(); got["vhost_action"] != "allow" {
		t.Fatalf("unlocked: the exemptions must lift the vhost challenge, got %+v", got)
	}
	b.setVhostLockdowns(map[string]time.Time{"shop.gr": time.Now().Add(time.Minute)})
	accessCalls = 0
	if got := decide(); got["vhost_action"] != "challenge" {
		t.Fatalf("locked: no exemption may lift the vhost challenge, got %+v", got)
	}
	if accessCalls != 0 {
		t.Fatalf("Access-Control consulted under a lockdown (%d calls)", accessCalls)
	}
	// An expired lockdown is no lockdown.
	b.setVhostLockdowns(map[string]time.Time{"shop.gr": time.Now().Add(-time.Second)})
	if got := decide(); got["vhost_action"] != "allow" {
		t.Fatalf("expired lockdown still held: %+v", got)
	}
}

func TestChallengePageExempt_Lockdown(t *testing.T) {
	b := exemptPageBridge(t)
	now := time.Now()
	if _, ok := b.challengePageExempt(readAloudIP, "shop.gr", readAloudUA, "/", now); !ok {
		t.Fatal("unlocked: Read-Aloud must be exempt on the challenge page")
	}
	b.setVhostLockdowns(map[string]time.Time{"shop.gr": now.Add(time.Minute)})
	if _, ok := b.challengePageExempt(readAloudIP, "shop.gr", readAloudUA, "/", now); ok {
		t.Fatal("locked: the challenge page must exempt nobody")
	}
}

func TestChallengeV2WaiverBar_Lockdown(t *testing.T) {
	SetChallengeV2Lockdown(func(host string) bool { return host == "shop.gr" })
	t.Cleanup(func() { SetChallengeV2Lockdown(nil) })
	if got := challengeV2WaiverBar(v2GrainVhost, "66.249.66.1", "shop.gr", "web"); got != v2WaiverLockdown {
		t.Fatalf("locked vhost: waiver bar = %q, want %q", got, v2WaiverLockdown)
	}
	if got := challengeV2WaiverBar(v2GrainVhost, "66.249.66.1", "other.gr", "web"); got != "" {
		t.Fatalf("unlocked vhost: waiver bar = %q, want none", got)
	}
}

// The uniqIP count under a lockdown exempts only CDN clients: a crawler is
// challenged there, so it counts.
func TestVhostChallengeExemptClient_Lockdown(t *testing.T) {
	b := appleExcludeBridge(t)
	now := time.Now()
	b.setVhostLockdowns(map[string]time.Time{"shop.gr": now.Add(time.Minute)})
	cases := []struct {
		ip, ua      string
		bp, bpCDN   bool
		want        bool
		description string
	}{
		{"40.77.167.1", "bingbot", true, false, false, "crawler bypass counts"},
		{"141.95.1.1", "qcbot", true, true, true, "CDN bypass stays exempt"},
		{"17.166.20.62", "applebot", false, false, false, "exclude-file match counts"},
		{"79.129.88.110", "mozilla/5.0", false, false, false, "a human counts"},
	}
	for _, c := range cases {
		if got := b.vhostChallengeExemptClient(c.ip, "shop.gr", c.ua, c.bp, c.bpCDN, now); got != c.want {
			t.Errorf("%s: got %v, want %v", c.description, got, c.want)
		}
	}
	if !b.vhostChallengeExemptClient("17.166.20.62", "other.gr", "applebot", false, false, now) {
		t.Error("an unlocked vhost keeps the exclude-file exemption")
	}
}

func TestParseSocketTSV_BypassCDN(t *testing.T) {
	base := "1791466170.6\t141.95.1.1\ta.gr\tGET\t/\tHTTP/2.0\t200\t7\t0.002\t0.001\t-\tqcbot\tcfm_apache\t"
	for bp, want := range map[string][2]bool{"1": {true, false}, "2": {true, true}, "0": {false, false}} {
		rec, ok := parseSocketTSV(base + bp)
		if !ok || rec.Bypass != want[0] || rec.BypassCDN != want[1] {
			t.Errorf("bp=%s: bypass=%v cdn=%v, want %v", bp, rec.Bypass, rec.BypassCDN, want)
		}
	}
}

func TestLockdownAPI(t *testing.T) {
	e, _ := lockdownTestEngine(t)
	post := func(handler func(http.ResponseWriter, *http.Request), target string, scoped bool) (int, map[string]any) {
		req := httptest.NewRequest(http.MethodPost, target, nil)
		if scoped {
			ctx := context.WithValue(req.Context(), CtxRoleKey{}, CtxRoleScoped)
			ctx = context.WithValue(ctx, CtxScopeKey{}, map[string]struct{}{"www.tenant.gr": {}})
			req = req.WithContext(ctx)
		}
		rr := httptest.NewRecorder()
		handler(rr, req)
		var m map[string]any
		_ = json.Unmarshal(rr.Body.Bytes(), &m)
		return rr.Code, m
	}

	// add with lockdown=1 arms both; the response says so.
	code, m := post(e.handleChallengeVhostAdd, "/api/v1/challenge/vhost/add?host=shop.gr&ttl=2h&lockdown=1&lockdown_ttl=20m", false)
	if code != http.StatusOK || m["lockdown"] != true || m["lockdown_until"] == nil {
		t.Fatalf("add lockdown=1: %d %+v", code, m)
	}
	// A re-arm without the field keeps it (the TUI / bots drilldown toggle).
	if code, m = post(e.handleChallengeVhostAdd, "/api/v1/challenge/vhost/add?host=shop.gr&ttl=2h", false); m["lockdown"] != true {
		t.Fatalf("re-arm without lockdown lifted it: %d %+v", code, m)
	}
	// An explicit lockdown=0 lifts it.
	if _, m = post(e.handleChallengeVhostAdd, "/api/v1/challenge/vhost/add?host=shop.gr&ttl=2h&lockdown=0", false); m["lockdown"] != false {
		t.Fatalf("lockdown=0 did not lift: %+v", m)
	}
	if code, _ = post(e.handleChallengeVhostAdd, "/api/v1/challenge/vhost/add?host=shop.gr&lockdown=maybe", false); code != http.StatusBadRequest {
		t.Fatalf("bad lockdown value accepted: %d", code)
	}
	if code, _ = post(e.handleChallengeVhostAdd, "/api/v1/challenge/vhost/add?host=*.wild.gr&lockdown=1", false); code != http.StatusBadRequest {
		t.Fatalf("wildcard lockdown accepted: %d", code)
	}

	// vhost/lockdown switches it in place.
	if code, _ = post(e.handleChallengeVhostLockdown, "/api/v1/challenge/vhost/lockdown?host=none.gr&lockdown=1", false); code != http.StatusConflict {
		t.Fatalf("no arm: want 409, got %d", code)
	}
	if code, _ = post(e.handleChallengeVhostLockdown, "/api/v1/challenge/vhost/lockdown?host=shop.gr", false); code != http.StatusBadRequest {
		t.Fatalf("missing lockdown: want 400, got %d", code)
	}
	code, m = post(e.handleChallengeVhostLockdown, "/api/v1/challenge/vhost/lockdown?host=www.shop.gr&lockdown=1&ttl=8h", false)
	if code != http.StatusOK || m["host"] != "shop.gr" || m["lockdown"] != true || m["lockdown_capped"] != true {
		t.Fatalf("lockdown on www. (apex arm), 8h: %d %+v", code, m)
	}

	// Scoped: allowed on its own vhost, refused on the apex arm it does not hold.
	e.ManualChallengeVhost("tenant.gr", time.Hour, "manual", "")
	if code, _ = post(e.handleChallengeVhostLockdown, "/api/v1/challenge/vhost/lockdown?host=www.tenant.gr&lockdown=1", true); code != http.StatusForbidden {
		t.Fatalf("scoped lockdown of an apex arm it does not hold: want 403, got %d", code)
	}
	if code, m = post(e.handleChallengeVhostAdd, "/api/v1/challenge/vhost/add?host=www.tenant.gr&ttl=1h&lockdown=1", true); code != http.StatusOK || m["lockdown"] != true {
		t.Fatalf("scoped add with lockdown on its own vhost: %d %+v", code, m)
	}

	// status reports it.
	req := httptest.NewRequest(http.MethodGet, "/api/v1/challenge/vhost/status?host=www.shop.gr", nil)
	rr := httptest.NewRecorder()
	e.handleChallengeVhostStatus(rr, req)
	if !strings.Contains(rr.Body.String(), `"lockdown":true`) {
		t.Fatalf("status lacks lockdown: %s", rr.Body.String())
	}
}

// The TUI reads the lockdown from vhost/status and its [L] key picks the
// right call: lift, lock an armed vhost in place, or arm both at once.
func TestLiveLockdown_StatusAndToggle(t *testing.T) {
	var got []string
	until := time.Now().Add(20 * time.Minute).UTC().Format(time.RFC3339)
	ts := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		got = append(got, r.URL.Path+"?"+r.URL.RawQuery)
		if r.URL.Path == "/api/v1/challenge/vhost/status" {
			_, _ = w.Write([]byte(`{"manual_active":true,"expires_at":"` + until + `","lockdown":true,"lockdown_until":"` + until + `"}`))
			return
		}
		_, _ = w.Write([]byte(`{"host":"shop.gr","lockdown":true}`))
	}))
	defer ts.Close()

	_, _, _, lock, err := fetchChallengeStatus(ts.URL, "shop.gr")
	if err != nil || lock == "" || lock == "?" {
		t.Fatalf("lockdown left not read: %q err=%v", lock, err)
	}

	for _, c := range []struct {
		snap liveSnapshot
		want string
	}{
		{liveSnapshot{ChallengeActive: true, ChallengeMode: "manual", ChallengeLockdown: "19m"}, "/api/v1/challenge/vhost/lockdown?host=shop.gr&lockdown=0"},
		{liveSnapshot{ChallengeActive: true, ChallengeMode: "manual"}, "/api/v1/challenge/vhost/lockdown?host=shop.gr&lockdown=1&ttl=30m"},
		{liveSnapshot{ChallengeActive: true, ChallengeMode: "auto"}, "/api/v1/challenge/vhost/add?host=shop.gr&ttl=30m&reason=live_lockdown&lockdown=1&lockdown_ttl=30m"},
		{liveSnapshot{}, "/api/v1/challenge/vhost/add?host=shop.gr&ttl=30m&reason=live_lockdown&lockdown=1&lockdown_ttl=30m"},
	} {
		got = nil
		liveLockdownToggle(ts.URL, "shop.gr", c.snap)
		if len(got) != 1 || got[0] != c.want {
			t.Errorf("snap %+v: called %v, want %s", c.snap, got, c.want)
		}
	}
}

// The CLI's add --lockdown / lockdown on|off build the right calls; a 409
// on "lockdown on" points at add --lockdown.
func TestCLILockdownCommands(t *testing.T) {
	var got []string
	conflict := false
	ts := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		got = append(got, r.URL.Path+"?"+r.URL.RawQuery)
		if conflict {
			w.WriteHeader(http.StatusConflict)
			_, _ = w.Write([]byte(`{"error":"no active manual challenge on shop.gr"}`))
			return
		}
		_, _ = w.Write([]byte(`{"host":"shop.gr","lockdown":true,"lockdown_until":"2030-01-01T00:00:00Z"}`))
	}))
	defer ts.Close()

	cases := []struct {
		run  func() error
		want string
	}{
		{func() error { return runChallengeAdd(ts.URL, []string{"shop.gr", "--lockdown"}) }, "lockdown=1"},
		{func() error { return runChallengeAdd(ts.URL, []string{"shop.gr", "--lockdown-ttl", "1h"}) }, "lockdown=1&lockdown_ttl=1h"},
		{func() error { return runChallengeAdd(ts.URL, []string{"shop.gr", "--no-lockdown"}) }, "lockdown=0"},
		{func() error { return runChallengeLockdown(ts.URL, []string{"shop.gr", "on", "--ttl", "45m"}) }, "/api/v1/challenge/vhost/lockdown?host=shop.gr&lockdown=1&ttl=45m"},
		{func() error { return runChallengeLockdown(ts.URL, []string{"shop.gr", "off"}) }, "/api/v1/challenge/vhost/lockdown?host=shop.gr&lockdown=0"},
	}
	for _, c := range cases {
		got = nil
		if err := c.run(); err != nil {
			t.Fatalf("command failed: %v", err)
		}
		if len(got) != 1 || !strings.Contains(got[0], c.want) {
			t.Errorf("called %v, want it to contain %q", got, c.want)
		}
	}
	// A plain add sends no lockdown field (it keeps the arm's).
	got = nil
	_ = runChallengeAdd(ts.URL, []string{"shop.gr"})
	if len(got) != 1 || strings.Contains(got[0], "lockdown") {
		t.Errorf("plain add must not touch the lockdown: %v", got)
	}
	if err := runChallengeLockdown(ts.URL, []string{"shop.gr", "maybe"}); err == nil {
		t.Error("a bad on/off value must be a usage error")
	}
	conflict = true
	if err := runChallengeLockdown(ts.URL, []string{"shop.gr", "on"}); err == nil || !strings.Contains(err.Error(), "add shop.gr --lockdown") {
		t.Errorf("409 must point at add --lockdown, got %v", err)
	}
}

package webdetector

import (
	"bytes"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"net/url"
	"strconv"
	"strings"
	"testing"
	"time"
)

func revokeFeed(t *testing.T, b *NginxBridge, v string) map[string]any {
	t.Helper()
	path := "/nginx/clearance/revoked"
	if v != "" {
		path += "?v=" + v
	}
	rr := httptest.NewRecorder()
	req := httptest.NewRequest(http.MethodGet, path, nil)
	req.Header.Set("X-CFM-Token", "tok")
	b.handleClearanceRevoked(rr, req)
	if rr.Code != http.StatusOK {
		t.Fatalf("feed status=%d body=%s", rr.Code, rr.Body.String())
	}
	var out map[string]any
	if err := json.Unmarshal(rr.Body.Bytes(), &out); err != nil {
		t.Fatalf("feed json: %v (%s)", err, rr.Body.String())
	}
	return out
}

func okTouch(t *testing.T, b *NginxBridge, ip, host string) map[string]any {
	t.Helper()
	rr := httptest.NewRecorder()
	body := bytes.NewBufferString(`{"ip":"` + ip + `","host":"` + host + `","scope":"web","ttl_sec":120}`)
	req := httptest.NewRequest(http.MethodPost, "/nginx/ok/touch", body)
	req.Header.Set("X-CFM-Token", "tok")
	b.handleOKTouch(rr, req)
	var out map[string]any
	_ = json.Unmarshal(rr.Body.Bytes(), &out)
	return out
}

func decisionIPAction(t *testing.T, b *NginxBridge, ip, host string) string {
	t.Helper()
	rr := httptest.NewRecorder()
	req := httptest.NewRequest(http.MethodGet, "/nginx/decision?ip="+ip+"&host="+host+"&scope=web", nil)
	req.Header.Set("X-CFM-Token", "tok")
	b.handleDecision(rr, req)
	var out map[string]any
	_ = json.Unmarshal(rr.Body.Bytes(), &out)
	s, _ := out["ip_action"].(string)
	return s
}

// A malpath challenge on a cleared client revokes its clearance: the edge is
// told (the feed), the solved-ok state that answered "allow" on the decision
// path is dropped, and a touch from the old cookie cannot write it back.
func TestMalpathChallengeRevokesClearance(t *testing.T) {
	t.Cleanup(func() { ConfigureClearanceRevoke(true) })
	b := NewNginxBridge("/tmp/cfm-test-clrrv.sock", "tok", time.Minute, time.Minute)
	const ip, host = "203.0.113.90", "a.example.com"

	okTouch(t, b, ip, host) // the client solved earlier: solved-ok on a.example.com
	if got := decisionIPAction(t, b, ip, host); got != "allow" {
		t.Fatalf("before: ip_action=%q", got)
	}
	empty := revokeFeed(t, b, "")
	if ips, _ := empty["ips"].(map[string]any); len(ips) != 0 {
		t.Fatalf("empty feed lists %v", ips)
	}

	b.ChallengeIPWithReason(ip, 10*time.Minute, "CHALLENGE_PATHS")
	if !b.ClearanceRevoked(ip) {
		t.Fatalf("a malpath challenge did not revoke the clearance")
	}
	// Before the fix the solved-ok state overrode the new per-IP challenge.
	if got := decisionIPAction(t, b, ip, host); got != "challenge" {
		t.Fatalf("revoked: ip_action=%q, want challenge (solved-ok must not override)", got)
	}
	if out := okTouch(t, b, ip, host); out["revoked"] != true {
		t.Fatalf("a touch during the revocation: %v", out)
	}
	if got := decisionIPAction(t, b, ip, host); got != "challenge" {
		t.Fatalf("a touch wrote solved-ok back: ip_action=%q", got)
	}

	feed := revokeFeed(t, b, empty["v"].(string))
	ips, _ := feed["ips"].(map[string]any)
	left, _ := ips[ip].(float64)
	if left < 590 || left > 600 {
		t.Fatalf("feed: %v, want %s with ~600s left", feed, ip)
	}
	if same := revokeFeed(t, b, feed["v"].(string)); same["same"] != true || same["ips"] != nil {
		t.Fatalf("an unchanged version must answer same: %v", same)
	}

	// The solve (web scope) ends it, and the feed says so.
	b.ClearIPScoped(ip, host, "web")
	if b.ClearanceRevoked(ip) {
		t.Fatalf("a solve left the revocation")
	}
	after := revokeFeed(t, b, feed["v"].(string))
	if after["same"] == true {
		t.Fatalf("the solve did not change the version")
	}
	if ips, _ := after["ips"].(map[string]any); len(ips) != 0 {
		t.Fatalf("feed after solve: %v", after)
	}
	if out := okTouch(t, b, ip, host); out["revoked"] == true {
		t.Fatalf("a touch after the solve is still refused")
	}
}

func TestClearanceRevokeOnlyMalpathAndKnob(t *testing.T) {
	t.Cleanup(func() { ConfigureClearanceRevoke(true) })
	b := NewNginxBridge("/tmp/cfm-test-clrrv.sock", "tok", time.Minute, time.Minute)

	b.ChallengeIPWithReason("203.0.113.91", time.Minute, "CHALLENGE_ERR_RATIO")
	b.ChallengeIP("203.0.113.92", time.Minute)
	for _, ip := range []string{"203.0.113.91", "203.0.113.92"} {
		if b.ClearanceRevoked(ip) {
			t.Fatalf("%s: a non-malpath challenge revoked the clearance", ip)
		}
	}

	ConfigureClearanceRevoke(false)
	b.ChallengeIPWithReason("203.0.113.93", time.Minute, "CHALLENGE_PATHS")
	if b.ClearanceRevoked("203.0.113.93") {
		t.Fatalf("CHALLENGE_PATHS_REVOKE=0 still revoked")
	}
}

// The reason-less echo of the bridge's own push, a refresh, and the ends of a
// revocation other than a solve.
func TestClearanceRevokeLifecycle(t *testing.T) {
	b := NewNginxBridge("/tmp/cfm-test-clrrv.sock", "tok", time.Minute, time.Minute)
	const ip = "203.0.113.94"

	b.ChallengeIPWithReason(ip, time.Minute, "CHALLENGE_PATHS")
	// A longer refresh extends it, a reason-less one keeps it.
	b.ChallengeIPWithReason(ip, 20*time.Minute, "CHALLENGE_PATHS")
	b.ChallengeIPWithReason(ip, time.Minute, "")
	b.mu.RLock()
	until := b.clrRevoked[ip]
	b.mu.RUnlock()
	if time.Until(until) < 19*time.Minute {
		t.Fatalf("a refresh did not extend (or shortened) the revocation: %v left", time.Until(until))
	}
	// It runs out with the challenge.
	b.mu.RLock()
	expired := !b.clearanceRevokedLocked(ip, time.Now().Add(21*time.Minute))
	b.mu.RUnlock()
	if !expired {
		t.Fatalf("the revocation outlived its challenge")
	}

	// /nginx/ip/clear ends it.
	rr := httptest.NewRecorder()
	req := httptest.NewRequest(http.MethodPost, "/nginx/ip/clear", bytes.NewBufferString(`{"ip":"`+ip+`"}`))
	req.Header.Set("X-CFM-Token", "tok")
	b.handleIPClear(rr, req)
	if b.ClearanceRevoked(ip) {
		t.Fatalf("/nginx/ip/clear left the revocation")
	}

	// A force unblock ends it.
	b.ChallengeIPWithReason(ip, time.Minute, "CHALLENGE_PATHS")
	b.ForceUnblock(ip)
	if b.ClearanceRevoked(ip) {
		t.Fatalf("a force unblock left the revocation")
	}
}

func TestClearanceRevokeCap(t *testing.T) {
	b := NewNginxBridge("/tmp/cfm-test-clrrv.sock", "tok", time.Minute, time.Minute)
	now := time.Now()
	b.mu.Lock()
	for i := 0; i < clearanceRevokeMax; i++ {
		b.revokeClearanceLocked("10.0."+strconv.Itoa(i/256)+"."+strconv.Itoa(i%256), now.Add(time.Minute), now)
	}
	b.revokeClearanceLocked("203.0.113.95", now.Add(time.Minute), now)
	full := len(b.clrRevoked)
	_, had := b.clrRevoked["203.0.113.95"]
	// An expired entry makes room.
	b.clrRevoked["10.0.0.0"] = now.Add(-time.Second)
	b.revokeClearanceLocked("203.0.113.96", now.Add(time.Minute), now)
	_, room := b.clrRevoked["203.0.113.96"]
	b.mu.Unlock()
	if full != clearanceRevokeMax || had {
		t.Fatalf("the cap was exceeded: %d entries, new one kept=%v", full, had)
	}
	if !room {
		t.Fatalf("an expired entry did not make room")
	}
}

// The challenge page does not bounce a revoked client back to next as
// "cleared": the edge challenged it on purpose (review finding on the first
// cut: a revoked client looped page → next → page and read as a CDN-cached
// challenge).
func TestChallengePage_RevokedClearanceIsServedThePage(t *testing.T) {
	useClearanceBridgeToken(t, unitTestBridgeSecret)
	resetThrottleStores(t)
	b := NewNginxBridge("/tmp/cfm-test-clrrv.sock", "tok", time.Minute, time.Minute)
	base, _ := startVerifyServerWithBridge(t, b)
	const ip, host, next = "203.0.113.97", "shop.example.com", "/account/"
	get := func() *http.Response {
		req, _ := http.NewRequest(http.MethodGet, base+challengePath+"?next="+url.QueryEscape(next), nil)
		req.Header.Set("User-Agent", "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/154.0.0.0 Safari/537.36")
		req.Header.Set("X-Real-IP", ip)
		req.Header.Set("X-Forwarded-Host", host)
		req.AddCookie(&http.Cookie{Name: "cfm_clearance", Value: issueClearanceToken(ip, host, "web", time.Now().Add(time.Hour))})
		resp, err := noFollow().Do(req)
		if err != nil {
			t.Fatal(err)
		}
		resp.Body.Close()
		return resp
	}
	b.ChallengeIPWithReason(ip, 10*time.Minute, "CHALLENGE_PATHS")
	if r := get(); r.StatusCode == http.StatusSeeOther {
		t.Fatalf("a revoked clearance was bounced to %q", r.Header.Get("Location"))
	}
	b.ClearIP(ip) // solved
	resetThrottleStores(t)
	if r := get(); r.StatusCode != http.StatusSeeOther || r.Header.Get("Location") != next {
		t.Fatalf("after the solve: %d %q, want the cleared bounce to next", r.StatusCode, r.Header.Get("Location"))
	}
}

// A reload builds a new bridge with an empty list and its version at 0: its
// versions must never match the old bridge's (review finding: an edge holding
// E:N kept a stale list and never learned the new one's revocations).
func TestClearanceRevokeEpochPerBridge(t *testing.T) {
	a := NewNginxBridge("/tmp/cfm-test-clrrv.sock", "tok", time.Minute, time.Minute)
	b := NewNginxBridge("/tmp/cfm-test-clrrv.sock", "tok", time.Minute, time.Minute)
	va := revokeFeed(t, a, "")["v"].(string)
	vb := revokeFeed(t, b, "")["v"].(string)
	if va == vb {
		t.Fatalf("two bridges share version %q", va)
	}
	if same := revokeFeed(t, b, va); same["same"] == true {
		t.Fatalf("the new bridge answered same to the old bridge's version")
	}
}

// The full decision answers clrrv (0/1) so an edge can drop its copy as soon as
// the daemon ends a revocation; the panel scope is never revoked.
func TestDecisionCarriesClearanceRevokedAndPanelUntouched(t *testing.T) {
	b := NewNginxBridge("/tmp/cfm-test-clrrv.sock", "tok", time.Minute, time.Minute)
	const ip, host = "203.0.113.98", "a.example.com"
	decision := func(scope string) map[string]any {
		rr := httptest.NewRecorder()
		req := httptest.NewRequest(http.MethodGet, "/nginx/decision?ip="+ip+"&host="+host+"&scope="+scope, nil)
		req.Header.Set("X-CFM-Token", "tok")
		b.handleDecision(rr, req)
		var out map[string]any
		_ = json.Unmarshal(rr.Body.Bytes(), &out)
		return out
	}
	if d := decision("web"); d["clrrv"] != float64(0) {
		t.Fatalf("unrevoked: clrrv=%v", d["clrrv"])
	}
	// A panel solve's okState survives the web revocation, and a panel touch
	// is not refused.
	b.mu.Lock()
	b.okState[okStateKey{IP: ip, Host: host, Scope: "panel:2083"}] = time.Now().Add(time.Hour)
	b.mu.Unlock()
	b.ChallengeIPWithReason(ip, 10*time.Minute, "CHALLENGE_PATHS")
	if d := decision("web"); d["clrrv"] != float64(1) {
		t.Fatalf("revoked: clrrv=%v", d["clrrv"])
	}
	if d := decision("panel:2083"); d["clrrv"] != float64(0) {
		t.Fatalf("panel scope reported revoked: %v", d["clrrv"])
	}
	b.mu.RLock()
	_, kept := b.okState[okStateKey{IP: ip, Host: host, Scope: "panel:2083"}]
	b.mu.RUnlock()
	if !kept {
		t.Fatalf("the web revocation dropped the panel okState")
	}
	rr := httptest.NewRecorder()
	req := httptest.NewRequest(http.MethodPost, "/nginx/ok/touch", bytes.NewBufferString(`{"ip":"`+ip+`","host":"`+host+`","scope":"panel:2083","ttl_sec":120}`))
	req.Header.Set("X-CFM-Token", "tok")
	b.handleOKTouch(rr, req)
	if strings.Contains(rr.Body.String(), "revoked") {
		t.Fatalf("a panel touch was refused: %s", rr.Body.String())
	}
	b.ClearIP(ip)
	if d := decision("web"); d["clrrv"] != float64(0) {
		t.Fatalf("after the solve: clrrv=%v", d["clrrv"])
	}
}

// Every reject of a held client extends the revocation: only a new entry or a
// move of more than a minute changes the version the edge polls by.
func TestClearanceRevokeVersionOnlyOnRealChange(t *testing.T) {
	b := NewNginxBridge("/tmp/cfm-test-clrrv.sock", "tok", time.Minute, time.Minute)
	now := time.Now()
	b.mu.Lock()
	defer b.mu.Unlock()
	b.revokeClearanceLocked("203.0.113.150", now.Add(time.Hour), now)
	v := b.clrRevokeVer
	b.revokeClearanceLocked("203.0.113.150", now.Add(time.Hour+30*time.Second), now.Add(30*time.Second))
	if b.clrRevokeVer != v {
		t.Fatalf("a 30s extension changed the version")
	}
	if !b.clrRevoked["203.0.113.150"].Equal(now.Add(time.Hour + 30*time.Second)) {
		t.Fatalf("the extension was not recorded")
	}
	b.revokeClearanceLocked("203.0.113.150", now.Add(2*time.Hour), now)
	if b.clrRevokeVer == v {
		t.Fatalf("an hour's extension did not change the version")
	}
}

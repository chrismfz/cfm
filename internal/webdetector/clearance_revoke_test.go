package webdetector

import (
	"bytes"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"strconv"
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

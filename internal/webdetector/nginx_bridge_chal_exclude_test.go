package webdetector

import (
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"net/url"
	"strings"
	"testing"
	"time"
)

// The operator challenge-exclude file is honoured at serve time: a request whose
// UA matches an exclude rule is not served the vhost-wide challenge (Meta's
// link-preview crawlers got "Just a moment…" on an auto suspicious_vhost
// challenge, 2026-10-01). skip_vhost_only lifts only the vhost-wide challenge,
// and a per-IP block is never softened.
func TestNginxBridgeChalExcludeHotDowngrade(t *testing.T) {
	b := NewNginxBridge("/tmp/cfm-test.sock", "tok", time.Minute, time.Minute)
	type call struct{ host, ua, rule string }
	var calls []call
	act := "skip"
	b.ChalExcludeHot = func(host, ua, asn, ptr, rule string) (string, bool) {
		calls = append(calls, call{host, ua, rule})
		if !strings.Contains(strings.ToLower(ua), "meta-externalads") {
			return "", false
		}
		if act == "skip_vhost_only" && rule != "CHALLENGE_VHOST" {
			return "", false
		}
		return act, true
	}

	const ip = "2a03:2880:24ff:48::"
	decide := func(ua string) map[string]any {
		b.mu.Lock()
		b.vhState["ligaapola.gr"] = bridgeVhostEntry{Action: "challenge", Expires: time.Now().Add(time.Minute)}
		b.mu.Unlock()
		q := url.Values{"ip": {ip}, "host": {"ligaapola.gr"}, "uri": {"/"}, "method": {"GET"}, "ua": {ua}}
		rr := httptest.NewRecorder()
		req := httptest.NewRequest(http.MethodGet, "/nginx/decision?"+q.Encode(), nil)
		req.Header.Set("X-CFM-Token", "tok")
		b.handleDecision(rr, req)
		var payload map[string]any
		_ = json.Unmarshal(rr.Body.Bytes(), &payload)
		return payload
	}
	meta := "meta-externalads/1.1 (+https://developers.facebook.com/docs/sharing/webmasters/crawler)"

	if got := decide(meta); got["vhost_action"] != "allow" || got["ip_action"] != "allow" {
		t.Fatalf("excluded crawler must not be vhost-challenged, got %+v", got)
	}
	if len(calls) == 0 || calls[0].ua != meta || calls[0].rule != "CHALLENGE_VHOST" {
		t.Fatalf("matcher not called with the request UA / vhost rule: %+v", calls)
	}
	if got := decide("Mozilla/5.0 (Windows NT 10.0) Chrome/150"); got["vhost_action"] != "challenge" {
		t.Fatalf("non-matching UA must stay challenged, got %+v", got)
	}

	// Per-IP challenge: lifted by skip, NOT by skip_vhost_only.
	setIP := func(action string) {
		b.mu.Lock()
		b.ipState[ip] = bridgeIPEntry{Action: action, Expires: time.Now().Add(time.Minute)}
		b.mu.Unlock()
	}
	setIP("challenge")
	if got := decide(meta); got["ip_action"] != "allow" || got["vhost_action"] != "allow" {
		t.Fatalf("skip must lift a per-IP challenge too, got %+v", got)
	}
	act = "skip_vhost_only"
	if got := decide(meta); got["ip_action"] != "challenge" || got["vhost_action"] != "allow" {
		t.Fatalf("skip_vhost_only must lift only the vhost-wide challenge, got %+v", got)
	}

	// A block is never softened (and the matcher is not even consulted).
	act = "skip"
	setIP("block")
	calls = nil
	if got := decide(meta); got["ip_action"] != "block" {
		t.Fatalf("exclude must not soften a block, got %+v", got)
	}
	if len(calls) != 0 {
		t.Fatalf("matcher consulted for a blocked IP: %+v", calls)
	}
}

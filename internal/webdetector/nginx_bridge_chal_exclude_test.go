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

// The operator challenge-exclude file is honoured at serve time against the
// VHOST-WIDE challenge: a request whose UA + ASN match an exclude rule is not
// served it (Meta's link-preview crawlers got "Just a moment…" on an auto
// suspicious_vhost challenge, 2026-10-01). A per-IP challenge (WAF push, geo
// floor, log-driven emit) and a block are never lifted.
func TestNginxBridgeChalExcludeHotDowngrade(t *testing.T) {
	b := NewNginxBridge("/tmp/cfm-test.sock", "tok", time.Minute, time.Minute)
	asnByIP := map[string]uint32{"2a03:2880:24ff:48::": 32934, "198.51.100.7": 16509}
	asnLookups := 0
	b.chalExcludeASNFn = func(ip string) uint32 { asnLookups++; return asnByIP[ip] }
	type call struct{ host, ua, asn, rule string }
	var calls []call
	// Shaped like the shipped rule: asn=as32934; ua=*meta*; action=skip — the
	// "AS<n>" string the bridge hands over is what the detectors matcher keys on.
	b.ChalExcludeHot = func(host, ua string, asn, ptr func() string, rule string) (string, string, bool) {
		if !strings.Contains(strings.ToLower(ua), "meta") {
			calls = append(calls, call{host, ua, "", rule})
			return "", "", false
		}
		a := asn()
		calls = append(calls, call{host, ua, a, rule})
		return "skip", "asn=as32934; ua=*meta*; action=skip", a == "AS32934"
	}

	decide := func(ip, ua string) map[string]any {
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
	const metaIP = "2a03:2880:24ff:48::"
	meta := "meta-externalads/1.1 (+https://developers.facebook.com/docs/sharing/webmasters/crawler)"

	if got := decide(metaIP, meta); got["vhost_action"] != "allow" || got["ip_action"] != "allow" {
		t.Fatalf("excluded crawler must not be vhost-challenged, got %+v", got)
	}
	if len(calls) != 1 || calls[0].ua != meta || calls[0].asn != "AS32934" || calls[0].rule != "CHALLENGE_VHOST" {
		t.Fatalf("matcher not called once with the request UA / AS<n> / vhost rule: %+v", calls)
	}
	if n := b.snapshotBridgeStats(0, 0).ChallengeExcludeLifts; n != 1 {
		t.Fatalf("ChallengeExcludeLifts = %d, want 1", n)
	}
	if got := decide("198.51.100.7", meta); got["vhost_action"] != "challenge" {
		t.Fatalf("meta UA off the Meta ASN must stay challenged, got %+v", got)
	}
	if n := b.snapshotBridgeStats(0, 0).ChallengeExcludeLifts; n != 1 {
		t.Fatalf("a non-lift counted: ChallengeExcludeLifts = %d, want 1", n)
	}
	asnLookups = 0
	if got := decide(metaIP, "Mozilla/5.0 (Windows NT 10.0) Chrome/150"); got["vhost_action"] != "challenge" {
		t.Fatalf("non-matching UA must stay challenged, got %+v", got)
	}
	if asnLookups != 0 {
		t.Fatalf("ASN resolved for a request no rule could match (%d lookups)", asnLookups)
	}

	// A per-IP challenge is NOT lifted (it may be a WAF challenge-tier push or
	// the geo floor), only the vhost-wide one.
	setIP := func(action string) {
		b.mu.Lock()
		b.ipState[metaIP] = bridgeIPEntry{Action: action, Expires: time.Now().Add(time.Minute)}
		b.mu.Unlock()
	}
	setIP("challenge")
	if got := decide(metaIP, meta); got["ip_action"] != "challenge" || got["vhost_action"] != "allow" {
		t.Fatalf("only the vhost-wide challenge may be lifted, got %+v", got)
	}

	// A block is never softened (and the matcher is not even consulted).
	setIP("block")
	calls = nil
	if got := decide(metaIP, meta); got["ip_action"] != "block" {
		t.Fatalf("exclude must not soften a block, got %+v", got)
	}
	if len(calls) != 0 {
		t.Fatalf("matcher consulted for a blocked IP: %+v", calls)
	}
}

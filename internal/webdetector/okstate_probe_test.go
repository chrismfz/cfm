package webdetector

import (
	"encoding/json"
	"fmt"
	"net/http"
	"net/http/httptest"
	"strings"
	"sync"
	"testing"
	"time"
)

func captureOKProbe(t *testing.T) func() []string {
	t.Helper()
	resetOKProbeForTest()
	var mu sync.Mutex
	var lines []string
	prev := okProbeLogf
	okProbeLogf = func(format string, args ...interface{}) {
		mu.Lock()
		lines = append(lines, fmt.Sprintf(format, args...))
		mu.Unlock()
	}
	t.Cleanup(func() { okProbeLogf = prev; resetOKProbeForTest() })
	return func() []string {
		mu.Lock()
		defer mu.Unlock()
		return append([]string(nil), lines...)
	}
}

// okState on: a client from the IP that solved passes a vhost challenge with
// no cookie of its own, and the probe says so (mode=allow), once per pair per
// okProbeLogEvery.
func TestOKStateProbe_Allow(t *testing.T) {
	got := captureOKProbe(t)
	b := NewNginxBridge("/tmp/cfm-test-okprobe.sock", "tok", time.Minute, 45*time.Minute)
	const ip, host = "203.0.113.70", "shop.example.gr"
	b.ChallengeVhostWithReason(host, time.Hour, "manual")
	b.ClearIPScoped(ip, host, "web") // the IP solved
	if a := decisionVhostAction(t, b, ip, host); a != "allow" {
		t.Fatalf("vhost_action=%q, want okState's allow", a)
	}
	decisionVhostAction(t, b, ip, host)
	lines := got()
	if len(lines) != 1 || !strings.Contains(lines[0], "okstate mode=allow ip="+ip+" host="+host+" scope=web vh=challenge ipa=allow solved_ago=") {
		t.Fatalf("lines=%q, want one mode=allow line", lines)
	}
}

// okState off (OPENRESTY_OK_IP_TTL = 0): the same client is challenged, and
// the probe records what okState would have let through (mode=would). A pair
// that never solved writes nothing.
func TestOKStateProbe_Would(t *testing.T) {
	got := captureOKProbe(t)
	b := NewNginxBridge("/tmp/cfm-test-okprobe0.sock", "tok", time.Minute, 0)
	const ip, host = "203.0.113.71", "shop.example.gr"
	b.ChallengeVhostWithReason(host, time.Hour, "manual")
	if a := decisionVhostAction(t, b, "203.0.113.72", host); a != "challenge" {
		t.Fatalf("unsolved: vhost_action=%q", a)
	}
	if len(got()) != 0 {
		t.Fatalf("a pair that never solved wrote %q", got())
	}
	b.ClearIPScoped(ip, host, "web")
	if a := decisionVhostAction(t, b, ip, host); a != "challenge" {
		t.Fatalf("TTL 0: vhost_action=%q, want challenge (cookie-only)", a)
	}
	lines := got()
	if len(lines) != 1 || !strings.Contains(lines[0], "okstate mode=would ip="+ip) {
		t.Fatalf("lines=%q, want one mode=would line", lines)
	}
}

// okState clears a per-IP block too, not only a challenge: the probe must
// show that one (ipa=block), it is the worse case.
func TestOKStateProbe_AllowOverABlock(t *testing.T) {
	got := captureOKProbe(t)
	b := NewNginxBridge("/tmp/cfm-test-okprobeb.sock", "tok", time.Minute, 45*time.Minute)
	const ip, host = "203.0.113.73", "shop.example.gr"
	b.ClearIPScoped(ip, host, "web")
	b.mu.Lock()
	b.ipState[ip] = bridgeIPEntry{Action: "block", Expires: time.Now().Add(time.Hour)}
	b.mu.Unlock()
	if a := decisionIPAction(t, b, ip, host); a != "allow" {
		t.Fatalf("ip_action=%q: okState no longer clears a block (update this test)", a)
	}
	lines := got()
	if len(lines) != 1 || !strings.Contains(lines[0], "okstate mode=allow ip="+ip) || !strings.Contains(lines[0], " ipa=block ") {
		t.Fatalf("lines=%q, want one mode=allow line with ipa=block", lines)
	}
}

func decisionVhostAction(t *testing.T, b *NginxBridge, ip, host string) string {
	t.Helper()
	rr := httptestDecision(t, b, ip, host)
	s, _ := rr["vhost_action"].(string)
	return s
}

func httptestDecision(t *testing.T, b *NginxBridge, ip, host string) map[string]any {
	t.Helper()
	rr := httptest.NewRecorder()
	req := httptest.NewRequest(http.MethodGet, "/nginx/decision?ip="+ip+"&host="+host+"&scope=web&ua=x", nil)
	req.Header.Set("X-CFM-Token", "tok")
	b.handleDecision(rr, req)
	var out map[string]any
	_ = json.Unmarshal(rr.Body.Bytes(), &out)
	return out
}

// A real verify records the solve for the probe under its host and scope.
// The release goes through ClearIP, which carries no host, so before this the
// probe never saw a solve and wrote no mode=would line at all (0 fleet-wide,
// 2026-11-26 read).
func TestOKStateProbe_VerifyRecordsTheSolve(t *testing.T) {
	got := captureOKProbe(t)
	base, _ := startVerifyServer(t)
	const ip, host = "198.51.100.73", "shop.example"
	body := `{"v":1,"wd":false,"ptr":12,"tch":0,"key":0,"mv":400}`
	if resp := verifyPoster(t, base, ip, host, confirmUA, time.Now().UTC())(body, nil); resp.StatusCode != http.StatusSeeOther {
		t.Fatalf("web solve: status=%d, want 303", resp.StatusCode)
	}
	if _, ok := okProbeSolved.get(okProbeKey(ip, host, "web"), time.Now()); !ok {
		t.Fatal("the web solve was not recorded for the okstate probe")
	}
	// End to end: the edge's decision for the same pair (no cookie of its
	// own, TTL 0) reads the verify's record and writes the would line.
	b := NewNginxBridge("/tmp/cfm-test-okprobe-e2e.sock", "tok", time.Minute, 0)
	b.ChallengeVhostWithReason(host, time.Hour, "manual")
	if a := decisionVhostAction(t, b, ip, host); a != "challenge" {
		t.Fatalf("TTL 0: vhost_action=%q, want challenge", a)
	}
	if lines := got(); len(lines) != 1 || !strings.Contains(lines[0], "okstate mode=would ip="+ip+" host="+host+" scope=web") {
		t.Fatalf("lines=%q, want one mode=would line from the verify's solve", lines)
	}
	panel := map[string]string{"X-CFM-Panel-Port": "2083", "X-Forwarded-Port": "2083"}
	if resp := verifyPoster(t, base, ip, host, confirmUA, time.Now().UTC())(body, panel); resp.StatusCode != http.StatusSeeOther {
		t.Fatalf("panel solve: status=%d, want 303", resp.StatusCode)
	}
	if _, ok := okProbeSolved.get(okProbeKey(ip, host, "panel:2083"), time.Now()); !ok {
		t.Fatal("the panel solve was not recorded for the okstate probe")
	}
}

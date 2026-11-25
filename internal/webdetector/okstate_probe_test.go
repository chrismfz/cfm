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

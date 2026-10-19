package apiserver

// Tests for edge_health Check F (cdn-cached-challenge): a CDN in front of the
// edge serving CFM's challenge from its cache (mars, anastasiadi.gr,
// 2026-10-19).

import (
	"context"
	"strings"
	"testing"
	"time"

	webdet "cfm/internal/webdetector"
)

func TestCDNCachedChallenge_NamesTheHost(t *testing.T) {
	defer stubEdgeHealth(t)()
	stubDropScan(t, 1000, nil)
	last := time.Unix(dropTestNow-120, 0)
	edgeHealthCDNSuspects = func(now time.Time) []webdet.CDNCacheSuspect {
		if !now.Equal(time.Unix(dropTestNow, 0)) {
			t.Errorf("Check F read the tracker at %v, want the report's clock", now)
		}
		return []webdet.CDNCacheSuspect{
			{Host: "www.anastasiadi.gr", IPs: 41, Bounces: 147, First: last.Add(-time.Hour), Last: last},
			{Host: "anastasiadi.gr", IPs: 9, Bounces: 32, First: last, Last: last},
			// One client bouncing many times (it chose the Host header) stays
			// out of triage: the threshold is on distinct IPs.
			{Host: "happy-nest.gr", IPs: 1, Bounces: 40, First: last, Last: last},
		}
	}
	rep := buildEdgeHealthReport(context.Background(), 1000)
	f := findFinding(t, rep, "cdn-cached-challenge")
	if f["severity"] != "warn" {
		t.Fatalf("severity = %v, want warn", f["severity"])
	}
	s := f["summary"].(string)
	if !strings.Contains(s, "www.anastasiadi.gr, anastasiadi.gr") || strings.Contains(s, "happy-nest.gr") {
		t.Fatalf("summary = %q, want the two hosts at or over the floor and not the stray one", s)
	}
	if n, _ := f["next"].(string); !strings.Contains(n, "Cache-Control") || !strings.Contains(n, "purge") {
		t.Fatalf("next = %q, want the CDN rule fix and a purge", n)
	}
	hosts := f["evidence"].(map[string]any)["hosts"].([]map[string]any)
	if len(hosts) != 2 || hosts[0]["ips"] != 41 || hosts[0]["bounces"] != 147 {
		t.Fatalf("evidence hosts = %v", hosts)
	}
	if rep["overall"] != "warn" {
		t.Fatalf("overall = %v, want warn", rep["overall"])
	}
}

func TestCDNCachedChallenge_QuietIsOK(t *testing.T) {
	defer stubEdgeHealth(t)()
	stubDropScan(t, 1000, nil)
	f := findFinding(t, buildEdgeHealthReport(context.Background(), 1000), "cdn-cached-challenge")
	if f["severity"] != "ok" {
		t.Fatalf("severity = %v, want ok with no suspects", f["severity"])
	}
	// An empty list, never JSON null.
	if hosts, ok := f["evidence"].(map[string]any)["hosts"].([]map[string]any); !ok || hosts == nil {
		t.Fatalf("evidence hosts = %#v, want an empty list", f["evidence"].(map[string]any)["hosts"])
	}
}

// Without a challenge server nothing can bounce: Check F measured nothing,
// which is unknown, never an all-clear.
func TestCDNCachedChallenge_NoChallengeServerIsUnknown(t *testing.T) {
	defer stubEdgeHealth(t)()
	stubDropScan(t, 1000, nil)
	edgeHealthChallengeServing = func() bool { return false }
	f := findFinding(t, buildEdgeHealthReport(context.Background(), 1000), "cdn-cached-challenge")
	if f["severity"] != "unknown" {
		t.Fatalf("severity = %v, want unknown when the challenge server is not serving", f["severity"])
	}
}

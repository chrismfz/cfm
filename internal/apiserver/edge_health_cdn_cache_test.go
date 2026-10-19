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
			{Host: "www.anastasiadi.gr", Count: 147, First: last.Add(-time.Hour), Last: last},
			{Host: "anastasiadi.gr", Count: 32, First: last, Last: last},
			// One stray bounce (a bridge-token rotation window) stays out of triage.
			{Host: "happy-nest.gr", Count: 2, First: last, Last: last},
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
	if len(hosts) != 2 || hosts[0]["count"] != 147 {
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
}

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
			// out of triage: the threshold is on distinct clients.
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

// Without a challenge server this node serves no challenge page a CDN could
// cache: Check F is ok, marked measured=false, and leaves overall alone (an
// unknown there pinned overall on every node running without it).
func TestCDNCachedChallenge_NoChallengeServerIsNotMeasured(t *testing.T) {
	defer stubEdgeHealth(t)()
	stubDropScan(t, 1000, nil)
	base := buildEdgeHealthReport(context.Background(), 1000)["overall"]
	edgeHealthChallengeServing = func() bool { return false }
	rep := buildEdgeHealthReport(context.Background(), 1000)
	f := findFinding(t, rep, "cdn-cached-challenge")
	if f["severity"] != "ok" || f["evidence"].(map[string]any)["measured"] != false ||
		!strings.Contains(f["summary"].(string), "not measured") {
		t.Fatalf("finding = %v, want ok, measured=false, \"not measured\"", f)
	}
	if rep["overall"] != base {
		t.Fatalf("overall = %v, want %v as with the server up", rep["overall"], base)
	}
}

// The tracker outlives a listener that stopped after counting (a reload builds
// a new Engine; the old Serve exits first): what it counted still warns.
func TestCDNCachedChallenge_SuspectsWarnWhileNotServing(t *testing.T) {
	defer stubEdgeHealth(t)()
	stubDropScan(t, 1000, nil)
	edgeHealthChallengeServing = func() bool { return false }
	last := time.Unix(dropTestNow-120, 0)
	edgeHealthCDNSuspects = func(time.Time) []webdet.CDNCacheSuspect {
		return []webdet.CDNCacheSuspect{{Host: "www.anastasiadi.gr", IPs: 5, Bounces: 9, First: last, Last: last}}
	}
	if f := findFinding(t, buildEdgeHealthReport(context.Background(), 1000), "cdn-cached-challenge"); f["severity"] != "warn" {
		t.Fatalf("severity = %v, want warn: counted suspects outrank a stopped listener", f["severity"])
	}
}

// orion, 2026-10-21: cleared bounces that reached the edge directly (no
// trusted proxy) are listed in evidence.direct_hosts and named in the summary,
// but never raise the warning: a browser re-opening the challenge address, or
// a CDN the edge does not trust as a proxy. A relayed suspect still warns.
func TestCDNCachedChallenge_DirectAndDownloadBouncesAreListedNotWarned(t *testing.T) {
	defer stubEdgeHealth(t)()
	stubDropScan(t, 1000, nil)
	last := time.Unix(dropTestNow-120, 0)
	edgeHealthDirectBounces = func(time.Time) []webdet.CDNCacheSuspect {
		return []webdet.CDNCacheSuspect{
			{Host: "www.mathematica.gr", IPs: 6, Bounces: 7, First: last, Last: last},
			{Host: "one-client.gr", IPs: 1, Bounces: 9, First: last, Last: last},
		}
	}
	rep := buildEdgeHealthReport(context.Background(), 1000)
	f := findFinding(t, rep, "cdn-cached-challenge")
	if f["severity"] != "ok" || rep["overall"] == "warn" {
		t.Fatalf("direct bounces only: severity %v, overall %v; want ok", f["severity"], rep["overall"])
	}
	ev := f["evidence"].(map[string]any)
	direct := ev["direct_hosts"].([]map[string]any)
	if len(direct) != 1 || direct[0]["host"] != "www.mathematica.gr" || direct[0]["ips"] != 6 {
		t.Fatalf("direct_hosts = %v, want mathematica.gr only (the floor applies)", direct)
	}
	if hosts := ev["hosts"].([]map[string]any); len(hosts) != 0 {
		t.Fatalf("hosts = %v, want none", hosts)
	}
	if s := f["summary"].(string); !strings.Contains(s, "1 vhost(s) had cleared visitors bounce back to the challenge DIRECTLY") {
		t.Fatalf("summary = %q, want the direct note", s)
	}
	if d := ev["download_hosts"].([]map[string]any); len(d) != 0 {
		t.Fatalf("download_hosts = %v, want an empty list", d)
	}

	// A relayed download (a CDN rule caching file extensions only, or a phone
	// re-tapping a download behind the CDN): listed, not a warning.
	edgeHealthDownloadBounces = func(time.Time) []webdet.CDNCacheSuspect {
		return []webdet.CDNCacheSuspect{{Host: "cf-pdfs.example", IPs: 3, Bounces: 3, First: last, Last: last}}
	}
	f = findFinding(t, buildEdgeHealthReport(context.Background(), 1000), "cdn-cached-challenge")
	if f["severity"] != "ok" || !strings.Contains(f["summary"].(string), "for a DOWNLOAD") {
		t.Fatalf("relayed downloads: %v %q, want ok with the download note", f["severity"], f["summary"])
	}
	if d := f["evidence"].(map[string]any)["download_hosts"].([]map[string]any); len(d) != 1 || d[0]["host"] != "cf-pdfs.example" {
		t.Fatalf("download_hosts = %v", d)
	}

	// Not measured: the note still reads on its own.
	edgeHealthChallengeServing = func() bool { return false }
	f = findFinding(t, buildEdgeHealthReport(context.Background(), 1000), "cdn-cached-challenge")
	if s := f["summary"].(string); f["severity"] != "ok" || !strings.HasPrefix(s, "not measured") || !strings.Contains(s, "bounce back to the challenge DIRECTLY") {
		t.Fatalf("measured=false: %v %q", f["severity"], s)
	}
	edgeHealthChallengeServing = func() bool { return true }

	edgeHealthCDNSuspects = func(time.Time) []webdet.CDNCacheSuspect {
		return []webdet.CDNCacheSuspect{{Host: "www.amabilecreations.com", IPs: 4, Bounces: 6, First: last, Last: last}}
	}
	f = findFinding(t, buildEdgeHealthReport(context.Background(), 1000), "cdn-cached-challenge")
	if s := f["summary"].(string); f["severity"] != "warn" || !strings.Contains(s, "www.amabilecreations.com") || !strings.Contains(s, "DIRECTLY") || !strings.Contains(s, "for a DOWNLOAD") {
		t.Fatalf("relayed suspect: %v %q, want warn naming it, with both notes", f["severity"], s)
	}
}

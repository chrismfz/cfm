package webdetector

import (
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"path/filepath"
	"testing"
	"time"
)

// edgeRec builds a request the edge answered with upstream / status.
func edgeRec(host, uri, upstream string, status int, toUpstream bool) LogRec {
	return LogRec{IP: "203.0.113.7", Host: host, Method: "GET", URI: uri, UA: tmChrome152, Status: status, Bytes: 500, Upstream: toUpstream, UpstreamName: upstream}
}

func feedOutcomes(s *trafficMixStore, at time.Time) {
	for i := 0; i < 10; i++ {
		tmFeed(s, tmOrigin("203.0.113.7", "a.example", "GET", "/p", tmChrome152, 200, 0.05), at)
	}
	for i := 0; i < 4; i++ {
		tmFeed(s, tmOrigin("203.0.113.8", "www.a.example", "GET", "/p", tmChrome152, 200, 0.05), at)
	}
	for i := 0; i < 3; i++ {
		tmFeed(s, edgeRec("a.example", "/p", "cfm_challenge", 403, false), at)
	}
	tmFeed(s, edgeRec("a.example", "/__cfm_challenge?next=%2Fp", "cfm_apache", 200, true), at)
	// A cleared / exempt client the page sends on (303): no page served.
	tmFeed(s, edgeRec("a.example", "/__cfm_challenge?next=%2Fp", "cfm_apache", 303, true), at)
	tmFeed(s, edgeRec("a.example", "/__cfm_verify", "cfm_apache", 303, false), at)
	tmFeed(s, edgeRec("a.example", "/__cfm_verify", "cfm_apache", 303, false), at)
	tmFeed(s, edgeRec("a.example", "/__cfm_verify", "cfm_apache", 403, false), at)
	tmFeed(s, edgeRec("a.example", "/x", "cfm_block", 403, false), at)
	tmFeed(s, edgeRec("a.example", "/x", "cfm_block", 403, false), at)
	tmFeed(s, edgeRec("a.example", "/y", "cfm_block_rule", 403, false), at)
	// A busy vhost with a high challenged share, and a busy one without.
	for i := 0; i < 300; i++ {
		tmFeed(s, tmOrigin("203.0.113.9", "b.example", "GET", "/", tmChrome152, 200, 0.01), at)
		tmFeed(s, tmOrigin("203.0.113.9", "c.example", "GET", "/", tmChrome152, 200, 0.01), at)
	}
	for i := 0; i < 100; i++ {
		tmFeed(s, edgeRec("b.example", "/", "cfm_challenge", 403, false), at)
	}
}

func TestEdgeOutcomesHostAndNode(t *testing.T) {
	s := newTrafficMixStore()
	now := time.Now()
	feedOutcomes(s, now.Add(-30*time.Minute))
	// Three hours ago: inside 6h and 24h, outside 1h.
	tmFeed(s, edgeRec("a.example", "/p", "cfm_challenge", 403, false), now.Add(-3*time.Hour))

	a := s.Outcomes(now, 24*time.Hour, "A.example", false)
	o := a.Outcomes
	if a.Requests != 26 || o.Challenged != 9 || o.ChallengePages != 1 || o.VerifySentOn != 2 || o.VerifyRefused != 1 || o.Blocked != 2 || o.RuleBlocked != 1 || o.Origin != 14 {
		t.Fatalf("a.example 24h: %d requests, %+v", a.Requests, *o)
	}
	if a.StepSec != 3600 || a.Since%3600 != 0 || a.Hosts != nil {
		t.Fatalf("step %d since %d hosts %v", a.StepSec, a.Since, a.Hosts)
	}
	var sum, ch int64
	for i, p := range a.Series {
		if p.T%3600 != 0 || (i > 0 && p.T != a.Series[i-1].T+3600) || p.Outcomes == nil {
			t.Fatalf("series point %d: %+v", i, p)
		}
		sum += p.Requests
		ch += p.Outcomes.Challenged
	}
	if sum != a.Requests || ch != o.Challenged || len(a.Series) < 24 || len(a.Series) > 25 {
		t.Fatalf("series: %d points, %d requests, %d challenged", len(a.Series), sum, ch)
	}

	// 1h: the 3-hours-ago page is out; 5-minute steps.
	h1 := s.Outcomes(now, time.Hour, "a.example", false)
	if h1.Outcomes.Challenged != 8 || h1.StepSec != tmBucketSec {
		t.Fatalf("1h: %+v step %d", *h1.Outcomes, h1.StepSec)
	}
	// 6h: 15-minute steps, the old page is in.
	if h6 := s.Outcomes(now, 6*time.Hour, "a.example", false); h6.Outcomes.Challenged != 9 || h6.StepSec != 900 {
		t.Fatalf("6h: %+v step %d", *h6.Outcomes, h6.StepSec)
	}
	// www.x never brings x.
	if w := s.Outcomes(now, 24*time.Hour, "www.a.example", false); w.Requests != 4 {
		t.Fatalf("www.a.example: %d", w.Requests)
	}

	node := s.Outcomes(now, 24*time.Hour, "", true)
	if node.Requests != 26+300+300+100 {
		t.Fatalf("node requests %d", node.Requests)
	}
	for i := 0; i < 250; i++ {
		tmFeed(s, tmOrigin("203.0.113.9", "www.c.example", "GET", "/", tmChrome152, 200, 0.01), now.Add(-20*time.Minute))
	}
	node = s.Outcomes(now, 24*time.Hour, "", true)
	if len(node.Hosts) != 2 || node.Hosts[0].Host != "b.example" || node.Hosts[1].Host != "c.example" || node.Hosts[0].Outcomes.Challenged != 100 || node.Hosts[1].Requests != 550 {
		t.Fatalf("node hosts (min %d requests, most challenged first): %+v", edgeOutcomeHostMinReq, node.Hosts)
	}
	if s.Outcomes(now, 24*time.Hour, "", false).Hosts != nil {
		t.Fatal("hosts without withHosts")
	}
	// An empty store answers zeros, never an error.
	if e := newTrafficMixStore().Outcomes(now, time.Hour, "", true); e.Requests != 0 || e.Outcomes == nil || len(e.Series) == 0 {
		t.Fatalf("empty store: %+v", e)
	}
}

func TestEdgeOutcomesAPIScope(t *testing.T) {
	prev := trafficMix
	trafficMix = newTrafficMixStore()
	t.Cleanup(func() { trafficMix = prev })
	feedOutcomes(trafficMix, time.Now().Add(-10*time.Minute))

	dir := t.TempDir()
	e := NewEngine(Config{
		HistoryEnabled: true, HistoryDBPath: filepath.Join(dir, "h.db"),
		ChallengeExcludeStorePath: filepath.Join(dir, "c.json"), WAFExcludeStorePath: filepath.Join(dir, "w.json"),
	})
	if e.history == nil {
		t.Fatal("no history store")
	}
	now := time.Now().Unix()
	for i, ev := range []HistoryEvent{
		{Type: "challenge_issued", Host: "a.example", IP: "198.51.100.1", Reason: "CHALLENGE_ERR_RATIO"},
		{Type: "challenge_issued", Host: "a.example", IP: "198.51.100.1", Reason: "CHALLENGE_ERR_RATIO"},
		{Type: "challenge_issued", Host: "www.a.example", IP: "198.51.100.2", Reason: "CHALLENGE_ERR_RATIO"},
		{Type: "challenge_issued", Host: "b.example", IP: "198.51.100.3", Reason: "WAF_LONG_PATH:SEG"},
		{Type: "challenge_solved", Host: "a.example", IP: "198.51.100.1", Reason: "x"},
	} {
		ev.TsUnix = now - int64(60*(i+1))
		e.history.Append(ev)
	}

	call := func(r *http.Request) (*httptest.ResponseRecorder, EdgeOutcomes) {
		rr := httptest.NewRecorder()
		e.handleEdgeOutcomes(rr, r)
		var out EdgeOutcomes
		_ = json.Unmarshal(rr.Body.Bytes(), &out)
		return rr, out
	}
	const p = "/api/v1/webdet/edge-outcomes"

	rr, node := call(adminReq("GET", p+"?hours=24"))
	if rr.Code != 200 || len(node.Hosts) == 0 || node.Hours != 24 {
		t.Fatalf("admin node: %d %s", rr.Code, rr.Body.String())
	}
	if len(node.Reasons) != 2 || node.Reasons[0].Reason != "CHALLENGE_ERR_RATIO" || node.Reasons[0].Decisions != 3 || node.Reasons[0].Addresses != 2 {
		t.Fatalf("admin reasons: %+v", node.Reasons)
	}
	_, ah := call(adminReq("GET", p+"?hours=6&host=a.example"))
	if ah.Requests != 25 || ah.Hosts != nil || len(ah.Reasons) != 1 || ah.Reasons[0].Decisions != 3 {
		t.Fatalf("admin host: %+v", ah)
	}

	if rr, _ := call(scopedReq("GET", p+"?hours=24", "a.example")); rr.Code != http.StatusBadRequest {
		t.Fatalf("scoped without host: %d", rr.Code)
	}
	if rr, _ := call(scopedReq("GET", p+"?hours=24&host=b.example", "a.example")); rr.Code != http.StatusForbidden {
		t.Fatalf("scoped, another site: %d", rr.Code)
	}
	rr, sc := call(scopedReq("GET", p+"?hours=24&host=a.example", "a.example"))
	if rr.Code != 200 || sc.Requests != 25 || sc.Hosts != nil || sc.Reasons != nil {
		t.Fatalf("scoped own site: %d %s", rr.Code, rr.Body.String())
	}
	for _, q := range []string{"?hours=7&host=a.example", "?hours=x&host=a.example", "?hours=168&host=a.example"} {
		if rr, _ := call(adminReq("GET", p+q)); rr.Code != http.StatusBadRequest {
			t.Fatalf("%s: %d", q, rr.Code)
		}
	}
	if rr, _ := call(adminReq("POST", p)); rr.Code != http.StatusMethodNotAllowed {
		t.Fatalf("POST: %d", rr.Code)
	}
	var raw map[string]interface{}
	_, _ = call(scopedReq("GET", p+"?hours=24&host=a.example", "a.example"))
	rr, _ = call(scopedReq("GET", p+"?hours=24&host=a.example", "a.example"))
	_ = json.Unmarshal(rr.Body.Bytes(), &raw)
	if _, ok := raw["reasons"]; ok {
		t.Fatal("a scoped reply carries the reasons key")
	}
}

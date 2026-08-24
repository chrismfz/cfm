package webdetector

import (
	"fmt"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"
)

// TestNginxBridgeHandlerBodyCaps verifies audit F49: the previously unbounded
// bridge POST handlers now cap their request body via http.MaxBytesReader.
//
// Two properties per handler:
//   - a body over the cap is rejected (400) instead of being buffered whole —
//     so a compromised/buggy edge can't spike RSS by streaming a giant body;
//   - a generously-large *legitimate* body is still accepted — the cap must
//     never reject real traffic (for ip_push that includes a padded-URI attack
//     we explicitly want to autoblock, so its forensic push must go through).
func TestNginxBridgeHandlerBodyCaps(t *testing.T) {
	const tok = "tok"
	pad := func(n int) string { return strings.Repeat("A", n) }

	post := func(h func(http.ResponseWriter, *http.Request), path, body string) int {
		rr := httptest.NewRecorder()
		req := httptest.NewRequest(http.MethodPost, path, strings.NewReader(body))
		req.Header.Set("X-CFM-Token", tok)
		h(rr, req)
		return rr.Code
	}

	cases := []struct {
		name    string
		pick    func(b *NginxBridge) func(http.ResponseWriter, *http.Request)
		path    string
		okBody  string // generously large but legitimate -> 200
		bigBody string // over the cap -> 400
	}{
		{
			name: "ip_push",
			pick: func(b *NginxBridge) func(http.ResponseWriter, *http.Request) { return b.handleIPPush },
			path: "/nginx/ip",
			// 128KB URI: a legit maxed push (operator-raised header buffers)
			// we must never reject. Well under the 256KB cap.
			okBody:  fmt.Sprintf(`{"ip":"203.0.113.5","action":"block","uri":"/%s"}`, pad(128*1024)),
			bigBody: fmt.Sprintf(`{"ip":"203.0.113.5","action":"block","uri":"/%s"}`, pad(300*1024)),
		},
		{
			name:    "ip_clear",
			pick:    func(b *NginxBridge) func(http.ResponseWriter, *http.Request) { return b.handleIPClear },
			path:    "/nginx/ip/clear",
			okBody:  `{"ip":"203.0.113.5"}`,
			bigBody: fmt.Sprintf(`{"ip":"%s"}`, pad(8*1024)),
		},
		{
			name:    "vhost_push",
			pick:    func(b *NginxBridge) func(http.ResponseWriter, *http.Request) { return b.handleVhostPush },
			path:    "/nginx/vhost",
			okBody:  `{"host":"example.com","ttl_sec":600,"reason":"scanner"}`,
			bigBody: fmt.Sprintf(`{"host":"%s.com"}`, pad(8*1024)),
		},
		{
			name:    "vhost_clear",
			pick:    func(b *NginxBridge) func(http.ResponseWriter, *http.Request) { return b.handleVhostClear },
			path:    "/nginx/vhost/clear",
			okBody:  `{"host":"example.com"}`,
			bigBody: fmt.Sprintf(`{"host":"%s"}`, pad(8*1024)),
		},
		{
			name: "waf_stats",
			pick: func(b *NginxBridge) func(http.ResponseWriter, *http.Request) { return b.handleWAFStats },
			path: "/nginx/waf/stats",
			// A fat-but-legit batch (~1MB of hostname) under the 2MB cap.
			okBody:  fmt.Sprintf(`{"rows":[{"hour_unix":1,"host":"%s","count":1}]}`, pad(1024*1024)),
			bigBody: fmt.Sprintf(`{"rows":[{"hour_unix":1,"host":"%s","count":1}]}`, pad(3*1024*1024)),
		},
	}

	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			b := NewNginxBridge("/tmp/cfm-test.sock", tok, time.Minute, time.Minute)
			if code := post(c.pick(b), c.path, c.okBody); code != http.StatusOK {
				t.Fatalf("legit body rejected: status=%d (cap is too tight — it must never reject real traffic)", code)
			}
			if code := post(c.pick(b), c.path, c.bigBody); code != http.StatusBadRequest {
				t.Fatalf("oversized body not rejected: status=%d, want 400 (body cap not enforced)", code)
			}
		})
	}
}

func TestNginxBridgeObserveCarriesUA(t *testing.T) {
	b := NewNginxBridge("/tmp/cfm-test.sock", "tok", time.Minute, time.Minute)
	var gotUA string
	b.SetObserveHook(func(_, _, _, _ string, _ int, _, ua string) {
		gotUA = ua
	})

	rr := httptest.NewRecorder()
	req := httptest.NewRequest(http.MethodPost, "/nginx/observe", strings.NewReader(
		`{"ip":"203.0.113.5","host":"shop.example","uri":"/checkout","method":"post","status":403,"reason":"WAF_SQLI","ua":"Mozilla/5.0 Legit"}`,
	))
	req.Header.Set("X-CFM-Token", "tok")
	b.handleObserve(rr, req)

	if rr.Code != http.StatusOK {
		t.Fatalf("observe status=%d body=%s", rr.Code, rr.Body.String())
	}
	if gotUA != "Mozilla/5.0 Legit" {
		t.Fatalf("observe UA=%q, want propagated user agent", gotUA)
	}
}

// TestNginxBridgeWAFStatsRowGuard verifies the per-push row-count ceiling added
// for F49: the /nginx/waf/stats handler fans out one persistence hook per row,
// so it caps the fan-out at maxWAFStatsRows regardless of how many rows a
// (compromised/buggy) edge packs into one push — while a normal batch (the edge
// snapshots at most get_keys(2000) buckets) is processed in full.
func TestNginxBridgeWAFStatsRowGuard(t *testing.T) {
	build := func(nRows int) string {
		var sb strings.Builder
		sb.WriteString(`{"rows":[`)
		for i := 0; i < nRows; i++ {
			if i > 0 {
				sb.WriteByte(',')
			}
			fmt.Fprintf(&sb, `{"hour_unix":%d,"host":"h","count":1}`, i)
		}
		sb.WriteString(`]}`)
		return sb.String()
	}

	run := func(nRows int) int {
		b := NewNginxBridge("/tmp/cfm-test.sock", "tok", time.Minute, time.Minute)
		var fired int
		// No dispatcher started (unit test) => dispatchHook runs inline on this
		// goroutine, so a plain counter is race-free.
		b.OnWAFStats = func(hourUnix int64, host string, count int) { fired++ }

		rr := httptest.NewRecorder()
		req := httptest.NewRequest(http.MethodPost, "/nginx/waf/stats", strings.NewReader(build(nRows)))
		req.Header.Set("X-CFM-Token", "tok")
		b.handleWAFStats(rr, req)
		if rr.Code != http.StatusOK {
			t.Fatalf("nRows=%d status=%d body=%s", nRows, rr.Code, rr.Body.String())
		}
		return fired
	}

	// A normal batch is processed in full — the guard must not clip legit rows.
	if got := run(2000); got != 2000 {
		t.Fatalf("legit 2000-row batch fanned out %d hooks, want 2000 (row guard clipped a real batch)", got)
	}
	// An over-large batch is capped at exactly maxWAFStatsRows.
	if got := run(maxWAFStatsRows + 500); got != maxWAFStatsRows {
		t.Fatalf("over-large batch fanned out %d hooks, want %d (row guard not enforced)", got, maxWAFStatsRows)
	}
}

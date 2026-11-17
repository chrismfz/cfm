package mysql

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/http"
	"net/http/httptest"
	"strings"
	"sync/atomic"
	"testing"
	"time"
)

// testLifecycle returns a lifecycle whose connect fails until ok is set, and
// whose governor never touches a database.
func testLifecycle(failWith error, ok *atomic.Bool, attempts *atomic.Int32) *GovernorLifecycle {
	l := NewGovernorLifecycle()
	l.newGovernor = func(cfg GovernorConfig) (*Governor, error) {
		attempts.Add(1)
		if !ok.Load() {
			return nil, failWith
		}
		g := &Governor{cfg: cfg}
		g.state.Mode = cfg.Mode
		g.state.Flavor = "test"
		return g, nil
	}
	l.run = func(context.Context, *Governor) {}
	l.pacing = retryPacing{min: time.Millisecond, max: 4 * time.Millisecond, noCreds: time.Millisecond}
	return l
}

func waitFor(t *testing.T, what string, cond func() bool) {
	t.Helper()
	deadline := time.Now().Add(5 * time.Second)
	for !cond() {
		if time.Now().After(deadline) {
			t.Fatalf("timed out waiting for %s", what)
		}
		time.Sleep(time.Millisecond)
	}
}

func serve(h http.Handler, path string) *httptest.ResponseRecorder {
	rec := httptest.NewRecorder()
	h.ServeHTTP(rec, httptest.NewRequest(http.MethodGet, path, nil))
	return rec
}

// The orion case: MySQL comes up after the daemon. The governor must start on
// a retry, and its routes must answer 503 JSON (never fall through to HTML)
// until then, then the real handler.
func TestLifecycleStartsGovernorWhenMySQLComesUpLater(t *testing.T) {
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()

	var ok atomic.Bool
	var attempts atomic.Int32
	l := testLifecycle(fmt.Errorf("connect via /root/.my.cnf failed: %w", errors.New("connection refused")), &ok, &attempts)

	var cfgCalls atomic.Int32
	cfg := func() *GovernorConfig {
		cfgCalls.Add(1)
		return &GovernorConfig{Mode: "enforce"}
	}
	if g := l.Start(ctx, cfg); g != nil {
		t.Fatalf("Start returned a governor while MySQL is down")
	}

	rec := serve(l.AdminHandler(), "/api/v1/mysql/state")
	if rec.Code != http.StatusServiceUnavailable {
		t.Fatalf("admin route while down: HTTP %d, want 503", rec.Code)
	}
	if ct := rec.Header().Get("Content-Type"); !strings.Contains(ct, "json") {
		t.Fatalf("admin route while down: Content-Type %q, want JSON", ct)
	}
	var body map[string]string
	if err := json.Unmarshal(rec.Body.Bytes(), &body); err != nil {
		t.Fatalf("503 body is not JSON: %v: %s", err, rec.Body)
	}
	if body["error"] != "mysql governor not running" || !strings.Contains(body["reason"], "connection refused") {
		t.Fatalf("503 body = %v", body)
	}

	// Scoped callers get no reason (it names the node's credential files).
	rec = serve(l.ScopedHandler(), "/api/v1/mysql/user-summary?user=x")
	if rec.Code != http.StatusServiceUnavailable || strings.Contains(rec.Body.String(), "reason") {
		t.Fatalf("scoped route while down: HTTP %d %s", rec.Code, rec.Body)
	}

	waitFor(t, "a few retries", func() bool { return attempts.Load() >= 3 })
	ok.Store(true)
	waitFor(t, "governor start", func() bool { return l.Governor() != nil })

	if l.Status() != "" {
		t.Fatalf("Status after start = %q, want empty", l.Status())
	}
	if got := l.Governor().cfg.Mode; got != "enforce" {
		t.Fatalf("governor mode = %q: the retry must use the config current at that attempt", got)
	}
	if cfgCalls.Load() != attempts.Load() {
		t.Fatalf("config read %d times for %d attempts, want once per attempt", cfgCalls.Load(), attempts.Load())
	}

	rec = serve(l.AdminHandler(), "/api/v1/mysql/state")
	if rec.Code != http.StatusOK {
		t.Fatalf("admin route after start: HTTP %d %s", rec.Code, rec.Body)
	}
	var st GovernorState
	if err := json.Unmarshal(rec.Body.Bytes(), &st); err != nil || st.Flavor != "test" {
		t.Fatalf("state after start = %+v (%v)", st, err)
	}

	// Started: no more attempts.
	n := attempts.Load()
	time.Sleep(20 * time.Millisecond)
	if attempts.Load() != n {
		t.Fatalf("retry kept running after the governor started")
	}
}

// MySQL up at daemon start: the governor starts inline, no retry goroutine.
func TestLifecycleStartsInlineWhenMySQLIsUp(t *testing.T) {
	var ok atomic.Bool
	ok.Store(true)
	var attempts atomic.Int32
	l := testLifecycle(nil, &ok, &attempts)
	if g := l.Start(context.Background(), nil); g == nil {
		t.Fatal("Start returned nil with MySQL up")
	}
	if g := l.Start(context.Background(), nil); g == nil || attempts.Load() != 1 {
		t.Fatalf("second Start: gov=%v attempts=%d, want the same governor and no new attempt", g, attempts.Load())
	}
}

// A node without a database must not retry forever after shutdown.
func TestLifecycleRetryStopsWithContext(t *testing.T) {
	ctx, cancel := context.WithCancel(context.Background())
	var ok atomic.Bool
	var attempts atomic.Int32
	l := testLifecycle(errNoCredentials, &ok, &attempts)
	l.Start(ctx, nil)
	waitFor(t, "a retry", func() bool { return attempts.Load() >= 2 })
	cancel()
	time.Sleep(10 * time.Millisecond)
	n := attempts.Load()
	time.Sleep(20 * time.Millisecond)
	if attempts.Load() != n {
		t.Fatalf("retry kept running after the context ended")
	}
	if !strings.Contains(l.Status(), "no MySQL credentials") {
		t.Fatalf("Status = %q", l.Status())
	}
}

func TestNextRetryDelay(t *testing.T) {
	p := NewGovernorLifecycle().pacing
	backoff := p.min
	connErr := errors.New("connection refused")
	var got []time.Duration
	for i := 0; i < 9; i++ {
		got = append(got, p.next(connErr, &backoff))
	}
	want := []time.Duration{5 * time.Second, 10 * time.Second, 20 * time.Second, 40 * time.Second,
		80 * time.Second, 160 * time.Second, 5 * time.Minute, 5 * time.Minute, 5 * time.Minute}
	for i := range want {
		if got[i] != want[i] {
			t.Fatalf("connect backoff = %v, want %v", got, want)
		}
	}

	wrapped := fmt.Errorf("mysql_governor: cannot connect: %w", errNoCredentials)
	if d := p.next(wrapped, &backoff); d != retryNoCredsDelay {
		t.Fatalf("no-credentials delay = %v, want %v", d, retryNoCredsDelay)
	}
	if backoff != retryMinDelay {
		t.Fatalf("no-credentials must reset the connect backoff, got %v", backoff)
	}
}

func TestGovernorRespError(t *testing.T) {
	mk := func(code int, ct, body string) *http.Response {
		h := http.Header{}
		h.Set("Content-Type", ct)
		return &http.Response{StatusCode: code, Header: h, Body: io.NopCloser(strings.NewReader(body))}
	}

	if err := governorRespError(mk(200, "application/json; charset=utf-8", `{}`)); err != nil {
		t.Fatalf("2xx JSON: %v", err)
	}

	err := governorRespError(mk(503, "application/json; charset=utf-8",
		`{"error":"mysql governor not running","reason":"no MySQL credentials found"}`))
	if err == nil || !strings.Contains(err.Error(), "mysql governor not running: no MySQL credentials found") {
		t.Fatalf("503: %v", err)
	}

	// An older daemon: the route is not registered, the web UI answers HTML.
	err = governorRespError(mk(200, "text/html; charset=utf-8", "<!doctype html>"))
	if err == nil || !strings.Contains(err.Error(), "not JSON") || strings.Contains(err.Error(), "invalid character") {
		t.Fatalf("HTML: %v", err)
	}
}

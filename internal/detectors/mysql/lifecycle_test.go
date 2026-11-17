package mysql

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strconv"
	"strings"
	"sync/atomic"
	"testing"
	"time"
)

// testLifecycle returns a lifecycle whose connect fails with failWith until ok
// is set, and whose governor never touches a database.
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

func connRefused() error {
	return fmt.Errorf("mysql_governor: cannot connect: %w",
		&connectError{source: "/root/.my.cnf", err: errors.New("dial unix /run/mysqld/mysqld.sock: connect: connection refused")})
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

// assertStopped fails if attempts still grow: the loop must have exited.
func assertStopped(t *testing.T, attempts *atomic.Int32, why string) {
	t.Helper()
	time.Sleep(10 * time.Millisecond)
	n := attempts.Load()
	time.Sleep(20 * time.Millisecond)
	if attempts.Load() != n {
		t.Fatalf("connect loop kept running %s", why)
	}
}

// The orion case: MySQL comes up after the daemon. The governor must start on
// a retry, and its routes must answer 503 JSON (never fall through to HTML)
// until then, then the real handler.
func TestLifecycleStartsGovernorWhenMySQLComesUpLater(t *testing.T) {
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()

	var ok atomic.Bool
	var attempts atomic.Int32
	l := testLifecycle(connRefused(), &ok, &attempts)

	var cfgCalls atomic.Int32
	cfg := func() *GovernorConfig {
		cfgCalls.Add(1)
		return &GovernorConfig{Enabled: true, Mode: "enforce"}
	}
	l.Start(ctx, cfg)
	waitFor(t, "a few failed attempts", func() bool { return attempts.Load() >= 3 })

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
	// Admin: a one-word state in `error` (what MCP carries), the detail in
	// `reason` (what only the admin HTTP API shows).
	if body["error"] != "mysql governor not running: connect failed" || !strings.Contains(body["reason"], "connection refused") {
		t.Fatalf("503 body = %v", body)
	}

	// Scoped callers get neither the state nor the reason (it names the
	// node's credential files).
	rec = serve(l.ScopedHandler(), "/api/v1/mysql/user-summary?user=x")
	var sb map[string]string
	if rec.Code != http.StatusServiceUnavailable || json.Unmarshal(rec.Body.Bytes(), &sb) != nil ||
		len(sb) != 1 || sb["error"] != "mysql governor not running" {
		t.Fatalf("scoped route while down: HTTP %d %s", rec.Code, rec.Body)
	}

	ok.Store(true)
	waitFor(t, "governor start", func() bool { return l.Governor() != nil })

	if l.Status() != "" {
		t.Fatalf("Status after start = %q, want empty", l.Status())
	}
	if got := l.Governor().cfg.Mode; got != "enforce" {
		t.Fatalf("governor mode = %q: an attempt must use the config current at that attempt", got)
	}
	if cfgCalls.Load() != attempts.Load() {
		t.Fatalf("config read %d times for %d attempts, want once per attempt", cfgCalls.Load(), attempts.Load())
	}

	for _, h := range []http.Handler{l.AdminHandler(), l.AdminHandler()} { // built once, then reused
		rec = serve(h, "/api/v1/mysql/state")
		if rec.Code != http.StatusOK {
			t.Fatalf("admin route after start: HTTP %d %s", rec.Code, rec.Body)
		}
		var st GovernorState
		if err := json.Unmarshal(rec.Body.Bytes(), &st); err != nil || st.Flavor != "test" {
			t.Fatalf("state after start = %+v (%v)", st, err)
		}
	}
	assertStopped(t, &attempts, "after the governor started")
}

// MySQL up at daemon start: one attempt, and Start never blocks on it.
func TestLifecycleStartReturnsAtOnceAndConnectsOnce(t *testing.T) {
	var ok atomic.Bool
	ok.Store(true)
	var attempts atomic.Int32
	l := testLifecycle(nil, &ok, &attempts)
	release := make(chan struct{})
	inner := l.newGovernor
	l.newGovernor = func(cfg GovernorConfig) (*Governor, error) {
		<-release // a database that answers slowly
		return inner(cfg)
	}

	done := make(chan struct{})
	go func() { l.Start(context.Background(), nil); close(done) }()
	select {
	case <-done:
	case <-time.After(2 * time.Second):
		t.Fatal("Start blocked on the connect")
	}
	close(release)
	waitFor(t, "governor start", func() bool { return l.Governor() != nil })

	l.Start(context.Background(), nil)
	assertStopped(t, &attempts, "after a second Start")
	if attempts.Load() != 1 {
		t.Fatalf("attempts = %d, want 1", attempts.Load())
	}
}

// [mysql_governor] ENABLED = 0 must keep the governor from starting, with no
// connection attempted, until the operator re-enables it.
func TestLifecycleDisabledNeverConnectsUntilReEnabled(t *testing.T) {
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	var ok atomic.Bool
	ok.Store(true) // MySQL is up: only the config keeps it off
	var attempts atomic.Int32
	l := testLifecycle(nil, &ok, &attempts)

	var enabled atomic.Bool
	var cfgCalls atomic.Int32
	l.Start(ctx, func() *GovernorConfig {
		cfgCalls.Add(1)
		return &GovernorConfig{Enabled: enabled.Load()}
	})
	waitFor(t, "several config polls", func() bool { return cfgCalls.Load() >= 3 })
	if attempts.Load() != 0 || l.Governor() != nil {
		t.Fatalf("disabled governor: %d connect attempts, governor=%v; want none", attempts.Load(), l.Governor())
	}
	if !strings.Contains(l.Status(), "ENABLED = 0") {
		t.Fatalf("Status = %q, want the disabled reason", l.Status())
	}

	enabled.Store(true)
	waitFor(t, "governor start after re-enable", func() bool { return l.Governor() != nil })
}

// A governor held by its config (detectors.conf unreadable on first load)
// makes no connection, says why, and starts once the hold lifts.
func TestLifecycleHeldThenReleased(t *testing.T) {
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	var ok atomic.Bool
	ok.Store(true)
	var attempts atomic.Int32
	l := testLifecycle(nil, &ok, &attempts)
	var held atomic.Bool
	held.Store(true)
	var cfgCalls atomic.Int32
	l.Start(ctx, func() *GovernorConfig {
		cfgCalls.Add(1)
		if held.Load() {
			return &GovernorConfig{Enabled: false, HoldReason: "waiting for a readable detectors.conf"}
		}
		return &GovernorConfig{Enabled: true}
	})
	waitFor(t, "several config polls", func() bool { return cfgCalls.Load() >= 3 })
	if attempts.Load() != 0 || l.State() != "held" || !strings.Contains(l.Status(), "readable detectors.conf") {
		t.Fatalf("held: attempts=%d state=%q status=%q", attempts.Load(), l.State(), l.Status())
	}
	held.Store(false)
	waitFor(t, "governor start after the hold", func() bool { return l.Governor() != nil })
}

func TestGovState(t *testing.T) {
	for _, c := range []struct {
		err  error
		want string
	}{
		{fmt.Errorf("x: %w", errNoCredentials), "no credentials"},
		{errGovernorDisabled, "disabled"},
		{fmt.Errorf("%w: why", errGovernorHeld), "held"},
		{connRefused(), "connect failed"},
		{errors.New("boom"), "failed"},
	} {
		if got := govState(c.err); got != c.want {
			t.Errorf("govState(%v) = %q, want %q", c.err, got, c.want)
		}
	}
}

// A node without a database must not retry forever after shutdown.
func TestLifecycleRetryStopsWithContext(t *testing.T) {
	ctx, cancel := context.WithCancel(context.Background())
	var ok atomic.Bool
	var attempts atomic.Int32
	l := testLifecycle(fmt.Errorf("mysql_governor: cannot connect: %w", errNoCredentials), &ok, &attempts)
	l.Start(ctx, nil)
	waitFor(t, "a retry", func() bool { return attempts.Load() >= 2 })
	cancel()
	assertStopped(t, &attempts, "after the context ended")
	if !strings.Contains(l.Status(), "no MySQL credentials") {
		t.Fatalf("Status = %q", l.Status())
	}
}

// Retry-After tells the client when the next attempt actually is.
func TestLifecycleRetryAfterFollowsSchedule(t *testing.T) {
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	var ok atomic.Bool
	var attempts atomic.Int32
	l := testLifecycle(fmt.Errorf("mysql_governor: cannot connect: %w", errNoCredentials), &ok, &attempts)
	l.pacing = retryPacing{min: time.Hour, max: time.Hour, noCreds: 10 * time.Minute}
	l.Start(ctx, nil)
	waitFor(t, "the first attempt", func() bool { return l.retryAfterSeconds() > 0 })

	rec := serve(l.AdminHandler(), "/api/v1/mysql/state")
	s, err := strconv.Atoi(rec.Header().Get("Retry-After"))
	if err != nil || s < 590 || s > 600 {
		t.Fatalf("Retry-After = %q, want ~600 (the no-credentials poll)", rec.Header().Get("Retry-After"))
	}

	// Its value tells the node's state apart (5-40 s vs ~300 s): scoped
	// (cPanel user) callers get neither it nor the reason.
	rec = serve(l.ScopedHandler(), "/api/v1/mysql/user-summary?user=x")
	if h := rec.Header().Get("Retry-After"); h != "" || rec.Code != http.StatusServiceUnavailable {
		t.Fatalf("scoped 503: HTTP %d Retry-After %q, want 503 without the header", rec.Code, h)
	}
}

func TestNextRetryDelay(t *testing.T) {
	p := NewGovernorLifecycle().pacing
	backoff := p.min
	var got []time.Duration
	for i := 0; i < 9; i++ {
		got = append(got, p.next(connRefused(), &backoff))
	}
	want := []time.Duration{5 * time.Second, 10 * time.Second, 20 * time.Second, 40 * time.Second,
		80 * time.Second, 160 * time.Second, 5 * time.Minute, 5 * time.Minute, 5 * time.Minute}
	for i := range want {
		if got[i] != want[i] {
			t.Fatalf("connect backoff = %v, want %v", got, want)
		}
	}

	for _, e := range []error{fmt.Errorf("mysql_governor: cannot connect: %w", errNoCredentials), errGovernorDisabled} {
		if d := p.next(e, &backoff); d != retryNoCredsDelay {
			t.Fatalf("%v: delay = %v, want %v", e, d, retryNoCredsDelay)
		}
		if backoff != retryMinDelay {
			t.Fatalf("%v must reset the connect backoff, got %v", e, backoff)
		}
	}
}

// The log de-duplicates on the failure class, which must not change when only
// the driver's wording does.
func TestFailureClassIsStableAcrossWording(t *testing.T) {
	wrap := func(err error) error {
		return fmt.Errorf("mysql_governor: cannot connect: %w", &connectError{source: "DSN", err: err})
	}
	a := failureClass(wrap(errors.New("dial tcp 10.0.0.5:3306: i/o timeout")))
	b := failureClass(wrap(context.DeadlineExceeded))
	if a != b || a != "connect:DSN" {
		t.Fatalf("classes %q / %q, want both connect:DSN", a, b)
	}
	if failureClass(fmt.Errorf("x: %w", errNoCredentials)) != "no-credentials" || failureClass(errGovernorDisabled) != "disabled" {
		t.Fatal("no-credentials / disabled not classified")
	}
}

// openDB tells "no credentials" from "connect failed", names the source, and
// never puts the DSN's password in an error.
func TestOpenDBClassifiesFailuresWithoutLeakingTheDSN(t *testing.T) {
	dir := t.TempDir()
	oRoot, oGov, oDA := rootMyCnfPath, governorCnfPath, daMySQLConfigPath
	t.Cleanup(func() { rootMyCnfPath, governorCnfPath, daMySQLConfigPath = oRoot, oGov, oDA })
	rootMyCnfPath = filepath.Join(dir, "root.my.cnf")
	governorCnfPath = filepath.Join(dir, "mysql_governor.cnf")
	daMySQLConfigPath = filepath.Join(dir, "da-mysql.conf")
	oTimeout := openPingTimeout
	openPingTimeout = 2 * time.Second
	t.Cleanup(func() { openPingTimeout = oTimeout })

	// No source at all: a node without a database.
	if _, err := openDB(GovernorConfig{}); !errors.Is(err, errNoCredentials) {
		t.Fatalf("no sources: err = %v, want errNoCredentials", err)
	}

	// A config file, but nothing listens on its socket.
	sock := filepath.Join(dir, "absent.sock")
	if err := os.WriteFile(governorCnfPath, []byte("[client]\nuser=cfm_governor\npassword=s3cretPW\nsocket="+sock+"\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	_, err := openDB(GovernorConfig{})
	var ce *connectError
	if !errors.As(err, &ce) || ce.source != governorCnfPath || errors.Is(err, errNoCredentials) {
		t.Fatalf("down socket: err = %v, want a connectError from %s", err, governorCnfPath)
	}
	if strings.Contains(err.Error(), "s3cretPW") {
		t.Fatalf("error leaks the password: %v", err)
	}

	// An unparsable explicit DSN, tried first: its error must not quote it.
	_, err = openDB(GovernorConfig{DSN: "root:s3cretPW@bogus(nowhere"})
	if err == nil || strings.Contains(err.Error(), "s3cretPW") {
		t.Fatalf("bad DSN: err = %v, want an error without the password", err)
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

	// The admin guard's 403 goes through http.Error: JSON body, text/plain.
	// It is a token problem and must not be blamed on the governor.
	err = governorRespError(mk(403, "text/plain; charset=utf-8", `{"error":"admin token required"}`+"\n"))
	if err == nil || !strings.Contains(err.Error(), "admin token required (HTTP 403)") || strings.Contains(err.Error(), "governor") {
		t.Fatalf("403: %v", err)
	}
	err = governorRespError(mk(502, "text/html", "<html>Bad Gateway</html>"))
	if err == nil || !strings.Contains(err.Error(), "HTTP 502: <html>Bad Gateway</html>") || strings.Contains(err.Error(), "governor") {
		t.Fatalf("502: %v", err)
	}
}

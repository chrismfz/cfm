package agent

import (
	"encoding/json"
	"errors"
	"io"
	"net/http"
	"net/http/httptest"
	"sync/atomic"
	"testing"
	"time"

	"cfm/internal/edgeengine"
	"cfm/internal/firewall"
)

// stubBackend satisfies firewall.Backend; the probe never calls it directly
// because heartbeatDNATStatusFn is stubbed.
type stubBackend struct{ firewall.Backend }

func stubDNATProbe(t *testing.T, fn func(firewall.Backend) (bool, error), timeout time.Duration) {
	t.Helper()
	origFn, origTimeout := heartbeatDNATStatusFn, heartbeatDNATTimeout
	t.Cleanup(func() { heartbeatDNATStatusFn, heartbeatDNATTimeout = origFn, origTimeout })
	heartbeatDNATStatusFn = fn
	heartbeatDNATTimeout = timeout
}

func TestHeartbeatDNATStatus_Fast(t *testing.T) {
	for _, want := range []bool{true, false} {
		stubDNATProbe(t, func(firewall.Backend) (bool, error) { return want, nil }, time.Second)
		r := &Runner{backend: stubBackend{}}
		got := r.heartbeatDNATStatus()
		if got == nil || *got != want {
			t.Fatalf("want %v, got %v", want, got)
		}
	}
}

func TestHeartbeatDNATStatus_ErrorOmits(t *testing.T) {
	stubDNATProbe(t, func(firewall.Backend) (bool, error) { return true, errors.New("boom") }, time.Second)
	r := &Runner{backend: stubBackend{}}
	if got := r.heartbeatDNATStatus(); got != nil {
		t.Fatalf("probe error must omit dnat_enabled, got %v", *got)
	}
}

func TestHeartbeatDNATStatus_NilBackend(t *testing.T) {
	var calls atomic.Int32
	stubDNATProbe(t, func(firewall.Backend) (bool, error) { calls.Add(1); return true, nil }, time.Second)
	r := &Runner{}
	if got := r.heartbeatDNATStatus(); got != nil {
		t.Fatalf("nil backend must omit dnat_enabled, got %v", *got)
	}
	if calls.Load() != 0 {
		t.Fatalf("probe must not run without a backend")
	}
}

// A stalled probe (the nftlib netlink read) must not hold the heartbeat, must
// not be restarted while stuck (no goroutine pile-up behind the backend lock),
// and must be usable again once it returns.
func TestHeartbeatDNATStatus_StallIsBoundedAndSingleFlight(t *testing.T) {
	release := make(chan struct{})
	var calls atomic.Int32
	const timeout = time.Second
	stubDNATProbe(t, func(firewall.Backend) (bool, error) {
		if calls.Add(1) == 1 {
			<-release // first probe wedges until released
		}
		return true, nil
	}, timeout)
	r := &Runner{backend: stubBackend{}}

	start := time.Now()
	if got := r.heartbeatDNATStatus(); got != nil {
		t.Fatalf("timed-out probe must omit dnat_enabled, got %v", *got)
	}
	if el := time.Since(start); el > timeout+2*time.Second {
		t.Fatalf("stalled probe held the caller for %s", el)
	}

	// Still stuck: later beats skip the probe instead of waiting the timeout.
	for i := 0; i < 3; i++ {
		start = time.Now()
		if got := r.heartbeatDNATStatus(); got != nil {
			t.Fatalf("beat %d while stuck: want nil, got %v", i, *got)
		}
		if el := time.Since(start); el >= timeout/2 {
			t.Fatalf("beat %d while stuck waited %s instead of skipping", i, el)
		}
	}
	if n := calls.Load(); n != 1 {
		t.Fatalf("probe started %d times while stuck, want 1", n)
	}

	close(release)
	deadline := time.Now().Add(5 * time.Second)
	for !r.dnatProbe.inflight.TryLock() {
		if time.Now().After(deadline) {
			t.Fatal("released probe never cleared the in-flight guard")
		}
		time.Sleep(time.Millisecond)
	}
	r.dnatProbe.inflight.Unlock()

	got := r.heartbeatDNATStatus()
	if got == nil || !*got {
		t.Fatalf("after recovery want true, got %v", got)
	}
	if n := calls.Load(); n != 2 {
		t.Fatalf("want 2 probe runs after recovery, got %d", n)
	}
}

func TestLogThrottled(t *testing.T) {
	orig := heartbeatDNATLogEvery
	t.Cleanup(func() { heartbeatDNATLogEvery = orig })
	heartbeatDNATLogEvery = time.Hour

	var p dnatProbeState
	p.logThrottled("first %d", 1)
	first := p.lastLog
	if first.IsZero() || p.suppressed != 0 {
		t.Fatalf("first line must be written: lastLog=%v suppressed=%d", first, p.suppressed)
	}
	p.logThrottled("second")
	p.logThrottled("third")
	if p.suppressed != 2 || !p.lastLog.Equal(first) {
		t.Fatalf("lines inside the window must be held back: suppressed=%d", p.suppressed)
	}
	heartbeatDNATLogEvery = 0
	p.logThrottled("after window")
	if p.suppressed != 0 || !p.lastLog.After(first) {
		t.Fatalf("a line after the window must be written and reset the count: suppressed=%d", p.suppressed)
	}
}

// End to end: with the firewall read wedged, the heartbeat POST still reaches
// cfm-web promptly and carries no dnat_enabled key (so cfm-web keeps the last
// known value instead of flipping it).
func TestDoHeartbeat_SentDespiteStalledDNATProbe(t *testing.T) {
	release := make(chan struct{})
	t.Cleanup(func() { close(release) })
	stubDNATProbe(t, func(firewall.Backend) (bool, error) { <-release; return true, nil }, 50*time.Millisecond)

	origLook := edgeengine.LookPath
	t.Cleanup(func() { edgeengine.LookPath = origLook })
	edgeengine.LookPath = func(string) (string, error) { return "", errors.New("no systemctl in test") }

	got := make(chan map[string]any, 1)
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, req *http.Request) {
		if req.URL.Path != "/api/agent/heartbeat" {
			http.NotFound(w, req)
			return
		}
		b, _ := io.ReadAll(req.Body)
		var body map[string]any
		_ = json.Unmarshal(b, &body)
		got <- body
		w.WriteHeader(http.StatusOK)
	}))
	defer srv.Close()

	r := New(Config{BaseURL: srv.URL, Token: "t", Interval: time.Hour})
	r.SetBackend(stubBackend{})

	done := make(chan struct{})
	go func() { r.doHeartbeat(t.Context()); close(done) }()

	select {
	case body := <-got:
		if _, ok := body["dnat_enabled"]; ok {
			t.Fatalf("heartbeat must omit dnat_enabled while the probe is stuck, got %v", body["dnat_enabled"])
		}
	case <-time.After(3 * time.Second):
		t.Fatal("heartbeat was not sent while the DNAT probe was stalled")
	}
	select {
	case <-done:
	case <-time.After(3 * time.Second):
		t.Fatal("doHeartbeat did not return")
	}
}

// The heartbeat must keep flowing while the work loop is wedged — here on a
// pending-unblocks call that never answers, standing in for an unblock stuck
// behind a stalled firewall backend.
func TestHeartbeatLoop_IndependentOfStuckWorkLoop(t *testing.T) {
	stubDNATProbe(t, func(firewall.Backend) (bool, error) { return true, nil }, time.Second)
	origLook := edgeengine.LookPath
	t.Cleanup(func() { edgeengine.LookPath = origLook })
	edgeengine.LookPath = func(string) (string, error) { return "", errors.New("no systemctl in test") }

	release := make(chan struct{})
	var heartbeats, unblockCalls atomic.Int32
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, req *http.Request) {
		switch req.URL.Path {
		case "/api/agent/heartbeat":
			heartbeats.Add(1)
			w.WriteHeader(http.StatusOK)
		case "/api/blocklist/pending-unblocks":
			unblockCalls.Add(1)
			<-release // wedge the work loop
			_, _ = w.Write([]byte(`{"pending_unblocks":[]}`))
		default:
			http.NotFound(w, req)
		}
	}))
	r := New(Config{BaseURL: srv.URL, Token: "t", Interval: 20 * time.Millisecond})
	r.SetBackend(stubBackend{})
	// Cleanups run LIFO: unwedge the handler, stop the runner, then close the
	// server — so a failing assertion can't leave the test hanging.
	t.Cleanup(srv.Close)
	t.Cleanup(r.Stop)
	t.Cleanup(func() { close(release) })
	r.Start()

	deadline := time.Now().Add(5 * time.Second)
	for unblockCalls.Load() == 0 {
		if time.Now().After(deadline) {
			t.Fatal("work loop never reached pending-unblocks")
		}
		time.Sleep(5 * time.Millisecond)
	}
	before := heartbeats.Load()
	for heartbeats.Load() < before+5 {
		if time.Now().After(deadline) {
			t.Fatalf("heartbeats stalled with the work loop: %d before, %d now", before, heartbeats.Load())
		}
		time.Sleep(5 * time.Millisecond)
	}
}

func TestCheckWorkLoopStuck(t *testing.T) {
	now := time.Now()
	r := &Runner{}

	r.checkWorkLoopStuck(now) // idle
	if r.workStuckLogAt.Load() != 0 {
		t.Fatal("idle work loop must not be reported")
	}
	r.workBusySince.Store(now.Add(-30 * time.Second).UnixNano())
	r.checkWorkLoopStuck(now)
	if r.workStuckLogAt.Load() != 0 {
		t.Fatal("a normal-length tick must not be reported")
	}
	r.workBusySince.Store(now.Add(-workLoopStuckAfter - time.Second).UnixNano())
	r.checkWorkLoopStuck(now)
	first := r.workStuckLogAt.Load()
	if first == 0 {
		t.Fatal("a tick past workLoopStuckAfter must be reported")
	}
	r.checkWorkLoopStuck(now.Add(time.Minute))
	if r.workStuckLogAt.Load() != first {
		t.Fatal("repeat reports must be throttled")
	}
	r.checkWorkLoopStuck(now.Add(6 * time.Minute))
	if r.workStuckLogAt.Load() == first {
		t.Fatal("report must repeat after the throttle window")
	}
}

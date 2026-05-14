package sslcollector

import (
	"context"
	"fmt"
	"os"
	"strings"
	"sync"
	"sync/atomic"
	"testing"
	"time"
)

// stubSystemctl provides a controllable runner replacement for tests.
type stubSystemctl struct {
	mu      sync.Mutex
	calls   []string
	isAct   map[string]bool   // service -> active?
	mainPID map[string]string // service -> MainPID string ("1234" or "0")
}

func (s *stubSystemctl) run(_ context.Context, args ...string) ([]byte, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	s.calls = append(s.calls, strings.Join(args, " "))
	if len(args) >= 3 && args[0] == "is-active" && args[1] == "--quiet" {
		svc := args[2]
		if s.isAct[svc] {
			return nil, nil
		}
		return nil, fmt.Errorf("inactive")
	}
	if len(args) >= 5 && args[0] == "show" && args[1] == "-p" && args[2] == "MainPID" && args[3] == "--value" {
		svc := args[4]
		v := s.mainPID[svc]
		if v == "" {
			v = "0"
		}
		return []byte(v + "\n"), nil
	}
	if len(args) >= 2 && args[0] == "reload" {
		return nil, nil
	}
	return nil, fmt.Errorf("stub: unhandled args %v", args)
}

func resetNudgeState() {
	nudgeOnce = sync.Once{}
}

// withStubs swaps the package-level injection points for the duration of
// a test. Returns a function the test must defer to restore originals.
// The `now` value is what nowFn returns — fixing it lets tests assert
// the socketReadyAt comparison deterministically. Use time.Time{} to
// keep real wall-clock time (legacy behaviour).
func withStubs(stub *stubSystemctl, ready bool, startFn func(int) (time.Time, error), now time.Time) func() {
	origRun := systemctlRunner
	origReady := socketReady
	origStart := processStartTimeFn
	origNow := nowFn
	origInterval := nudgePollInterval
	origBudget := nudgeTotalBudget
	systemctlRunner = stub.run
	socketReady = func() bool { return ready }
	processStartTimeFn = startFn
	if !now.IsZero() {
		nowFn = func() time.Time { return now }
	}
	nudgePollInterval = 5 * time.Millisecond
	nudgeTotalBudget = 1 * time.Second
	return func() {
		systemctlRunner = origRun
		socketReady = origReady
		processStartTimeFn = origStart
		nowFn = origNow
		nudgePollInterval = origInterval
		nudgeTotalBudget = origBudget
	}
}

// Base time used by tests for deterministic timestamp comparisons.
// socketReadyAt = base + 100s in tests that fix nowFn — edge start
// times below that are "before ready" (→ reload); above are "after
// ready" (→ skip).
var testBase = time.Unix(1_700_000_000, 0)
var testReadyAt = testBase.Add(100 * time.Second)

func TestNudgeEdge_ReloadsWhenEdgeStartedBeforeSocketReady(t *testing.T) {
	resetNudgeState()
	stub := &stubSystemctl{
		isAct:   map[string]bool{"angie": true},
		mainPID: map[string]string{"angie": "111"},
	}
	// edge pid 111 started 90s before socketReady — classic case where
	// the edge predates cfm or raced cfm at cold boot.
	startFn := func(pid int) (time.Time, error) {
		if pid == 111 {
			return testBase.Add(10 * time.Second), nil
		}
		return testBase.Add(30 * time.Second), nil
	}
	defer withStubs(stub, true, startFn, testReadyAt)()

	col := New(Config{})
	col.exact = map[string]*Entry{"x.example.com": {Fingerprint: "fp1"}}

	done := make(chan struct{})
	go func() { nudgeEdge(context.Background(), col); close(done) }()
	select {
	case <-done:
	case <-time.After(2 * time.Second):
		t.Fatalf("nudgeEdge did not finish")
	}

	stub.mu.Lock()
	defer stub.mu.Unlock()
	var sawReload bool
	for _, c := range stub.calls {
		if strings.HasPrefix(c, "reload angie") {
			sawReload = true
		}
	}
	if !sawReload {
		t.Fatalf("expected reload call, got %v", stub.calls)
	}
}

// Regression test for the "cold boot, cfm wins race by 2s" case (the
// mars edge bug). Edge starts AFTER cfm's pid but BEFORE cfm's socket
// is bound; the old gate (comparing to cfm.pid.start) wrongly skipped
// reload, leaving workers with an empty _store until manual reload.
func TestNudgeEdge_ReloadsWhenEdgeStartedAfterCFMButBeforeSocketReady(t *testing.T) {
	resetNudgeState()
	stub := &stubSystemctl{
		isAct:   map[string]bool{"angie": true},
		mainPID: map[string]string{"angie": "111"},
	}
	// Timeline: cfm pid at t+30s, edge pid at t+50s, socket ready at
	// t+100s. Edge.start > cfm.start would have skipped under the old
	// gate; edge.start < socketReadyAt correctly reloads.
	startFn := func(pid int) (time.Time, error) {
		if pid == 111 {
			return testBase.Add(50 * time.Second), nil
		}
		return testBase.Add(30 * time.Second), nil
	}
	defer withStubs(stub, true, startFn, testReadyAt)()

	col := New(Config{})
	col.exact = map[string]*Entry{"x.example.com": {Fingerprint: "fp1"}}

	done := make(chan struct{})
	go func() { nudgeEdge(context.Background(), col); close(done) }()
	<-done

	stub.mu.Lock()
	defer stub.mu.Unlock()
	var sawReload bool
	for _, c := range stub.calls {
		if strings.HasPrefix(c, "reload angie") {
			sawReload = true
		}
	}
	if !sawReload {
		t.Fatalf("expected reload for cold-boot race (edge after cfm but before sockReady); calls=%v", stub.calls)
	}
}

func TestNudgeEdge_SkipsWhenEdgeStartedAfterSocketReady(t *testing.T) {
	resetNudgeState()
	stub := &stubSystemctl{
		isAct:   map[string]bool{"angie": true},
		mainPID: map[string]string{"angie": "111"},
	}
	// Edge starts 50s AFTER socketReadyAt — admin started angie long
	// after cfm was already up. No reload needed; workers init against
	// a healthy state on their first try.
	startFn := func(pid int) (time.Time, error) {
		if pid == 111 {
			return testReadyAt.Add(50 * time.Second), nil
		}
		return testBase.Add(30 * time.Second), nil
	}
	defer withStubs(stub, true, startFn, testReadyAt)()

	col := New(Config{})
	col.exact = map[string]*Entry{"x.example.com": {Fingerprint: "fp1"}}

	done := make(chan struct{})
	go func() { nudgeEdge(context.Background(), col); close(done) }()
	<-done

	stub.mu.Lock()
	defer stub.mu.Unlock()
	for _, c := range stub.calls {
		if strings.HasPrefix(c, "reload angie") {
			t.Fatalf("did not expect reload when edge started after socketReady; calls=%v", stub.calls)
		}
	}
}

func TestNudgeEdge_ProceedsToReloadWhenStarttimeUnreadable(t *testing.T) {
	resetNudgeState()
	stub := &stubSystemctl{
		isAct:   map[string]bool{"angie": true},
		mainPID: map[string]string{"angie": "111"},
	}
	startFn := func(pid int) (time.Time, error) {
		return time.Time{}, fmt.Errorf("simulated /proc parse failure")
	}
	defer withStubs(stub, true, startFn, testReadyAt)()

	col := New(Config{})
	col.exact = map[string]*Entry{"x.example.com": {Fingerprint: "fp1"}}

	done := make(chan struct{})
	go func() { nudgeEdge(context.Background(), col); close(done) }()
	<-done

	stub.mu.Lock()
	defer stub.mu.Unlock()
	var sawReload bool
	for _, c := range stub.calls {
		if strings.HasPrefix(c, "reload angie") {
			sawReload = true
		}
	}
	if !sawReload {
		t.Fatalf("expected reload defensively when starttime unreadable, got %v", stub.calls)
	}
}

func TestNudgeEdge_NoActiveService(t *testing.T) {
	resetNudgeState()
	stub := &stubSystemctl{isAct: map[string]bool{}}
	startFn := func(int) (time.Time, error) { return testBase, nil }
	defer withStubs(stub, true, startFn, testReadyAt)()

	col := New(Config{})
	col.exact = map[string]*Entry{"x.example.com": {Fingerprint: "fp1"}}

	done := make(chan struct{})
	go func() { nudgeEdge(context.Background(), col); close(done) }()
	<-done

	stub.mu.Lock()
	defer stub.mu.Unlock()
	for _, c := range stub.calls {
		if strings.HasPrefix(c, "reload ") {
			t.Fatalf("did not expect reload with no active service; calls=%v", stub.calls)
		}
	}
}

func TestNudgeEdge_TimesOutWaitingForCerts(t *testing.T) {
	resetNudgeState()
	stub := &stubSystemctl{}
	startFn := func(int) (time.Time, error) { return testBase, nil }
	// Real wall-clock here so the deadline can actually trip.
	restore := withStubs(stub, true, startFn, time.Time{})
	nudgeTotalBudget = 50 * time.Millisecond
	nudgePollInterval = 2 * time.Millisecond
	defer restore()

	col := New(Config{}) // no certs ever loaded

	var reloads int32
	stubRun := func(ctx context.Context, args ...string) ([]byte, error) {
		if len(args) >= 1 && args[0] == "reload" {
			atomic.AddInt32(&reloads, 1)
		}
		return stub.run(ctx, args...)
	}
	systemctlRunner = stubRun

	done := make(chan struct{})
	go func() { nudgeEdge(context.Background(), col); close(done) }()
	select {
	case <-done:
	case <-time.After(500 * time.Millisecond):
		t.Fatalf("nudgeEdge did not finish")
	}
	if atomic.LoadInt32(&reloads) != 0 {
		t.Fatalf("expected no reloads on timeout, got %d", reloads)
	}
}

func TestNudgeEdge_SocketNotReadyHoldsOffReload(t *testing.T) {
	resetNudgeState()
	stub := &stubSystemctl{
		isAct:   map[string]bool{"angie": true},
		mainPID: map[string]string{"angie": "111"},
	}
	startFn := func(int) (time.Time, error) { return testBase, nil }
	// socketReady stays false → nudge times out → no reload.
	// Real wall-clock so the deadline can actually trip.
	restore := withStubs(stub, false, startFn, time.Time{})
	nudgeTotalBudget = 50 * time.Millisecond
	defer restore()

	col := New(Config{})
	col.exact = map[string]*Entry{"x.example.com": {Fingerprint: "fp1"}}

	done := make(chan struct{})
	go func() { nudgeEdge(context.Background(), col); close(done) }()
	<-done

	stub.mu.Lock()
	defer stub.mu.Unlock()
	for _, c := range stub.calls {
		if strings.HasPrefix(c, "reload ") {
			t.Fatalf("did not expect reload when socket never came up; calls=%v", stub.calls)
		}
	}
}

func TestProcessStartTime_ReadsOurOwnPid(t *testing.T) {
	got, err := processStartTime(0)
	if err == nil {
		t.Fatalf("expected error for pid 0, got %v", got)
	}
	if _, err := processStartTime(99999999); err == nil {
		t.Fatalf("expected error for non-existent pid")
	}
	// Our own pid must parse and yield a time in the past (within the
	// last few hours).
	t0, err := processStartTime(os.Getpid())
	if err != nil {
		t.Fatalf("unexpected error reading our own pid: %v", err)
	}
	if t0.IsZero() {
		t.Fatalf("expected non-zero start time")
	}
	if time.Since(t0) < 0 || time.Since(t0) > 24*time.Hour {
		t.Fatalf("start time looks wrong: %v (now=%v)", t0, time.Now())
	}
}

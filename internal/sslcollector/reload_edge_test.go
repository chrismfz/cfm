package sslcollector

import (
	"context"
	"fmt"
	"strings"
	"sync"
	"sync/atomic"
	"testing"
	"time"
)

// stubSystemctl provides a controllable runner replacement for tests.
type stubSystemctl struct {
	mu     sync.Mutex
	calls  []string
	isAct  map[string]bool   // service -> active?
	tsResp map[string]string // service -> ActiveEnterTimestamp value
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
	if len(args) >= 5 && args[0] == "show" && args[1] == "-p" && args[2] == "ActiveEnterTimestamp" && args[3] == "--value" {
		return []byte(s.tsResp[args[4]] + "\n"), nil
	}
	if len(args) >= 2 && args[0] == "reload" {
		return nil, nil
	}
	return nil, fmt.Errorf("stub: unhandled args %v", args)
}

func resetNudgeState() {
	nudgeOnce = sync.Once{}
}

func TestNudgeEdge_ReloadsWhenEdgeStartedBefore(t *testing.T) {
	resetNudgeState()
	stub := &stubSystemctl{
		isAct: map[string]bool{"angie": true},
		tsResp: map[string]string{
			// well in the past, will be "before" our bind time
			"angie": "Mon 2000-01-01 00:00:00 UTC",
		},
	}
	origRun := systemctlRunner
	origProbe := socketPathProbe
	origInterval := nudgePollInterval
	defer func() {
		systemctlRunner = origRun
		socketPathProbe = origProbe
		nudgePollInterval = origInterval
	}()
	systemctlRunner = stub.run
	socketPathProbe = func() bool { return true }
	nudgePollInterval = 5 * time.Millisecond

	col := New(Config{})
	// Seed at least one cert so Stats().UniquePairs > 0.
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
			break
		}
	}
	if !sawReload {
		t.Fatalf("expected reload call, got %v", stub.calls)
	}
}

func TestNudgeEdge_SkipsWhenEdgeStartedAfter(t *testing.T) {
	resetNudgeState()
	future := time.Now().Add(1 * time.Hour).UTC().Format("Mon 2006-01-02 15:04:05 MST")
	stub := &stubSystemctl{
		isAct:  map[string]bool{"angie": true},
		tsResp: map[string]string{"angie": future},
	}
	origRun := systemctlRunner
	origProbe := socketPathProbe
	origInterval := nudgePollInterval
	defer func() {
		systemctlRunner = origRun
		socketPathProbe = origProbe
		nudgePollInterval = origInterval
	}()
	systemctlRunner = stub.run
	socketPathProbe = func() bool { return true }
	nudgePollInterval = 5 * time.Millisecond

	col := New(Config{})
	col.exact = map[string]*Entry{"x.example.com": {Fingerprint: "fp1"}}

	done := make(chan struct{})
	go func() { nudgeEdge(context.Background(), col); close(done) }()
	<-done

	stub.mu.Lock()
	defer stub.mu.Unlock()
	for _, c := range stub.calls {
		if strings.HasPrefix(c, "reload angie") {
			t.Fatalf("did not expect reload when edge started after sslcollector; calls=%v", stub.calls)
		}
	}
}

func TestNudgeEdge_NoActiveService(t *testing.T) {
	resetNudgeState()
	stub := &stubSystemctl{isAct: map[string]bool{}}
	origRun := systemctlRunner
	origProbe := socketPathProbe
	origInterval := nudgePollInterval
	defer func() {
		systemctlRunner = origRun
		socketPathProbe = origProbe
		nudgePollInterval = origInterval
	}()
	systemctlRunner = stub.run
	socketPathProbe = func() bool { return true }
	nudgePollInterval = 5 * time.Millisecond

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
	origRun := systemctlRunner
	origProbe := socketPathProbe
	origInterval := nudgePollInterval
	origBudget := nudgeTotalBudget
	defer func() {
		systemctlRunner = origRun
		socketPathProbe = origProbe
		nudgePollInterval = origInterval
		nudgeTotalBudget = origBudget
	}()
	systemctlRunner = stub.run
	socketPathProbe = func() bool { return true }
	nudgePollInterval = 2 * time.Millisecond
	nudgeTotalBudget = 50 * time.Millisecond

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

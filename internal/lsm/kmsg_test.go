//go:build linux

package lsm

import (
	"bytes"
	"fmt"
	"io"
	"strings"
	"sync"
	"testing"
	"time"
)

// captureKmsg replaces kmsgOpenFn with one that writes into a
// bytes.Buffer the test can inspect. Returns the buffer and a
// cleanup function. Also resets the global writer state so each
// test starts fresh.
func captureKmsg(t *testing.T) (*bytes.Buffer, func()) {
	t.Helper()
	var (
		buf bytes.Buffer
		mu  sync.Mutex
	)
	prevOpen := kmsgOpenFn
	kmsgOpenFn = func(string) (io.WriteCloser, error) {
		return &syncBufWriter{buf: &buf, mu: &mu}, nil
	}

	prevWriter := defaultKmsg
	defaultKmsg = &kmsgWriter{
		cfg:  DefaultKmsgConf(),
		rate: map[PolicyID]*kmsgRateBucket{},
	}

	return &buf, func() {
		kmsgOpenFn = prevOpen
		defaultKmsg = prevWriter
	}
}

// syncBufWriter is a thread-safe io.WriteCloser backed by bytes.Buffer.
type syncBufWriter struct {
	buf *bytes.Buffer
	mu  *sync.Mutex
}

func (w *syncBufWriter) Write(p []byte) (int, error) {
	w.mu.Lock()
	defer w.mu.Unlock()
	return w.buf.Write(p)
}
func (w *syncBufWriter) Close() error { return nil }

func TestKmsgStatef_PreservesTagAndPriority(t *testing.T) {
	buf, cleanup := captureKmsg(t)
	defer cleanup()

	KmsgStatef("ALIVE", "enabled %d policies pinned=%s", 2, "/sys/fs/bpf/cfm")

	got := buf.String()
	wantContains := []string{
		"<13>",                  // notice priority
		"CFM-LSM:",              // brand prefix
		"ALIVE:",                // tag
		"enabled 2 policies",    // formatted arg interpolation
		"pinned=/sys/fs/bpf/cfm",
	}
	for _, s := range wantContains {
		if !strings.Contains(got, s) {
			t.Errorf("kmsg output missing %q; got: %q", s, got)
		}
	}
	if !strings.HasSuffix(got, "\n") {
		t.Errorf("kmsg output must end with newline; got: %q", got)
	}
}

func TestKmsgStatef_ISSUE_UsesErrPriority(t *testing.T) {
	buf, cleanup := captureKmsg(t)
	defer cleanup()

	KmsgStatef("ISSUE", "drain error: %v", fmt.Errorf("broken"))

	got := buf.String()
	if !strings.HasPrefix(got, "<11>") {
		t.Errorf("ISSUE should use err priority <11>; got: %q", got)
	}
}

func TestKmsgStatef_DisabledByConfig_NoOutput(t *testing.T) {
	buf, cleanup := captureKmsg(t)
	defer cleanup()

	ConfigureKmsg(KmsgConf{StateTransitions: false, DetectEvents: true, DetectRatePerMin: 10})
	KmsgStatef("ALIVE", "this should not appear")

	if buf.Len() != 0 {
		t.Errorf("expected zero output with StateTransitions=false; got %q", buf.String())
	}
}

func TestKmsgDetect_FormatsEvent(t *testing.T) {
	buf, cleanup := captureKmsg(t)
	defer cleanup()

	KmsgDetect(Event{
		PolicyID: PolicyMemfdExec,
		PID:      12345,
		UID:      1001,
		Comm:     "php-fpm",
		Filename: "memfd:payload",
	})

	got := buf.String()
	for _, want := range []string{"<12>", "DETECT:", "CFML-EXEC-001", "pid=12345", "uid=1001", "comm=php-fpm", "path=memfd:payload"} {
		if !strings.Contains(got, want) {
			t.Errorf("DETECT line missing %q; got: %q", want, got)
		}
	}
}

func TestKmsgDetect_OmitsPathWhenEmpty(t *testing.T) {
	buf, cleanup := captureKmsg(t)
	defer cleanup()

	KmsgDetect(Event{
		PolicyID: PolicyReverseShell,
		PID:      99,
		UID:      0,
		Comm:     "bash",
		// Filename empty
	})

	got := buf.String()
	if strings.Contains(got, "path=") {
		t.Errorf("DETECT line should not include path= when Filename is empty; got: %q", got)
	}
	if !strings.Contains(got, "comm=bash") {
		t.Errorf("DETECT line should still include comm; got: %q", got)
	}
}

func TestKmsgDetect_DisabledByConfig_NoOutput(t *testing.T) {
	buf, cleanup := captureKmsg(t)
	defer cleanup()

	ConfigureKmsg(KmsgConf{StateTransitions: true, DetectEvents: false, DetectRatePerMin: 10})
	KmsgDetect(Event{PolicyID: PolicyMemfdExec, PID: 1, Comm: "x"})

	if buf.Len() != 0 {
		t.Errorf("expected zero output with DetectEvents=false; got %q", buf.String())
	}
}

func TestRateAllow_CapsBurst(t *testing.T) {
	w := &kmsgWriter{
		cfg:  KmsgConf{DetectRatePerMin: 3},
		rate: map[PolicyID]*kmsgRateBucket{},
	}
	now := time.Now()

	got := []bool{}
	for i := 0; i < 5; i++ {
		allow, summary := w.rateAllow(PolicyMemfdExec, 3, now)
		got = append(got, allow)
		if summary != "" {
			t.Errorf("call %d: unexpected summary line %q on first window", i, summary)
		}
	}
	want := []bool{true, true, true, false, false}
	for i := range want {
		if got[i] != want[i] {
			t.Errorf("call %d: allow=%t, want %t", i, got[i], want[i])
		}
	}
}

func TestRateAllow_RollsAndEmitsSummary(t *testing.T) {
	w := &kmsgWriter{
		cfg:  KmsgConf{DetectRatePerMin: 2},
		rate: map[PolicyID]*kmsgRateBucket{},
	}
	t0 := time.Now()

	// Fill the window: 2 allowed, 3 suppressed.
	for i := 0; i < 5; i++ {
		w.rateAllow(PolicyMemfdExec, 2, t0)
	}

	// Roll past 60s. The first call in the new window should
	// return summary="...suppressed=3 in_last=60s" AND allow=true
	// (because the window reset, and this is the first event in it).
	t1 := t0.Add(61 * time.Second)
	allow, summary := w.rateAllow(PolicyMemfdExec, 2, t1)
	if !allow {
		t.Errorf("first event in new window should be allowed; got false")
	}
	if !strings.Contains(summary, "suppressed=3") || !strings.Contains(summary, "in_last=60s") {
		t.Errorf("summary missing suppressed count; got %q", summary)
	}
}

func TestRateAllow_PerPolicyIsolation(t *testing.T) {
	// Saturating one policy must not affect another.
	w := &kmsgWriter{
		cfg:  KmsgConf{DetectRatePerMin: 2},
		rate: map[PolicyID]*kmsgRateBucket{},
	}
	now := time.Now()

	for i := 0; i < 5; i++ {
		w.rateAllow(PolicyMemfdExec, 2, now)
	}
	allow, _ := w.rateAllow(PolicyReverseShell, 2, now)
	if !allow {
		t.Errorf("ReverseShell's first event should pass despite MemfdExec saturation")
	}
}

func TestKmsgLine_TruncatedWhenTooLong(t *testing.T) {
	buf, cleanup := captureKmsg(t)
	defer cleanup()

	// Build a >1024 byte tail.
	long := strings.Repeat("X", 2000)
	KmsgStatef("ALIVE", "%s", long)

	got := buf.String()
	if len(got) > kmsgMaxLine {
		t.Errorf("kmsg line exceeded kmsgMaxLine (%d): got %d bytes", kmsgMaxLine, len(got))
	}
	if !strings.HasSuffix(got, "\n") {
		t.Errorf("truncated line must still end with newline; got: %q", got[len(got)-10:])
	}
}

func TestKmsgOpenFailure_IsSilent(t *testing.T) {
	// If kmsgOpenFn returns an error (no /dev/kmsg, EACCES in a
	// stripped container, etc.), subsequent calls must not panic
	// and must produce no output.
	prevOpen := kmsgOpenFn
	prevWriter := defaultKmsg
	defer func() {
		kmsgOpenFn = prevOpen
		defaultKmsg = prevWriter
	}()

	kmsgOpenFn = func(string) (io.WriteCloser, error) {
		return nil, fmt.Errorf("no kmsg here")
	}
	defaultKmsg = &kmsgWriter{
		cfg:  DefaultKmsgConf(),
		rate: map[PolicyID]*kmsgRateBucket{},
	}

	// Multiple calls — must not panic.
	KmsgStatef("ALIVE", "test")
	KmsgStatef("STATE", "test")
	KmsgDetect(Event{PolicyID: PolicyMemfdExec, PID: 1, Comm: "x"})
	// Nothing to assert beyond "did not panic".
}

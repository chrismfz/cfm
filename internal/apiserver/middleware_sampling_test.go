package apiserver

import (
	"testing"
	"time"
)

func TestShouldLogSessionCookieAuth_SamplingWindow(t *testing.T) {
	sessionCookieAuthLogMu.Lock()
	original := sessionCookieAuthLastLog
	sessionCookieAuthLastLog = time.Time{}
	sessionCookieAuthLogMu.Unlock()
	t.Cleanup(func() {
		sessionCookieAuthLogMu.Lock()
		sessionCookieAuthLastLog = original
		sessionCookieAuthLogMu.Unlock()
	})

	base := time.Unix(1_700_000_000, 0)

	if !shouldLogSessionCookieAuth(base) {
		t.Fatalf("expected first call to be logged")
	}
	if shouldLogSessionCookieAuth(base.Add(59 * time.Second)) {
		t.Fatalf("expected call inside sampling window to be suppressed")
	}
	if !shouldLogSessionCookieAuth(base.Add(60 * time.Second)) {
		t.Fatalf("expected call at sampling boundary to be logged")
	}
}

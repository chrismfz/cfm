package dnat

import (
	"context"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strconv"
	"strings"
	"testing"
)

func TestPersistAndLoadIntentWeb(t *testing.T) {
	dir := t.TempDir()
	orig := webDNATIntentPath
	webDNATIntentPath = filepath.Join(dir, "dnat_enabled")
	t.Cleanup(func() { webDNATIntentPath = orig })

	if _, present := LoadIntent(ScopeWeb); present {
		t.Fatalf("expected no intent file initially")
	}

	if err := PersistIntent(ScopeWeb, true); err != nil {
		t.Fatalf("persist ON: %v", err)
	}
	enabled, present := LoadIntent(ScopeWeb)
	if !present || !enabled {
		t.Fatalf("expected ON intent, got enabled=%v present=%v", enabled, present)
	}

	if err := PersistIntent(ScopeWeb, false); err != nil {
		t.Fatalf("persist OFF: %v", err)
	}
	enabled, present = LoadIntent(ScopeWeb)
	if !present || enabled {
		t.Fatalf("expected OFF intent, got enabled=%v present=%v", enabled, present)
	}

	b, err := os.ReadFile(webDNATIntentPath)
	if err != nil {
		t.Fatalf("read: %v", err)
	}
	if strings.TrimSpace(string(b)) != "0" {
		t.Fatalf("unexpected file content %q", string(b))
	}
}

func TestPersistAndLoadIntentCPanel(t *testing.T) {
	dir := t.TempDir()
	orig := panelChallengeEnabledStatePath
	panelChallengeEnabledStatePath = filepath.Join(dir, "panel_challenge_enabled")
	panelChallengeModeStatePath = panelChallengeEnabledStatePath
	t.Cleanup(func() {
		panelChallengeEnabledStatePath = orig
		panelChallengeModeStatePath = orig
	})

	if err := PersistIntent(ScopeCPanel, true); err != nil {
		t.Fatalf("persist ON: %v", err)
	}
	enabled, present := LoadIntent(ScopeCPanel)
	if !present || !enabled {
		t.Fatalf("expected ON intent, got enabled=%v present=%v", enabled, present)
	}
}

func TestProbeEdgeHealthyOK(t *testing.T) {
	plain := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path != edgeHealthPath {
			t.Errorf("unexpected path %q", r.URL.Path)
		}
		w.WriteHeader(200)
		_, _ = w.Write([]byte("ready=1\nversion=test\n"))
	}))
	t.Cleanup(plain.Close)
	tls1 := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(200)
	}))
	t.Cleanup(tls1.Close)

	plainPort := mustHostPort(t, plain.URL)
	tlsPort := mustHostPort(t, tls1.URL)

	ports := []EdgePort{
		{Port: plainPort, TLS: false, Healthz: true},
		{Port: tlsPort, TLS: true, Healthz: true},
	}
	ok, reason := probeEdgeHealthy(context.Background(), ScopeWeb, ports)
	if !ok {
		t.Fatalf("expected probe ok, got reason=%q", reason)
	}
	if pr := GetLastProbe(ScopeWeb); !pr.OK {
		t.Fatalf("expected last probe ok, got %+v", pr)
	}
}

func TestProbeEdgeHealthyHTTPStatusFail(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(500)
	}))
	t.Cleanup(srv.Close)
	port := mustHostPort(t, srv.URL)

	ok, reason := probeEdgeHealthy(context.Background(), ScopeWeb, []EdgePort{
		{Port: port, TLS: false, Healthz: true},
	})
	if ok {
		t.Fatalf("expected probe fail")
	}
	if !strings.Contains(reason, "status=500") {
		t.Fatalf("expected reason to mention status=500, got %q", reason)
	}
}

func TestProbeEdgeHealthyTCPFail(t *testing.T) {
	ok, reason := probeEdgeHealthy(context.Background(), ScopeWeb, []EdgePort{
		{Port: 1, TLS: false, Healthz: true},
	})
	if ok {
		t.Fatalf("expected probe fail")
	}
	if !strings.HasPrefix(reason, "tcp:") {
		t.Fatalf("expected reason to start with tcp:, got %q", reason)
	}
}

func TestLogTransitionRecordsLast(t *testing.T) {
	transitionMu.Lock()
	transitions = map[DNATScope]LastTransition{}
	transitionMu.Unlock()

	LogTransition(ScopeWeb, "ON", "manual", "")
	lt := GetLastTransition(ScopeWeb)
	if lt.State != "ON" || lt.Action != "manual" {
		t.Fatalf("unexpected last transition: %+v", lt)
	}
	if lt.At.IsZero() {
		t.Fatalf("expected non-zero timestamp")
	}

	LogTransition(ScopeWeb, "OFF", "failsafe-off", "tcp:127.0.0.1:9080 err=refused")
	lt = GetLastTransition(ScopeWeb)
	if lt.State != "OFF" || lt.Action != "failsafe-off" || !strings.Contains(lt.Reason, "refused") {
		t.Fatalf("unexpected last transition: %+v", lt)
	}
}

func mustHostPort(t *testing.T, url string) int {
	t.Helper()
	url = strings.TrimPrefix(strings.TrimPrefix(url, "https://"), "http://")
	parts := strings.Split(url, ":")
	if len(parts) != 2 {
		t.Fatalf("unexpected URL %q", url)
	}
	p, err := strconv.Atoi(parts[1])
	if err != nil {
		t.Fatalf("port parse: %v", err)
	}
	return p
}


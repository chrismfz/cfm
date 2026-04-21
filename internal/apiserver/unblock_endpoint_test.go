package apiserver

import (
	"context"
	"encoding/json"
	"net"
	"net/http"
	"net/http/httptest"
	"strings"
	"sync"
	"testing"
	"time"

	"cfm/internal/firewall"
	"cfm/internal/unblock"
)

type stubFirewallBackend struct {
	removed []string
}

func (s *stubFirewallBackend) EnsureBase() error                                     { return nil }
func (s *stubFirewallBackend) AddBlock(net.IP, string, *time.Duration) error         { return nil }
func (s *stubFirewallBackend) ListBlocks() ([]firewall.BlockedEntry, error)          { return nil, nil }
func (s *stubFirewallBackend) ListAllows() ([]firewall.BlockedEntry, error)          { return nil, nil }
func (s *stubFirewallBackend) AddAllow(net.IP, *time.Duration) error                 { return nil }
func (s *stubFirewallBackend) RemoveAllow(net.IP) error                              { return nil }
func (s *stubFirewallBackend) AddBlockNet(string, *time.Duration) error              { return nil }
func (s *stubFirewallBackend) RemoveBlockNet(string) error                           { return nil }
func (s *stubFirewallBackend) AddAllowNet(string, *time.Duration) error              { return nil }
func (s *stubFirewallBackend) RemoveAllowNet(string) error                           { return nil }
func (s *stubFirewallBackend) AddIgnore(net.IP, *time.Duration) error                { return nil }
func (s *stubFirewallBackend) RemoveIgnore(net.IP) error                             { return nil }
func (s *stubFirewallBackend) AddIgnoreNet(string, *time.Duration) error             { return nil }
func (s *stubFirewallBackend) RemoveIgnoreNet(string) error                          { return nil }
func (s *stubFirewallBackend) AddChallenge(net.IP, *time.Duration) error             { return nil }
func (s *stubFirewallBackend) RemoveChallenge(net.IP) error                          { return nil }
func (s *stubFirewallBackend) ReportBlock(string, string, string, string, int) error { return nil }
func (s *stubFirewallBackend) RemoveBlock(ip net.IP) error {
	s.removed = append(s.removed, ip.String())
	return nil
}

func TestUnblockRejectsNonPOSTMethods(t *testing.T) {
	h := makeUnblockHandler(nil, "/tmp")
	req := httptest.NewRequest(http.MethodGet, "/unblock?ip=192.0.2.10", nil)
	rr := httptest.NewRecorder()

	h.ServeHTTP(rr, req)

	if rr.Code != http.StatusMethodNotAllowed {
		t.Fatalf("expected 405, got %d", rr.Code)
	}
	if allow := rr.Header().Get("Allow"); allow != http.MethodPost {
		t.Fatalf("expected Allow POST, got %q", allow)
	}
}

func TestUnblockPOSTWithValidPayloadProceeds(t *testing.T) {
	be := &stubFirewallBackend{}
	origUnblockDo := unblockDo
	var wg sync.WaitGroup
	wg.Add(1)
	unblockDo = func(_ context.Context, ip net.IP, _ unblock.Options) (unblock.Result, error) {
		defer wg.Done()
		return unblock.Result{WasBlocked: false}, nil
	}
	t.Cleanup(func() {
		wg.Wait()
		unblockDo = origUnblockDo
	})

	h := makeUnblockHandler(be, t.TempDir())
	req := httptest.NewRequest(http.MethodPost, "/unblock", strings.NewReader(`{"ip":"192.0.2.10"}`))
	req.Header.Set("Content-Type", "application/json")
	req.RemoteAddr = "198.51.100.25:12345"
	rr := httptest.NewRecorder()

	h.ServeHTTP(rr, req)
	wg.Wait()

	if rr.Code != http.StatusOK {
		t.Fatalf("expected 200, got %d body=%s", rr.Code, rr.Body.String())
	}
	if len(be.removed) != 1 || be.removed[0] != "192.0.2.10" {
		t.Fatalf("expected RemoveBlock to be called for 192.0.2.10, got %v", be.removed)
	}

	var body map[string]any
	if err := json.Unmarshal(rr.Body.Bytes(), &body); err != nil {
		t.Fatalf("decode response: %v", err)
	}
	if ok, _ := body["ok"].(bool); !ok {
		t.Fatalf("expected ok=true, got %v", body)
	}
	if gotIP, _ := body["ip"].(string); gotIP != "192.0.2.10" {
		t.Fatalf("expected ip=192.0.2.10, got %q", gotIP)
	}
}

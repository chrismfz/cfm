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

	"cfm/internal/blocklists"
	"cfm/internal/config"
	"cfm/internal/enrich"
	"cfm/internal/firewall"
	"cfm/internal/reporting"
	"cfm/internal/unblock"
)

type stubFirewallBackend struct {
	removed []string
}

var _ firewall.Backend = (*stubFirewallBackend)(nil)

func (s *stubFirewallBackend) EnsureBase() error                                 { return nil }
func (s *stubFirewallBackend) AddBlock(net.IP, string, *time.Duration) error     { return nil }
func (s *stubFirewallBackend) ListBlocks() ([]firewall.BlockedEntry, error)      { return nil, nil }
func (s *stubFirewallBackend) ListAllows() ([]firewall.BlockedEntry, error)      { return nil, nil }
func (s *stubFirewallBackend) AddAllow(net.IP, *time.Duration) error             { return nil }
func (s *stubFirewallBackend) RemoveAllow(net.IP) error                          { return nil }
func (s *stubFirewallBackend) AddBlockNet(string, *time.Duration) error          { return nil }
func (s *stubFirewallBackend) RemoveBlockNet(string) error                       { return nil }
func (s *stubFirewallBackend) AddAllowNet(string, *time.Duration) error          { return nil }
func (s *stubFirewallBackend) RemoveAllowNet(string) error                       { return nil }
func (s *stubFirewallBackend) AddIgnore(net.IP, *time.Duration) error            { return nil }
func (s *stubFirewallBackend) RemoveIgnore(net.IP) error                         { return nil }
func (s *stubFirewallBackend) AddIgnoreNet(string, *time.Duration) error         { return nil }
func (s *stubFirewallBackend) RemoveIgnoreNet(string) error                      { return nil }
func (s *stubFirewallBackend) AddChallenge(net.IP, *time.Duration) error         { return nil }
func (s *stubFirewallBackend) RemoveChallenge(net.IP) error                      { return nil }
func (s *stubFirewallBackend) SetChallengeRedirectEnabled(bool)                  {}
func (s *stubFirewallBackend) CleanupChallengeRedirect() error                   { return nil }
func (s *stubFirewallBackend) DropEverything() error                             { return nil }
func (s *stubFirewallBackend) ResetTable() error                                 { return nil }
func (s *stubFirewallBackend) SetConfigDir(string)                               {}
func (s *stubFirewallBackend) EnableEnrichment(...string)                        {}
func (s *stubFirewallBackend) GetEnricher() *enrich.Enricher                     { return nil }
func (s *stubFirewallBackend) SetReporter(reporting.Reporter)                    {}
func (s *stubFirewallBackend) SetChallengeLogger(func(string, ...any))           {}
func (s *stubFirewallBackend) ApplyFloodRules(*config.Config) error              { return nil }
func (s *stubFirewallBackend) ApplyHardeningRules(*config.Config) error          { return nil }
func (s *stubFirewallBackend) ApplyPortsPolicy(*config.PortsConfig) error        { return nil }
func (s *stubFirewallBackend) ApplyConnlimit([]config.ConnlimitRule) error       { return nil }
func (s *stubFirewallBackend) ApplyPortFlood([]config.PortFloodRule) error       { return nil }
func (s *stubFirewallBackend) ApplySMTPBlock(*config.SMTPBlockConfig) error      { return nil }
func (s *stubFirewallBackend) ApplyOutboundObserve(*config.OutboundConfig) error { return nil }
func (s *stubFirewallBackend) DumpFloodCounters()                                {}
func (s *stubFirewallBackend) DumpThrottledIPs()                                 {}
func (s *stubFirewallBackend) LoadPortScanner()                                  {}
func (s *stubFirewallBackend) DNATStatus(string, string) (bool, error)           { return false, nil }
func (s *stubFirewallBackend) DNATShow(string, string) (string, error)           { return "", nil }
func (s *stubFirewallBackend) DNATOn(string, string, int, int) error             { return nil }
func (s *stubFirewallBackend) DNATOff(string, string) error                      { return nil }
func (s *stubFirewallBackend) EnsureDNATAccepts() error                          { return nil }
func (s *stubFirewallBackend) PanelDNATOn(int) error                             { return nil }
func (s *stubFirewallBackend) PanelDNATOff() error                               { return nil }
func (s *stubFirewallBackend) PanelDNATStatus() (bool, string, error)            { return false, "", nil }
func (s *stubFirewallBackend) EnsurePanelDNATAccepts() ([]string, error)         { return nil, nil }
func (s *stubFirewallBackend) RemovePanelDNATAccepts() ([]string, error)         { return nil, nil }
func (s *stubFirewallBackend) PanelDNATAcceptState() map[int]string              { return nil }
func (s *stubFirewallBackend) EnsureChallengeRedirect(string, string) error      { return nil }
func (s *stubFirewallBackend) ApplyFeed(context.Context, blocklists.Feed, *blocklists.FetchResult) error {
	return nil
}
func (s *stubFirewallBackend) RebuildExternalUnions() error              { return nil }
func (s *stubFirewallBackend) PruneExternalFeeds([]string) error         { return nil }
func (s *stubFirewallBackend) DropFeedSets(string)                       {}
func (s *stubFirewallBackend) RemoveFeedByKey(string) error              { return nil }
func (s *stubFirewallBackend) DeleteSetIfExists(string) error            { return nil }
func (s *stubFirewallBackend) EnsureSetDynamic(string, bool, bool) error { return nil }
func (s *stubFirewallBackend) ReplaceSetFlushAdd(string, []string, *time.Duration) error {
	return nil
}
func (s *stubFirewallBackend) AddElementsBulk(string, []string, *time.Duration) error { return nil }
func (s *stubFirewallBackend) HasElem(string, string) (bool, error)                   { return false, nil }
func (s *stubFirewallBackend) ListSetElementsRaw(string) ([]string, error)            { return nil, nil }
func (s *stubFirewallBackend) ListSetElementsTimed(string) ([]firewall.SetElementTimed, error) {
	return nil, nil
}
func (s *stubFirewallBackend) ListTableJSON(string, string) ([]byte, error)          { return nil, nil }
func (s *stubFirewallBackend) ListSetJSON(string, string, string) ([]byte, error)    { return nil, nil }
func (s *stubFirewallBackend) ListTableTextNoDNS(string, string) (string, error)     { return "", nil }
func (s *stubFirewallBackend) ListChainText(string, string, string) (string, error)  { return "", nil }
func (s *stubFirewallBackend) FlushSet(string, string, string) error                 { return nil }
func (s *stubFirewallBackend) ReportBlock(string, string, string, string, int) error { return nil }
func (s *stubFirewallBackend) RemoveBlock(ip net.IP) error {
	s.removed = append(s.removed, ip.String())
	return nil
}
func (s *stubFirewallBackend) RemoveBlockBatch(ips []net.IP) error {
	for _, ip := range ips {
		s.removed = append(s.removed, ip.String())
	}
	return nil
}

// slowFirewallBackend makes the nft point-lookup block, simulating exec-engine
// nft lock contention on a busy node — the condition that made cfm-web time out.
type slowFirewallBackend struct {
	*stubFirewallBackend
	delay time.Duration
}

func (s *slowFirewallBackend) HasElem(string, string) (bool, error) {
	time.Sleep(s.delay)
	return false, nil
}

// A slow firewall backend must NOT make the handler exceed its response budget:
// the fast path is abandoned at the deadline and the response is sent promptly,
// flagged fastpath_done=false (the cleanup goroutine still guarantees removal).
func TestUnblockFastPathBudgetBounded(t *testing.T) {
	be := &slowFirewallBackend{stubFirewallBackend: &stubFirewallBackend{}, delay: 2 * time.Second}
	origUnblockDo := unblockDo
	var wg sync.WaitGroup
	wg.Add(1)
	unblockDo = func(_ context.Context, _ net.IP, _ unblock.Options) (*unblock.Result, error) {
		defer wg.Done()
		return &unblock.Result{}, nil
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

	start := time.Now()
	h.ServeHTTP(rr, req)
	elapsed := time.Since(start)

	// Budget is 800ms; the backend blocks 2s. The response must land well under
	// cfm-web's ~1.2s node-call deadline despite the slow backend.
	if elapsed > 1200*time.Millisecond {
		t.Fatalf("handler blocked %s on a slow backend — response budget not enforced", elapsed)
	}
	if rr.Code != http.StatusOK {
		t.Fatalf("expected 200, got %d", rr.Code)
	}
	var body map[string]any
	if err := json.Unmarshal(rr.Body.Bytes(), &body); err != nil {
		t.Fatalf("decode: %v", err)
	}
	if ok, _ := body["ok"].(bool); !ok {
		t.Fatalf("expected ok=true, got %v", body)
	}
	if done, _ := body["fastpath_done"].(bool); done {
		t.Fatalf("fastpath_done should be false when the nft path is still blocked at the budget: %v", body)
	}
	wg.Wait()
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
	unblockDo = func(_ context.Context, ip net.IP, _ unblock.Options) (*unblock.Result, error) {
		defer wg.Done()
		return &unblock.Result{WasBlocked: false}, nil
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

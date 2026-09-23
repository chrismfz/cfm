package apiserver

import (
	"context"
	"encoding/json"
	"net"
	"net/http"
	"net/http/httptest"
	"runtime"
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

func (s *stubFirewallBackend) EnsureBase() error                             { return nil }
func (s *stubFirewallBackend) AddBlock(net.IP, string, *time.Duration) error { return nil }
func (s *stubFirewallBackend) AddBlockBatch([]firewall.BlockEntry) (firewall.BlockBatchResult, error) {
	return firewall.BlockBatchResult{}, nil
}
func (s *stubFirewallBackend) AddAllowBatch([]firewall.BlockEntry) (firewall.BlockBatchResult, error) {
	return firewall.BlockBatchResult{}, nil
}
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
func (s *stubFirewallBackend) DropEverything() error                             { return nil }
func (s *stubFirewallBackend) ResetTable() error                                 { return nil }
func (s *stubFirewallBackend) SetConfigDir(string)                               {}
func (s *stubFirewallBackend) EnableEnrichment(...string)                        {}
func (s *stubFirewallBackend) GetEnricher() *enrich.Enricher                     { return nil }
func (s *stubFirewallBackend) SetReporter(reporting.Reporter)                    {}
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
// nftFinished is closed once the (possibly abandoned) nft goroutine reaches
// RemoveBlock, giving a test a deterministic join point so it never leaves that
// goroutine running past the test and contaminating a sibling's goroutine count.
type slowFirewallBackend struct {
	*stubFirewallBackend
	delay       time.Duration
	nftFinished chan struct{}
	once        sync.Once
}

func (s *slowFirewallBackend) HasElem(string, string) (bool, error) {
	time.Sleep(s.delay)
	return false, nil
}

func (s *slowFirewallBackend) RemoveBlock(ip net.IP) error {
	err := s.stubFirewallBackend.RemoveBlock(ip)
	if s.nftFinished != nil {
		s.once.Do(func() { close(s.nftFinished) })
	}
	return err
}

// waitStableGoroutines returns once the live goroutine count has held steady for
// a short window (or the timeout elapses). Taking a baseline only at quiescence
// drains any goroutine a prior test left running, so the count is a trustworthy
// reference rather than one inflated by unrelated in-flight goroutines.
func waitStableGoroutines(timeout time.Duration) int {
	deadline := time.Now().Add(timeout)
	last, stable := -1, 0
	for {
		runtime.GC()
		n := runtime.NumGoroutine()
		if n == last {
			if stable++; stable >= 5 { // ~100ms unchanged
				return n
			}
		} else {
			last, stable = n, 0
		}
		if !time.Now().Before(deadline) {
			return n
		}
		time.Sleep(20 * time.Millisecond)
	}
}

// A slow firewall backend must NOT make the handler exceed its response budget:
// the fast path is abandoned at the deadline and the response is sent promptly,
// flagged fastpath_done=false (the cleanup goroutine still guarantees removal).
func TestUnblockFastPathBudgetBounded(t *testing.T) {
	be := &slowFirewallBackend{
		stubFirewallBackend: &stubFirewallBackend{},
		delay:               1200 * time.Millisecond,
		nftFinished:         make(chan struct{}),
	}
	origUnblockDo := unblockDo
	var wg sync.WaitGroup
	wg.Add(1)
	unblockDo = func(_ context.Context, _ net.IP, _ unblock.Options) (*unblock.Result, error) {
		defer wg.Done()
		return &unblock.Result{}, nil
	}
	t.Cleanup(func() {
		<-be.nftFinished // join the abandoned nft goroutine; leave no cross-test stray
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

	// Budget is 800ms; the backend blocks 1.2s. The response must land well under
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
}

// When the fast path is abandoned at the budget, the nft goroutine finishes its
// slow HasElem+RemoveBlock AFTER the handler has already responded, then sends
// its result. That send must not block forever: a regression that nil-ed the
// send-target channel variable on the budget path turned `nftDone <- wb` into
// `nil <- wb`, leaking the goroutine (and racing the variable). Here the nft
// backend is slower than the budget, so the goroutine is always abandoned; the
// buffered cap-1 channel must still let it send and return. We assert it by
// watching the live goroutine count settle back to baseline.
func TestUnblockAbandonedNftGoroutineDoesNotLeak(t *testing.T) {
	be := &slowFirewallBackend{
		stubFirewallBackend: &stubFirewallBackend{},
		delay:               1200 * time.Millisecond,
		nftFinished:         make(chan struct{}),
	}
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
	req := httptest.NewRequest(http.MethodPost, "/unblock", strings.NewReader(`{"ip":"192.0.2.11"}`))
	req.Header.Set("Content-Type", "application/json")
	req.RemoteAddr = "198.51.100.26:12345"
	rr := httptest.NewRecorder()

	// Baseline only at quiescence, so a goroutine left running by a prior test
	// can't inflate it (an inflated baseline would let a real leak drop back to
	// it and pass — the false-negative we must avoid).
	base := waitStableGoroutines(4 * time.Second)

	h.ServeHTTP(rr, req) // abandons the nft goroutine at the 800ms budget
	wg.Wait()            // fire-and-forget cleanup has finished
	<-be.nftFinished     // nft goroutine reached RemoveBlock; correct code now returns

	// After RemoveBlock the nft goroutine performs its buffered send and returns,
	// so the live count returns to baseline. The pre-fix nil-channel send would
	// block forever on that send, pinning the count one above baseline.
	deadline := time.Now().Add(3 * time.Second)
	for {
		runtime.GC()
		if runtime.NumGoroutine() <= base {
			return // settled — no leak
		}
		if !time.Now().Before(deadline) {
			t.Fatalf("goroutine count did not return to baseline %d (still %d) — abandoned fast-path goroutine leaked", base, runtime.NumGoroutine())
		}
		time.Sleep(20 * time.Millisecond)
	}
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

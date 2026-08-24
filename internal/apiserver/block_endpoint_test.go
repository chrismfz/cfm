package apiserver

import (
	"bytes"
	"encoding/json"
	"errors"
	"fmt"
	"net"
	"net/http"
	"net/http/httptest"
	"sync"
	"testing"
	"time"
)

// blockRecorderBackend records AddBlock calls (the shared stubFirewallBackend
// in unblock_endpoint_test.go is a pure no-op).
type blockRecorderBackend struct {
	stubFirewallBackend
	mu      sync.Mutex
	blocked []string
	ttls    []*time.Duration
	failFor map[string]bool
}

func (b *blockRecorderBackend) AddBlock(ip net.IP, _ string, ttl *time.Duration) error {
	b.mu.Lock()
	defer b.mu.Unlock()
	if b.failFor[ip.String()] {
		return errors.New("nft add element failed (test)")
	}
	b.blocked = append(b.blocked, ip.String())
	b.ttls = append(b.ttls, ttl)
	return nil
}

type stubSelfIPs struct{ ips map[string]bool }

func (s stubSelfIPs) Contains(ip string) bool { return s.ips[ip] }
func (s stubSelfIPs) Refresh()                {}

type batchResp struct {
	OK      bool                `json:"ok"`
	Blocked []string            `json:"blocked"`
	Skipped []map[string]string `json:"skipped"`
	Failed  []map[string]string `json:"failed"`
}

func doBatch(t *testing.T, h http.HandlerFunc, body any, remoteAddr, xff string) (*httptest.ResponseRecorder, batchResp) {
	t.Helper()
	raw, err := json.Marshal(body)
	if err != nil {
		t.Fatalf("marshal: %v", err)
	}
	req := httptest.NewRequest(http.MethodPost, "/api/v1/firewall/block/batch", bytes.NewReader(raw))
	req.Header.Set("Content-Type", "application/json")
	if remoteAddr != "" {
		req.RemoteAddr = remoteAddr
	}
	if xff != "" {
		req.Header.Set("X-Forwarded-For", xff)
	}
	rr := httptest.NewRecorder()
	h.ServeHTTP(rr, req)
	var out batchResp
	_ = json.Unmarshal(rr.Body.Bytes(), &out)
	return rr, out
}

func skipReasons(rows []map[string]string) map[string]string {
	out := make(map[string]string, len(rows))
	for _, r := range rows {
		out[r["ip"]] = r["reason"]
	}
	return out
}

// One batch mixing every per-IP outcome: blocked, invalid, duplicate,
// self-IP skip, caller-IP skip, and a backend failure — the rest of the
// batch must proceed past each skip/failure.
func TestBlockBatch_PerIPOutcomes(t *testing.T) {
	be := &blockRecorderBackend{failFor: map[string]bool{"198.51.100.9": true}}
	self := stubSelfIPs{ips: map[string]bool{"203.0.113.1": true}}
	h := makeBlockBatchHandler(be, self)

	// httptest default RemoteAddr is 192.0.2.1:1234 (not loopback), so the
	// caller guard must key off it and ignore any XFF header.
	rr, out := doBatch(t, h, map[string]any{
		"ips": []string{
			"198.51.100.7",  // blocked
			"not-an-ip",     // invalid
			"198.51.100.7",  // duplicate
			"203.0.113.1",   // self_ip
			"192.0.2.1",     // caller_ip (RemoteAddr host)
			"198.51.100.9",  // backend failure
			"198.51.100.10", // blocked — must still run after the failure
		},
		"ttl":    "6h",
		"reason": "test-bulk",
	}, "", "8.8.8.8")

	if rr.Code != http.StatusOK {
		t.Fatalf("expected 200, got %d body=%s", rr.Code, rr.Body.String())
	}
	if out.OK {
		t.Fatalf("ok must be false when any IP failed, body=%s", rr.Body.String())
	}
	wantBlocked := []string{"198.51.100.7", "198.51.100.10"}
	if fmt.Sprint(out.Blocked) != fmt.Sprint(wantBlocked) {
		t.Fatalf("blocked = %v, want %v", out.Blocked, wantBlocked)
	}
	if fmt.Sprint(be.blocked) != fmt.Sprint(wantBlocked) {
		t.Fatalf("backend AddBlock calls = %v, want %v", be.blocked, wantBlocked)
	}
	for _, ttl := range be.ttls {
		if ttl == nil || *ttl != 6*time.Hour {
			t.Fatalf("AddBlock ttl = %v, want 6h", ttl)
		}
	}
	reasons := skipReasons(out.Skipped)
	if reasons["not-an-ip"] != "invalid" {
		t.Fatalf("expected invalid skip, got %v", out.Skipped)
	}
	if reasons["198.51.100.7"] != "duplicate" {
		t.Fatalf("expected duplicate skip, got %v", out.Skipped)
	}
	if reasons["203.0.113.1"] != "self_ip" {
		t.Fatalf("expected self_ip skip, got %v", out.Skipped)
	}
	if reasons["192.0.2.1"] != "caller_ip" {
		t.Fatalf("expected caller_ip skip, got %v", out.Skipped)
	}
	if len(out.Failed) != 1 || out.Failed[0]["ip"] != "198.51.100.9" {
		t.Fatalf("failed = %v, want just 198.51.100.9", out.Failed)
	}
}

// Behind the edge proxy (loopback RemoteAddr) the caller guard must use the
// canonical single X-Forwarded-For value written by the edge.
func TestBlockBatch_CallerIPBehindProxy(t *testing.T) {
	be := &blockRecorderBackend{}
	h := makeBlockBatchHandler(be, stubSelfIPs{})

	_, out := doBatch(t, h, map[string]any{
		"ips": []string{"198.51.100.20", "203.0.113.50"},
		"ttl": "1h",
	}, "127.0.0.1:9999", "203.0.113.50")

	if reasons := skipReasons(out.Skipped); reasons["203.0.113.50"] != "caller_ip" {
		t.Fatalf("expected caller_ip skip via XFF, got skipped=%v blocked=%v", out.Skipped, out.Blocked)
	}
	if fmt.Sprint(out.Blocked) != fmt.Sprint([]string{"198.51.100.20"}) {
		t.Fatalf("blocked = %v, want [198.51.100.20]", out.Blocked)
	}
}

// Empty TTL means permanent: AddBlock must receive a nil *time.Duration
// (an nft entry with no timeout), mirroring the single-block endpoint.
func TestBlockBatch_EmptyTTLIsPermanent(t *testing.T) {
	be := &blockRecorderBackend{}
	h := makeBlockBatchHandler(be, stubSelfIPs{})

	rr, out := doBatch(t, h, map[string]any{
		"ips": []string{"198.51.100.30"},
		"ttl": "",
	}, "", "")

	if rr.Code != http.StatusOK || !out.OK {
		t.Fatalf("expected ok, got %d body=%s", rr.Code, rr.Body.String())
	}
	if len(be.ttls) != 1 || be.ttls[0] != nil {
		t.Fatalf("permanent block must pass nil ttl, got %v", be.ttls)
	}
}

func TestBlockBatch_BadRequests(t *testing.T) {
	be := &blockRecorderBackend{}
	h := makeBlockBatchHandler(be, stubSelfIPs{})

	// Invalid TTL.
	rr, _ := doBatch(t, h, map[string]any{"ips": []string{"198.51.100.40"}, "ttl": "bogus"}, "", "")
	if rr.Code != http.StatusBadRequest {
		t.Fatalf("invalid ttl: expected 400, got %d", rr.Code)
	}
	// Empty list.
	rr, _ = doBatch(t, h, map[string]any{"ips": []string{}}, "", "")
	if rr.Code != http.StatusBadRequest {
		t.Fatalf("empty ips: expected 400, got %d", rr.Code)
	}
	// Over the cap.
	big := make([]string, blockBatchMaxIPs+1)
	for i := range big {
		big[i] = fmt.Sprintf("198.51.%d.%d", i/256, i%256)
	}
	rr, _ = doBatch(t, h, map[string]any{"ips": big}, "", "")
	if rr.Code != http.StatusBadRequest {
		t.Fatalf("over cap: expected 400, got %d", rr.Code)
	}
	if len(be.blocked) != 0 {
		t.Fatalf("bad requests must not reach the backend, got %v", be.blocked)
	}
}

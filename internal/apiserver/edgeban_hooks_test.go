package apiserver

import (
	"bytes"
	"context"
	"encoding/json"
	"net"
	"net/http"
	"net/http/httptest"
	"path/filepath"
	"strings"
	"sync"
	"testing"
	"time"

	"cfm/internal/edgeban"
	"cfm/internal/firewall"
	"cfm/internal/unblock"
)

// installEdgeStore installs a Default edge ban store (temp path) and returns
// a reconcile helper that makes the given addresses "held by nft".
func installEdgeStore(t *testing.T) (*edgeban.Store, func(ips ...string)) {
	t.Helper()
	s := edgeban.New(filepath.Join(t.TempDir(), "edgeban.json"))
	edgeban.SetDefault(s)
	t.Cleanup(func() { edgeban.SetDefault(nil) })
	return s, func(ips ...string) {
		var b []firewall.SetElementTimed
		for _, ip := range ips {
			b = append(b, firewall.SetElementTimed{Elem: ip})
		}
		s.Reconcile(edgeban.Snapshot{Blocks: b, ReadAt: time.Now().Add(time.Second)})
	}
}

// A manual ban (single and cfm-admin's "Block selected" batch) is enforced
// at the edge too.
func TestManualBlockEndpointsFeedEdgeBan(t *testing.T) {
	s, held := installEdgeStore(t)

	h := makeBlockHandler(&stubFirewallBackend{})
	raw, _ := json.Marshal(map[string]any{"ip": "198.51.100.30", "ttl": "2h", "reason": "x"})
	req := httptest.NewRequest(http.MethodPost, "/api/v1/firewall/block", bytes.NewReader(raw))
	req.Header.Set("Content-Type", "application/json")
	rr := httptest.NewRecorder()
	h.ServeHTTP(rr, req)
	if rr.Code != http.StatusOK {
		t.Fatalf("single block: %d %s", rr.Code, rr.Body.String())
	}

	bh := makeBlockBatchHandler(&blockRecorderBackend{}, stubSelfIPs{})
	if rr, out := doBatch(t, bh, map[string]any{"ips": []string{"198.51.100.31"}, "ttl": "6h"}, "", ""); rr.Code != http.StatusOK || !out.OK {
		t.Fatalf("batch block: %d %s", rr.Code, rr.Body.String())
	}

	held("198.51.100.30", "198.51.100.31")
	for _, ip := range []string{"198.51.100.30", "198.51.100.31"} {
		if ok, _ := s.Banned(ip); !ok {
			t.Errorf("%s: manual ban not in the edge ban store", ip)
		}
	}
}

// The API unblock lifts the edge ban.
func TestUnblockEndpointLiftsEdgeBan(t *testing.T) {
	s, held := installEdgeStore(t)
	s.Add(net.ParseIP("192.0.2.10"), nil, "waf_security", false)
	held("192.0.2.10")

	origUnblockDo := unblockDo
	var wg sync.WaitGroup
	wg.Add(1)
	unblockDo = func(_ context.Context, _ net.IP, _ unblock.Options) (*unblock.Result, error) {
		defer wg.Done()
		return &unblock.Result{}, nil
	}
	t.Cleanup(func() { wg.Wait(); unblockDo = origUnblockDo })

	h := makeUnblockHandler(&stubFirewallBackend{}, t.TempDir())
	req := httptest.NewRequest(http.MethodPost, "/unblock", strings.NewReader(`{"ip":"192.0.2.10"}`))
	req.Header.Set("Content-Type", "application/json")
	req.RemoteAddr = "198.51.100.25:12345"
	rr := httptest.NewRecorder()
	h.ServeHTTP(rr, req)
	wg.Wait()
	// The nft remove runs in its own goroutine; give it a moment.
	deadline := time.Now().Add(2 * time.Second)
	for time.Now().Before(deadline) {
		if ok, _ := s.Banned("192.0.2.10"); !ok {
			return
		}
		time.Sleep(10 * time.Millisecond)
	}
	t.Fatal("API unblock left the edge ban")
}

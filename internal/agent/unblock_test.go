package agent

import (
	"context"
	"errors"
	"net"
	"net/http"
	"net/http/httptest"
	"strings"
	"sync/atomic"
	"testing"

	"cfm/internal/firewall"
)

// unblockBackend records the backend calls an agent unblock makes.
type unblockBackend struct {
	firewall.Backend
	ensureBase atomic.Int32
	removed    atomic.Int32
	batches    atomic.Int32
	batchIPs   atomic.Int32
}

func (b *unblockBackend) EnsureBase() error        { b.ensureBase.Add(1); return nil }
func (b *unblockBackend) RemoveBlock(net.IP) error { b.removed.Add(1); return nil }
func (b *unblockBackend) RemoveBlockBatch(ips []net.IP) error {
	b.batches.Add(1)
	b.batchIPs.Add(int32(len(ips)))
	return nil
}
func (b *unblockBackend) ListTableTextNoDNS(string, string) (string, error) {
	return "", errors.New("no feed sets in this test")
}

// Processing an unblock request never runs EnsureBase. It used to run it per
// IP (and unblock.Do ran it again): 2x 10-70s on busy nodes, per IP, on the
// agent's work loop.
func TestProcessUnblocks_NoEnsureBase(t *testing.T) {
	t.Setenv("PATH", t.TempDir()) // never run a real csf/fail2ban/imunify here
	var confirmed atomic.Int32
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if strings.HasSuffix(r.URL.Path, "/unblock-confirm") {
			confirmed.Add(1)
		}
		w.WriteHeader(http.StatusOK)
	}))
	defer srv.Close()

	be := &unblockBackend{}
	api := &APIClient{BaseURL: srv.URL, Token: "t", HTTP: srv.Client()}
	api.ProcessUnblocks(context.Background(), be, t.TempDir(), []PendingUnblock{{ID: 7, IP: "198.51.100.1"}}, nil)

	if n := be.ensureBase.Load(); n != 0 {
		t.Errorf("EnsureBase ran %d times, want 0", n)
	}
	if be.removed.Load() != 1 || confirmed.Load() != 1 {
		t.Errorf("removed %d, confirmed %d; want the IP removed and the request confirmed once", be.removed.Load(), confirmed.Load())
	}
}

// A batch of requests is one unblock for all their IPs — one block-set write,
// however many requests — and every request is confirmed, an invalid IP too
// (so it doesn't come back every tick).
func TestProcessUnblocks_OneBatch(t *testing.T) {
	t.Setenv("PATH", t.TempDir())
	var confirmed atomic.Int32
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if strings.HasSuffix(r.URL.Path, "/unblock-confirm") {
			confirmed.Add(1)
		}
		w.WriteHeader(http.StatusOK)
	}))
	defer srv.Close()

	be := &unblockBackend{}
	api := &APIClient{BaseURL: srv.URL, Token: "t", HTTP: srv.Client()}
	reqs := []PendingUnblock{
		{ID: 1, IP: "198.51.100.1"}, {ID: 2, IP: "198.51.100.2"},
		{ID: 3, IP: "198.51.100.1"}, {ID: 4, IP: "not-an-ip"},
	}
	api.ProcessUnblocks(context.Background(), be, t.TempDir(), reqs, nil)

	if be.batches.Load() != 1 || be.batchIPs.Load() != 2 || be.removed.Load() != 0 {
		t.Errorf("%d batch writes of %d IPs, %d single removes; want one batch of the 2 distinct IPs",
			be.batches.Load(), be.batchIPs.Load(), be.removed.Load())
	}
	if confirmed.Load() != 4 {
		t.Errorf("confirmed %d requests, want all 4", confirmed.Load())
	}
}

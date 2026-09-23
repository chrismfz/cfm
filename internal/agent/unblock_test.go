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
}

func (b *unblockBackend) EnsureBase() error        { b.ensureBase.Add(1); return nil }
func (b *unblockBackend) RemoveBlock(net.IP) error { b.removed.Add(1); return nil }
func (b *unblockBackend) ListTableTextNoDNS(string, string) (string, error) {
	return "", errors.New("no feed sets in this test")
}

// Processing an unblock request never runs EnsureBase. It used to run it per
// IP (and unblock.Do ran it again): 2x 10-70s on busy nodes, per IP, on the
// agent's work loop.
func TestProcessUnblockRequest_NoEnsureBase(t *testing.T) {
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
	api.ProcessUnblockRequest(context.Background(), be, t.TempDir(), 7, "198.51.100.1", nil)

	if n := be.ensureBase.Load(); n != 0 {
		t.Errorf("EnsureBase ran %d times, want 0", n)
	}
	if be.removed.Load() != 1 || confirmed.Load() != 1 {
		t.Errorf("removed %d, confirmed %d; want the IP removed and the request confirmed once", be.removed.Load(), confirmed.Load())
	}
}

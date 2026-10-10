package cli

import (
	"net"
	"net/http"
	"net/http/httptest"
	"sync"
	"testing"
	"time"

	"cfm/internal/firewall"
)

type allowBlockFake struct{ firewall.Backend }

func (allowBlockFake) AddAllow(net.IP, *time.Duration) error         { return nil }
func (allowBlockFake) AddBlock(net.IP, string, *time.Duration) error { return nil }

// `cfm block` and `cfm allow` tell the running daemon, which enforces (or
// lifts) the ban at the edge for a client behind a trusted proxy.
func TestBlockAndAllowNotifyTheDaemon(t *testing.T) {
	var mu sync.Mutex
	var got []string
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		mu.Lock()
		got = append(got, r.Method+" "+r.URL.Path+"?"+r.URL.RawQuery)
		mu.Unlock()
		w.WriteHeader(http.StatusOK)
	}))
	defer srv.Close()
	EdgeBanBaseURL = srv.URL
	t.Cleanup(func() { EdgeBanBaseURL = "" })

	exists := func() bool { return true }
	if rc := RunBlock([]string{"203.0.113.40", "--ttl", "1h"}, allowBlockFake{}, "", exists); rc != 0 {
		t.Fatalf("block rc=%d", rc)
	}
	if rc := RunAllow([]string{"203.0.113.40", "--ttl", "1h"}, allowBlockFake{}, "", exists); rc != 0 {
		t.Fatalf("allow rc=%d", rc)
	}
	mu.Lock()
	defer mu.Unlock()
	want := []string{
		"POST /api/v1/webdet/edge-ban?ip=203.0.113.40&ttl=1h0m0s",
		"POST /api/v1/webdet/edge-ban?ip=203.0.113.40&unban=1",
	}
	if len(got) != len(want) || got[0] != want[0] || got[1] != want[1] {
		t.Fatalf("daemon calls %v, want %v", got, want)
	}
}

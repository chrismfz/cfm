package apiserver

import (
	"context"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"

	"cfm/internal/blocklists"
)

func TestFirewallFeeds_NoManager(t *testing.T) {
	h := makeFirewallFeedsHandler(func() *blocklists.Manager { return nil })
	rr := httptest.NewRecorder()
	h.ServeHTTP(rr, httptest.NewRequest(http.MethodGet, "/api/v1/firewall/feeds", nil))
	if rr.Code != http.StatusOK || !strings.Contains(rr.Body.String(), `"available":false`) {
		t.Fatalf("got %d %s", rr.Code, rr.Body.String())
	}
}

func TestFirewallFeeds_ReportsTokenAndRedacts(t *testing.T) {
	origin := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.Header.Get("Token") != "sekrit-token" {
			w.WriteHeader(http.StatusUnauthorized)
			return
		}
		_, _ = w.Write([]byte("1.2.3.4\n5.6.7.8\n"))
	}))
	defer origin.Close()

	mgr := blocklists.NewManager(blocklists.ApplierFunc(func(context.Context, blocklists.Feed, *blocklists.FetchResult) error { return nil }))
	mgr.SetAPIAuth(origin.URL, "sekrit-token")
	mgr.Reload([]blocklists.Feed{{Name: "MYBLOCK", Type: blocklists.TypeBlock, Interval: time.Hour, URL: origin.URL + "/blacklist.txt?key=apikey123"}})
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	mgr.Start(ctx)
	defer mgr.Stop()

	h := makeFirewallFeedsHandler(func() *blocklists.Manager { return mgr })
	var body string
	for i := 0; i < 200; i++ {
		rr := httptest.NewRecorder()
		h.ServeHTTP(rr, httptest.NewRequest(http.MethodGet, "/api/v1/firewall/feeds", nil))
		body = rr.Body.String()
		if strings.Contains(body, `"last_v4":2`) {
			break
		}
		time.Sleep(10 * time.Millisecond)
	}
	for _, want := range []string{`"token_sent":true`, `"api_origin":true`, `"last_http":200`, `"failing":0`, `"token_rejected":0`, `/blacklist.txt?REDACTED`, `"type":"BLOCK"`} {
		if !strings.Contains(body, want) {
			t.Errorf("missing %s in %s", want, body)
		}
	}
	for _, leak := range []string{"sekrit-token", "apikey123"} {
		if strings.Contains(body, leak) {
			t.Errorf("response leaks %q: %s", leak, body)
		}
	}
}

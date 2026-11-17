package blocklists

import (
	"context"
	"net/http"
	"net/http/httptest"
	"sync/atomic"
	"testing"

	"cfm/internal/proxyipfilter"
)

// The proxied-client filter gets every applied feed (the first fetch, a
// changed one; a skipped re-fetch keeps what it had), and loses one Reload
// removes, including when that feed's fetch was in flight.
func TestManagerFeedsTheProxiedIPFilter(t *testing.T) {
	proxyipfilter.ResetForTest()
	t.Cleanup(proxyipfilter.ResetForTest)
	var body atomic.Value
	body.Store("20.43.87.186\n45.138.12.0/24\n")
	ts := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		_, _ = w.Write([]byte(body.Load().(string)))
	}))
	defer ts.Close()

	var inApply func()
	m := NewManager(applierFunc(func(context.Context, Feed, *FetchResult) error {
		if inApply != nil {
			inApply()
		}
		return nil
	}))
	feed := Feed{Name: "MYBLOCK", Type: TypeBlock, URL: ts.URL}
	r := &runner{feed: feed}
	m.mu.Lock()
	m.runs[feed.Name] = r
	m.feeds = map[string]Feed{feed.Name: feed}
	m.mu.Unlock()

	m.fetchOnce(context.Background(), r)
	if v := proxyipfilter.Check("45.138.12.9"); len(v.Blocks) != 1 || v.Blocks[0] != "feed:myblock" {
		t.Fatalf("first fetch: %+v", v)
	}
	m.fetchOnce(context.Background(), r) // unchanged: skipped, still there
	if !proxyipfilter.Check("20.43.87.186").Listed() {
		t.Fatal("a skipped re-fetch lost the feed")
	}
	body.Store("198.51.100.1\n")
	m.fetchOnce(context.Background(), r)
	if proxyipfilter.Check("20.43.87.186").Listed() || !proxyipfilter.Check("198.51.100.1").Listed() {
		t.Fatal("a changed feed did not replace the old content")
	}

	// Reload removes the feed while its fetch is in flight (inside the apply):
	// the finished fetch must not bring it back.
	body.Store("203.0.113.9\n")
	inApply = func() { m.Reload(nil) }
	m.fetchOnce(context.Background(), r)
	if proxyipfilter.Check("203.0.113.9").Listed() || proxyipfilter.Check("198.51.100.1").Listed() {
		t.Fatal("a removed feed is still (or again) in the filter")
	}

	// An ALLOW feed cancels.
	proxyipfilter.SetFeed("MYBLOCK", false, []string{"192.0.2.7"}, nil)
	allow := Feed{Name: "MYALLOW", Type: TypeAllow, URL: ts.URL}
	ra := &runner{feed: allow}
	body.Store("192.0.2.7\n")
	inApply = nil
	m.mu.Lock()
	m.runs[allow.Name] = ra
	m.mu.Unlock()
	m.fetchOnce(context.Background(), ra)
	if v := proxyipfilter.Check("192.0.2.7"); len(v.Allows) != 1 || v.Enforce {
		t.Fatalf("allow feed: %+v", v)
	}
}

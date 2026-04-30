package blocklists

import (
	"context"
	"errors"
	"net/http"
	"net/http/httptest"
	"testing"
)

type applierFunc func(ctx context.Context, f Feed, res *FetchResult) error

func (f applierFunc) ApplyFeed(ctx context.Context, feed Feed, res *FetchResult) error {
	return f(ctx, feed, res)
}

func TestManagerFetchOnceSurfacesApplyErrorInStatus(t *testing.T) {
	ts := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		w.WriteHeader(http.StatusOK)
		_, _ = w.Write([]byte("1.2.3.4\n"))
	}))
	defer ts.Close()

	m := NewManager(applierFunc(func(context.Context, Feed, *FetchResult) error {
		return errors.New("backend apply failed")
	}))
	r := &runner{feed: Feed{Name: "x", URL: ts.URL}}
	m.fetchOnce(context.Background(), r)

	if r.lastErr == nil {
		t.Fatalf("expected apply error to be retained")
	}
	if got := r.lastErr.Error(); got == "" {
		t.Fatalf("expected non-empty error")
	}
}

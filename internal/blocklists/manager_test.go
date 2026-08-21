package blocklists

import (
	"context"
	"errors"
	"net/http"
	"net/http/httptest"
	"sync/atomic"
	"testing"
	"time"
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

func TestHashResultOrderIndependent(t *testing.T) {
	a := &FetchResult{V4: []string{"1.1.1.1", "2.2.2.2"}, V6: []string{"2001:db8::1"}}
	b := &FetchResult{V4: []string{"2.2.2.2", "1.1.1.1"}, V6: []string{"2001:db8::1"}}
	if hashResult(a) != hashResult(b) {
		t.Fatalf("reordered-but-equal content should hash equal")
	}
	c := &FetchResult{V4: []string{"1.1.1.1", "3.3.3.3"}, V6: []string{"2001:db8::1"}}
	if hashResult(a) == hashResult(c) {
		t.Fatalf("different content should hash differently")
	}
	// Moving an element across the v4/v6 boundary must change the hash.
	d := &FetchResult{V4: []string{"1.1.1.1"}, V6: []string{"2.2.2.2", "2001:db8::1"}}
	if hashResult(a) == hashResult(d) {
		t.Fatalf("v4/v6 split should affect the hash")
	}
	// hashResult must not sort the caller's slice in place.
	unsorted := []string{"2.2.2.2", "1.1.1.1"}
	_ = hashResult(&FetchResult{V4: unsorted})
	if unsorted[0] != "2.2.2.2" {
		t.Fatalf("hashResult mutated the caller's slice")
	}
}

func TestManagerFetchOnceSkipsUnchanged(t *testing.T) {
	var body atomic.Value
	body.Store("1.2.3.4\n5.6.7.8\n")
	ts := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		_, _ = w.Write([]byte(body.Load().(string)))
	}))
	defer ts.Close()

	applies := 0
	m := NewManager(applierFunc(func(context.Context, Feed, *FetchResult) error {
		applies++
		return nil
	}))
	r := &runner{feed: Feed{Name: "x", URL: ts.URL}}

	m.fetchOnce(context.Background(), r) // first fetch → apply
	m.fetchOnce(context.Background(), r) // identical content → skip
	if applies != 1 {
		t.Fatalf("unchanged feed re-applied: applies=%d, want 1", applies)
	}

	body.Store("1.2.3.4\n9.9.9.9\n") // content changed
	m.fetchOnce(context.Background(), r)
	if applies != 2 {
		t.Fatalf("changed feed not re-applied: applies=%d, want 2", applies)
	}
}

// A failed apply must not advance the content hash, so the next identical fetch
// retries instead of being skipped.
func TestManagerFetchOnceRetriesAfterApplyError(t *testing.T) {
	ts := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		_, _ = w.Write([]byte("1.2.3.4\n"))
	}))
	defer ts.Close()

	attempts := 0
	m := NewManager(applierFunc(func(context.Context, Feed, *FetchResult) error {
		attempts++
		if attempts == 1 {
			return errors.New("transient apply failure")
		}
		return nil
	}))
	r := &runner{feed: Feed{Name: "x", URL: ts.URL}}

	m.fetchOnce(context.Background(), r) // apply fails → hash not stored
	m.fetchOnce(context.Background(), r) // same content, but must retry (not skip)
	if attempts != 2 {
		t.Fatalf("apply after a failure was skipped: attempts=%d, want 2", attempts)
	}
	if r.lastErr != nil {
		t.Fatalf("second apply succeeded but lastErr = %v", r.lastErr)
	}
}

// Even with unchanged content, a feed must be re-applied at least every
// feedResyncInterval so cleared sets self-heal.
func TestManagerFetchOnceResyncsAfterInterval(t *testing.T) {
	ts := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		_, _ = w.Write([]byte("1.2.3.4\n"))
	}))
	defer ts.Close()

	applies := 0
	m := NewManager(applierFunc(func(context.Context, Feed, *FetchResult) error {
		applies++
		return nil
	}))
	r := &runner{feed: Feed{Name: "x", URL: ts.URL}}

	m.fetchOnce(context.Background(), r) // first → apply
	m.fetchOnce(context.Background(), r) // unchanged, within window → skip
	if applies != 1 {
		t.Fatalf("expected skip within resync window, applies=%d", applies)
	}

	// Simulate the resync interval elapsing since the last apply.
	r.lastApply = r.lastApply.Add(-feedResyncInterval - time.Minute)
	m.fetchOnce(context.Background(), r) // unchanged but stale → force re-apply
	if applies != 2 {
		t.Fatalf("expected forced resync after interval, applies=%d", applies)
	}
}

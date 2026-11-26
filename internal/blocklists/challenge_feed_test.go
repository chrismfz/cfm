package blocklists

import (
	"context"
	"net/http"
	"net/http/httptest"
	"reflect"
	"strings"
	"testing"

	"cfm/internal/proxyipfilter"
)

func TestParseConfigChallenge(t *testing.T) {
	feeds, err := ParseConfig(strings.NewReader("TOR|CHALLENGE|3600|0|https://check.torproject.org/torbulkexitlist\ntor2|challenge|3600|0|https://example.org/x\n"))
	if err != nil || len(feeds) != 2 {
		t.Fatalf("feeds %v err %v", feeds, err)
	}
	for _, f := range feeds {
		if f.Type != TypeChallenge || f.Type.String() != "CHALLENGE" {
			t.Errorf("%s: type %v", f.Name, f.Type)
		}
	}
}

// A CHALLENGE feed never reaches nft: the applier is not called, the filter
// gets it as a challenge list (not a block source), and the nft prune does
// not keep sets for it.
func TestManagerChallengeFeedSkipsNFT(t *testing.T) {
	proxyipfilter.ResetForTest()
	t.Cleanup(proxyipfilter.ResetForTest)
	ts := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		_, _ = w.Write([]byte("185.220.101.1\n2001:db8::/32\n"))
	}))
	defer ts.Close()

	applied := 0
	m := NewManager(applierFunc(func(context.Context, Feed, *FetchResult) error {
		applied++
		return nil
	}))
	feed := Feed{Name: "TOR", Type: TypeChallenge, URL: ts.URL}
	r := &runner{feed: feed}
	m.mu.Lock()
	m.runs[feed.Name] = r
	m.feeds = map[string]Feed{feed.Name: feed}
	m.mu.Unlock()
	m.fetchOnce(context.Background(), r)

	if applied != 0 {
		t.Fatalf("a CHALLENGE feed was applied to nft %d times", applied)
	}
	if v := proxyipfilter.Check("185.220.101.1"); v.Listed() {
		t.Fatalf("a CHALLENGE feed is a block source: %+v", v)
	}
	for _, ip := range []string{"185.220.101.1", "2001:db8::5"} {
		if v := proxyipfilter.CheckChallenge(ip); len(v.Lists) != 1 || v.Lists[0] != "feed:TOR" || v.Enforce {
			t.Errorf("%s: %+v (log mode by default)", ip, v)
		}
	}
	if r.lastErr != nil || r.lastAppliedAt.IsZero() {
		t.Errorf("status: err %v applied %v", r.lastErr, r.lastAppliedAt)
	}

	got := NFTFeedNames([]Feed{{Name: "MYBLOCK", Type: TypeBlock}, feed, {Name: "MYALLOW", Type: TypeAllow}})
	if !reflect.DeepEqual(got, []string{"MYBLOCK", "MYALLOW"}) {
		t.Errorf("NFTFeedNames = %v", got)
	}
}

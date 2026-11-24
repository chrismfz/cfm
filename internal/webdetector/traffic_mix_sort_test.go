package webdetector

import (
	"net/http/httptest"
	"os"
	"path/filepath"
	"regexp"
	"slices"
	"sort"
	"testing"
	"time"
)

// "By requests" picks the BUSIEST clients, not the costliest ones reordered:
// a client that would not make the origin-time top N makes the requests one.
func TestTrafficMix_SortPicksTheTopByThatColumn(t *testing.T) {
	s := newTrafficMixStore()
	now := tmBase()
	// slow: few requests, much origin time; busy: many cheap requests.
	for i := 0; i < 3; i++ {
		tmFeed(s, tmOrigin("198.51.100.1", "a.gr", "GET", "/", "slowbot/1", 200, 5), now)
	}
	for i := 0; i < 50; i++ {
		tmFeed(s, tmOrigin("198.51.100.2", "a.gr", "GET", "/", "busybot/1", 200, 0.01), now)
	}
	tmFeed(s, LogRec{IP: "198.51.100.3", Host: "a.gr", Method: "GET", URI: "/big", UA: "fatbot/1", Status: 200, Bytes: 1 << 30, URT: 0.02, Upstream: true, UpstreamName: "cfm_apache"}, now)

	first := func(sortBy string) string {
		m := s.SnapshotSorted(now.Add(time.Minute), 6*time.Hour, "", false, 10, 1, sortBy)
		if len(m.Clients) != 1 {
			t.Fatalf("%s: %d clients", sortBy, len(m.Clients))
		}
		return m.Clients[0].Client
	}
	for sortBy, want := range map[string]string{
		TrafficMixSortOrigin:   "slowbot",
		TrafficMixSortRequests: "busybot",
		TrafficMixSortBytes:    "fatbot",
		"":                     "slowbot",
	} {
		if got := first(sortBy); got != want {
			t.Errorf("sort=%q: top client %q, want %q", sortBy, got, want)
		}
	}
	// ips: the bot with the most distinct IPs in the last hour.
	s2 := newTrafficMixStore()
	n2 := time.Now().Add(-10 * time.Minute)
	for i := 0; i < 5; i++ {
		tmFeed(s2, tmOrigin("203.0.113."+string(rune('1'+i)), "a.gr", "GET", "/", "spreadbot/1", 200, 0.01), n2)
	}
	for i := 0; i < 9; i++ {
		tmFeed(s2, tmOrigin("203.0.113.99", "a.gr", "GET", "/", "onebot/1", 200, 1), n2)
	}
	if m := s2.SnapshotSorted(time.Now(), time.Hour, "", false, 10, 1, TrafficMixSortIPs); len(m.Clients) != 1 || m.Clients[0].Client != "spreadbot" {
		t.Fatalf("sort=ips: %+v", m.Clients)
	}
}

func TestTrafficMix_SortParam(t *testing.T) {
	e := &Engine{}
	for q, want := range map[string]int{"": 200, "requests": 200, "IPS": 200, "rate": 400, "x": 400} {
		rr := httptest.NewRecorder()
		e.handleTrafficMix(rr, manualIPReq(CtxRoleAdmin, "/api/v1/webdet/traffic-mix?sort="+q, ""))
		if rr.Code != want {
			t.Errorf("sort=%q: %d, want %d (%s)", q, rr.Code, want, rr.Body.String())
		}
	}
}

// traffic-model.js CLIENT_SORTS sends exactly the sorts the API takes.
func TestTrafficMix_SortsMirroredInTrafficModel(t *testing.T) {
	js, err := os.ReadFile(filepath.Join("..", "webui", "static", "assets", "webdet", "traffic-model.js"))
	if err != nil {
		t.Skipf("traffic-model.js not found: %v", err)
	}
	block := regexp.MustCompile(`(?s)export const CLIENT_SORTS = Object\.freeze\(\{(.*?)\}\);`).FindSubmatch(js)
	if block == nil {
		t.Fatal("traffic-model.js has no CLIENT_SORTS")
	}
	var params []string
	for _, m := range regexp.MustCompile(`param: "([a-z]+)"`).FindAllSubmatch(block[1], -1) {
		if p := string(m[1]); !slices.Contains(params, p) {
			params = append(params, p)
		}
	}
	want := slices.Clone(TrafficMixSorts)
	sort.Strings(params)
	sort.Strings(want)
	if !slices.Equal(params, want) {
		t.Fatalf("traffic-model.js sends %v, the API takes %v", params, want)
	}
}

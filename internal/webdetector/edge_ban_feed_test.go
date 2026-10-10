package webdetector

import (
	"encoding/json"
	"net"
	"net/http"
	"net/http/httptest"
	"testing"
	"time"

	"cfm/internal/edgeban"
)

type edgeBanReply struct {
	Gen       string           `json:"gen"`
	Unchanged bool             `json:"unchanged"`
	IPs       map[string]int64 `json:"ips"`
}

func fetchEdgeBan(t *testing.T, b *NginxBridge, gen, token string) (int, edgeBanReply) {
	t.Helper()
	rr := httptest.NewRecorder()
	req := httptest.NewRequest(http.MethodGet, "/nginx/edgeban?gen="+gen, nil)
	req.Header.Set("X-CFM-Token", token)
	b.handleEdgeBan(rr, req)
	var r edgeBanReply
	_ = json.Unmarshal(rr.Body.Bytes(), &r)
	return rr.Code, r
}

// The feed the edge pulls: every banned address (less IGNORE_IPS) with its
// expiry, under a generation that is the content's hash: unchanged content
// answers "unchanged", a change gives a new generation, and the same content
// gives the same generation again (a daemon restart keeps the edge's copy).
func TestEdgeBanFeed(t *testing.T) {
	s := installEdgeBans(t, "34.153.214.160", "203.0.113.5")
	ttl := time.Hour
	s.Add(net.ParseIP("198.51.100.7"), &ttl, "manual", true) // added after the read: still answered
	b := NewNginxBridge("/tmp/cfm-test.sock", "tok", time.Minute, time.Minute)
	b.bypassFunc = func(ip string) bool { return ip == "203.0.113.5" } // IGNORE_IPS

	if code, _ := fetchEdgeBan(t, b, "", "wrong"); code != http.StatusForbidden {
		t.Fatalf("bad token: http %d, want 403", code)
	}
	code, r := fetchEdgeBan(t, b, "", "tok")
	if code != 200 || r.Gen == "" || r.Unchanged {
		t.Fatalf("first fetch: http %d %+v", code, r)
	}
	if exp, ok := r.IPs["34.153.214.160"]; !ok || exp != 0 {
		t.Errorf("permanent ban: %v %v, want expiry 0", exp, ok)
	}
	if exp := r.IPs["198.51.100.7"]; exp < time.Now().Add(59*time.Minute).Unix() {
		t.Errorf("timed ban expiry %d, want ~now+1h", exp)
	}
	if _, ok := r.IPs["203.0.113.5"]; ok {
		t.Error("an IGNORE_IPS address is in the feed")
	}

	if _, again := fetchEdgeBan(t, b, r.Gen, "tok"); !again.Unchanged || again.Gen != r.Gen || again.IPs != nil {
		t.Fatalf("same content with its generation: %+v, want unchanged", again)
	}

	s.Remove("34.153.214.160")
	_, after := fetchEdgeBan(t, b, r.Gen, "tok")
	if after.Unchanged || after.Gen == r.Gen {
		t.Fatalf("after an unban: %+v, want a new generation", after)
	}
	if _, ok := after.IPs["34.153.214.160"]; ok {
		t.Error("the unbanned address is still in the feed")
	}
	s.Add(net.ParseIP("34.153.214.160"), nil, "waf_security", false)
	if _, back := fetchEdgeBan(t, b, "", "tok"); back.Gen != r.Gen {
		t.Errorf("the same content again: gen %s, want %s", back.Gen, r.Gen)
	}

	// The kill switch and a store not yet reconciled send an empty list.
	edgeban.SetEnabled(false)
	_, off := fetchEdgeBan(t, b, "", "tok")
	edgeban.SetEnabled(true)
	if len(off.IPs) != 0 || off.Gen == "" {
		t.Errorf("EDGE_BAN=0: %+v, want an empty list", off)
	}
	// A store that has not reconciled (a daemon start) knows nothing either
	// way: "not ready", no list, so the edge keeps its copy.
	edgeban.SetDefault(edgeban.New(""))
	rr := httptest.NewRecorder()
	req := httptest.NewRequest(http.MethodGet, "/nginx/edgeban", nil)
	req.Header.Set("X-CFM-Token", "tok")
	b.handleEdgeBan(rr, req)
	var cold map[string]any
	_ = json.Unmarshal(rr.Body.Bytes(), &cold)
	if cold["ready"] != false || cold["ips"] != nil || cold["gen"] != nil {
		t.Errorf("unreconciled store: %s, want {\"ready\":false}", rr.Body.String())
	}
}

// The feed is built once per change: an unchanged store answers from the
// cache, a write or an expiry inside it rebuilds it.
func TestEdgeBanFeedCache(t *testing.T) {
	s := installEdgeBans(t, "34.153.214.160")
	b := NewNginxBridge("/tmp/cfm-test.sock", "tok", time.Minute, time.Minute)
	gen1, ips1 := b.edgeBanFeed()
	if gen2, ips2 := b.edgeBanFeed(); gen2 != gen1 || len(ips2) != len(ips1) {
		t.Fatal("unchanged store: a different feed")
	}
	calls := 0
	b.bypassFunc = func(string) bool { calls++; return false }
	b.edgeBanFeed()
	if calls != 0 {
		t.Fatal("unchanged store: the feed was rebuilt")
	}
	short := 1500 * time.Millisecond
	s.Add(net.ParseIP("198.51.100.9"), &short, "manual", true)
	gen3, ips3 := b.edgeBanFeed()
	if gen3 == gen1 || ips3["198.51.100.9"] == 0 {
		t.Fatalf("after a ban: gen %s ips %v, want the new ban", gen3, ips3)
	}
	time.Sleep(short + 100*time.Millisecond)
	if _, ips4 := b.edgeBanFeed(); len(ips4) != 1 {
		t.Fatalf("after the timed ban expired: %v, want it gone (rebuilt at its expiry)", ips4)
	}
}

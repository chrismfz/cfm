package webdetector

import (
	"encoding/json"
	"net"
	"net/http"
	"net/http/httptest"
	"net/url"
	"strconv"
	"testing"
	"time"

	"cfm/internal/edgeban"
)

type edgeBanReply struct {
	Ready *bool            `json:"ready"`
	Epoch string           `json:"epoch"`
	Seq   uint64           `json:"seq"`
	Mode  string           `json:"mode"`
	Full  bool             `json:"full"`
	IPs   map[string]int64 `json:"ips"`
	Set   map[string]int64 `json:"set"`
	Del   []string         `json:"del"`
}

func pollEdgeBan(t *testing.T, b *NginxBridge, q url.Values, token string) (int, edgeBanReply, string) {
	t.Helper()
	rr := httptest.NewRecorder()
	req := httptest.NewRequest(http.MethodGet, "/nginx/edgeban?"+q.Encode(), nil)
	req.Header.Set("X-CFM-Token", token)
	b.handleEdgeBan(rr, req)
	var r edgeBanReply
	_ = json.Unmarshal(rr.Body.Bytes(), &r)
	return rr.Code, r, rr.Body.String()
}

func at(r edgeBanReply) url.Values {
	return url.Values{"epoch": {r.Epoch}, "seq": {strconv.FormatUint(r.Seq, 10)}}
}

// The edge pulls the whole list first, then only what changed since its
// position: a ban, an unban, an expiry. An edge out of reach (another epoch,
// a position the journal no longer covers, or one ahead of it) gets the
// whole list again.
func TestEdgeBanJournal(t *testing.T) {
	s := installEdgeBans(t, "34.153.214.160", "203.0.113.5")
	b := NewNginxBridge("/tmp/cfm-test.sock", "tok", time.Minute, time.Minute)
	b.bypassFunc = func(ip string) bool { return ip == "203.0.113.5" } // IGNORE_IPS

	if code, _, _ := pollEdgeBan(t, b, url.Values{}, "wrong"); code != http.StatusForbidden {
		t.Fatalf("bad token: http %d, want 403", code)
	}
	_, first, raw := pollEdgeBan(t, b, url.Values{}, "tok")
	if !first.Full || first.Epoch == "" || first.Mode != "log" {
		t.Fatalf("first poll: %s, want the whole list in log mode", raw)
	}
	if exp, ok := first.IPs["34.153.214.160"]; !ok || exp != 0 {
		t.Errorf("permanent ban: %v %v", exp, ok)
	}
	if _, ok := first.IPs["203.0.113.5"]; ok {
		t.Error("an IGNORE_IPS address is in the list")
	}

	// Nothing changed: an empty change set, same position.
	_, idle, raw := pollEdgeBan(t, b, at(first), "tok")
	if idle.Full || len(idle.Set) != 0 || len(idle.Del) != 0 || idle.Seq != first.Seq {
		t.Fatalf("idle poll: %s, want no changes", raw)
	}
	if idle.Del == nil {
		t.Error(`del must be [] on the wire, never null`)
	}

	ttl := time.Hour
	s.Add(net.ParseIP("198.51.100.7"), &ttl, "manual", true)
	s.Remove("34.153.214.160")
	_, ch, raw := pollEdgeBan(t, b, at(idle), "tok")
	if ch.Full || ch.Set["198.51.100.7"] < time.Now().Add(59*time.Minute).Unix() || len(ch.Del) != 1 || ch.Del[0] != "34.153.214.160" {
		t.Fatalf("changes: %s, want +198.51.100.7 and -34.153.214.160", raw)
	}
	// The same position asked again gets the same changes (the edge could
	// not write them).
	if _, again, _ := pollEdgeBan(t, b, at(idle), "tok"); len(again.Set) != 1 || len(again.Del) != 1 {
		t.Errorf("the same position again: %+v", again)
	}

	// Out of reach: another epoch, a position ahead, a forced full.
	for name, q := range map[string]url.Values{
		"other epoch": {"epoch": {"nope"}, "seq": {"1"}},
		"ahead":       {"epoch": {ch.Epoch}, "seq": {strconv.FormatUint(ch.Seq+5, 10)}},
		"full=1":      {"epoch": {ch.Epoch}, "seq": {strconv.FormatUint(ch.Seq, 10)}, "full": {"1"}},
		"bad seq":     {"epoch": {ch.Epoch}, "seq": {"x"}},
	} {
		if _, r, raw := pollEdgeBan(t, b, q, "tok"); !r.Full || r.IPs["198.51.100.7"] == 0 {
			t.Errorf("%s: %s, want the whole list", name, raw)
		}
	}

	// A position the trimmed journal no longer covers gets the whole list.
	j := &b.edgeBanJournal
	j.mu.Lock()
	j.log = j.log[len(j.log)-1:]
	j.mu.Unlock()
	if _, r, raw := pollEdgeBan(t, b, at(first), "tok"); !r.Full {
		t.Errorf("behind the journal: %s, want the whole list", raw)
	}

	// The mode rides on every reply.
	edgeban.SetEdgeMode("enforce")
	defer edgeban.SetEdgeMode("log")
	if _, r, _ := pollEdgeBan(t, b, at(ch), "tok"); r.Mode != "enforce" {
		t.Errorf("mode %q, want enforce", r.Mode)
	}

	// EDGE_BAN = 0: the list empties through the usual changes.
	edgeban.SetEnabled(false)
	_, off, raw := pollEdgeBan(t, b, at(ch), "tok")
	edgeban.SetEnabled(true)
	if off.Full || len(off.Del) != 1 || off.Del[0] != "198.51.100.7" {
		t.Errorf("EDGE_BAN=0: %s, want the remaining ban deleted", raw)
	}
}

// A store that has not reconciled (a daemon start) knows nothing either
// way: "not ready" and no list, so the edge keeps its copy.
func TestEdgeBanNotReady(t *testing.T) {
	edgeban.SetDefault(edgeban.New(""))
	t.Cleanup(func() { edgeban.SetDefault(nil) })
	b := NewNginxBridge("/tmp/cfm-test.sock", "tok", time.Minute, time.Minute)
	_, r, raw := pollEdgeBan(t, b, url.Values{}, "tok")
	if r.Ready == nil || *r.Ready || r.IPs != nil || r.Epoch != "" {
		t.Fatalf("unreconciled store: %s, want {\"ready\":false}", raw)
	}
}

// The journal is resynced only when the store's version moves, an entry in
// it expires, or edgeBanSyncMax passes: an idle poll does no list scan.
func TestEdgeBanSyncOnlyOnChange(t *testing.T) {
	s := installEdgeBans(t, "34.153.214.160")
	b := NewNginxBridge("/tmp/cfm-test.sock", "tok", time.Minute, time.Minute)
	_, first, _ := pollEdgeBan(t, b, url.Values{}, "tok")
	scans := 0
	b.bypassFunc = func(string) bool { scans++; return false }
	pollEdgeBan(t, b, at(first), "tok")
	if scans != 0 {
		t.Fatal("an idle poll scanned the list")
	}
	short := 1500 * time.Millisecond
	s.Add(net.ParseIP("198.51.100.9"), &short, "manual", true)
	_, ch, _ := pollEdgeBan(t, b, at(first), "tok")
	if ch.Set["198.51.100.9"] == 0 {
		t.Fatalf("after a ban: %+v", ch)
	}
	time.Sleep(short + 100*time.Millisecond)
	if _, exp, raw := pollEdgeBan(t, b, at(ch), "tok"); len(exp.Del) != 1 {
		t.Fatalf("after the timed ban expired: %s, want it deleted", raw)
	}
}

// The edge's counters ride on its polls; the status shows them.
func TestEdgeBanStatusCounters(t *testing.T) {
	installEdgeBans(t, "34.153.214.160")
	b := NewNginxBridge("/tmp/cfm-test.sock", "tok", time.Minute, time.Minute)
	pollEdgeBan(t, b, url.Values{"would": {"7"}, "blocked": {"2"}}, "tok")
	pollEdgeBan(t, b, url.Values{"would": {"3"}, "blocked": {"-9"}}, "tok")
	st := b.EdgeBanStatus()
	if st.WouldBlock != 10 || st.Blocked != 2 || st.Published != 1 || !st.Ready || st.Mode != "log" || st.LastPoll.IsZero() {
		t.Fatalf("status %+v", st)
	}
	if b.Status().EdgeBan.Published != 1 {
		t.Error("the bridge status carries the edge-ban status")
	}
}

// A store cleared after failed nft reads (the table gone after `cfm
// disable`) knows its bans are not enforced: the edge's copy is emptied
// through the usual changes, not kept as for a daemon start.
func TestEdgeBanClearedEmptiesTheEdge(t *testing.T) {
	s := installEdgeBans(t, "34.153.214.160")
	b := NewNginxBridge("/tmp/cfm-test.sock", "tok", time.Minute, time.Minute)
	_, first, _ := pollEdgeBan(t, b, url.Values{}, "tok")
	s.Clear()
	_, r, raw := pollEdgeBan(t, b, at(first), "tok")
	if r.Ready != nil || len(r.Del) != 1 || r.Del[0] != "34.153.214.160" {
		t.Fatalf("cleared store: %s, want the ban deleted", raw)
	}
}

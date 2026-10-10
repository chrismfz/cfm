package webdetector

import (
	"crypto/rand"
	"encoding/hex"
	"encoding/json"
	"net/http"
	"strconv"
	"strings"
	"sync"
	"time"

	"cfm/internal/edgeban"
	"cfm/internal/logging"
)

// The edge's copy of the edge bans (cfm_edgeban.lua) is kept current by a
// pull: one worker per node polls GET /nginx/edgeban every few seconds. The
// reply carries only what changed since the edge's position in a journal of
// changes, so its cost follows the changes, not the list (a ban storm moves a
// few lines per poll, not the whole list each time). The whole list is sent
// on the edge's first poll, after a daemon restart (a new epoch), when the
// edge is further behind than the journal reaches, and when the edge asks
// for it (every ~10 minutes, a consistency check).

// edgeBanFeedMax bounds the list. The store holds the web-related and manual
// bans only (not fleet feeds or cfm.deny), a few thousand at most on a busy
// node; the edge dict (cfm_edgeban, 8m, two slots) holds ~25k.
const edgeBanFeedMax = 20000

// edgeBanJournalMax is how many changes the journal keeps. An edge further
// behind gets the whole list.
const edgeBanJournalMax = 4096

// edgeBanSyncMax bounds how long the published list goes unchecked against
// the store when nothing bumps its version (IGNORE_IPS can change under it on
// a config reload).
const edgeBanSyncMax = 5 * time.Minute

// edgeBanChange is one journal line: ip banned until Exp (unix seconds, 0 =
// permanent), or lifted (Del).
type edgeBanChange struct {
	Seq uint64
	IP  string
	Exp int64
	Del bool
}

// edgeBanJournal is what the edge should hold (published) and how it got
// there (log, ascending Seq).
type edgeBanJournal struct {
	mu        sync.Mutex
	epoch     string
	seq       uint64
	published map[string]int64
	log       []edgeBanChange
	version   uint64    // edgeban.Version() at the last sync
	recheck   time.Time // the earliest expiry in published, or edgeBanSyncMax after the sync
	logged    time.Time // last truncation warning

	// What the edge reported on its polls, for the status view.
	lastPoll   time.Time
	lastFull   time.Time
	wouldBlock int64
	blocked    int64
	syncDur    time.Duration
}

// EdgeBanStatus is the edge-ban part of the bridge status (cfm debug, the
// admin API): what the edge was last sent and what it reported back.
type EdgeBanStatus struct {
	Enabled    bool      `json:"enabled"`
	Mode       string    `json:"mode"`
	Ready      bool      `json:"ready"`
	Store      int       `json:"store"`
	Published  int       `json:"published"`
	Epoch      string    `json:"epoch,omitempty"`
	Seq        uint64    `json:"seq"`
	LastPoll   time.Time `json:"last_poll,omitzero"`
	LastFull   time.Time `json:"last_full,omitzero"`
	WouldBlock int64     `json:"would_block"`
	Blocked    int64     `json:"blocked"`
	SyncMS     float64   `json:"last_sync_ms"`
}

func newEdgeBanEpoch() string {
	var b [6]byte
	if _, err := rand.Read(b[:]); err != nil {
		return strconv.FormatInt(time.Now().UnixNano(), 36)
	}
	return hex.EncodeToString(b[:])
}

// current is the list the edge must hold now: every address the store
// answers banned, less IGNORE_IPS (the decision path skips those too), with
// its expiry in unix seconds (0 = permanent); capped at edgeBanFeedMax.
func (b *NginxBridge) edgeBanCurrent(j *edgeBanJournal, now time.Time) (map[string]int64, time.Time) {
	items := edgeban.List()
	cur := make(map[string]int64, len(items))
	recheck := now.Add(edgeBanSyncMax)
	truncated := 0
	for _, it := range items {
		if b.bypassFunc != nil && b.bypassFunc(it.IP) {
			continue
		}
		if len(cur) >= edgeBanFeedMax {
			truncated++
			continue
		}
		var exp int64
		if !it.Expires.IsZero() {
			exp = it.Expires.Unix()
			if it.Expires.Before(recheck) {
				recheck = it.Expires
			}
		}
		cur[it.IP] = exp
	}
	if truncated > 0 && now.Sub(j.logged) > 10*time.Minute {
		j.logged = now
		logging.Logf("[edgeban] %d bans, the edge copy takes %d: %d left out (the last in address-string order)", len(cur)+truncated, edgeBanFeedMax, truncated)
	}
	return cur, recheck
}

// sync brings the published list to the store's, journalling the
// difference. Cheap when nothing changed (a version compare).
func (b *NginxBridge) edgeBanSync(j *edgeBanJournal, now time.Time) {
	ver := edgeban.Version()
	if j.published != nil && j.version == ver && now.Before(j.recheck) {
		return
	}
	t0 := time.Now()
	cur, recheck := b.edgeBanCurrent(j, now)
	if j.published == nil {
		j.epoch = newEdgeBanEpoch()
		j.published = map[string]int64{}
	}
	for ip, exp := range cur {
		if old, ok := j.published[ip]; !ok || old != exp {
			j.seq++
			j.log = append(j.log, edgeBanChange{Seq: j.seq, IP: ip, Exp: exp})
		}
	}
	for ip := range j.published {
		if _, ok := cur[ip]; !ok {
			j.seq++
			j.log = append(j.log, edgeBanChange{Seq: j.seq, IP: ip, Del: true})
		}
	}
	if n := len(j.log) - edgeBanJournalMax; n > 0 {
		j.log = append([]edgeBanChange(nil), j.log[n:]...)
	}
	j.published, j.version, j.recheck = cur, ver, recheck
	j.syncDur = time.Since(t0)
}

// edgeBanReply builds the reply for an edge at (epoch, seq): the changes
// since, or the whole list.
func (b *NginxBridge) edgeBanReply(epoch string, seq uint64, haveSeq, wantFull bool) map[string]any {
	j := &b.edgeBanJournal
	j.mu.Lock()
	defer j.mu.Unlock()
	now := time.Now()
	b.edgeBanSync(j, now)
	j.lastPoll = now
	out := map[string]any{"epoch": j.epoch, "seq": j.seq, "mode": edgeban.EdgeMode()}
	// The journal reaches back to the line after oldest-1: an edge at seq can
	// be caught up iff nothing it lacks was trimmed.
	oldest := j.seq + 1
	if len(j.log) > 0 {
		oldest = j.log[0].Seq
	}
	inReach := haveSeq && epoch == j.epoch && seq <= j.seq && seq+1 >= oldest
	if wantFull || !inReach {
		ips := make(map[string]int64, len(j.published))
		for ip, exp := range j.published {
			ips[ip] = exp
		}
		out["full"] = true
		out["ips"] = ips
		j.lastFull = now
		return out
	}
	// The final state of every address changed since seq.
	set := map[string]int64{}
	var del []string
	last := map[string]edgeBanChange{}
	for _, c := range j.log {
		if c.Seq > seq {
			last[c.IP] = c
		}
	}
	for ip, c := range last {
		if c.Del {
			del = append(del, ip)
		} else {
			set[ip] = c.Exp
		}
	}
	if del == nil {
		del = []string{} // [] on the wire, never null
	}
	out["set"] = set
	out["del"] = del
	return out
}

// handleEdgeBan serves GET /nginx/edgeban to cfm_edgeban.lua.
//
//	?epoch=E&seq=N   the edge's position; absent or not in reach: the whole list
//	&full=1          the whole list anyway (the edge's periodic check)
//	&would=W&blocked=B  the edge's counters since its last poll (status only)
//
// Replies (all carry "epoch", "seq" and "mode", log|enforce):
//
//	{"full":true,"ips":{"203.0.113.5":1760000000,"198.51.100.7":0}}
//	{"set":{ip:expiry,...},"del":[ip,...]}       the changes since seq
//	{"ready":false}   the store has not reconciled yet (a daemon start, nft
//	                  unreadable): the edge keeps the copy it has
//
// Expiry is unix seconds, 0 permanent. EDGE_BAN = 0 empties the list (the
// edge drops every entry through the usual changes).
func (b *NginxBridge) handleEdgeBan(w http.ResponseWriter, r *http.Request) {
	if !b.checkToken(r) {
		http.Error(w, "forbidden", http.StatusForbidden)
		return
	}
	if r.Method != http.MethodGet {
		http.Error(w, "method", http.StatusMethodNotAllowed)
		return
	}
	q := r.URL.Query()
	b.edgeBanCount(q.Get("would"), q.Get("blocked"))
	if s := edgeban.Default(); edgeban.Enabled() && (s == nil || !s.Ready()) {
		writeEdgeBanJSON(w, map[string]any{"ready": false, "mode": edgeban.EdgeMode()})
		return
	}
	seqStr := strings.TrimSpace(q.Get("seq"))
	seq, err := strconv.ParseUint(seqStr, 10, 64)
	haveSeq := seqStr != "" && err == nil
	writeEdgeBanJSON(w, b.edgeBanReply(strings.TrimSpace(q.Get("epoch")), seq, haveSeq, q.Get("full") == "1"))
}

// edgeBanCount adds the edge's reported counters (bounded: a counter is a
// count since the last poll, a few thousand at most).
func (b *NginxBridge) edgeBanCount(would, blocked string) {
	wv, _ := strconv.ParseInt(would, 10, 64)
	bv, _ := strconv.ParseInt(blocked, 10, 64)
	if wv <= 0 && bv <= 0 {
		return
	}
	const max = 1 << 30
	j := &b.edgeBanJournal
	j.mu.Lock()
	if wv > 0 && wv < max {
		j.wouldBlock += wv
	}
	if bv > 0 && bv < max {
		j.blocked += bv
	}
	j.mu.Unlock()
}

// EdgeBanStatus reports the edge-ban feed (zero value without a bridge).
func (b *NginxBridge) EdgeBanStatus() EdgeBanStatus {
	st := EdgeBanStatus{Enabled: edgeban.Enabled(), Mode: edgeban.EdgeMode()}
	if s := edgeban.Default(); s != nil {
		st.Ready = s.Ready()
		st.Store = s.Len()
	}
	if b == nil {
		return st
	}
	j := &b.edgeBanJournal
	j.mu.Lock()
	defer j.mu.Unlock()
	st.Published, st.Epoch, st.Seq = len(j.published), j.epoch, j.seq
	st.LastPoll, st.LastFull = j.lastPoll, j.lastFull
	st.WouldBlock, st.Blocked = j.wouldBlock, j.blocked
	st.SyncMS = float64(j.syncDur.Microseconds()) / 1000
	return st
}

func writeEdgeBanJSON(w http.ResponseWriter, out any) {
	buf, err := json.Marshal(out)
	if err != nil {
		http.Error(w, "encode", http.StatusInternalServerError)
		return
	}
	w.Header().Set("Content-Type", "application/json")
	w.Header().Set("Content-Length", strconv.Itoa(len(buf)))
	_, _ = w.Write(buf)
}

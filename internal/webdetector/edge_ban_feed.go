package webdetector

import (
	"crypto/rand"
	"encoding/hex"
	"encoding/json"
	"net/http"
	"net/netip"
	"sort"
	"strconv"
	"strings"
	"sync"
	"time"

	"cfm/internal/edgeban"
	"cfm/internal/firewall"
	"cfm/internal/logging"
	"cfm/internal/proxyipfilter"
)

// The edge's copy of the edge bans (cfm_edgeban.lua) is kept current by a
// pull: one worker per node polls GET /nginx/edgeban every few seconds. The
// reply carries only what changed since the edge's position in a journal of
// changes, so its cost follows the changes, not the list (a ban storm moves a
// few lines per poll, not the whole list each time). The whole list is sent
// on the edge's first poll, after a daemon restart (a new epoch), when the
// edge is further behind than the journal reaches, and when the edge asks
// for it (every ~10 minutes, a consistency check).

// The list the edge gets is capped by what its dict holds: the edge reports
// it on every poll (cap=, from the dict's capacity: two copies of the list
// fit, cfm_edgeban.lua), and an edge that does not (Lua older than the
// report, or the upgrade-lag dict cfm_decisions) gets edgeBanLegacyCap, what
// the 16m dict was sized for. edgeBanFeedMax bounds any report. The store
// holds the web-related and manual bans only (not fleet feeds or cfm.deny),
// but with 7-day WAF bans that is 36 000–58 000 on the busiest nodes
// (2026-11-25), and with the old fixed 20 000 cap two thirds of earth's bans
// never reached its edge.
const (
	edgeBanLegacyCap = 20000
	edgeBanFeedMax   = 200000
)

// edgeBanJournalMax is how many changes the journal keeps. An edge further
// behind gets the whole list.
const edgeBanJournalMax = 4096

// edgeBanSyncMax bounds how long the published list goes unchecked against
// the store when nothing bumps its version (IGNORE_IPS can change under it on
// a config reload). An expiry alone does not resync: the edge drops an
// entry at its expiry by itself (the dict TTL), and with ~20 000 TTL bans the
// earliest expiry is always seconds away, so resyncing on it rebuilt the
// whole list on nearly every poll. Expired bans leave the published list at
// the next resync: the store's reconcile (every ~2 minutes) deletes them,
// which moves the version, and this bound covers a reconcile that cannot
// read nft.
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
	recheck   time.Time // edgeBanSyncMax after the last whole rebuild
	logged    time.Time // last truncation warning

	// Where the last rebuild left the store's change log (edgeban.ChangePos):
	// a sync applies the keys changed since instead of rebuilding.
	gen, cseq uint64
	// The cap the published list was built for, and whether bans were left
	// out of it then: over the cap, every new ban rebuilds (the longest
	// bans win), as before.
	builtCap  int
	truncated bool
	edgeCap   int       // what the edge last reported its dict holds (0: no report)
	edgeCapAt time.Time // when it last reported one
	// rebuilding: a rebuild runs beside the polls (edgeBanRebuildBeside).
	rebuilding bool

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
	Cleared    bool      `json:"cleared"` // nft unreadable: the edge was told to drop its copy
	Store      int       `json:"store"`
	Published  int       `json:"published"`
	Epoch      string    `json:"epoch,omitempty"`
	Seq        uint64    `json:"seq"`
	LastPoll   time.Time `json:"last_poll,omitzero"`
	LastFull   time.Time `json:"last_full,omitzero"`
	WouldBlock int64     `json:"would_block"`
	Blocked    int64     `json:"blocked"`
	SyncMS     float64   `json:"last_sync_ms"`
	// Cap is how many bans the edge's list takes (its dict, or the legacy
	// 20 000 when the edge does not say); LeftOut, whether the last rebuild
	// had to leave bans out (the soonest to expire).
	Cap     int  `json:"cap"`
	LeftOut bool `json:"left_out"`
	// The rest of nft's IP filter for a proxied client (internal/proxyipfilter):
	// its modes, would-block / blocked / allowed counts and each source's size.
	ProxiedIPFilter map[string]any `json:"proxied_ipfilter"`
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
// its expiry in unix seconds (0 = permanent); capped at capN (the longest
// bans kept), with how many were left out.
func (b *NginxBridge) edgeBanCurrent(capN int) (map[string]int64, int) {
	items := edgeban.List()
	if len(items) > capN {
		// Over the cap, keep the longest bans: permanent first, then the
		// latest expiry (address order would drop a whole storm of new bans).
		// Many manual permanent bans can thus crowd out fresh autoblocks.
		sort.SliceStable(items, func(a, c int) bool {
			ea, ec := items[a].Expires, items[c].Expires
			if ea.IsZero() != ec.IsZero() {
				return ea.IsZero()
			}
			if ea.Equal(ec) {
				return items[a].IP < items[c].IP // List is unordered: ties stay deterministic
			}
			return ea.After(ec)
		})
	}
	cur := make(map[string]int64, min(len(items), capN))
	truncated := 0
	for _, it := range items {
		if b.edgeBanSkipped(it.IP) {
			continue
		}
		if len(cur) >= capN {
			truncated++
			continue
		}
		cur[it.IP] = edgeBanExp(it)
	}
	return cur, truncated
}

// edgeBanSkipped reports whether the list leaves k out although the store
// bans it: IGNORE_IPS (the decision path skips those too), and for an IPv6
// client /64 ban, IGNORE_IPS / IGNORE_NETS and the trusted proxies touching
// any of it (the address check cannot read a prefix).
func (b *NginxBridge) edgeBanSkipped(k string) bool {
	if b.bypassFunc != nil && b.bypassFunc(k) {
		return true
	}
	if p, err := netip.ParsePrefix(k); err == nil && firewall.ClientNetExempted(p) != "" {
		return true
	}
	return false
}

// edgeBanExp is an item's expiry on the wire: unix seconds, 0 permanent.
func edgeBanExp(it edgeban.Item) int64 {
	if it.Expires.IsZero() {
		return 0
	}
	return it.Expires.Unix()
}

// edgeBanCapGrace is how long an edge's cap report stands for polls that
// carry none: during an edge reload, old-generation workers (older Lua) and
// new ones take turns polling, and a cap flipping between their answers
// rebuilt the list, and journalled tens of thousands of changes, each time.
const edgeBanCapGrace = 10 * time.Minute

// noteEdgeCap records a poll's cap report (0: none).
func (j *edgeBanJournal) noteEdgeCap(c int, now time.Time) {
	if c > 0 {
		j.edgeCap, j.edgeCapAt = c, now
		return
	}
	if now.Sub(j.edgeCapAt) > edgeBanCapGrace {
		j.edgeCap = 0
	}
}

// edgeBanCap is the cap for the edge's list now (see edgeBanLegacyCap).
func (j *edgeBanJournal) edgeBanCap() int {
	if j.edgeCap <= 0 {
		return edgeBanLegacyCap
	}
	return min(j.edgeCap, edgeBanFeedMax)
}

// edgeBanRebuildAsync runs the rebuilds a poll asks for beside the poll
// (edgeBanRebuildBeside), the first one excepted. A rebuild of the whole list
// took 150–220 ms with 58 000 bans on an EL8 node, and the edge's read gives
// up after decision_timeout_ms (300 ms): inside the poll, a larger list would
// lose the poll. The tests turn it off, to see a rebuild in the poll that
// asked for it.
var edgeBanRebuildAsync = true

// sync brings the published list to the store's, journalling the
// difference. Cheap when nothing changed (a version compare); a change the
// store's change log names is applied key by key (edgeBanApplyChanges); the
// whole list is rebuilt on the first sync (in the poll) and, beside the
// polls, on a change that moves every answer (a new change-log generation),
// a changed cap, a ban added or lifted while bans are left out, and every
// edgeBanSyncMax. Until that rebuild lands the edge gets the changes applied
// so far.
func (b *NginxBridge) edgeBanSync(j *edgeBanJournal, now time.Time) {
	ver := edgeban.Version()
	capN := j.edgeBanCap()
	rebuild := j.published == nil || !now.Before(j.recheck) || capN != j.builtCap
	if !rebuild && j.version == ver {
		return
	}
	t0 := time.Now()
	if j.published != nil && capN == j.builtCap {
		if b.edgeBanApplyChanges(j) {
			j.version = ver
		} else {
			rebuild = true
		}
	}
	if !rebuild {
		j.syncDur = time.Since(t0)
		return
	}
	if j.published == nil || !edgeBanRebuildAsync {
		gen, cseq := edgeban.ChangePos() // before List: later changes are applied next time
		cur, truncated := b.edgeBanCurrent(capN)
		b.edgeBanPublish(j, cur, truncated, gen, cseq, ver, capN, now, t0)
		return
	}
	if !j.rebuilding {
		j.rebuilding = true
		go b.edgeBanRebuildBeside(capN)
	}
}

// edgeBanRebuildBeside rebuilds the list off the poll path: the store read
// and the list outside the journal's lock, the publish under it.
func (b *NginxBridge) edgeBanRebuildBeside(capN int) {
	t0 := time.Now()
	ver := edgeban.Version()
	gen, cseq := edgeban.ChangePos() // before List: later changes are applied next time
	cur, truncated := b.edgeBanCurrent(capN)
	j := &b.edgeBanJournal
	j.mu.Lock()
	defer j.mu.Unlock()
	j.rebuilding = false
	b.edgeBanPublish(j, cur, truncated, gen, cseq, ver, capN, time.Now(), t0)
}

// edgeBanPublish makes cur the published list (j.mu held), journalling the
// difference: cur was built from the store at change-log position
// (gen, cseq) and version ver, for capN.
func (b *NginxBridge) edgeBanPublish(j *edgeBanJournal, cur map[string]int64, truncated int, gen, cseq, ver uint64, capN int, now, t0 time.Time) {
	if j.published == nil {
		j.epoch = newEdgeBanEpoch()
		j.published = map[string]int64{}
	}
	for ip, exp := range cur {
		if old, ok := j.published[ip]; !ok || old != exp {
			j.journal(edgeBanChange{IP: ip, Exp: exp})
		}
	}
	for ip := range j.published {
		if _, ok := cur[ip]; !ok {
			j.journal(edgeBanChange{IP: ip, Del: true})
		}
	}
	j.trimJournal()
	j.published, j.version, j.recheck = cur, ver, now.Add(edgeBanSyncMax)
	j.gen, j.cseq, j.builtCap, j.truncated = gen, cseq, capN, truncated > 0
	j.syncDur = time.Since(t0)
	if truncated > 0 && now.Sub(j.logged) > 10*time.Minute {
		j.logged = now
		logging.Logf("[edgeban] %d bans, the edge copy takes %d: %d left out (the soonest to expire); a larger cfm_edgeban dict takes more", len(cur)+truncated, capN, truncated)
	}
}

// edgeBanResync makes the next poll rebuild the list (the bypass lists
// changed: IGNORE_IPS / IGNORE_NETS on a config reload).
func (b *NginxBridge) edgeBanResync() {
	j := &b.edgeBanJournal
	j.mu.Lock()
	j.recheck = time.Time{}
	j.mu.Unlock()
}

// edgeBanApplyChanges applies the keys the store changed since the last sync
// to the published list: each key looked up again, then set, updated or
// deleted. False when the list must be rebuilt instead (the change log says
// so, or a new ban needs room the cap does not leave: which bans go is the
// rebuild's choice).
func (b *NginxBridge) edgeBanApplyChanges(j *edgeBanJournal) bool {
	keys, gen, cseq, ok := edgeban.ChangesSince(j.gen, j.cseq)
	if !ok {
		return false
	}
	for _, k := range keys {
		it, want := edgeban.Lookup(k)
		if want && b.edgeBanSkipped(k) {
			want = false
		}
		old, have := j.published[k]
		switch {
		case want && !have:
			if j.truncated || len(j.published) >= j.builtCap {
				return false
			}
			exp := edgeBanExp(it)
			j.published[k] = exp
			j.journal(edgeBanChange{IP: k, Exp: exp})
		case want && have:
			if exp := edgeBanExp(it); exp != old {
				j.published[k] = exp
				j.journal(edgeBanChange{IP: k, Exp: exp})
			}
		case !want && have:
			delete(j.published, k)
			j.journal(edgeBanChange{IP: k, Del: true})
			if j.truncated {
				return false // a slot freed: the longest left-out ban takes it
			}
		}
	}
	j.trimJournal()
	j.gen, j.cseq = gen, cseq
	return true
}

// journal appends one change with the next sequence number.
func (j *edgeBanJournal) journal(c edgeBanChange) {
	j.seq++
	c.Seq = j.seq
	j.log = append(j.log, c)
}

// trimJournal keeps the last edgeBanJournalMax changes.
func (j *edgeBanJournal) trimJournal() {
	if n := len(j.log) - edgeBanJournalMax; n > 0 {
		j.log = append([]edgeBanChange(nil), j.log[n:]...)
	}
}

// edgeBanReply builds the reply for an edge at (epoch, seq): the changes
// since, or the whole list.
func (b *NginxBridge) edgeBanReply(epoch string, seq uint64, haveSeq, wantFull bool, edgeCap int) map[string]any {
	j := &b.edgeBanJournal
	j.mu.Lock()
	defer j.mu.Unlock()
	now := time.Now()
	j.noteEdgeCap(edgeCap, now)
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
//	&cap=C           how many entries the edge's dict holds a list of (two
//	                 copies fit); absent: edgeBanLegacyCap
//
// Replies (all carry "epoch", "seq" and "mode", log|enforce):
//
//	{"full":true,"ips":{"203.0.113.5":1760000000,"198.51.100.7":0}}
//	{"set":{ip:expiry,...},"del":[ip,...]}       the changes since seq
//	{"ready":false}   the store has not reconciled since the daemon started:
//	                  the edge keeps the copy it has (a store Cleared after
//	                  failed nft reads publishes an empty list instead)
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
	// Not ready since a start: nothing known either way, the edge keeps its
	// copy. Cleared (nft unreadable three times, the table gone after `cfm
	// disable`): the bans are not enforced any more, so the list published
	// is empty (List answers nothing) and the edge drops its copy.
	if s := edgeban.Default(); edgeban.Enabled() && (s == nil || (!s.Ready() && !s.Cleared())) {
		writeEdgeBanJSON(w, map[string]any{"ready": false, "mode": edgeban.EdgeMode()})
		return
	}
	seqStr := strings.TrimSpace(q.Get("seq"))
	seq, err := strconv.ParseUint(seqStr, 10, 64)
	haveSeq := seqStr != "" && err == nil
	edgeCap, _ := strconv.Atoi(strings.TrimSpace(q.Get("cap")))
	writeEdgeBanJSON(w, b.edgeBanReply(strings.TrimSpace(q.Get("epoch")), seq, haveSeq, q.Get("full") == "1", max(edgeCap, 0)))
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
	st := EdgeBanStatus{Enabled: edgeban.Enabled(), Mode: edgeban.EdgeMode(), ProxiedIPFilter: proxyipfilter.Stats()}
	if s := edgeban.Default(); s != nil {
		st.Ready = s.Ready()
		st.Cleared = s.Cleared()
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
	st.Cap, st.LeftOut = j.edgeBanCap(), j.truncated
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

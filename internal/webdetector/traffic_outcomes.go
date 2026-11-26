package webdetector

// traffic_outcomes.go: what the edge did with the requests, over a window and
// per time step, for the whole node or one vhost. The cfm-admin Protection
// page's Challenges tab reads it (GET /api/v1/webdet/edge-outcomes): how much
// reached the site, how much was challenged or stopped, and how the challenge
// pages were answered.
//
// It reads the traffic mix ring (traffic_mix.go: the edge's own log, 5-minute
// buckets, 24 h), the same outcome counts as the Web Traffic page, without its
// client and per-minute walks. Two limits it inherits, stated in the reply's
// note: a bucket older than an hour keeps its busiest tmOldMaxHosts vhosts, so
// a small vhost's older hours can undercount; and "passed" is a verify the
// challenge answered 303 (sent on), read from the log status, not the
// challenge server's own verdict.
//
// Scope: an admin reads the node or any vhost; a scoped (cPanel) token must
// name a vhost it holds (scopeCheckHost), and never gets the per-vhost table
// or the per-address reasons (the operator's policy).

import (
	"net/http"
	"sort"
	"strconv"
	"strings"
	"time"
)

// EdgeOutcomePoint is one step of the series: requests and what the edge did
// with them.
type EdgeOutcomePoint struct {
	T        int64               `json:"t"`
	Requests int64               `json:"requests"`
	Outcomes *TrafficMixOutcomes `json:"outcomes"`
}

// EdgeOutcomeHost is one vhost's totals in the node view.
type EdgeOutcomeHost struct {
	Host     string              `json:"host"`
	Requests int64               `json:"requests"`
	Outcomes *TrafficMixOutcomes `json:"outcomes"`
}

// ChallengeReasonCount is one reason of the per-address challenge decisions.
type ChallengeReasonCount struct {
	Reason    string `json:"reason"`
	Decisions int    `json:"decisions"`
	Addresses int    `json:"addresses"`
}

// EdgeOutcomes is the reply of GET /api/v1/webdet/edge-outcomes.
type EdgeOutcomes struct {
	Schema   string              `json:"schema"`
	Host     string              `json:"host,omitempty"`
	Hours    int                 `json:"hours"`
	Since    int64               `json:"since"`
	Until    int64               `json:"until"`
	StepSec  int64               `json:"step_sec"`
	Requests int64               `json:"requests"`
	Outcomes *TrafficMixOutcomes `json:"outcomes"`
	Series   []EdgeOutcomePoint  `json:"series"`
	// Hosts: the node view only (admin, no host): the vhosts most challenged
	// (by share), among those with edgeOutcomeHostMinReq requests or more.
	Hosts []EdgeOutcomeHost `json:"hosts,omitempty"`
	// Reasons: admin only. The per-address challenge decisions of the window
	// by reason (history challenge_issued rows). A vhost-wide challenge covers
	// every visitor and writes no such row, so it is not among them.
	Reasons []ChallengeReasonCount `json:"reasons,omitempty"`
	Note    string                 `json:"note"`
}

const (
	edgeOutcomeHostMinReq = 200
	edgeOutcomeHostLimit  = 15
	edgeOutcomeReasonMax  = 12
	edgeOutcomesNote      = "read from the edge's own log (the traffic mix): passed = a verify the challenge answered 303, refused = 403; older than an hour, each 5-minute bucket keeps its busiest vhosts only, so a small vhost's older hours can undercount"
)

// edgeOutcomeHostKeys: a vhost and its www. alias (cPanel lists a domain
// without its www. name, nginx serves both). Never the reverse: www.x does not
// bring x, which may be another account's.
func edgeOutcomeHostKeys(host string) []string {
	host = strings.ToLower(strings.TrimSpace(host))
	if host == "" {
		return nil
	}
	if strings.HasPrefix(host, "www.") {
		return []string{host}
	}
	return []string{host, "www." + host}
}

// edgeOutcomeStep is the series step for a window: 5 minutes up to an hour,
// 15 minutes up to 6 hours, an hour beyond.
func edgeOutcomeStep(window time.Duration) int64 {
	switch {
	case window <= time.Hour:
		return tmBucketSec
	case window <= 6*time.Hour:
		return 3 * tmBucketSec
	}
	return 12 * tmBucketSec
}

// Outcomes sums the edge outcomes of the window ending at now (inclusive of
// the bucket holding it), for the node (host "") or one vhost and its www.
// alias, per step. withHosts adds the node view's per-vhost totals.
func (s *trafficMixStore) Outcomes(now time.Time, window time.Duration, host string, withHosts bool) EdgeOutcomes {
	if window < tmBucketSec*time.Second {
		window = tmBucketSec * time.Second
	}
	if window > 24*time.Hour {
		window = 24 * time.Hour
	}
	step := edgeOutcomeStep(window)
	nowSec := now.Unix()
	keys := edgeOutcomeHostKeys(host)
	// The window starts on a step boundary, so every point covers one step.
	firstB := ((nowSec - int64(window/time.Second)) / step * step) / tmBucketSec
	lastB := nowSec / tmBucketSec
	if lastB-firstB >= tmBuckets {
		firstB = lastB - tmBuckets + 1
		firstB = (firstB*tmBucketSec + step - 1) / step * step / tmBucketSec
	}
	out := EdgeOutcomes{Schema: "webdet.edge_outcomes.v1", Host: strings.ToLower(strings.TrimSpace(host)), Since: firstB * tmBucketSec, Until: nowSec, StepSec: step, Note: edgeOutcomesNote}

	var total tmOut
	var totalReq int64
	hosts := map[string]*tmSmall{}
	var cur *EdgeOutcomePoint
	var curOut tmOut
	flush := func() {
		if cur != nil {
			cur.Outcomes = tmOutcomesOut(cur.Requests, curOut)
			out.Series = append(out.Series, *cur)
		}
	}
	for id := firstB; id <= lastB; id++ {
		t := id * tmBucketSec / step * step
		if cur == nil || cur.T != t {
			flush()
			cur, curOut = &EdgeOutcomePoint{T: t}, tmOut{}
		}
		// The lock per bucket, as snapshot: observe takes it on every request.
		s.mu.Lock()
		b := &s.buckets[id%tmBuckets]
		if b.id != id {
			s.mu.Unlock()
			continue
		}
		var req int64
		var o tmOut
		if len(keys) == 0 {
			for i := 0; i < tmClasses; i++ {
				req += b.c[i].Req
				o.add(b.c[i].Out)
			}
			if withHosts {
				for hk, hv := range b.hosts {
					if hk == tmOtherKey {
						continue
					}
					acc := hosts[hk]
					if acc == nil {
						acc = &tmSmall{}
						hosts[hk] = acc
					}
					for i := 0; i < tmClasses; i++ {
						acc.addSmall(hv[i])
					}
				}
			}
		} else {
			for _, hk := range keys {
				hv := b.hosts[hk]
				if hv == nil {
					continue
				}
				for i := 0; i < tmClasses; i++ {
					req += hv[i].Req
					o.add(hv[i].out())
				}
			}
		}
		s.mu.Unlock()
		cur.Requests += req
		curOut.add(o)
		totalReq += req
		total.add(o)
	}
	flush()
	out.Requests = totalReq
	out.Outcomes = tmOutcomesOut(totalReq, total)
	out.Hours = int((out.Until - out.Since + 3599) / 3600)

	if withHosts && len(keys) == 0 {
		for hk, acc := range hosts {
			if acc.Req < edgeOutcomeHostMinReq {
				continue
			}
			out.Hosts = append(out.Hosts, EdgeOutcomeHost{Host: hk, Requests: acc.Req, Outcomes: tmOutcomesOut(acc.Req, acc.out())})
		}
		share := func(h EdgeOutcomeHost) float64 { return float64(h.Outcomes.Challenged) / float64(h.Requests) }
		sort.Slice(out.Hosts, func(i, j int) bool {
			a, b := share(out.Hosts[i]), share(out.Hosts[j])
			if a != b {
				return a > b
			}
			if out.Hosts[i].Requests != out.Hosts[j].Requests {
				return out.Hosts[i].Requests > out.Hosts[j].Requests
			}
			return out.Hosts[i].Host < out.Hosts[j].Host
		})
		if len(out.Hosts) > edgeOutcomeHostLimit {
			out.Hosts = out.Hosts[:edgeOutcomeHostLimit]
		}
	}
	return out
}

// ChallengeReasons counts the per-address challenge decisions (history
// challenge_issued rows) since fromUnix by reason: decisions and distinct
// addresses. host "" = every vhost; a vhost also takes its www. alias.
func (s *HistoryStore) ChallengeReasons(host string, fromUnix int64, limit int) ([]ChallengeReasonCount, error) {
	if s == nil || s.db == nil {
		return []ChallengeReasonCount{}, nil
	}
	if limit <= 0 {
		limit = edgeOutcomeReasonMax
	}
	clauses := []string{"event_type = 'challenge_issued'", "ts_unix >= ?"}
	args := []interface{}{fromUnix}
	if keys := edgeOutcomeHostKeys(host); len(keys) > 0 {
		ph := strings.TrimSuffix(strings.Repeat("?,", len(keys)), ",")
		clauses = append(clauses, "host IN ("+ph+")")
		for _, k := range keys {
			args = append(args, k)
		}
	}
	args = append(args, limit)
	s.mu.Lock()
	defer s.mu.Unlock()
	rows, err := s.db.Query(`
SELECT COALESCE(NULLIF(reason, ''), '(none)') AS r, COUNT(*) AS n, COUNT(DISTINCT ip) AS ips
FROM history_events
WHERE `+strings.Join(clauses, " AND ")+`
GROUP BY r
ORDER BY n DESC, r
LIMIT ?`, args...)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	out := []ChallengeReasonCount{}
	for rows.Next() {
		var c ChallengeReasonCount
		if err := rows.Scan(&c.Reason, &c.Decisions, &c.Addresses); err != nil {
			return nil, err
		}
		out = append(out, c)
	}
	return out, rows.Err()
}

// edgeOutcomeHours: the windows the API takes (the traffic mix ring holds 24 h).
var edgeOutcomeHours = []int{1, 6, 24}

// handleEdgeOutcomes serves GET /api/v1/webdet/edge-outcomes?hours=1|6|24[&host=].
//
// Admin: host optional (none = the node, with the per-vhost table and the
// per-address challenge reasons). Scoped (cPanel) token: host required and in
// its scope (scopeCheckHost: 400 without one, 403 outside), and the reply
// carries no per-vhost table and no reasons: the reasons name the operator's
// detectors and WAF rules, never a site owner's to see.
func (e *Engine) handleEdgeOutcomes(w http.ResponseWriter, r *http.Request) {
	if !RequireScopedOrAdmin(w, r) {
		return
	}
	if r.Method != http.MethodGet {
		writeJSON(w, http.StatusMethodNotAllowed, map[string]string{"error": "GET only"})
		return
	}
	q := r.URL.Query()
	host := strings.ToLower(strings.TrimSpace(q.Get("host")))
	if !scopeCheckHost(w, r, host) {
		return
	}
	hours := 24
	if v := strings.TrimSpace(q.Get("hours")); v != "" {
		n, err := strconv.Atoi(v)
		ok := err == nil
		if ok {
			ok = false
			for _, h := range edgeOutcomeHours {
				if h == n {
					ok = true
				}
			}
		}
		if !ok {
			writeJSON(w, http.StatusBadRequest, map[string]string{"error": "hours: 1, 6 or 24"})
			return
		}
		hours = n
	}
	admin := IsAdminRequest(r)
	now := time.Now()
	out := trafficMix.Outcomes(now, time.Duration(hours)*time.Hour, host, admin && host == "")
	out.Hours = hours
	if admin && e != nil && e.history != nil {
		if rs, err := e.history.ChallengeReasons(host, out.Since, edgeOutcomeReasonMax); err == nil {
			out.Reasons = rs
		}
	}
	writeJSON(w, http.StatusOK, out)
}

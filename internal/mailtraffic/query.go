package mailtraffic

import (
	"database/sql"
	"fmt"
	"sort"
	"time"

	"cfm/internal/mailmeter"
)

// Totals is the whole-window sum of each counter within the caller's scope.
type Totals struct {
	Outbound    int64 `json:"outbound"`
	LocalSubmit int64 `json:"local_submit"`
	Inbound     int64 `json:"inbound"`
	OverQuota   int64 `json:"over_quota"`
	Throttled   int64 `json:"throttled"`
	AuthFailed  int64 `json:"auth_failed"`
	Rejected    int64 `json:"rejected"`
}

// ProviderOutcomes is one remote provider's delivery tally over the window.
type ProviderOutcomes struct {
	Provider  string `json:"provider"`
	Delivered int64  `json:"delivered"`
	Deferred  int64  `json:"deferred"`
	Bounced   int64  `json:"bounced"`
}

// ReasonCount is one normalized failure/defer reason and its count.
type ReasonCount struct {
	Reason string `json:"reason"`
	Count  int64  `json:"count"`
}

// Deliverability is the outbound remote-delivery health view: how each provider
// (Gmail, Microsoft, …) is treating this server's mail, and the top reasons for
// defers/bounces. Host-wide (delivery lines aren't reliably attributable to a
// tenant), so it is admin-only. NOTE: deferred counts include exim retries —
// each `==` retry of one stuck message is a separate event — so a few stuck
// messages inflate "deferred"; that is intentional (it reflects live pressure).
type Deliverability struct {
	ByProvider []ProviderOutcomes `json:"by_provider"` // most active first
	TopReasons []ReasonCount      `json:"top_reasons"` // non-ok defer/bounce reasons, count desc
	Delivered  int64              `json:"delivered"`
	Deferred   int64              `json:"deferred"`
	Bounced    int64              `json:"bounced"`
}

// Summary is the read view served by GET /api/v1/mail/traffic. All lists are
// already scope-filtered and capped to the requested limit. The HTTP handler
// wraps it in the usual {ok, schema, available, …} envelope, so Summary itself
// carries only the data (window + scope + the breakdowns).
type Summary struct {
	Window string `json:"window"`
	Scope  string `json:"scope"` // "admin" | "scoped"

	// Deliverability is populated for admins only (host-wide data); nil/omitted
	// for scoped callers.
	Deliverability *Deliverability `json:"deliverability,omitempty"`

	TopOutboundSenders  []mailmeter.AddrCount `json:"top_outbound_senders"`
	TopLocalSubmitters  []mailmeter.AddrCount `json:"top_local_submitters"` // admin-only (unix users)
	TopInboundMailboxes []mailmeter.AddrCount `json:"top_inbound_mailboxes"`
	MostSentDomains     []mailmeter.AddrCount `json:"most_sent_domains"`
	TopAuthFailed       []mailmeter.AddrCount `json:"top_auth_failed"`
	TopThrottled        []mailmeter.AddrCount `json:"top_throttled"`
	TopOverQuota        []mailmeter.AddrCount `json:"top_over_quota"`

	Totals Totals `json:"totals"`
}

// TrafficSummary returns the top-N / per-domain views over the last `hours`.
// scope follows CFM's convention: nil = admin (whole server, no filter); a
// non-nil set = a scoped caller limited to exactly those domains (an EMPTY set
// therefore matches nothing and yields empty lists — fail closed). limit caps
// each list (<=0 → a sane default).
func (s *Store) TrafficSummary(hours int, scope map[string]struct{}, limit int) (Summary, error) {
	return s.trafficSummaryAt(time.Now(), hours, scope, limit)
}

func (s *Store) trafficSummaryAt(now time.Time, hours int, scope map[string]struct{}, limit int) (Summary, error) {
	if hours <= 0 {
		hours = 24
	}
	if limit <= 0 {
		limit = 20
	}
	cutoff := bucketOf(now.Add(-time.Duration(hours) * time.Hour))

	sum := Summary{
		Window: fmt.Sprintf("%dh", hours),
		Scope:  "admin",
		// Non-nil empty slices so the JSON is [] not null.
		TopOutboundSenders:  []mailmeter.AddrCount{},
		TopLocalSubmitters:  []mailmeter.AddrCount{},
		TopInboundMailboxes: []mailmeter.AddrCount{},
		MostSentDomains:     []mailmeter.AddrCount{},
		TopAuthFailed:       []mailmeter.AddrCount{},
		TopThrottled:        []mailmeter.AddrCount{},
		TopOverQuota:        []mailmeter.AddrCount{},
	}
	if scope != nil {
		sum.Scope = "scoped"
		if len(scope) == 0 {
			return sum, nil // scoped but owns nothing → empty, no query
		}
	}

	// Group-by-address lists (each keyed on its own counter column).
	for _, spec := range []struct {
		col string
		dst *[]mailmeter.AddrCount
	}{
		{"outbound", &sum.TopOutboundSenders},
		{"local_sub", &sum.TopLocalSubmitters},
		{"inbound", &sum.TopInboundMailboxes},
		{"auth_failed", &sum.TopAuthFailed},
		{"throttled", &sum.TopThrottled},
		{"over_quota", &sum.TopOverQuota},
	} {
		rows, err := s.topByAddr(spec.col, cutoff, scope, limit)
		if err != nil {
			return sum, err
		}
		*spec.dst = rows
	}

	// Most-sent domains: outbound summed per domain (real mail domains only).
	dom, err := s.topDomains(cutoff, scope, limit)
	if err != nil {
		return sum, err
	}
	sum.MostSentDomains = dom

	tot, err := s.totals(cutoff, scope)
	if err != nil {
		return sum, err
	}
	sum.Totals = tot

	// Deliverability is host-wide → admin only (nil scope).
	if scope == nil {
		dl, err := s.deliverability(cutoff, limit)
		if err != nil {
			return sum, err
		}
		sum.Deliverability = dl
	}
	return sum, nil
}

// deliverability aggregates the mail_delivery counters over the window into the
// per-provider outcome matrix and the top non-ok reasons.
func (s *Store) deliverability(cutoff int64, limit int) (*Deliverability, error) {
	dl := &Deliverability{ByProvider: []ProviderOutcomes{}, TopReasons: []ReasonCount{}}

	rows, err := s.db.Query(
		`SELECT provider, outcome, SUM(n) FROM mail_delivery WHERE bucket>=? GROUP BY provider, outcome`, cutoff)
	if err != nil {
		return dl, err
	}
	byProv := map[string]*ProviderOutcomes{}
	order := []string{}
	for rows.Next() {
		var prov string
		var outcome int
		var n int64
		if err := rows.Scan(&prov, &outcome, &n); err != nil {
			rows.Close()
			return dl, err
		}
		po := byProv[prov]
		if po == nil {
			po = &ProviderOutcomes{Provider: prov}
			byProv[prov] = po
			order = append(order, prov)
		}
		switch mailmeter.Outcome(outcome) {
		case mailmeter.Delivered:
			po.Delivered += n
			dl.Delivered += n
		case mailmeter.Deferred:
			po.Deferred += n
			dl.Deferred += n
		case mailmeter.Bounced:
			po.Bounced += n
			dl.Bounced += n
		}
	}
	rows.Close()
	if err := rows.Err(); err != nil {
		return dl, err
	}
	for _, prov := range order {
		dl.ByProvider = append(dl.ByProvider, *byProv[prov])
	}
	sort.Slice(dl.ByProvider, func(i, j int) bool {
		ti := dl.ByProvider[i].Delivered + dl.ByProvider[i].Deferred + dl.ByProvider[i].Bounced
		tj := dl.ByProvider[j].Delivered + dl.ByProvider[j].Deferred + dl.ByProvider[j].Bounced
		if ti != tj {
			return ti > tj
		}
		return dl.ByProvider[i].Provider < dl.ByProvider[j].Provider
	})
	if limit > 0 && len(dl.ByProvider) > limit {
		dl.ByProvider = dl.ByProvider[:limit]
	}

	// Top defer/bounce reasons (skip clean deliveries and unclassified blanks).
	rr, err := s.db.Query(
		`SELECT reason, SUM(n) c FROM mail_delivery
		 WHERE bucket>=? AND reason NOT IN ('ok','') GROUP BY reason ORDER BY c DESC, reason ASC LIMIT ?`,
		cutoff, limit)
	if err != nil {
		return dl, err
	}
	defer rr.Close()
	for rr.Next() {
		var rc ReasonCount
		if err := rr.Scan(&rc.Reason, &rc.Count); err != nil {
			return dl, err
		}
		dl.TopReasons = append(dl.TopReasons, rc)
	}
	return dl, rr.Err()
}

// topByAddr returns the top addresses by a single counter column over the
// window. col is an internal constant (never user input), so interpolating it is
// safe. A scoped caller's domain filter naturally excludes host-wide "*" and
// local-user rows (their domain is "*", never in a vhost allowlist).
func (s *Store) topByAddr(col string, cutoff int64, scope map[string]struct{}, limit int) ([]mailmeter.AddrCount, error) {
	q := `SELECT address, SUM(` + col + `) c FROM mail_counters WHERE bucket>=? AND ` + col + `>0`
	args := []any{cutoff}
	if scope != nil {
		frag, a := inClause(scope)
		q += frag
		args = append(args, a...)
	}
	q += ` GROUP BY address ORDER BY c DESC, address ASC LIMIT ?`
	args = append(args, limit)
	return scanAddrCounts(s.db, q, args)
}

func (s *Store) topDomains(cutoff int64, scope map[string]struct{}, limit int) ([]mailmeter.AddrCount, error) {
	q := `SELECT domain, SUM(outbound) c FROM mail_counters WHERE bucket>=? AND outbound>0 AND domain<>?`
	args := []any{cutoff, mailmeter.HostWide}
	if scope != nil {
		frag, a := inClause(scope)
		q += frag
		args = append(args, a...)
	}
	q += ` GROUP BY domain ORDER BY c DESC, domain ASC LIMIT ?`
	args = append(args, limit)
	return scanAddrCounts(s.db, q, args)
}

func (s *Store) totals(cutoff int64, scope map[string]struct{}) (Totals, error) {
	q := `SELECT
		COALESCE(SUM(outbound),0), COALESCE(SUM(local_sub),0), COALESCE(SUM(inbound),0),
		COALESCE(SUM(over_quota),0), COALESCE(SUM(throttled),0), COALESCE(SUM(auth_failed),0),
		COALESCE(SUM(rejected),0)
		FROM mail_counters WHERE bucket>=?`
	args := []any{cutoff}
	if scope != nil {
		frag, a := inClause(scope)
		q += frag
		args = append(args, a...)
	}
	var t Totals
	err := s.db.QueryRow(q, args...).Scan(
		&t.Outbound, &t.LocalSubmit, &t.Inbound, &t.OverQuota, &t.Throttled, &t.AuthFailed, &t.Rejected)
	return t, err
}

func scanAddrCounts(db *sql.DB, q string, args []any) ([]mailmeter.AddrCount, error) {
	rows, err := db.Query(q, args...)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	out := []mailmeter.AddrCount{}
	for rows.Next() {
		var ac mailmeter.AddrCount
		if err := rows.Scan(&ac.Addr, &ac.Count); err != nil {
			return nil, err
		}
		out = append(out, ac)
	}
	return out, rows.Err()
}

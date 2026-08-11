package mailtraffic

import (
	"database/sql"
	"fmt"
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

// Summary is the read view served by GET /api/v1/mail/traffic. All lists are
// already scope-filtered and capped to the requested limit. The HTTP handler
// wraps it in the usual {ok, schema, available, …} envelope, so Summary itself
// carries only the data (window + scope + the breakdowns).
type Summary struct {
	Window string `json:"window"`
	Scope  string `json:"scope"` // "admin" | "scoped"

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
	return sum, nil
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

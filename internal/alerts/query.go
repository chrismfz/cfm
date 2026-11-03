package alerts

import (
	"database/sql"
	"encoding/json"
	"errors"
	"fmt"
	"strconv"
	"strings"
	"time"
)

// Filter selects alerts. Every set field narrows the result (AND); list
// fields match any of their values (OR within the field).
type Filter struct {
	From, To    time.Time // [From, To); zero = unbounded
	Categories  []string  // WAF, WEB, MYSQL, ... (case-insensitive)
	Kinds       []string  // exact kinds, case-insensitive
	MinSeverity string    // info | warning | critical
	IP          string    // exact address
	Country     string    // ISO-2 ("GR") or a substring of the display name
	ASN         string    // number ("6799", "AS6799") or a substring of the name
	Vhost       string    // exact website
	Deliveries  []string  // notified, deduped, notifier_off, ...
	Mode        string    // ttl | permanent
	Query       string    // substring of reason, kind, ptr, asn, vhost or samples
	Before      *Cursor   // only rows after this one in List order (paging)
}

// Cursor is a position in List's order (newest first: ts_unix, then id).
type Cursor struct {
	TsUnix int64
	ID     int64
}

func (c Cursor) String() string { return strconv.FormatInt(c.TsUnix, 10) + "." + strconv.FormatInt(c.ID, 10) }

// ParseCursor reads a Page.NextCursor back.
func ParseCursor(s string) (Cursor, error) {
	ts, id, ok := strings.Cut(strings.TrimSpace(s), ".")
	if ok {
		t, err1 := strconv.ParseInt(ts, 10, 64)
		i, err2 := strconv.ParseInt(id, 10, 64)
		if err1 == nil && err2 == nil && t > 0 && i > 0 {
			return Cursor{TsUnix: t, ID: i}, nil
		}
	}
	return Cursor{}, fmt.Errorf("invalid cursor")
}

func (f Filter) where() (string, []any) {
	var conds []string
	var args []any
	if !f.From.IsZero() {
		conds = append(conds, "ts_unix >= ?")
		args = append(args, f.From.Unix())
	}
	if !f.To.IsZero() {
		conds = append(conds, "ts_unix < ?")
		args = append(args, f.To.Unix())
	}
	in := func(col string, vals []string, upper bool) {
		var clean []any
		for _, v := range vals {
			v = strings.TrimSpace(v)
			if v == "" {
				continue
			}
			if upper {
				v = strings.ToUpper(v)
			}
			clean = append(clean, v)
		}
		if len(clean) == 0 {
			return
		}
		conds = append(conds, col+" IN ("+strings.TrimSuffix(strings.Repeat("?,", len(clean)), ",")+")")
		args = append(args, clean...)
	}
	in("category", f.Categories, true)
	in("UPPER(kind)", f.Kinds, true)
	in("delivery", f.Deliveries, false)
	if r := SeverityRank(f.MinSeverity); r > 1 {
		var sev []string
		for _, s := range []string{"info", "warning", "critical"} {
			if SeverityRank(s) >= r {
				sev = append(sev, s)
			}
		}
		in("severity", sev, false)
	}
	if v := strings.TrimSpace(f.IP); v != "" {
		conds = append(conds, "ip = ?")
		args = append(args, v)
	}
	if v := strings.TrimSpace(f.Country); v != "" {
		if len(v) == 2 {
			conds = append(conds, "country_iso = ?")
			args = append(args, strings.ToUpper(v))
		} else {
			conds = append(conds, "country LIKE ? ESCAPE '\\'")
			args = append(args, likeArg(v))
		}
	}
	if v := strings.TrimSpace(f.ASN); v != "" {
		if n := ParseASN(v); n > 0 && strings.TrimLeft(strings.ToUpper(v), "AS0123456789 ") == "" {
			conds = append(conds, "asn_num = ?")
			args = append(args, n)
		} else {
			conds = append(conds, "asn LIKE ? ESCAPE '\\'")
			args = append(args, likeArg(v))
		}
	}
	if v := strings.TrimSpace(f.Vhost); v != "" {
		conds = append(conds, "vhost = ?")
		args = append(args, strings.ToLower(v))
	}
	if v := strings.TrimSpace(f.Mode); v != "" {
		conds = append(conds, "mode = ?")
		args = append(args, strings.ToLower(v))
	}
	if v := strings.TrimSpace(f.Query); v != "" {
		var ors []string
		for _, col := range []string{"reason", "kind", "ptr", "asn", "vhost", "samples"} {
			ors = append(ors, col+" LIKE ? ESCAPE '\\'")
			args = append(args, likeArg(v))
		}
		conds = append(conds, "("+strings.Join(ors, " OR ")+")")
	}
	if c := f.Before; c != nil {
		conds = append(conds, "(ts_unix < ? OR (ts_unix = ? AND id < ?))")
		args = append(args, c.TsUnix, c.TsUnix, c.ID)
	}
	if len(conds) == 0 {
		return "", nil
	}
	return " WHERE " + strings.Join(conds, " AND "), args
}

// likeArg wraps v for a LIKE substring match, escaping its own wildcards.
func likeArg(v string) string {
	r := strings.NewReplacer(`\`, `\\`, `%`, `\%`, `_`, `\_`)
	return "%" + r.Replace(v) + "%"
}

// Page is one page of List.
type Page struct {
	Rows       []Record `json:"rows"`
	Limit      int      `json:"limit"`
	HasMore    bool     `json:"has_more"`
	NextCursor string   `json:"next_cursor,omitempty"`
}

const cols = `id, ts_unix, host, category, kind, severity, ip, country, country_iso, asn, asn_num, ptr,
    vhost, reason, mode, ttl_sec, count, section, delivery, event_id, samples, extra`

// List returns the rows matching f, newest first (by event time), at most limit.
func (s *Store) List(f Filter, limit int) (Page, error) {
	if limit <= 0 {
		limit = 100
	}
	where, args := f.where()
	q := "SELECT " + cols + " FROM alerts" + where + " ORDER BY ts_unix DESC, id DESC LIMIT ?"
	args = append(args, limit+1)
	rows, err := s.ro.Query(q, args...)
	if err != nil {
		return Page{}, err
	}
	defer rows.Close()
	page := Page{Rows: []Record{}, Limit: limit}
	for rows.Next() {
		r, err := scanRecord(rows)
		if err != nil {
			return Page{}, err
		}
		if len(page.Rows) == limit {
			page.HasMore = true
			break
		}
		page.Rows = append(page.Rows, r)
	}
	if err := rows.Err(); err != nil {
		return Page{}, err
	}
	if page.HasMore {
		last := page.Rows[len(page.Rows)-1]
		page.NextCursor = Cursor{TsUnix: last.TsUnix, ID: last.ID}.String()
	}
	return page, nil
}

func scanRecord(rows *sql.Rows) (Record, error) {
	var r Record
	var samples, extra string
	if err := rows.Scan(&r.ID, &r.TsUnix, &r.Host, &r.Category, &r.Kind, &r.Severity, &r.IP, &r.Country,
		&r.CountryISO, &r.ASN, &r.ASNNum, &r.PTR, &r.Vhost, &r.Reason, &r.Mode, &r.TTLSec, &r.Count,
		&r.Section, &r.Delivery, &r.EventID, &samples, &extra); err != nil {
		return r, err
	}
	r.Time = time.Unix(r.TsUnix, 0).UTC().Format(time.RFC3339)
	if samples != "" {
		_ = json.Unmarshal([]byte(samples), &r.Samples)
	}
	if extra != "" {
		_ = json.Unmarshal([]byte(extra), &r.Extra)
	}
	return r, nil
}

// GroupColumns are the dimensions Summary can group by, mapped to their SQL.
// hour/day bucket the timestamp (UTC).
var GroupColumns = map[string]string{
	"category": "category",
	"kind":     "kind",
	"severity": "severity",
	"ip":       "ip",
	"country":  "country_iso",
	"asn":      "asn_num",
	"vhost":    "vhost",
	"reason":   "reason",
	"mode":     "mode",
	"delivery": "delivery",
	"section":  "section",
	"hour":     "strftime('%Y-%m-%dT%H:00:00Z', ts_unix, 'unixepoch')",
	"day":      "strftime('%Y-%m-%d', ts_unix, 'unixepoch')",
}

// Group is one Summary row: the group's key values and its tallies.
type Group struct {
	Key         map[string]string `json:"key"`
	Count       int64             `json:"count"`
	DistinctIPs int64             `json:"distinct_ips"`
	FirstUnix   int64             `json:"first_unix"`
	LastUnix    int64             `json:"last_unix"`
	// Label fills in what a bare key hides: the ASN's name for an asn group,
	// the country's name for a country group.
	Label string `json:"label,omitempty"`
}

// Summary is the result of grouping.
type Summary struct {
	GroupBy     []string `json:"group_by"`
	Total       int64    `json:"total"`
	DistinctIPs int64    `json:"distinct_ips"`
	Groups      []Group  `json:"groups"`
	Truncated   bool     `json:"truncated"`
}

// ErrBadGroupBy is returned (wrapped) for a group_by Summarize does not take.
var ErrBadGroupBy = errors.New("invalid group_by")

// Summarize groups the rows matching f by up to three dimensions
// (GroupColumns) and returns the top groups by count — or, when the first
// dimension is hour/day, in time order.
func (s *Store) Summarize(f Filter, groupBy []string, top int) (Summary, error) {
	dims, err := normalizeGroupBy(groupBy)
	if err != nil {
		return Summary{}, err
	}
	if top <= 0 {
		top = 50
	}
	sum := Summary{GroupBy: dims, Groups: []Group{}}
	where, args := f.where()
	if err := s.ro.QueryRow("SELECT COUNT(*), COUNT(DISTINCT NULLIF(ip, '')) FROM alerts"+where, args...).
		Scan(&sum.Total, &sum.DistinctIPs); err != nil {
		return sum, err
	}
	sum.Groups, sum.Truncated, err = s.groups(f, dims, top)
	return sum, err
}

// normalizeGroupBy validates group_by (default category, at most three known
// dimensions) and returns it lower-cased, without touching the caller's slice.
func normalizeGroupBy(groupBy []string) ([]string, error) {
	if len(groupBy) == 0 {
		return []string{"category"}, nil
	}
	if len(groupBy) > 3 {
		return nil, fmt.Errorf("%w: at most 3 dimensions", ErrBadGroupBy)
	}
	dims := make([]string, 0, len(groupBy))
	for _, g := range groupBy {
		g = strings.ToLower(strings.TrimSpace(g))
		if _, ok := GroupColumns[g]; !ok {
			return nil, fmt.Errorf("%w: unknown dimension %q", ErrBadGroupBy, g)
		}
		dims = append(dims, g)
	}
	return dims, nil
}

// groups runs the GROUP BY for already-validated dims: the top groups and
// whether there were more.
func (s *Store) groups(f Filter, dims []string, top int) ([]Group, bool, error) {
	exprs := make([]string, 0, len(dims))
	for _, g := range dims {
		exprs = append(exprs, GroupColumns[g])
	}
	// a label column for the first asn/country dimension
	label := "''"
	for _, g := range dims {
		if g == "asn" {
			label = "MAX(asn)"
			break
		}
		if g == "country" {
			label = "MAX(country)"
			break
		}
	}
	order := "COUNT(*) DESC"
	if dims[0] == "hour" || dims[0] == "day" {
		order = "1 ASC, COUNT(*) DESC"
	}
	where, args := f.where()
	q := "SELECT " + strings.Join(exprs, ", ") + ", COUNT(*), COUNT(DISTINCT NULLIF(ip, '')), MIN(ts_unix), MAX(ts_unix), " +
		label + " FROM alerts" + where + " GROUP BY " + strings.Join(exprs, ", ") + " ORDER BY " + order + " LIMIT ?"
	rows, err := s.ro.Query(q, append(args, top+1)...)
	if err != nil {
		return nil, false, err
	}
	defer rows.Close()
	out := []Group{}
	truncated := false
	for rows.Next() {
		keys := make([]sql.NullString, len(dims))
		dest := make([]any, 0, len(dims)+5)
		for i := range keys {
			dest = append(dest, &keys[i])
		}
		var g Group
		var lbl sql.NullString
		dest = append(dest, &g.Count, &g.DistinctIPs, &g.FirstUnix, &g.LastUnix, &lbl)
		if err := rows.Scan(dest...); err != nil {
			return nil, false, err
		}
		if len(out) == top {
			truncated = true
			break
		}
		g.Key = make(map[string]string, len(dims))
		for i, name := range dims {
			g.Key[name] = keys[i].String
		}
		g.Label = lbl.String
		out = append(out, g)
	}
	return out, truncated, rows.Err()
}

// Overview is the Alerts page header in one read: the window's tallies, its
// top kind and country, and the per-category counts for the category chips.
type Overview struct {
	Total       int64   `json:"total"`
	DistinctIPs int64   `json:"distinct_ips"`
	NotNotified int64   `json:"not_notified"` // delivery is anything but notified
	TopKind     *Group  `json:"top_kind"`
	TopCountry  *Group  `json:"top_country"`
	Categories  []Group `json:"categories"` // counted WITHOUT f's category filter, so every chip shows its count
}

// Overview computes the page header for f.
func (s *Store) Overview(f Filter) (Overview, error) {
	var ov Overview
	where, args := f.where()
	if err := s.ro.QueryRow("SELECT COUNT(*), COUNT(DISTINCT NULLIF(ip, '')), COALESCE(SUM(delivery <> 'notified'), 0) FROM alerts"+where, args...).
		Scan(&ov.Total, &ov.DistinctIPs, &ov.NotNotified); err != nil {
		return ov, err
	}
	for dim, dst := range map[string]**Group{"kind": &ov.TopKind, "country": &ov.TopCountry} {
		g, _, err := s.groups(f, []string{dim}, 1)
		if err != nil {
			return ov, err
		}
		if len(g) > 0 {
			*dst = &g[0]
		}
	}
	all := f
	all.Categories = nil
	cats, _, err := s.groups(all, []string{"category"}, 100)
	if err != nil {
		return ov, err
	}
	ov.Categories = cats
	return ov, nil
}

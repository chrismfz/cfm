package webdetector

import (
	"net/http"
	"regexp"
	"sort"
	"strconv"
	"strings"
	"sync"
	"time"
)

// The login-outcome corpus (docs/webdetector-signals-v2.md §2, phase 0).
//
// The edge sends, on every login POST, what it alone can see: whether the
// response set WordPress's logged-in cookie with a real value, the
// Set-Cookie NAMES and the Location PATH (log-cfm.lua column 14,
// LogRec.Auth). authOutcome turns those into a verdict. Nothing counts logins
// yet. This corpus groups those lines by their shape (tag, outcome, upstream,
// status, path, Location, cookie names) so a fleet read can decide, per CMS, which shape is
// a success and which a failure, before any signal is keyed on it. A rule
// written from memory is what made the first hunt read 302s as successes.
//
// Bounded: at most authCorpusCap shapes, each with a few example hosts and
// distinct-IP / distinct-host counts capped at authCorpusSetCap. A shape past
// the cap is counted in Dropped, not stored. It lives in memory only (a daemon
// restart or config reload empties it) and it is node-wide, so its API is
// admin-only. It holds no cookie value, no query string and no request body.

const (
	maxAuthField     = 256
	authCorpusCap    = 2000
	authCorpusSetCap = 64
	authCorpusHosts  = 5
	authCorpusMaxURI = 96
	authCorpusDefLim = 100
	authCorpusMaxLim = 1000
)

// authField is a parsed LogRec.Auth: the facts the edge saw. The outcome
// is the daemon's call (authOutcome).
type authField struct {
	Tag      string // WP_LOGIN, JOOMLA_ADMIN, ... (auth_endpoint_tag minus AUTH_)
	LoggedIn bool   // a wordpress_logged_in_* cookie with a real value
	Loc      string // the Location path, query and host dropped at the edge
	Cookies  []string
	Action   string // the query's action, when present
}

// parseAuthField reads "<TAG>;li=<0|1>;l=<loc>;c=<a,b>[;a=<action>]". An
// empty or malformed value is not a login line.
func parseAuthField(s string) (authField, bool) {
	if s == "" || s == "-" {
		return authField{}, false
	}
	parts := strings.Split(s, ";")
	if parts[0] == "" || strings.ContainsAny(parts[0], ":=,") || len(parts) < 2 {
		return authField{}, false
	}
	af := authField{Tag: parts[0]}
	sawLI := false
	for _, p := range parts[1:] {
		k, v, ok := strings.Cut(p, "=")
		if !ok {
			continue
		}
		switch k {
		case "li":
			sawLI = true
			af.LoggedIn = v == "1"
		case "l":
			af.Loc = v
		case "c":
			if v != "" {
				af.Cookies = strings.Split(v, ",")
			}
		case "a":
			af.Action = v
		}
	}
	if !sawLI {
		return authField{}, false
	}
	return af, true
}

// authOutcome is the verdict on one login line: "ok", "fail", "na" (another
// wp-login.php action) or "?" (not known). Only an answer from the site's
// origin counts: a login POST CFM routed to its challenge server or blocked
// at the edge says nothing about the password. WordPress is the one CMS
// whose rule is verified (docs/webdetector-signals-v2.md §2); every other tag
// is "?" until the corpus decides its rule, and that rule goes here.
func authOutcome(rec LogRec, af authField) string {
	if !strings.HasPrefix(rec.UpstreamName, "cfm_apache") {
		return "?"
	}
	switch af.Tag {
	case "WP_LOGIN":
		// The cookie first: the query's action cannot hide a success, since
		// PHP's $_REQUEST lets a body action=login override it.
		if af.LoggedIn {
			return "ok"
		}
		if af.Action != "" && af.Action != "login" {
			// A real lostpassword/register POST, or a login hidden behind a
			// query action: both answer 200 on a failure, so the line is kept
			// apart (na) rather than counted as a failed login.
			return "na"
		}
		st := rec.Status
		if st == 200 || (st >= 300 && st < 400 && strings.Contains(strings.ToLower(af.Loc), "login")) {
			return "fail"
		}
	}
	return "?"
}

// Shape normalisation: hex runs (a Joomla session cookie is an md5 name,
// WordPress's is wordpress_logged_in_<md5>) and digit runs (ids in a path)
// collapse, so one CMS's logins fold into a few shapes instead of one per
// site.
var (
	authHexRun   = regexp.MustCompile(`[0-9a-f]{12,}`)
	authDigitRun = regexp.MustCompile(`[0-9]+`)
)

func authShape(s string) string {
	s = strings.ToLower(s)
	s = authHexRun.ReplaceAllString(s, "<h>")
	return authDigitRun.ReplaceAllString(s, "<n>")
}

// authRouteKeys are the query fields that say WHICH action a front
// controller runs. auth_endpoint_tag tags every Joomla admin POST, a save as
// well as the login, and OpenCart / PrestaShop route the login through
// index.php too, so a path without them would fold a login and an article
// save into one shape. Every other field (a token, a redirect target, a
// username) is dropped.
var authRouteKeys = map[string]bool{
	"option": true, "task": true, "route": true, "controller": true, "action": true, "view": true,
}

func authPathShape(uri string) string {
	p, q, _ := strings.Cut(uri, "?")
	if i := strings.IndexByte(p, '#'); i >= 0 {
		p = p[:i]
	}
	if i := strings.IndexByte(q, '#'); i >= 0 {
		q = q[:i]
	}
	var keep []string
	for _, kv := range strings.Split(q, "&") {
		k, v, _ := strings.Cut(kv, "=")
		if !authRouteKeys[k] {
			continue
		}
		if len(v) > 32 {
			v = v[:32]
		}
		keep = append(keep, k+"="+v)
		if len(keep) == 3 {
			break
		}
	}
	if len(keep) > 0 {
		sort.Strings(keep)
		p += "?" + strings.Join(keep, "&")
	}
	p = authShape(p)
	if len(p) > authCorpusMaxURI {
		p = p[:authCorpusMaxURI]
	}
	return p
}

func authCookieShape(names []string) string {
	if len(names) == 0 {
		return ""
	}
	seen := make(map[string]struct{}, len(names))
	out := make([]string, 0, len(names))
	for _, n := range names {
		n = authShape(n)
		if _, dup := seen[n]; dup || n == "" {
			continue
		}
		seen[n] = struct{}{}
		out = append(out, n)
	}
	sort.Strings(out)
	return strings.Join(out, ",")
}

// AuthCorpusEntry is one shape and what was seen with it.
type AuthCorpusEntry struct {
	Tag      string   `json:"tag"`
	Outcome  string   `json:"outcome"`
	Upstream string   `json:"upstream"`
	LoggedIn bool     `json:"logged_in_cookie"`
	Method   string   `json:"method"`
	Status   int      `json:"status"`
	Path     string   `json:"path"`
	Location string   `json:"location"`
	Cookies  string   `json:"cookies"`
	Action   string   `json:"action,omitempty"`
	Count    int64    `json:"count"`
	IPs      int      `json:"ips"`   // distinct, capped at authCorpusSetCap
	Hosts    int      `json:"hosts"` // distinct, capped at authCorpusSetCap
	Capped   bool     `json:"capped,omitempty"`
	Examples []string `json:"example_hosts"`
	FirstTS  int64    `json:"first_ts"`
	LastTS   int64    `json:"last_ts"`

	ipSet   map[string]struct{}
	hostSet map[string]struct{}
}

type authCorpus struct {
	mu      sync.Mutex
	entries map[string]*AuthCorpusEntry
	totals  map[string]map[string]int64 // tag → outcome → lines
	dropped int64
	dropTag map[string]int64 // shapes refused at the cap, per tag
	since   int64
	cap     int
}

func newAuthCorpus(capacity int) *authCorpus {
	if capacity <= 0 {
		capacity = authCorpusCap
	}
	return &authCorpus{
		entries: make(map[string]*AuthCorpusEntry),
		totals:  make(map[string]map[string]int64),
		dropTag: make(map[string]int64),
		since:   time.Now().Unix(),
		cap:     capacity,
	}
}

func addCapped(set map[string]struct{}, v string) (map[string]struct{}, bool) {
	if set == nil {
		set = make(map[string]struct{})
	}
	if _, ok := set[v]; ok {
		return set, false
	}
	if len(set) >= authCorpusSetCap {
		return set, true
	}
	set[v] = struct{}{}
	return set, false
}

func (c *authCorpus) add(rec LogRec, host string) {
	af, ok := parseAuthField(rec.Auth)
	if !ok {
		return
	}
	outcome := authOutcome(rec, af)
	e := AuthCorpusEntry{
		Tag:      af.Tag,
		Outcome:  outcome,
		Upstream: rec.UpstreamName,
		LoggedIn: af.LoggedIn,
		Method:   rec.Method,
		Status:   rec.Status,
		Path:     authPathShape(rec.URI),
		Location: authShape(af.Loc),
		Cookies:  authCookieShape(af.Cookies),
		Action:   af.Action,
	}
	li := "0"
	if e.LoggedIn {
		li = "1"
	}
	key := e.Tag + "\x00" + e.Outcome + "\x00" + e.Upstream + "\x00" + li + "\x00" + e.Method + "\x00" + strconv.Itoa(e.Status) + "\x00" +
		e.Path + "\x00" + e.Location + "\x00" + e.Cookies + "\x00" + e.Action
	ts := int64(rec.TS)

	c.mu.Lock()
	defer c.mu.Unlock()
	t := c.totals[af.Tag]
	if t == nil {
		if len(c.totals) >= 64 { // tags come from one fixed Lua list
			c.dropped++
			return
		}
		t = make(map[string]int64)
		c.totals[af.Tag] = t
	}
	t[outcome]++

	cur := c.entries[key]
	if cur == nil {
		if len(c.entries) >= c.cap {
			c.dropped++
			c.dropTag[af.Tag]++
			return
		}
		e.FirstTS = ts
		cur = &e
		c.entries[key] = cur
	}
	cur.Count++
	cur.LastTS = ts
	var full bool
	cur.ipSet, full = addCapped(cur.ipSet, rec.IP)
	cur.Capped = cur.Capped || full
	var isNew bool
	if _, seen := cur.hostSet[host]; !seen {
		isNew = true
	}
	cur.hostSet, full = addCapped(cur.hostSet, host)
	cur.Capped = cur.Capped || full
	if isNew && !full && len(cur.Examples) < authCorpusHosts {
		cur.Examples = append(cur.Examples, host)
	}
}

// AuthCorpusSnapshot is what the API returns.
type AuthCorpusSnapshot struct {
	Schema  string `json:"schema"`
	Since   int64  `json:"since"`
	Shapes  int    `json:"shapes"`
	Cap     int    `json:"cap"`
	Dropped int64  `json:"dropped"`
	// DroppedByTag says whose shapes the cap refused: their lines are in
	// Totals but in no entry.
	DroppedByTag map[string]int64            `json:"dropped_by_tag,omitempty"`
	Totals       map[string]map[string]int64 `json:"totals"`
	Entries      []AuthCorpusEntry           `json:"entries"`
}

func (c *authCorpus) snapshot(tag, outcome string, limit int) AuthCorpusSnapshot {
	if limit <= 0 {
		limit = authCorpusDefLim
	}
	if limit > authCorpusMaxLim {
		limit = authCorpusMaxLim
	}
	tag = strings.ToUpper(strings.TrimSpace(tag))
	c.mu.Lock()
	out := AuthCorpusSnapshot{
		Schema:  "webdet.auth_corpus.v1",
		Since:   c.since,
		Shapes:  len(c.entries),
		Cap:     c.cap,
		Dropped: c.dropped,
		Totals:  make(map[string]map[string]int64, len(c.totals)),
	}
	for k, n := range c.dropTag {
		if tag != "" && k != tag {
			continue
		}
		if out.DroppedByTag == nil {
			out.DroppedByTag = make(map[string]int64)
		}
		out.DroppedByTag[k] = n
	}
	for k, m := range c.totals {
		if tag != "" && k != tag {
			continue
		}
		cp := make(map[string]int64, len(m))
		for o, n := range m {
			cp[o] = n
		}
		out.Totals[k] = cp
	}
	for _, e := range c.entries {
		if tag != "" && e.Tag != tag {
			continue
		}
		if outcome != "" && e.Outcome != outcome {
			continue
		}
		cp := *e
		cp.IPs, cp.Hosts = len(e.ipSet), len(e.hostSet)
		cp.Examples = append([]string(nil), e.Examples...)
		cp.ipSet, cp.hostSet = nil, nil
		out.Entries = append(out.Entries, cp)
	}
	c.mu.Unlock()
	sort.Slice(out.Entries, func(i, j int) bool {
		a, b := out.Entries[i], out.Entries[j]
		if a.Count != b.Count {
			return a.Count > b.Count
		}
		if a.Tag != b.Tag {
			return a.Tag < b.Tag
		}
		return a.Path+a.Location+a.Cookies < b.Path+b.Location+b.Cookies
	})
	if len(out.Entries) > limit {
		out.Entries = out.Entries[:limit]
	}
	return out
}

// handleAuthCorpus serves GET /api/v1/webdet/auth-corpus. Admin-only: the
// corpus is node-wide (example hosts of every tenant). Backs the MCP
// auth_corpus tool. Query params (optional): tag (e.g. JOOMLA_ADMIN),
// outcome (ok|fail|na|?), limit (default 100, max 1000).
func (e *Engine) handleAuthCorpus(w http.ResponseWriter, r *http.Request) {
	if !RequireAdmin(w, r) {
		return
	}
	if e.authCorpus == nil {
		writeJSON(w, http.StatusOK, AuthCorpusSnapshot{Schema: "webdet.auth_corpus.v1"})
		return
	}
	q := r.URL.Query()
	limit, _ := strconv.Atoi(strings.TrimSpace(q.Get("limit")))
	writeJSON(w, http.StatusOK, e.authCorpus.snapshot(q.Get("tag"), strings.TrimSpace(q.Get("outcome")), limit))
}

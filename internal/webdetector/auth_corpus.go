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
// The edge sends, on every login POST, the outcome it can tell (WordPress
// only, so far) plus the response's Set-Cookie NAMES and Location PATH
// (log-cfm.lua column 14, LogRec.Auth). Nothing counts logins yet. This
// corpus groups those lines by their shape (tag, outcome, status, path,
// Location, cookie names) so a fleet read can decide, per CMS, which shape is
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

// authField is a parsed LogRec.Auth.
type authField struct {
	Tag     string // WP_LOGIN, JOOMLA_ADMIN, ... (auth_endpoint_tag minus AUTH_)
	Outcome string // ok | fail | na | ?
	Loc     string // the Location path, query dropped at the edge
	Cookies []string
	Action  string // a wp-login action other than login (outcome na)
}

// parseAuthField reads "<TAG>:<outcome>;l=<loc>;c=<a,b>[;a=<action>]". An
// empty or malformed value is not a login line.
func parseAuthField(s string) (authField, bool) {
	if s == "" || s == "-" {
		return authField{}, false
	}
	parts := strings.Split(s, ";")
	head := parts[0]
	i := strings.IndexByte(head, ':')
	if i <= 0 || i == len(head)-1 {
		return authField{}, false
	}
	af := authField{Tag: head[:i], Outcome: head[i+1:]}
	switch af.Outcome {
	case "ok", "fail", "na", "?":
	default:
		return authField{}, false
	}
	for _, p := range parts[1:] {
		k, v, ok := strings.Cut(p, "=")
		if !ok {
			continue
		}
		switch k {
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
	return af, true
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
	e := AuthCorpusEntry{
		Tag:      af.Tag,
		Outcome:  af.Outcome,
		Method:   rec.Method,
		Status:   rec.Status,
		Path:     authPathShape(rec.URI),
		Location: authShape(af.Loc),
		Cookies:  authCookieShape(af.Cookies),
		Action:   af.Action,
	}
	key := e.Tag + "\x00" + e.Outcome + "\x00" + e.Method + "\x00" + strconv.Itoa(e.Status) + "\x00" +
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
	t[af.Outcome]++

	cur := c.entries[key]
	if cur == nil {
		if len(c.entries) >= c.cap {
			c.dropped++
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
	Schema  string                      `json:"schema"`
	Since   int64                       `json:"since"`
	Shapes  int                         `json:"shapes"`
	Cap     int                         `json:"cap"`
	Dropped int64                       `json:"dropped"`
	Totals  map[string]map[string]int64 `json:"totals"`
	Entries []AuthCorpusEntry           `json:"entries"`
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

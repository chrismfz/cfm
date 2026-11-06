package webdetector

import (
	"hash/fnv"
	"net/http"
	"net/netip"
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
// Bounded: at most authCorpusCap shapes, at most authCorpusPerNet of them
// created by one /24 (or IPv6 /64), each with a few example hosts and
// distinct-IP / distinct-host counts (FNV hashes, capped at authCorpusSetCap).
// A full corpus evicts its least-used shape, so it never freezes. Lines whose
// new shape is refused (a network past its share) are counted in Dropped. It
// lives in memory only (a daemon restart or config reload empties it) and it
// is node-wide, so its API is admin-only. It holds no cookie value, no query
// string beyond a few route fields, and no request body.

const (
	// The edge's field tops out near 530 bytes (tag, 96-byte Location, 8
	// cookie names of 48, a 24-byte action); a cut one would lose its tail.
	maxAuthField      = 640
	authCorpusMaxHost = 128
	// authCorpusPerNet is how many live shapes one network (a /24, or a /64
	// for IPv6) may hold: shapes come from request paths an attacker chooses.
	// A shape's slot is released when it is evicted, so the bookkeeping
	// never outgrows the corpus.
	authCorpusPerNet = 16
	// authCorpusEvictBatch is how many least-used shapes one full-corpus
	// scan evicts.
	authCorpusEvictBatch = 20
	authCorpusCap        = 2000
	authCorpusSetCap     = 64
	authCorpusHosts      = 5
	authCorpusMaxURI     = 96
	authCorpusDefLim     = 100
	authCorpusMaxLim     = 1000
)

// authField is a parsed LogRec.Auth: the facts the edge saw. The outcome
// is the daemon's call (authOutcome).
type authField struct {
	Tag      string // WP_LOGIN, JOOMLA_ADMIN, ... (auth_endpoint_tag minus AUTH_)
	LoggedIn bool   // a wordpress_logged_in_* cookie with a real value
	MFA      bool   // li=2: a real one set and cleared in the same answer (a 2FA password step)
	Loc      string // the Location path, query and host dropped at the edge
	Cookies  []string
	Action   string // the query's action, when present
	Cross    bool   // the Location left the request's scheme or host
}

// parseAuthField reads "<TAG>;li=<0|1|2>[;a=<action>][;x=1];l=<loc>;c=<a,b>" (keys
// in any order). An
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
			af.MFA = v == "2"
		case "l":
			af.Loc = v
		case "c":
			if v != "" {
				af.Cookies = strings.Split(v, ",")
			}
		case "a":
			af.Action = v
		case "x":
			af.Cross = v == "1"
		}
	}
	if !sawLI {
		return authField{}, false
	}
	return af, true
}

// authOutcome is the verdict on one login line: "ok", "fail", "mfa" (a 2FA
// password step), "na" (another wp-login.php action) or "?" (not known). Only an answer from the site's
// origin counts: a login POST CFM routed to its challenge server or blocked
// at the edge says nothing about the password. WordPress is the one CMS
// whose rule is verified (docs/webdetector-signals-v2.md §2); every other tag
// is "?" until the corpus decides its rule, and that rule goes here.
func authOutcome(rec LogRec, af authField) string {
	// The conf presets $cfm_upstream to cfm_apache and some edge exits keep
	// it, so an upstream must also have answered (urt was not "-").
	if !rec.Upstream || !strings.HasPrefix(rec.UpstreamName, "cfm_apache") {
		return "?"
	}
	switch af.Tag {
	case "WP_LOGIN":
		// The cookie first: the query's action cannot hide a success, since
		// PHP's $_REQUEST lets a body action=login override it.
		if af.LoggedIn {
			return "ok"
		}
		if af.MFA {
			// The origin set a real wordpress_logged_in_ cookie and cleared
			// it in the same answer (the edge's li=2): a 2FA plugin (Two
			// Factor, WP 2FA) accepted the PASSWORD and shows its
			// second-factor form. Not a failure: an admin's every 2FA login
			// read as one, enough for a ban. A cleared cookie with no real
			// one before it is no such step: wp-login.php?reauth=1 clears it
			// on every failed login.
			return "mfa"
		}
		if wpNonLoginActions[af.Action] {
			// A real lostpassword/register POST, or a login hidden behind a
			// query action: a body action=login overrides the query's in
			// PHP's $_REQUEST, so ?action=lostpassword with a login body
			// runs the login. Both answer 200 on a failure (the form again),
			// and the edge cannot tell them apart, so a 200 is a failure:
			// otherwise every failure of a brute forcer that adds the query
			// read as na and was never counted. A lostpassword / register
			// form shown again is a failed attempt too (an unknown user).
			// Anything else (the redirect after a reset mail) stays na. Any
			// other action value is a login: wp-login.php runs its login
			// case for an unknown one.
			if rec.Status == 200 {
				return "fail"
			}
			return "na"
		}
		// A failure is the form again (200), or WordPress / a hide-login
		// plugin sending the client back to a login page: wp_redirect, a
		// 302 (or a 303). A 301/308 to the login page is the site's
		// canonical redirect (http to https, www), which moves the POST
		// before WordPress reads it: no outcome (lelaki.gr, 2026-11-05).
		st := rec.Status
		if af.Cross && st >= 300 && st < 400 {
			// A redirect to another scheme or host is a canonical one
			// (http to https, bare to www), whatever its status: Apache's
			// [R] is a 302. It moved the POST before WordPress read it.
			return "?"
		}
		if st == 200 || ((st == 302 || st == 303) && strings.Contains(strings.ToLower(af.Loc), "login")) {
			return "fail"
		}
	}
	return "?"
}

// wpNonLoginActions are wp-login.php's own actions other than login (its
// $default_actions); every other value, an unknown one included, runs the
// login. The edge sends the query's last `action`, URL-decoded, as PHP reads
// it.
var wpNonLoginActions = map[string]bool{
	"confirm_admin_email": true, "postpass": true, "logout": true, "lostpassword": true,
	"retrievepassword": true, "resetpass": true, "rp": true, "register": true,
	"checkemail": true, "confirmaction": true, "entered_recovery_mode": true,
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

// authUserSegments are first path segments whose next segment is a person
// (BuddyPress /members/<user>/, Ultimate Member /user/<user>/, author pages):
// the corpus must not keep a username, nor make a shape per user.
var authUserSegments = map[string]bool{
	"members": true, "member": true, "user": true, "users": true, "author": true, "profile": true, "u": true,
}

// authLocShape keeps the Location's first two path segments (enough to tell
// /wp-login.php, /wp-admin/, /administrator/index.php and a dashboard route
// apart), folding a person's name after a user segment.
func authLocShape(loc string) string {
	if loc == "" {
		return ""
	}
	trail := strings.HasSuffix(loc, "/")
	segs := strings.Split(strings.Trim(loc, "/"), "/")
	more := len(segs) > 2
	if more {
		segs = segs[:2]
	}
	if len(segs) == 2 && authUserSegments[strings.ToLower(segs[0])] {
		segs[1] = "<user>"
	}
	out := "/" + strings.Join(segs, "/")
	switch {
	case more:
		out += "/…"
	case trail && out != "/":
		out += "/"
	}
	return authShape(out)
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

	key     string
	net     string              // the network that created it (authCorpusPerNet)
	ipSet   map[uint64]struct{} // FNV hashes: distinct counts only, no strings kept
	hostSet map[uint64]struct{}
}

type authCorpus struct {
	mu      sync.Mutex
	entries map[string]*AuthCorpusEntry
	totals  map[string]map[string]int64 // tag → outcome → lines
	dropped int64
	dropTag map[string]int64 // lines whose new shape was refused, per tag
	evicted int64            // least-used shapes evicted to make room
	byNet   map[string]int   // live shapes per creating network
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
		byNet:   make(map[string]int),
		since:   time.Now().Unix(),
		cap:     capacity,
	}
}

func authHash(v string) uint64 {
	h := fnv.New64a()
	_, _ = h.Write([]byte(v))
	return h.Sum64()
}

func addCapped(set map[uint64]struct{}, v string) (map[uint64]struct{}, bool, bool) {
	if set == nil {
		set = make(map[uint64]struct{})
	}
	k := authHash(v)
	if _, ok := set[k]; ok {
		return set, false, false
	}
	if len(set) >= authCorpusSetCap {
		return set, true, false
	}
	set[k] = struct{}{}
	return set, false, true
}

// authNet is the network a client's share is counted on: its /24, or its /64
// for IPv6, so one host's neighbours (or one IPv6 prefix) share a quota.
func authNet(ip string) string {
	a, err := netip.ParseAddr(ip)
	if err != nil {
		return ip
	}
	bits := 24
	if a.Is6() && !a.Is4In6() {
		bits = 64
	}
	p, err := a.Unmap().Prefix(bits)
	if err != nil {
		return ip
	}
	return p.String()
}

// add records one login line. Every string it keeps is cloned: the parsed
// fields are substrings of the socket line (up to 256 KB), and keeping one
// would pin the whole line for the corpus's life (the access ring's lesson,
// access_ring.go).
func (c *authCorpus) add(rec LogRec, host string) {
	af, ok := parseAuthField(rec.Auth)
	if !ok {
		return
	}
	c.addParsed(rec, host, af, authOutcome(rec, af))
}

// addParsed is add for a line already parsed (the engine parses once for
// the corpus and the login ledger).
func (c *authCorpus) addParsed(rec LogRec, host string, af authField, outcome string) {
	if len(host) > authCorpusMaxHost {
		host = host[:authCorpusMaxHost]
	}
	e := AuthCorpusEntry{
		Tag:      af.Tag,
		Outcome:  outcome,
		Upstream: rec.UpstreamName,
		LoggedIn: af.LoggedIn,
		Method:   rec.Method,
		Status:   rec.Status,
		Path:     authPathShape(rec.URI),
		Location: authLocShape(af.Loc),
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
		c.totals[strings.Clone(af.Tag)] = t
	}
	t[outcome]++

	cur := c.entries[key]
	if cur == nil {
		netKey := authNet(rec.IP)
		if c.byNet[netKey] >= authCorpusPerNet {
			c.dropped++
			c.dropTag[af.Tag]++
			return
		}
		if len(c.entries) >= c.cap && !c.evictLocked() {
			c.dropped++
			c.dropTag[af.Tag]++
			return
		}
		c.byNet[netKey]++ // netip's String() is its own string
		e.net = netKey
		e.Tag, e.Upstream, e.Method = strings.Clone(e.Tag), strings.Clone(e.Upstream), strings.Clone(e.Method)
		e.Path, e.Location = strings.Clone(e.Path), strings.Clone(e.Location)
		e.Cookies, e.Action = strings.Clone(e.Cookies), strings.Clone(e.Action)
		e.key = key // built by concatenation: its own memory
		e.FirstTS = ts
		cur = &e
		c.entries[key] = cur
	}
	cur.Count++
	cur.LastTS = ts
	var full bool
	cur.ipSet, full, _ = addCapped(cur.ipSet, rec.IP)
	cur.Capped = cur.Capped || full
	var newHost bool
	cur.hostSet, full, newHost = addCapped(cur.hostSet, host)
	cur.Capped = cur.Capped || full
	if newHost && len(cur.Examples) < authCorpusHosts {
		cur.Examples = append(cur.Examples, strings.Clone(host))
	}
}

// evictLocked makes room by dropping the least-used shapes (the lowest
// count, oldest last sighting first) and releasing their networks' slots.
// Any shape can go, so neither junk nor a busy week can freeze the corpus:
// what stays is what keeps being seen. It evicts authCorpusEvictBatch at a
// time, so the O(cap) scan is paid once per batch, not on every new shape a
// botnet's unique paths bring (18 µs a shape with one per scan).
func (c *authCorpus) evictLocked() bool {
	batch := c.cap / 50 // 2% of the corpus, at most authCorpusEvictBatch
	if batch < 1 {
		batch = 1
	}
	if batch > authCorpusEvictBatch {
		batch = authCorpusEvictBatch
	}
	victims := make([]*AuthCorpusEntry, 0, batch+1)
	less := func(a, b *AuthCorpusEntry) bool {
		return a.Count < b.Count || (a.Count == b.Count && a.LastTS < b.LastTS)
	}
	for _, e := range c.entries {
		// Keep victims sorted, best victim first, at most a batch long.
		if len(victims) == batch && !less(e, victims[len(victims)-1]) {
			continue
		}
		k := sort.Search(len(victims), func(i int) bool { return less(e, victims[i]) })
		victims = append(victims, nil)
		copy(victims[k+1:], victims[k:])
		victims[k] = e
		if len(victims) > batch {
			victims = victims[:batch]
		}
	}
	for _, v := range victims {
		delete(c.entries, v.key)
		if n := c.byNet[v.net]; n <= 1 {
			delete(c.byNet, v.net)
		} else {
			c.byNet[v.net] = n - 1
		}
		c.evicted++
	}
	return len(victims) > 0
}

// AuthCorpusSnapshot is what the API returns.
type AuthCorpusSnapshot struct {
	Schema  string `json:"schema"`
	Since   int64  `json:"since"`
	Shapes  int    `json:"shapes"`
	Cap     int    `json:"cap"`
	Dropped int64  `json:"dropped"`
	Evicted int64  `json:"evicted"` // least-used shapes dropped to make room
	// DroppedByTag says whose lines found no room (a network past its
	// share): they are in Totals but in no entry.
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
	outcome = strings.ToLower(strings.TrimSpace(outcome))
	c.mu.Lock()
	out := AuthCorpusSnapshot{
		Schema:  "webdet.auth_corpus.v1",
		Since:   c.since,
		Shapes:  len(c.entries),
		Cap:     c.cap,
		Dropped: c.dropped,
		Evicted: c.evicted,
		Entries: []AuthCorpusEntry{},
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
		return a.key < b.key
	})
	if len(out.Entries) > limit {
		out.Entries = out.Entries[:limit]
	}
	return out
}

// handleAuthCorpus serves GET /api/v1/webdet/auth-corpus. Admin-only: the
// corpus is node-wide (example hosts of every tenant). Backs the MCP
// auth_corpus tool. Query params (optional): tag (e.g. JOOMLA_ADMIN),
// outcome (ok|fail|mfa|na|?), limit (default 100, max 1000).
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

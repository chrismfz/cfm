package blocklists

import (
	"context"
	"crypto/sha256"
	"errors"
	"fmt"
	"net/http"
	"net/url"
	"regexp"
	"sort"
	"strings"
	"sync"
	"time"
)

// Applier: ο manager δεν ξέρει nft. Του δίνεις έναν "εφαρμοστή" που ξέρει να
// μετατρέπει το FetchResult σε nft sets. Στο main θα του περάσουμε δικό σου.
type Applier interface {
	ApplyFeed(ctx context.Context, f Feed, res *FetchResult) error
}

type Pruner interface {
	PruneExternalFeeds(active []string) error
}

// ApplierFunc: βοηθητικό για να περάσεις σκέτη συνάρτηση ως Applier.
type ApplierFunc func(ctx context.Context, f Feed, res *FetchResult) error

func (fn ApplierFunc) ApplyFeed(ctx context.Context, f Feed, res *FetchResult) error {
	return fn(ctx, f, res)
}

type Manager struct {
	mu      sync.Mutex
	client  *http.Client
	applier Applier
	auth    APIAuth // cfm-web credential for feeds on the API_URL origin; guarded by mu

	feeds map[string]Feed
	runs  map[string]*runner

	ctx    context.Context
	cancel context.CancelFunc
	wg     sync.WaitGroup
}

// Τρέχει ανά feed σε δικό του goroutine
type runner struct {
	feed      Feed
	cancel    context.CancelFunc
	lastFetch time.Time
	lastErr   error
	lastV4    int
	lastV6    int
	interval  time.Duration

	// Wire view of the last fetch, for Status (so an operator can see a
	// cfm-web feed pull succeeding WITH a token). Written by the fetch
	// goroutine under Manager.mu, like lastFetch/lastErr are read.
	lastOK    time.Time
	lastHTTP  int
	tokenSent bool
	// tokenRejected: cfm-web refused the token on the last fetch (the body
	// says why); the fetch was retried without it.
	tokenRejected string
	lastAppliedAt time.Time // lastApply mirrored under mu for Status (lastApply itself is lock-free)

	// lastHash is the sha256 of the last content we successfully applied for this
	// feed; haveHash guards the first fetch. lastApply is when that apply
	// happened, used to force a periodic re-apply even when content is unchanged
	// (see feedResyncInterval). All three are accessed only from the feed's
	// single fetch goroutine (see fetchOnce), so no locking is needed — do NOT
	// read them from Status() or any other goroutine without adding
	// synchronization, as the fetch goroutine writes them lock-free.
	lastHash  [32]byte
	haveHash  bool
	lastApply time.Time
}

// feedResyncInterval bounds how long the content-hash skip may suppress a
// re-apply. Even when a feed's content is unchanged, we re-apply at least this
// often so the per-feed sets and global unions self-heal if anything cleared
// them out of band (e.g. an operator `cfm reset` without a daemon restart).
// Feed intervals are ≥ 1h (ParseConfig rejects anything shorter), so this is at
// most ~6 polls: it keeps the old per-tick re-apply's healing property within a
// bounded window while still skipping the vast majority of redundant applies for
// a frequently-polled feed. The check is consulted only at fetch time, so the
// skip only benefits feeds polled more often than this; a feed whose interval
// already exceeds feedResyncInterval re-applies on every poll (no skip), and its
// heal window is one interval.
//
// NOTE: a same-named feed whose URL/TTL is edited in place is a pre-existing
// limitation — startOneLocked keeps the running runner (and its captured Feed)
// until the daemon restarts. That is unchanged by (and out of scope for) the
// content-hash skip: the old source was already the one being applied, so the
// skip does not alter which content is enforced. Restarting a runner safely on
// an in-place edit needs to wait out the old goroutine's in-flight ApplyFeed
// (which ignores ctx), so it belongs in its own change.
const feedResyncInterval = 6 * time.Hour

func NewManager(applier Applier) *Manager {
	return &Manager{
		client:  &http.Client{Timeout: 30 * time.Second},
		applier: applier,
		feeds:   map[string]Feed{},
		runs:    map[string]*runner{},
	}
}

// SetAPIAuth installs (or, on a config reload, replaces) the cfm-web
// credential. It applies from each feed's next fetch.
func (m *Manager) SetAPIAuth(baseURL, token string) {
	m.mu.Lock()
	m.auth = APIAuth{BaseURL: baseURL, Token: token}
	m.mu.Unlock()
}

func (m *Manager) Start(ctx context.Context) {
	m.mu.Lock()
	defer m.mu.Unlock()
	if m.ctx != nil {
		return
	}
	m.ctx, m.cancel = context.WithCancel(ctx)
	// ξεκίνα όσα feeds υπάρχουν ήδη (αν είχε προηγηθεί Reload)
	for name := range m.feeds {
		m.startOneLocked(name)
	}
}

func (m *Manager) Stop() {
	m.mu.Lock()
	if m.cancel != nil {
		m.cancel()
	}
	for _, r := range m.runs {
		if r.cancel != nil {
			r.cancel()
		}
	}
	m.mu.Unlock()
	m.wg.Wait()
}

func (m *Manager) Reload(feeds []Feed) {
	m.mu.Lock()
	defer m.mu.Unlock()

	next := map[string]Feed{}
	for _, f := range feeds {
		next[f.Name] = f
	}

	// stop removed runners
	for name := range m.runs {
		if _, ok := next[name]; !ok {
			m.stopOneLocked(name)
		}
	}
	m.feeds = next

	// (Re)start
	for name := range m.feeds {
		m.startOneLocked(name)
	}

	// NEW: ask applier to prune stale per-feed sets
	if pr, ok := m.applier.(Pruner); ok {
		var active []string
		for name := range m.feeds {
			active = append(active, name)
		}
		_ = pr.PruneExternalFeeds(active)
	}
}

func (m *Manager) startOneLocked(name string) {
	f, ok := m.feeds[name]
	if !ok {
		return
	}
	// ήδη τρέχει;
	if _, ok := m.runs[name]; ok {
		return
	}
	// αν ο Manager δεν έχει ξεκινήσει ακόμη, θα ξεκινήσει στο Start
	if m.ctx == nil {
		return
	}

	iv := f.Interval
	if iv <= 0 {
		iv = time.Hour // default, αν δεν ορίστηκε
	}

	ctx, cancel := context.WithCancel(m.ctx)
	r := &runner{feed: f, cancel: cancel, interval: iv}
	m.runs[name] = r

	m.wg.Add(1)
	go func() {
		defer m.wg.Done()
		// Immediate fetch στην αρχή
		m.fetchOnce(ctx, r)

		t := time.NewTicker(r.interval)
		defer t.Stop()
		for {
			select {
			case <-ctx.Done():
				return
			case <-t.C:
				m.fetchOnce(ctx, r)
			}
		}
	}()
}

func (m *Manager) stopOneLocked(name string) {
	r, ok := m.runs[name]
	if !ok {
		return
	}
	if r.cancel != nil {
		r.cancel()
	}
	delete(m.runs, name)
}

func (m *Manager) fetchOnce(ctx context.Context, r *runner) {
	m.mu.Lock()
	auth := m.auth
	m.mu.Unlock()
	res, meta, err := fetchAndParse(ctx, m.client, r.feed, auth)
	// A refused token must not stop the lists while cfm-web still allows its
	// IP-only fallback for feeds: retry once without it, and report the
	// refusal (token_rejected) so the credential gets fixed before cfm-web
	// turns the fallback off. The header path never falls back to the IP.
	var tokenRejected string
	if err != nil && meta.TokenSent && (meta.HTTPStatus == http.StatusUnauthorized || meta.HTTPStatus == http.StatusForbidden) {
		tokenRejected = redactErr(err, r.feed.URL).Error()
		res, meta, err = fetchAndParse(ctx, m.client, r.feed, APIAuth{})
		if err != nil {
			err = fmt.Errorf("retried without token: %w", err)
		}
	}
	err = redactErr(err, r.feed.URL)
	m.mu.Lock()
	r.lastFetch = time.Now()
	r.lastErr = err
	r.tokenRejected = tokenRejected
	r.lastHTTP, r.tokenSent = meta.HTTPStatus, meta.TokenSent
	if err == nil && res != nil {
		r.lastOK = r.lastFetch
		r.lastV4, r.lastV6 = len(res.V4), len(res.V6)
	}
	m.mu.Unlock()
	if err != nil || res == nil {
		return
	}

	// Skip the (potentially very large) re-apply when the fetched content is
	// identical to what we last applied for this feed. A feed is re-fetched on
	// its interval but usually changes far less often; without this, every tick
	// flushed the per-feed set and re-added all elements (and rebuilt the global
	// unions) even when nothing changed — tens of thousands of nft element adds
	// per hour for a large list. It is safe to skip because enforcement is via
	// the permanent union sets (rebuilt from in-memory caches), which stay
	// correct while the content is unchanged; there is no per-element TTL to
	// refresh at the union layer. The hash is computed every poll — on a skip it
	// confirms the content is identical, and on an apply it becomes the new
	// baseline — so its cost (one sort + sha256) is not wasted on the apply path.
	h := hashResult(res)
	if r.haveHash && h == r.lastHash && time.Since(r.lastApply) < feedResyncInterval {
		return
	}

	if err := m.applier.ApplyFeed(ctx, r.feed, res); err != nil {
		m.mu.Lock()
		r.lastErr = fmt.Errorf("apply feed %q: %w", r.feed.Name, err)
		m.mu.Unlock()
		return
	}
	r.lastHash, r.haveHash = h, true
	r.lastApply = time.Now() // start the resync clock at apply completion
	m.mu.Lock()
	r.lastAppliedAt = r.lastApply
	r.lastErr = nil
	m.mu.Unlock()
}

// hashResult returns a content hash of a fetched feed that is independent of the
// order in which the source lists its entries, so a feed that reshuffles its
// lines but keeps the same set still hashes equal (and is skipped). It hashes
// copies, never mutating the caller's slices.
func hashResult(res *FetchResult) [32]byte {
	v4 := append([]string(nil), res.V4...)
	v6 := append([]string(nil), res.V6...)
	sort.Strings(v4)
	sort.Strings(v6)
	h := sha256.New()
	for _, s := range v4 {
		_, _ = h.Write([]byte(s))
		_, _ = h.Write([]byte{'\n'})
	}
	_, _ = h.Write([]byte{0}) // separator so v4/v6 boundary can't be shifted
	for _, s := range v6 {
		_, _ = h.Write([]byte(s))
		_, _ = h.Write([]byte{'\n'})
	}
	var out [32]byte
	copy(out[:], h.Sum(nil))
	return out
}

// FeedStatus is one feed's runtime state, served by GET /api/v1/firewall/feeds
// (MCP `blocklist_feeds`). URL has its query and userinfo removed: a feed URL
// may carry an API key (?key=…) and this view is not a secrets view.
type FeedStatus struct {
	Name      string        `json:"name"`
	Type      string        `json:"type"`
	URL       string        `json:"url"`
	Interval  time.Duration `json:"interval"`
	LastFetch time.Time     `json:"last_fetch"`
	LastOK    time.Time     `json:"last_ok,omitempty"`
	LastApply time.Time     `json:"last_apply,omitempty"`
	LastHTTP  int           `json:"last_http,omitempty"`
	LastErr   string        `json:"last_error,omitempty"`
	LastV4    int           `json:"last_v4"`
	LastV6    int           `json:"last_v6"`
	// APIOrigin: the feed is on the cfm.conf API_URL origin, so it is pulled
	// with AUTH_TOKEN. TokenSent: the last fetch actually carried it.
	APIOrigin bool `json:"api_origin"`
	TokenSent bool `json:"token_sent"`
	// TokenRejected: cfm-web refused AUTH_TOKEN on the last fetch (its reason,
	// e.g. "Invalid token" / "IP address mismatch"); the list was then pulled
	// without it through cfm-web's IP-only fallback, which will stop working.
	TokenRejected string `json:"token_rejected,omitempty"`
}

// Status returns every running feed, sorted by name.
func (m *Manager) Status() []FeedStatus {
	m.mu.Lock()
	defer m.mu.Unlock()
	out := make([]FeedStatus, 0, len(m.runs))
	for name, r := range m.runs {
		fs := FeedStatus{
			Name:          name,
			Type:          r.feed.Type.String(),
			URL:           redactURL(r.feed.URL),
			Interval:      r.interval,
			LastFetch:     r.lastFetch,
			LastOK:        r.lastOK,
			LastApply:     r.lastAppliedAt,
			LastHTTP:      r.lastHTTP,
			LastV4:        r.lastV4,
			LastV6:        r.lastV6,
			TokenSent:     r.tokenSent,
			TokenRejected: r.tokenRejected,
		}
		if u, err := url.Parse(r.feed.URL); err == nil {
			fs.APIOrigin = m.auth.tokenFor(u) != ""
		}
		if r.lastErr != nil {
			fs.LastErr = r.lastErr.Error()
		}
		out = append(out, fs)
	}
	sort.Slice(out, func(i, j int) bool { return out[i].Name < out[j].Name })
	return out
}

// APIHost is the API_URL host the token is scoped to ("" when unset).
func (m *Manager) APIHost() string {
	m.mu.Lock()
	defer m.mu.Unlock()
	if m.auth.Token == "" {
		return ""
	}
	return m.auth.host()
}

func redactURL(raw string) string {
	u, err := url.Parse(raw)
	if err != nil {
		return "(unparseable)"
	}
	u.User = nil
	if u.RawQuery != "" {
		u.RawQuery = "REDACTED"
	}
	u.Fragment = ""
	return u.String()
}

// redactErr keeps a feed's query/userinfo out of the stored error: net/http's
// *url.Error embeds the request URL (password stripped, query and username
// kept), and Status serves that error over the API and MCP.
func redactErr(err error, feedURL string) error {
	if err == nil {
		return nil
	}
	var ue *url.Error
	if errors.As(err, &ue) {
		ue.URL = redactURL(ue.URL)
	}
	msg := err.Error()
	if feedURL != "" {
		msg = strings.ReplaceAll(msg, feedURL, redactURL(feedURL))
	}
	// Any other URL in the text (a malformed redirect Location, …).
	msg = queryInText.ReplaceAllString(msg, "?REDACTED")
	return errors.New(msg)
}

var queryInText = regexp.MustCompile(`\?[^\s"'?]+`)

// The daemon's running manager, for the read-only status endpoint (the
// apiserver has no other handle on it). nil until the daemon registers one.
var (
	activeMu sync.Mutex
	active   *Manager
)

// SetActive registers the daemon's manager for ActiveManager.
func SetActive(m *Manager) {
	activeMu.Lock()
	active = m
	activeMu.Unlock()
}

// ActiveManager returns the registered manager, or nil.
func ActiveManager() *Manager {
	activeMu.Lock()
	defer activeMu.Unlock()
	return active
}

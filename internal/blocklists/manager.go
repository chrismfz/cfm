package blocklists

import (
	"context"
	"net/http"
	"sync"
	"time"
)

// Applier: ο manager δεν ξέρει nft. Του δίνεις έναν "εφαρμοστή" που ξέρει να
// μετατρέπει το FetchResult σε nft sets. Στο main θα του περάσουμε δικό σου.
type Applier interface {
	ApplyFeed(ctx context.Context, f Feed, res *FetchResult) error
}

// ApplierFunc: βοηθητικό για να περάσεις σκέτη συνάρτηση ως Applier.
type ApplierFunc func(ctx context.Context, f Feed, res *FetchResult) error
func (fn ApplierFunc) ApplyFeed(ctx context.Context, f Feed, res *FetchResult) error { return fn(ctx, f, res) }

type Manager struct {
	mu      sync.Mutex
	client  *http.Client
	applier Applier

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
}

func NewManager(applier Applier) *Manager {
	return &Manager{
		client:  &http.Client{Timeout: 30 * time.Second},
		applier: applier,
		feeds:   map[string]Feed{},
		runs:    map[string]*runner{},
	}
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

	// Index νέων feeds
	next := map[string]Feed{}
	for _, f := range feeds {
		next[f.Name] = f
	}

	// Σταμάτα όσα αφαιρέθηκαν
	for name := range m.runs {
		if _, ok := next[name]; !ok {
			m.stopOneLocked(name)
		}
	}

	// Ενημέρωσε τρέχον set feeds
	m.feeds = next

	// (Re)start όσα πρέπει
	for name := range m.feeds {
		m.startOneLocked(name)
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
	// Χρησιμοποιούμε τη δική σου ρουτίνα: FetchAndParse(ctx, client, Feed)
	res, err := FetchAndParse(ctx, m.client, r.feed)
	r.lastFetch = time.Now()
	r.lastErr = err
	if err != nil || res == nil {
		return
	}
	r.lastV4, r.lastV6 = len(res.V4), len(res.V6)
	_ = m.applier.ApplyFeed(ctx, r.feed, res) // best-effort: log errors εκεί που την υλοποιείς
}

// Προαιρετικό: για μελλοντικό `cfm status` να δείχνει κατάσταση feeds
type FeedStatus struct {
	Name      string        `json:"name"`
	Interval  time.Duration `json:"interval"`
	LastFetch time.Time     `json:"last_fetch"`
	LastErr   string        `json:"last_error,omitempty"`
	LastV4    int           `json:"last_v4"`
	LastV6    int           `json:"last_v6"`
}

func (m *Manager) Status() []FeedStatus {
	m.mu.Lock()
	defer m.mu.Unlock()
	var out []FeedStatus
	for name, r := range m.runs {
		fs := FeedStatus{
			Name:      name,
			Interval:  r.interval,
			LastFetch: r.lastFetch,
			LastV4:    r.lastV4,
			LastV6:    r.lastV6,
		}
		if r.lastErr != nil {
			fs.LastErr = r.lastErr.Error()
		}
		out = append(out, fs)
	}
	return out
}

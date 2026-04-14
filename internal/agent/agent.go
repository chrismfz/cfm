package agent

import (
	//	"bytes"
	"context"
	"crypto/tls"
	"net/http"
	"strings"
	"sync"
	"sync/atomic"
	"time"

	"cfm/internal/dnat"
	"cfm/internal/firewall"
	"cfm/internal/logging"
	"net"
)

type Config struct {
	BaseURL     string
	Token       string
	Version     string
	UserAgent   string
	Interval    time.Duration
	TLSInsecure bool
}

type Runner struct {
	client  *http.Client
	cfg     atomic.Value // holds Config
	stop    chan struct{}
	wg      sync.WaitGroup
	once    sync.Once
	backend firewall.Backend
	cfgDir  string
}

func New(cfg Config) *Runner {
	r := &Runner{
		client: &http.Client{
			Timeout: 15 * time.Second,
			Transport: &http.Transport{
				TLSClientConfig: &tls.Config{InsecureSkipVerify: cfg.TLSInsecure},
			},
		},
		stop: make(chan struct{}),
	}
	r.cfg.Store(normalize(cfg))
	return r
}

func (r *Runner) Start() { r.once.Do(func() { r.wg.Add(1); go r.loop() }) }
func (r *Runner) Stop() {
	select {
	case <-r.stop:
	default:
		close(r.stop)
	}
	r.wg.Wait()
}
func (r *Runner) Update(cfg Config) { r.cfg.Store(normalize(cfg)) }

// Setters so main can wire dependencies without exporting fields
func (r *Runner) SetBackend(b firewall.Backend) { r.backend = b }
func (r *Runner) SetConfigDir(dir string)       { r.cfgDir = dir }

var unblockMu sync.Mutex

func (r *Runner) fetchPendingUnblocks(ctx context.Context) {
	if !unblockMu.TryLock() {
		logging.LogfAPI("[unblock] previous run still in progress, skipping tick")
		return
	}
	defer unblockMu.Unlock()

	cfg := r.cur()
	if cfg.BaseURL == "" || cfg.Token == "" {
		return
	}

	api := &APIClient{BaseURL: cfg.BaseURL, Token: cfg.Token, HTTP: r.client}
	reqs, err := api.FetchPendingUnblocks()
	if err != nil {
		logging.LogfAPI("[unblock] fetch pending failed: %v", err)
		return
	}
	if len(reqs) == 0 {
		return
	}

	// batch-remove all IPs from nft in ONE process call
	ips := make([]net.IP, 0, len(reqs))
	for _, it := range reqs {
		if ip := net.ParseIP(it.IP); ip != nil {
			ips = append(ips, ip)
		}
	}
	if be, ok := r.backend.(interface{ RemoveBlockBatch([]net.IP) error }); ok {
		if err := be.RemoveBlockBatch(ips); err != nil {
			logging.LogfAPI("[unblock] batch nft remove error: %v", err)
		}
	}

	// confirm each sequentially (API calls, not nft)
	for _, it := range reqs {
		logging.LogfAPI("[unblock] pending ip=%s (id=%d) — processing", it.IP, it.ID)
		api.ProcessUnblockRequest(ctx, r.backend, r.cfgDir, it.ID, it.IP)
	}
}

func (r *Runner) loop() {
	defer r.wg.Done()
	t := time.NewTicker(r.cur().Interval)
	defer t.Stop()

	// fire immediately
	r.doHeartbeat(context.Background())

	for {
		select {
		case <-r.stop:
			return
		case <-t.C:
			r.doHeartbeat(context.Background())
			r.fetchPendingUnblocks(context.Background())
			r.syncConfigs(context.Background())

		}
		// (αν χρειαστεί dynamic interval, μπορούμε να αναδημιουργήσουμε ticker)
	}
}

func (r *Runner) cur() Config { return r.cfg.Load().(Config) }

func normalize(c Config) Config {
	if c.Interval <= 0 {
		c.Interval = 30 * time.Second
	}
	if c.UserAgent == "" {
		c.UserAgent = "cfm"
	}
	if c.BaseURL != "" && !strings.HasPrefix(c.BaseURL, "http://") && !strings.HasPrefix(c.BaseURL, "https://") {
		c.BaseURL = "https://" + c.BaseURL
	}
	return c
}

func (r *Runner) doHeartbeat(ctx context.Context) {
	cfg := r.cur()
	if cfg.BaseURL == "" || cfg.Token == "" {
		return
	}

	api := &APIClient{
		BaseURL: cfg.BaseURL,
		Token:   cfg.Token,
		HTTP:    r.client,
	}

	var dnatEnabled *bool
	if r.backend != nil {
		on, err := dnat.Status(r.backend)
		if err != nil {
			logging.LogfAPI("[agent] heartbeat dnat status check failed: %v", err)
		} else {
			dnatEnabled = &on
		}
	}

	if err := api.SendHeartbeat(ctx, cfg.Version, cfg.UserAgent, dnatEnabled); err != nil {
		logging.LogfAPI("[agent] heartbeat failed: %v", err)
	}
}

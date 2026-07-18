package agent

import (
	//	"bytes"
	"context"
	"crypto/tls"
	"net/http"
	"net/url"
	"reflect"
	"strings"
	"sync"
	"sync/atomic"
	"time"

	"cfm/internal/dnat"
	"cfm/internal/firewall"
	"cfm/internal/locate"
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
	client             *http.Client
	cfg                atomic.Value // holds Config
	stop               chan struct{}
	wg                 sync.WaitGroup
	once               sync.Once
	backend            firewall.Backend
	cfgDir             string
	heartbeatSuccesses uint64
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

	// Where-&-why search BEFORE any removal, so the nft state is still
	// intact when we capture it. Results ride back on unblock-confirm.
	found := make(map[int]*locate.Result, len(reqs))
	for _, it := range reqs {
		lctx, lcancel := context.WithTimeout(ctx, 15*time.Second)
		res, lerr := locate.Find(lctx, it.IP, locate.Options{BE: r.backend, ConfigDir: r.cfgDir})
		lcancel()
		if lerr != nil {
			logging.LogfAPI("[unblock] locate failed ip=%s: %v", it.IP, lerr)
			continue
		}
		found[it.ID] = res
		for _, l := range res.Locations {
			logging.LogfAPI("[unblock.found] ip=%s source=%s list=%s action=%s match=%s reason=%q",
				it.IP, l.Source, l.List, l.Action, l.Match, l.Reason)
		}
	}

	// batch-remove all IPs from nft in ONE process call
	ips := make([]net.IP, 0, len(reqs))
	for _, it := range reqs {
		if ip := net.ParseIP(it.IP); ip != nil {
			ips = append(ips, ip)
		}
	}
	if be, ok := r.backend.(interface{ RemoveBlockBatch([]net.IP) error }); ok {
		engine := "unknown"
		if m, ok := r.backend.(interface{ Engine() string }); ok {
			engine = m.Engine()
		}
		backendType := "<nil>"
		if t := reflect.TypeOf(r.backend); t != nil {
			backendType = t.String()
		}
		removeMethod := "RemoveBlockBatch"
		removeStart := time.Now()
		logging.LogfAPI("[unblock.exec] engine=%s backend_type=%s batch_size=%d method=%s", engine, backendType, len(ips), removeMethod)
		if err := be.RemoveBlockBatch(ips); err != nil {
			logging.LogfAPI("[unblock] batch nft remove error: %v", err)
		}
		logging.LogfAPI("[unblock.exec.done] engine=%s backend_type=%s batch_size=%d method=%s duration=%s", engine, backendType, len(ips), removeMethod, time.Since(removeStart))
	}

	// confirm each sequentially (API calls, not nft)
	for _, it := range reqs {
		logging.LogfAPI("[unblock] pending ip=%s (id=%d) — processing", it.IP, it.ID)
		api.ProcessUnblockRequest(ctx, r.backend, r.cfgDir, it.ID, it.IP, found[it.ID])
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

	var hb HeartbeatRequest
	if r.backend != nil {
		on, err := dnat.Status(r.backend)
		if err != nil {
			logging.LogfAPI("[agent] heartbeat dnat status check failed: %v", err)
		} else {
			hb.DNATEnabled = &on
		}
	}
	if edge, edgeVer, ok := detectEdge(ctx); ok {
		hb.Edge = &edge
		hb.EdgeVersion = &edgeVer
	}
	hb.Vitals = collectVitals()

	heartbeatHost := hostForLog(cfg.BaseURL)
	if logging.DebugEnabled() {
		logging.LogfAPI("[agent] heartbeat attempt host=%s", heartbeatHost)
	}

	statusCode, duration, err := api.SendHeartbeat(ctx, cfg.Version, cfg.UserAgent, hb)
	if err != nil {
		logging.LogfAPI("[agent] heartbeat failed: %v", err)
		return
	}

	successes := atomic.AddUint64(&r.heartbeatSuccesses, 1)
	const heartbeatSuccessLogEvery = uint64(20)
	if logging.DebugEnabled() || successes%heartbeatSuccessLogEvery == 0 {
		logging.LogfAPI("[agent] heartbeat ok host=%s status=%d duration=%s successes=%d", heartbeatHost, statusCode, duration, successes)
	}
}

func hostForLog(baseURL string) string {
	u, err := url.Parse(baseURL)
	if err != nil || u.Host == "" {
		return baseURL
	}
	return u.Host
}

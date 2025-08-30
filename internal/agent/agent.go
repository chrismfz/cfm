package agent

import (
	"bytes"
	"context"
	"crypto/tls"
	"net/http"
	"strings"
	"sync"
	"sync/atomic"
	"time"
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
	client *http.Client
	cfg    atomic.Value // holds Config
	stop   chan struct{}
	wg     sync.WaitGroup
	once   sync.Once
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
func (r *Runner) Stop()  { select { case <-r.stop: default: close(r.stop) }; r.wg.Wait() }
func (r *Runner) Update(cfg Config) { r.cfg.Store(normalize(cfg)) }

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
			// μελλοντικά: r.pollExecutions(), r.fetchPendingUnblocks(), r.syncConfigs()...
		}
		// (αν χρειαστεί dynamic interval, μπορούμε να αναδημιουργήσουμε ticker)
	}
}

func (r *Runner) doHeartbeat(ctx context.Context) {
	cfg := r.cur()
	if cfg.BaseURL == "" || cfg.Token == "" { return }
	url := cfg.BaseURL + "/api/agent/heartbeat"
	req, _ := http.NewRequestWithContext(ctx, "POST", url, bytes.NewReader(nil))
	req.Header.Set("Token", cfg.Token)
	req.Header.Set("Accept", "application/json")
	req.Header.Set("Content-Type", "application/json")
	req.Header.Set("X-Agent-Version", cfg.Version)
	if cfg.UserAgent != "" {
		req.Header.Set("agent", cfg.UserAgent)
		req.Header.Set("version", cfg.Version)
	}
	resp, err := r.client.Do(req)
	if err != nil { return }
	_ = resp.Body.Close()
}

func (r *Runner) cur() Config { return r.cfg.Load().(Config) }

func normalize(c Config) Config {
	if c.Interval <= 0 { c.Interval = 30 * time.Second }
	if c.UserAgent == "" { c.UserAgent = "cfm" }
	if c.BaseURL != "" && !strings.HasPrefix(c.BaseURL, "http://") && !strings.HasPrefix(c.BaseURL, "https://") {
		c.BaseURL = "https://" + c.BaseURL
	}
	return c
}

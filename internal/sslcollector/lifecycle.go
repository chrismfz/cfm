package sslcollector

import (
	"context"
	"fmt"
	"time"

	cfgpkg "cfm/internal/config"
	"cfm/internal/logging"
)

// SockLifecycle owns the start/stop/restart state of the SSLCollector
// unix socket server. Create once with NewSockLifecycle (passing the shared
// Collector), then call ApplyConfig on every daemon tick after config is
// parsed. It is a no-op when nothing relevant has changed.
type SockLifecycle struct {
	col    *Collector
	cancel context.CancelFunc
	cfgKey string
}

// NewSockLifecycle returns a ready-to-use SockLifecycle.
// col is the shared Collector instance created once at daemon startup.
func NewSockLifecycle(col *Collector) *SockLifecycle {
	return &SockLifecycle{col: col}
}

// ApplyConfig starts, stops, or restarts the socket server based on cfg.
// Safe to call on every tick — it only acts when something relevant changed.
func (l *SockLifecycle) ApplyConfig(ctx context.Context, cfg *cfgpkg.SSLCollectorSockConfig) {
	// apply defaults
	sp := cfg.SockPath
	if sp == "" {
		sp = "/var/run/sslcollector.sock"
	}
	ttl := cfg.PEMTTL
	if ttl <= 0 {
		ttl = 10 * time.Minute
	}
	max := cfg.PEMMax
	if max <= 0 {
		max = 50000
	}

	key := fmt.Sprintf("%t|%s|%s|%s|%d", cfg.Enabled, sp, cfg.Token, ttl, max)

	if !cfg.Enabled {
		if l.cancel != nil {
			l.cancel()
			l.cancel = nil
			l.cfgKey = ""
			logging.Logf("[sslcollector] sock server stopped (disabled)")
		}
		return
	}

	// no change — already running with same config
	if key == l.cfgKey && l.cancel != nil {
		return
	}

	// restart if config changed while running
	if l.cancel != nil {
		l.cancel()
		l.cancel = nil
	}

	c, cancel := context.WithCancel(ctx)
	l.cancel = cancel
	l.cfgKey = key

	go func(sockPath string) {
		err := ServeSock(c, l.col, SockServerConfig{
			Enabled:  true,
			SockPath: sockPath,
			Token:    cfg.Token,
			PEMTTL:   ttl,
			PEMMax:   max,
		})
		if err != nil && c.Err() == nil {
			logging.Logf("[sslcollector] sock server stopped: %v", err)
		}
	}(sp)

	logging.Logf("[sslcollector] sock server enabled path=%s ttl=%s max=%d", sp, ttl, max)
}

// Stop cleanly shuts down the socket server. Call on daemon exit.
func (l *SockLifecycle) Stop() {
	if l.cancel != nil {
		l.cancel()
		l.cancel = nil
	}
}

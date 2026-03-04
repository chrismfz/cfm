package vhostmap

import (
	"context"
	"fmt"
	"time"

	cfgpkg "cfm/internal/config"
	"cfm/internal/logging"
)

// Lifecycle owns the start/stop/restart state of the VHostMap runner.
// Create once with NewLifecycle, then call ApplyConfig on every daemon tick
// after config is parsed. It restarts automatically when config changes.
type Lifecycle struct {
	cancel context.CancelFunc
	cfgKey string // detects changes that require a restart
}

// NewLifecycle returns a ready-to-use Lifecycle.
func NewLifecycle() *Lifecycle {
	return &Lifecycle{}
}

// ApplyConfig starts, stops, or restarts the runner based on cfg.
// Safe to call on every tick — it only acts when something relevant changed.
func (l *Lifecycle) ApplyConfig(ctx context.Context, cfg *cfgpkg.VHostMapConfig) {
	// apply defaults
	if cfg.TTL <= 0 {
		cfg.TTL = 10 * time.Minute
	}
	if cfg.VarName == "" {
		cfg.VarName = "origin_http_ip"
	}
	if cfg.ReloadCmd == "" {
		cfg.ReloadCmd = "systemctl reload openresty"
	}

	key := fmt.Sprintf("%t|%s|%s|%s|%s|%s|%s",
		cfg.Enable, cfg.WritePath, cfg.TTL, cfg.VarName,
		cfg.Source, cfg.DefaultIP, cfg.ReloadCmd)

	if !cfg.Enable {
		if l.cancel != nil {
			l.cancel()
			l.cancel = nil
			l.cfgKey = ""
			logging.Logf("[vhostmap] stopped (disabled)")
		}
		return
	}

	if cfg.WritePath == "" {
		logging.Logf("[vhostmap] enabled but VHOST_MAP_WRITE is empty (skipping)")
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

	go func(cfg cfgpkg.VHostMapConfig) {
		_ = Run(c, Config{
			Enable:    true,
			WritePath: cfg.WritePath,
			TTL:       cfg.TTL,
			VarName:   cfg.VarName,
			Source:    cfg.Source,
			DefaultIP: cfg.DefaultIP,
			ReloadCmd: cfg.ReloadCmd,
		}, logAdapter{})
	}(*cfg)

	logging.Logf("[vhostmap] started write=%s ttl=%s var=%s",
		cfg.WritePath, cfg.TTL, cfg.VarName)
}

// Stop cleanly shuts down the runner. Call on daemon exit.
func (l *Lifecycle) Stop() {
	if l.cancel != nil {
		l.cancel()
		l.cancel = nil
	}
}

// logAdapter bridges vhostmap.Logger to cfm/internal/logging.
type logAdapter struct{}

func (logAdapter) Logf(f string, a ...any) { logging.Logf(f, a...) }

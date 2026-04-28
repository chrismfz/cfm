package outbound

import (
	"context"
	"math"
	"time"

	cfgpkg "cfm/internal/config"
	"cfm/internal/logging"
)

// Lifecycle owns the one-shot startup of the outbound NFLOG collector. Mirrors
// nflog.SnoopLifecycle: created once in main, ApplyConfig is invoked on every
// config-reload tick, and the first call where conditions are met spawns the
// reader. Subsequent calls are no-ops — phase 1 doesn't reload thresholds at
// runtime (that's a phase-2 concern that needs the analyzer to swap atomically).
type Lifecycle struct {
	started bool
	dnsdbg  *DNSDebugCapture
}

// NewLifecycle returns a fresh Lifecycle.
func NewLifecycle() *Lifecycle { return &Lifecycle{} }

// ApplyConfig starts the outbound collector if outbound is enabled, the NFLOG
// group is set, and the group is in range. Subsequent calls are no-ops.
func (l *Lifecycle) ApplyConfig(ctx context.Context, cfg *cfgpkg.OutboundConfig) {
	if l == nil || l.started {
		return
	}
	if cfg == nil || !cfg.Enabled || cfg.NFLOGGroup <= 0 {
		return
	}
	if cfg.NFLOGGroup > int(math.MaxUint16) {
		logging.Logf("[outbound] invalid NFLOG group %d (must be 1..65535) — skipping", cfg.NFLOGGroup)
		return
	}

	rt := buildRuntime(cfg)
	var dnsdbg *DNSDebugCapture
	if rt.DNSDebugEnabled {
		dnsdbg = NewDNSDebugCapture(rt)
		dnsdbg.Start(ctx)
	}
	cc := CollectorConfig{
		Group:   uint16(cfg.NFLOGGroup),
		Queue:   2048,
		Runtime: rt,
	}
	alerter := NewAlerter(rt, dnsdbg)

	l.started = true
	l.dnsdbg = dnsdbg
	go func() {
		if err := Start(ctx, cc, alerter); err != nil {
			logging.Logf("[outbound] nflog start error: %v", err)
			return
		}
		logging.Logf("[outbound] sentinel started (group=%d window=%s smtp/min=%d uniq_dst/min=%d http/min=%d dns/min=%d)",
			cc.Group, rt.Window, rt.SMTPPerWindow, rt.UniqueDstPerWindow, rt.HTTPPerWindow, rt.DNSPerWindow)
	}()
}

// buildRuntime resolves the persisted config into the analyzer-facing Runtime.
// Maps are cheap to allocate once and read-only thereafter.
func buildRuntime(cfg *cfgpkg.OutboundConfig) Runtime {
	rt := Runtime{
		Window:              time.Duration(cfg.WindowSec) * time.Second,
		SMTPPerWindow:       cfg.SMTPPerMin,
		UniqueDstPerWindow:  cfg.UniqueDstPerMin,
		HTTPPerWindow:       cfg.HTTPPerMin,
		DNSPerWindow:        cfg.DNSPerMin,
		DNSUniqDstMin:       cfg.DNSUniqDstMin,
		DNSSeverityMode:     cfg.DNSSeverityMode,
		DNSNXDOMAINRatio:    cfg.DNSNXRatioAlert,
		DedupCooldown:       time.Duration(cfg.LogDedupSec) * time.Second,
		QueueSampleLimit:    cfg.QueueSamples,
		NotifySeverity:      cfg.NotifySeverity,
		Enrich:              cfg.Enrich,
		SMTPPorts:           portSet(cfg.SMTPPorts),
		ScanPorts:           portSet(cfg.ScanPorts),
		HTTPPorts:           portSet(cfg.HTTPPorts),
		AllowUIDs:           uidSet(cfg.AllowUIDs),
		AllowGIDs:           uidSet(cfg.AllowGIDs),
		DNSDebugEnabled:     cfg.DNSDebugEnabled,
		DNSDebugSampleCount: cfg.DNSDebugSamples,
		DNSDebugDuration:    time.Duration(cfg.DNSDebugDurSec) * time.Second,
		DNSDebugDir:         cfg.DNSDebugDir,
	}
	if rt.Window <= 0 {
		rt.Window = 60 * time.Second
	}
	if rt.DedupCooldown <= 0 {
		rt.DedupCooldown = 5 * time.Minute
	}
	if rt.DNSDebugSampleCount <= 0 {
		rt.DNSDebugSampleCount = 100
	}
	if rt.DNSDebugDuration <= 0 {
		rt.DNSDebugDuration = 30 * time.Second
	}
	if rt.DNSDebugDir == "" {
		rt.DNSDebugDir = "/var/log/cfm/outbound"
	}
	return rt
}

func portSet(ports []uint16) map[uint16]struct{} {
	m := make(map[uint16]struct{}, len(ports))
	for _, p := range ports {
		if p == 0 {
			continue
		}
		m[p] = struct{}{}
	}
	return m
}

func uidSet(ids []uint32) map[uint32]struct{} {
	m := make(map[uint32]struct{}, len(ids))
	for _, id := range ids {
		m[id] = struct{}{}
	}
	return m
}

package nflog

import (
	"context"
	"math"

	cfgpkg "cfm/internal/config"
	"cfm/internal/logging"
)

// SnoopLifecycle owns the start-once lifecycle of the SMTP NFLOG snooper.
// Create once with NewSnoopLifecycle, then call ApplyConfig on every daemon
// tick. After the first successful start it becomes a no-op — the snooper
// runs until ctx is cancelled (daemon shutdown).
type SnoopLifecycle struct {
	started bool
}

// NewSnoopLifecycle returns a ready-to-use SnoopLifecycle.
func NewSnoopLifecycle() *SnoopLifecycle {
	return &SnoopLifecycle{}
}

// ApplyConfig starts the NFLOG snooper on the first call where conditions
// are met. Subsequent calls are no-ops.
//
// Conditions to start:
//   - SMTPBlock.Enabled
//   - SMTPBlock.LogEnabled
//   - SMTPBlock.LogNFLOG > 0  (NFLOG group number, not kernel log)
func (l *SnoopLifecycle) ApplyConfig(ctx context.Context, cfg *cfgpkg.SMTPBlockConfig) {
	if l.started {
		return
	}
	if !cfg.Enabled || !cfg.LogEnabled || cfg.LogNFLOG <= 0 {
		return
	}
	if cfg.LogNFLOG > int(math.MaxUint16) {
		logging.Logf("[smtpblock] invalid NFLOG group %d (must be 0..65535) — skipping snooper", cfg.LogNFLOG)
		return
	}

	l.started = true

	sc := FromConfig(cfg)
	sc.Queue = 1024

	go func() {
		if err := Start(ctx, sc); err != nil {
			logging.Logf("[smtpblock] nflog start error: %v", err)
		} else {
			logging.Logf("[smtpblock] nflog reader started (group=%d enrich=%v)", sc.Group, sc.Enrich)
		}
	}()
}

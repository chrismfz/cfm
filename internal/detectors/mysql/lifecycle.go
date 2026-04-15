package mysql

import (
	"context"

	"cfm/internal/logging"
)

// GovernorLifecycle owns the start-once lifecycle of the MySQL Governor.
//
// Unlike other lifecycle managers (e.g. MaxMind, SSLCollector) the
// governor is never restarted on config change — it shares the debug server
// mux which is also start-once. Call StartOnce on every daemon tick; after
// the first successful call it becomes a no-op and returns the same Governor.
//
// Config resolution (detectors.conf vs hardcoded defaults) is the caller's
// responsibility — this keeps the lifecycle free of import cycles between
// cfm/internal/detectors/mysql and cfm/internal/detectors.
type GovernorLifecycle struct {
	gov     *Governor
	started bool // true after first StartOnce call, even if gov is nil
}

// NewGovernorLifecycle returns a ready-to-use GovernorLifecycle.
func NewGovernorLifecycle() *GovernorLifecycle {
	return &GovernorLifecycle{}
}

// StartOnce creates and starts the governor on the first call.
// Subsequent calls are no-ops and return the same *Governor (may be nil if
// MySQL was unavailable on first attempt).
//
// Pass cfg=nil to use safe built-in defaults. Pass a *GovernorConfig from
// detectors.GetPendingGovernorConfig() when the operator has configured
// [mysql_governor] explicitly — those values override the defaults.
func (l *GovernorLifecycle) StartOnce(ctx context.Context, cfg *GovernorConfig) *Governor {
	if l.started {
		return l.gov
	}
	l.started = true

	// nil = caller has no config → use zero value; NewGovernor fills defaults.
	resolved := GovernorConfig{Enabled: true}
	if cfg != nil {
		resolved = *cfg
	}

	g, err := NewGovernor(resolved)
	if err != nil {
		// Non-fatal: MySQL may not be installed or credentials not yet set up.
		logging.Logf("[mysql/governor] disabled: %v", err)
		logging.LogfMYSQLGOVERNOR("[mysql/governor] disabled: %v", err)
		return nil
	}

	l.gov = g
	go g.Run(ctx)
	return g
}

// Governor returns the running *Governor, or nil if MySQL was unavailable.
// Safe to call before StartOnce — returns nil.
func (l *GovernorLifecycle) Governor() *Governor {
	return l.gov
}

package mysql

import (
	"context"
	"errors"
	"math"
	"net/http"
	"strconv"
	"sync/atomic"
	"time"

	"cfm/internal/logging"
)

// Retry pacing for a governor that is not running yet.
//
// Three cases, because the failures mean different things:
//   - no credentials anywhere (no DSN, /root/.my.cnf, governor cnf, DA conf):
//     most likely a node without a database. Each attempt only stats/reads a
//     few small files, never opens a socket, so a slow fixed poll lets a
//     database installed later be picked up at no real cost.
//   - [mysql_governor] ENABLED = 0: the operator opted out. No connection is
//     made; the same slow poll only re-reads the config, because a
//     detectors.conf edit applies without a restart and may re-enable it.
//   - credentials found but the connect/ping failed: the database is starting
//     (cfm.service has no ordering on mariadb/mysqld, on purpose: nodes without
//     a database must not wait on one), down, or the credentials are wrong.
//     Back off from retryMinDelay doubling to retryMaxDelay, so a DB that comes
//     up seconds after the daemon is caught almost at once, and a permanently
//     failing one costs one local connect every retryMaxDelay. A failed login
//     from localhost is ignored by the [mysql] detector (IGNORE_LOCALHOST,
//     default on), and the autoblock sink never blocks a loopback or self IP,
//     so wrong credentials never ban the node itself.
//
// database/sql reconnects on its own once a *sql.DB has worked, so this retry
// covers only the first connect; a running governor is never torn down (not by
// a later ENABLED = 0 either: that takes a daemon restart, as before).
const (
	retryMinDelay     = 5 * time.Second
	retryMaxDelay     = 5 * time.Minute
	retryNoCredsDelay = 5 * time.Minute
)

// errGovernorDisabled: [mysql_governor] ENABLED = 0.
var errGovernorDisabled = errors.New("disabled in detectors.conf ([mysql_governor] ENABLED = 0)")

// retryPacing is the pacing one lifecycle uses (the constants above; a test
// shrinks its own copy).
type retryPacing struct {
	min, max, noCreds time.Duration
}

// GovernorLifecycle owns the lifecycle of the MySQL Governor.
//
// Start is called once, from the start-once debug-server setup, and returns at
// once: a background goroutine connects (see the retry pacing above) until it
// succeeds or the daemon's context ends, so a database that answers slowly
// never holds up the API. The governor is never restarted on config change; an
// attempt uses the [mysql_governor] config current at that moment.
//
// The HTTP routes are served through AdminHandler/ScopedHandler, which exist
// from the start: while no governor runs they answer a JSON 503 instead of the
// path falling through to the web UI's catch-all (an HTML page the CLI then
// failed to parse as JSON: "invalid character '<'").
//
// Config resolution (detectors.conf vs hardcoded defaults) is the caller's
// responsibility — this keeps the lifecycle free of import cycles between
// cfm/internal/detectors/mysql and cfm/internal/detectors.
type GovernorLifecycle struct {
	gov       atomic.Pointer[Governor]
	status    atomic.Pointer[string] // why no governor runs yet; nil once started
	nextRetry atomic.Int64           // unix nanos of the next attempt; 0 = none scheduled
	started   atomic.Bool

	// newGovernor is NewGovernor; a seam for tests.
	newGovernor func(GovernorConfig) (*Governor, error)
	// run is (*Governor).Run; a seam for tests.
	run func(context.Context, *Governor)
	// pacing of the background retry.
	pacing retryPacing

	admin, scoped *lazyGovernorHandler
}

// NewGovernorLifecycle returns a ready-to-use GovernorLifecycle.
func NewGovernorLifecycle() *GovernorLifecycle {
	l := &GovernorLifecycle{
		newGovernor: NewGovernor,
		run:         func(ctx context.Context, g *Governor) { g.Run(ctx) },
		pacing:      retryPacing{min: retryMinDelay, max: retryMaxDelay, noCreds: retryNoCredsDelay},
	}
	l.admin = &lazyGovernorHandler{lc: l, register: (*Governor).RegisterHTTPAdmin, withReason: true}
	l.scoped = &lazyGovernorHandler{lc: l, register: (*Governor).RegisterHTTPScoped}
	s := "starting"
	l.status.Store(&s)
	return l
}

// Start begins connecting in the background and returns at once; it keeps
// trying until it succeeds or ctx ends. Only the first call does anything.
//
// cfg is called on every attempt: it returns the operator's [mysql_governor]
// config (detectors.GetPendingGovernorConfig; Enabled=false for ENABLED = 0),
// or nil for the built-in defaults. Use Governor() for the running governor.
func (l *GovernorLifecycle) Start(ctx context.Context, cfg func() *GovernorConfig) {
	if !l.started.CompareAndSwap(false, true) {
		return
	}
	go l.connectLoop(ctx, cfg)
}

func (l *GovernorLifecycle) attempt(ctx context.Context, cfg func() *GovernorConfig) error {
	resolved := GovernorConfig{Enabled: true} // nil = defaults; NewGovernor fills them
	if cfg != nil {
		if c := cfg(); c != nil {
			resolved = *c
		}
	}
	if !resolved.Enabled {
		return errGovernorDisabled
	}
	g, err := l.newGovernor(resolved)
	if err != nil {
		return err
	}
	l.gov.Store(g)
	l.status.Store(nil)
	l.nextRetry.Store(0)
	go l.run(ctx, g)
	return nil
}

func (l *GovernorLifecycle) connectLoop(ctx context.Context, cfg func() *GovernorConfig) {
	startedAt := time.Now()
	backoff := l.pacing.min
	lastClass := ""
	t := time.NewTimer(0)
	defer t.Stop()
	for attempts := 1; ; attempts++ {
		select {
		case <-ctx.Done():
			return
		case <-t.C:
		}
		if ctx.Err() != nil { // both ready: select picks at random
			return
		}
		err := l.attempt(ctx, cfg)
		if err == nil {
			if attempts > 1 {
				logging.Logf("[mysql/governor] started after %d attempts (%s)",
					attempts, time.Since(startedAt).Round(time.Second))
				logging.LogfMYSQLGOVERNOR("[mysql/governor] started after %d attempts (%s)",
					attempts, time.Since(startedAt).Round(time.Second))
			}
			return
		}
		l.setStatus(err)
		// One line per change of failure class, not per attempt and not per
		// change of wording (a driver timeout reads differently from one try
		// to the next): a node without a database would otherwise log every
		// five minutes forever.
		if c := failureClass(err); c != lastClass {
			if lastClass == "" {
				logging.Logf("[mysql/governor] not running yet: %v (retrying in the background)", err)
				logging.LogfMYSQLGOVERNOR("[mysql/governor] not running yet: %v (retrying in the background)", err)
			} else {
				logging.LogfMYSQLGOVERNOR("[mysql/governor] still not running: %v", err)
			}
			lastClass = c
		}
		d := l.pacing.next(err, &backoff)
		l.nextRetry.Store(time.Now().Add(d).UnixNano())
		t.Reset(d)
	}
}

// failureClass names why an attempt failed, stably across attempts: the
// error's wording can change while its cause does not.
func failureClass(err error) string {
	switch {
	case errors.Is(err, errNoCredentials):
		return "no-credentials"
	case errors.Is(err, errGovernorDisabled):
		return "disabled"
	}
	var ce *connectError
	if errors.As(err, &ce) {
		return "connect:" + ce.source
	}
	return "other"
}

// next returns how long to wait after err, advancing the connect backoff. A
// failure that made no connection (no credentials, disabled) resets the
// backoff: once a connect becomes possible, its first failure should be
// retried quickly again.
func (p retryPacing) next(err error, backoff *time.Duration) time.Duration {
	if errors.Is(err, errNoCredentials) || errors.Is(err, errGovernorDisabled) {
		*backoff = p.min
		return p.noCreds
	}
	d := *backoff
	*backoff = min(*backoff*2, p.max)
	return d
}

func (l *GovernorLifecycle) setStatus(err error) {
	s := err.Error()
	l.status.Store(&s)
}

// Governor returns the running *Governor, or nil while MySQL is unavailable.
// Safe to call before Start — returns nil.
func (l *GovernorLifecycle) Governor() *Governor {
	return l.gov.Load()
}

// Status returns why no governor runs, or "" once one does.
func (l *GovernorLifecycle) Status() string {
	if s := l.status.Load(); s != nil {
		return *s
	}
	return ""
}

// retryAfterSeconds returns the whole seconds until the next attempt, or 0
// when none is scheduled.
func (l *GovernorLifecycle) retryAfterSeconds() int {
	n := l.nextRetry.Load()
	if n == 0 {
		return 0
	}
	return max(1, int(math.Ceil(time.Until(time.Unix(0, n)).Seconds())))
}

// AdminHandler serves the admin-only governor routes (RegisterHTTPAdmin). The
// caller wraps it in its admin guard. While no governor runs it answers 503
// with the reason.
func (l *GovernorLifecycle) AdminHandler() http.Handler { return l.admin }

// ScopedHandler serves the user/db-filtered governor routes
// (RegisterHTTPScoped). The caller wraps it in its scope filter. While no
// governor runs it answers 503 without the reason: scoped (cPanel user)
// callers get no detail about the node's database credentials.
func (l *GovernorLifecycle) ScopedHandler() http.Handler { return l.scoped }

// lazyGovernorHandler dispatches to the governor's routes once it exists. The
// lifecycle stores a governor at most once and never replaces it, so the mux
// is built once.
type lazyGovernorHandler struct {
	lc         *GovernorLifecycle
	register   func(*Governor, *http.ServeMux)
	withReason bool

	mux atomic.Pointer[http.ServeMux]
}

func (h *lazyGovernorHandler) ServeHTTP(w http.ResponseWriter, r *http.Request) {
	if m := h.mux.Load(); m != nil {
		m.ServeHTTP(w, r)
		return
	}
	g := h.lc.Governor()
	if g == nil {
		body := map[string]string{"error": "mysql governor not running"}
		if h.withReason {
			body["reason"] = h.lc.Status()
		}
		if s := h.lc.retryAfterSeconds(); s > 0 {
			w.Header().Set("Retry-After", strconv.Itoa(s))
		}
		writeGovernorJSON(w, http.StatusServiceUnavailable, body)
		return
	}
	m := http.NewServeMux()
	h.register(g, m)
	if !h.mux.CompareAndSwap(nil, m) { // a concurrent first request built it
		m = h.mux.Load()
	}
	m.ServeHTTP(w, r)
}

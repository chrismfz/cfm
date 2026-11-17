package mysql

import (
	"context"
	"errors"
	"net/http"
	"sync"
	"sync/atomic"
	"time"

	"cfm/internal/logging"
)

// Retry pacing for a governor whose first connect failed.
//
// Two speeds, because the two failures mean different things:
//   - no credentials anywhere (no DSN, /root/.my.cnf, governor cnf, DA conf):
//     most likely a node without a database. Each attempt only stats/reads a
//     few small files, never opens a socket, so a slow fixed poll lets a
//     database installed later be picked up at no real cost.
//   - credentials found but the connect/ping failed: the database is starting
//     (cfm.service has no ordering on mariadb/mysqld, on purpose: nodes without
//     a database must not wait on one), down, or the credentials are wrong.
//     Back off from retryMinDelay doubling to retryMaxDelay, so a DB that comes
//     up seconds after the daemon is caught almost at once, and a permanently
//     failing one costs one local connect every retryMaxDelay. A failed login
//     from localhost is ignored by the [mysql] detector (IGNORE_LOCALHOST,
//     default on), so wrong credentials never ban the node itself.
//
// database/sql reconnects on its own once a *sql.DB has worked, so this retry
// covers only the first connect; a running governor is never torn down.
const (
	retryMinDelay     = 5 * time.Second
	retryMaxDelay     = 5 * time.Minute
	retryNoCredsDelay = 5 * time.Minute
)

// retryPacing is the pacing one lifecycle uses (the constants above; a test
// shrinks its own copy).
type retryPacing struct {
	min, max, noCreds time.Duration
}

// GovernorLifecycle owns the lifecycle of the MySQL Governor.
//
// Start is called once, from the start-once debug-server setup. If MySQL is
// reachable the governor starts synchronously; otherwise a background
// goroutine keeps trying (see the retry pacing above) until it connects or the
// daemon's context ends. The governor is never restarted on config change; a
// retry picks up the [mysql_governor] config current at that attempt.
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
	gov     atomic.Pointer[Governor]
	status  atomic.Pointer[string] // why no governor runs yet; nil once started
	started atomic.Bool

	// newGovernor is NewGovernor; a seam for tests.
	newGovernor func(GovernorConfig) (*Governor, error)
	// run is (*Governor).Run; a seam for tests.
	run func(context.Context, *Governor)
	// pacing of the background retry.
	pacing retryPacing

	adminOnce, scopedOnce sync.Once
	admin, scoped         *lazyGovernorHandler
}

// NewGovernorLifecycle returns a ready-to-use GovernorLifecycle.
func NewGovernorLifecycle() *GovernorLifecycle {
	l := &GovernorLifecycle{
		newGovernor: NewGovernor,
		run:         func(ctx context.Context, g *Governor) { g.Run(ctx) },
		pacing:      retryPacing{min: retryMinDelay, max: retryMaxDelay, noCreds: retryNoCredsDelay},
	}
	s := "not started"
	l.status.Store(&s)
	return l
}

// Start makes one connect attempt now and, if it fails, keeps retrying in the
// background until it succeeds or ctx ends. Only the first call does anything.
//
// cfg is called on every attempt: it returns the operator's [mysql_governor]
// config (detectors.GetPendingGovernorConfig), or nil for the built-in
// defaults. It returns the governor if the first attempt succeeded, else nil;
// use Governor() for the current one.
func (l *GovernorLifecycle) Start(ctx context.Context, cfg func() *GovernorConfig) *Governor {
	if !l.started.CompareAndSwap(false, true) {
		return l.gov.Load()
	}
	err := l.attempt(ctx, cfg)
	if err == nil {
		return l.gov.Load()
	}
	l.setStatus(err)
	logging.Logf("[mysql/governor] not running yet: %v (retrying in the background)", err)
	logging.LogfMYSQLGOVERNOR("[mysql/governor] not running yet: %v (retrying in the background)", err)
	go l.retry(ctx, cfg, err)
	return nil
}

func (l *GovernorLifecycle) attempt(ctx context.Context, cfg func() *GovernorConfig) error {
	resolved := GovernorConfig{Enabled: true} // nil = defaults; NewGovernor fills them
	if cfg != nil {
		if c := cfg(); c != nil {
			resolved = *c
		}
	}
	g, err := l.newGovernor(resolved)
	if err != nil {
		return err
	}
	l.gov.Store(g)
	l.status.Store(nil)
	go l.run(ctx, g)
	return nil
}

func (l *GovernorLifecycle) retry(ctx context.Context, cfg func() *GovernorConfig, lastErr error) {
	startedAt := time.Now()
	backoff := l.pacing.min
	attempts := 1
	t := time.NewTimer(l.pacing.next(lastErr, &backoff))
	defer t.Stop()
	for {
		select {
		case <-ctx.Done():
			return
		case <-t.C:
		}
		if ctx.Err() != nil { // both ready: select picks at random
			return
		}
		attempts++
		err := l.attempt(ctx, cfg)
		if err == nil {
			logging.Logf("[mysql/governor] started after %d attempts (%s after daemon start)",
				attempts, time.Since(startedAt).Round(time.Second))
			logging.LogfMYSQLGOVERNOR("[mysql/governor] started after %d attempts (%s after daemon start)",
				attempts, time.Since(startedAt).Round(time.Second))
			return
		}
		l.setStatus(err)
		// One line per change of reason, not per attempt: a node without a
		// database would otherwise log every five minutes forever.
		if err.Error() != lastErr.Error() {
			logging.LogfMYSQLGOVERNOR("[mysql/governor] still not running: %v", err)
		}
		lastErr = err
		t.Reset(l.pacing.next(err, &backoff))
	}
}

// next returns how long to wait after err, advancing the connect backoff. A
// no-credentials failure resets the backoff: when credentials appear, the
// first failed connect should be retried quickly again.
func (p retryPacing) next(err error, backoff *time.Duration) time.Duration {
	if errors.Is(err, errNoCredentials) {
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

// AdminHandler serves the admin-only governor routes (RegisterHTTPAdmin). The
// caller wraps it in its admin guard. While no governor runs it answers 503
// with the reason.
func (l *GovernorLifecycle) AdminHandler() http.Handler {
	l.adminOnce.Do(func() {
		l.admin = &lazyGovernorHandler{lc: l, register: (*Governor).RegisterHTTPAdmin, withReason: true}
	})
	return l.admin
}

// ScopedHandler serves the user/db-filtered governor routes
// (RegisterHTTPScoped). The caller wraps it in its scope filter. While no
// governor runs it answers 503 without the reason: scoped (cPanel user)
// callers get no detail about the node's database credentials.
func (l *GovernorLifecycle) ScopedHandler() http.Handler {
	l.scopedOnce.Do(func() {
		l.scoped = &lazyGovernorHandler{lc: l, register: (*Governor).RegisterHTTPScoped}
	})
	return l.scoped
}

// lazyGovernorHandler dispatches to the governor's routes once it exists.
type lazyGovernorHandler struct {
	lc         *GovernorLifecycle
	register   func(*Governor, *http.ServeMux)
	withReason bool

	mu     sync.Mutex
	forGov *Governor
	mux    *http.ServeMux
}

func (h *lazyGovernorHandler) ServeHTTP(w http.ResponseWriter, r *http.Request) {
	g := h.lc.Governor()
	if g == nil {
		body := map[string]string{"error": "mysql governor not running"}
		if h.withReason {
			body["reason"] = h.lc.Status()
		}
		w.Header().Set("Retry-After", "30")
		writeGovernorJSON(w, http.StatusServiceUnavailable, body)
		return
	}
	h.mu.Lock()
	if h.forGov != g {
		m := http.NewServeMux()
		h.register(g, m)
		h.forGov, h.mux = g, m
	}
	m := h.mux
	h.mu.Unlock()
	m.ServeHTTP(w, r)
}

package sslcollector

import (
	"context"
	"os"
	"os/exec"
	"strings"
	"sync"
	"time"

	"cfm/internal/logging"
)

// NudgeEdgeOnFirstReady runs once per cfm daemon lifetime. It waits for
// the sslcollector socket to be bound AND the daemon's cert index to
// have at least one entry; if the active edge service (angie or
// openresty) was started before our sslcollector bound, it issues one
// `systemctl reload <edge>` so the worker pool re-runs init_worker_by_lua_block
// against a now-ready socket (and, after this change, a freshly-written
// dump.json on disk).
//
// Background: on a cold boot the edge service starts via systemd well
// before cfm is up. Its workers run init_worker, fail to connect to the
// sslcollector unix socket, and seed an empty `_store`. Subsequent TLS
// handshakes fall through to the self-signed cert, which trips HSTS on
// any client that has already pinned the real cert. One graceful
// reload solves it: workers re-init, load_from_snapshot() reads the
// daemon-written dump.json, certs are live.
//
// Disabled with CFM_SSLCOLLECTOR_RELOAD_EDGE_ON_READY=0.
func NudgeEdgeOnFirstReady(ctx context.Context, col *Collector) {
	if v := strings.ToLower(strings.TrimSpace(os.Getenv("CFM_SSLCOLLECTOR_RELOAD_EDGE_ON_READY"))); v == "0" || v == "false" || v == "off" {
		return
	}
	nudgeOnce.Do(func() {
		go nudgeEdge(ctx, col)
	})
}

var nudgeOnce sync.Once

// pollInterval, totalBudget, and edgeServices are package-level so tests
// can shrink the budget and stub the runner.
var (
	nudgePollInterval = 500 * time.Millisecond
	nudgeTotalBudget  = 60 * time.Second
	edgeServiceNames  = []string{"angie", "openresty"}
)

// systemctlRunner is replaced in tests; defaults to exec.CommandContext.
var systemctlRunner = func(ctx context.Context, args ...string) ([]byte, error) {
	return exec.CommandContext(ctx, "systemctl", args...).CombinedOutput()
}

// socketPathProbe returns whether the sslcollector socket exists, so the
// nudge knows the daemon's HTTP-over-unix is reachable. The default
// path matches the one in cmd/cfm/main.go.
var socketPathProbe = func() bool {
	st, err := os.Stat("/var/run/sslcollector.sock")
	return err == nil && st.Mode()&os.ModeSocket != 0
}

func nudgeEdge(ctx context.Context, col *Collector) {
	deadline := time.Now().Add(nudgeTotalBudget)
	bindObservedAt := time.Time{}

	// Phase 1: wait for the socket to exist + at least one cert in the index.
	// Until both are true, an angie reload would just hit the same
	// not-ready state.
	for {
		if ctx.Err() != nil {
			return
		}
		if time.Now().After(deadline) {
			logging.Logf("[sslcollector] nudge: timed out waiting for socket+certs (60s); not reloading edge")
			return
		}
		if socketPathProbe() && col != nil && col.Stats().UniquePairs > 0 {
			bindObservedAt = time.Now()
			break
		}
		select {
		case <-ctx.Done():
			return
		case <-time.After(nudgePollInterval):
		}
	}

	svc, startedAt, ok := activeEdgeService(ctx)
	if !ok {
		logging.Logf("[sslcollector] nudge: no active edge service detected; nothing to reload")
		return
	}
	// Only reload if the edge was running before our sslcollector socket
	// became ready. If the edge started AFTER us (operator-driven
	// restart, fresh install, etc.) its init_worker will already see the
	// ready socket and the snapshot — no nudge needed.
	if !startedAt.IsZero() && startedAt.After(bindObservedAt) {
		logging.Logf("[sslcollector] nudge: edge %s started after sslcollector ready (%s vs %s); skipping reload",
			svc, startedAt.Format(time.RFC3339), bindObservedAt.Format(time.RFC3339))
		return
	}

	rctx, cancel := context.WithTimeout(ctx, 30*time.Second)
	defer cancel()
	out, err := systemctlRunner(rctx, "reload", svc)
	if err != nil {
		logging.Logf("[sslcollector] nudge: systemctl reload %s failed: %v (%s)", svc, err, strings.TrimSpace(string(out)))
		return
	}
	logging.Logf("[sslcollector] nudge: reloaded %s after first sslcollector-ready (edge started before us; workers now re-init against ready socket+snapshot)", svc)
}

// activeEdgeService returns the first edge service systemd reports as
// active along with its ActiveEnterTimestamp. Returns ok=false when
// none are active.
func activeEdgeService(ctx context.Context) (svc string, startedAt time.Time, ok bool) {
	for _, candidate := range edgeServiceNames {
		actCtx, cancel := context.WithTimeout(ctx, 3*time.Second)
		out, err := systemctlRunner(actCtx, "is-active", "--quiet", candidate)
		cancel()
		if err != nil || strings.TrimSpace(string(out)) != "" {
			// is-active --quiet exits 0 when active. Non-zero exit
			// produces an error from CombinedOutput; ignore and try the
			// next candidate.
			if err == nil {
				continue
			}
			continue
		}
		// Active. Look up its ActiveEnterTimestamp.
		startedAt = activeEnterTimestamp(ctx, candidate)
		return candidate, startedAt, true
	}
	return "", time.Time{}, false
}

func activeEnterTimestamp(ctx context.Context, svc string) time.Time {
	tCtx, cancel := context.WithTimeout(ctx, 3*time.Second)
	defer cancel()
	out, err := systemctlRunner(tCtx, "show", "-p", "ActiveEnterTimestamp", "--value", svc)
	if err != nil {
		return time.Time{}
	}
	v := strings.TrimSpace(string(out))
	if v == "" || v == "n/a" {
		return time.Time{}
	}
	// systemd format: "Mon 2006-01-02 15:04:05 MST"
	for _, layout := range []string{
		"Mon 2006-01-02 15:04:05 MST",
		"Mon 2006-01-02 15:04:05",
	} {
		if t, perr := time.Parse(layout, v); perr == nil {
			return t
		}
	}
	return time.Time{}
}

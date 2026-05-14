package sslcollector

import (
	"context"
	"net"
	"os"
	"os/exec"
	"strconv"
	"strings"
	"sync"
	"time"

	"cfm/internal/logging"
)

// NudgeEdgeOnFirstReady runs once per cfm daemon lifetime. It waits for
// the sslcollector socket to be bound AND the daemon's cert index to
// have at least one entry; if the active edge service (angie or
// openresty) was started before that ready state, it issues one
// `systemctl reload <edge>` so the worker pool re-runs init_worker_by_lua_block
// against a now-ready socket (and, after the snapshot-writer change, a
// freshly-written dump.json on disk).
//
// Background: on a cold boot the edge service starts via systemd well
// before cfm is up. Its workers run init_worker, fail to connect to the
// sslcollector unix socket, and seed an empty `_store`. Subsequent TLS
// handshakes fall through to the self-signed cert, which trips HSTS on
// any client that has already pinned the real cert. One graceful
// reload solves it: workers re-init, load_from_snapshot() reads the
// daemon-written dump.json, certs are live.
//
// The gate compares the edge's main-process start time to the moment
// cfm's socket+cert index became ready ("socketReadyAt"). Earlier
// versions used cfm's own pid start time, which misses the cold-boot
// case where cfm wins the systemd race by a couple of seconds but the
// edge still starts BEFORE cfm finishes binding the socket — the edge
// reports a later pid timestamp than cfm's, the old gate concluded
// "edge started after us, skip" and left workers permanently empty
// until the next manual reload. The socket-ready anchor handles that
// case (edge.start < socketReadyAt → reload) while still skipping the
// "admin started angie minutes after cfm came up" case (edge.start >
// socketReadyAt → skip).
//
// The comparison uses /proc/<pid>/stat starttimes (timezone-free) so
// the gate works on hosts running in any local timezone. An older
// version that parsed `systemctl show ActiveEnterTimestamp` silently
// failed on named zones like EEST/MSK.
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

// pollInterval, totalBudget, and edgeServiceNames are package-level so
// tests can shrink the budget and stub the runner.
var (
	nudgePollInterval = 500 * time.Millisecond
	nudgeTotalBudget  = 60 * time.Second
	edgeServiceNames  = []string{"angie", "openresty"}
)

// systemctlRunner is replaced in tests; defaults to exec.CommandContext.
var systemctlRunner = func(ctx context.Context, args ...string) ([]byte, error) {
	return exec.CommandContext(ctx, "systemctl", args...).CombinedOutput()
}

// socketReady probes /var/run/sslcollector.sock by actually dialing it
// with a short timeout. A bare os.Stat would also pass on a leftover
// socket inode from a previously-crashed cfm where no one is listening
// — the nudge would then reload an edge that immediately re-fails the
// dumpall. Dialing proves the daemon's HTTP-over-unix is reachable.
var socketReady = func() bool {
	c, err := net.DialTimeout("unix", "/var/run/sslcollector.sock", 250*time.Millisecond)
	if err != nil {
		return false
	}
	_ = c.Close()
	return true
}

// processStartTimeFn is replaced in tests.
var processStartTimeFn = processStartTime

// nowFn returns the current wall-clock time and is replaced in tests so
// the socket-ready anchor is deterministic.
var nowFn = time.Now

func nudgeEdge(ctx context.Context, col *Collector) {
	deadline := nowFn().Add(nudgeTotalBudget)

	// Phase 1: wait for the socket to accept connections + at least one
	// cert in the index. Until both are true, an edge reload would just
	// hit the same not-ready state.
	for {
		if ctx.Err() != nil {
			return
		}
		if nowFn().After(deadline) {
			logging.Logf("[sslcollector] nudge: timed out waiting for socket+certs (60s); not reloading edge")
			return
		}
		if socketReady() && col != nil && col.Stats().UniquePairs > 0 {
			break
		}
		select {
		case <-ctx.Done():
			return
		case <-time.After(nudgePollInterval):
		}
	}

	// Capture the moment everything became ready. Any edge worker whose
	// init_worker_by_lua_block ran before this point saw an unready
	// state (no socket bind, possibly no snapshot, no certs in the
	// index) and seeded an empty _store. Wall-clock precision is fine —
	// the gate uses second-granularity comparison.
	socketReadyAt := nowFn()

	svc, ok := activeEdgeService(ctx)
	if !ok {
		logging.Logf("[sslcollector] nudge: no active edge service detected; nothing to reload")
		return
	}

	// Reload if the edge's main process started before we became ready.
	// Three cases trip the gate, all correctly:
	//   1. Cold boot, edge wins race: edge.start < cfm.start < ready
	//   2. Cold boot, cfm wins race: cfm.start < edge.start < ready
	//      (previously skipped — this is the mars-style regression)
	//   3. `systemctl restart cfm` on long-lived edge: edge.start far
	//      before ready → reload. Workers had healthy state before the
	//      restart and would self-heal via /stats polling, but one
	//      explicit reload is cheaper than waiting for that recovery.
	// Skip only when the edge started AFTER we were ready (admin starts
	// angie minutes after cfm came up — workers init against a healthy
	// state on their first try, no reload needed).
	edgeStart, eerr := edgeStartTime(ctx, svc)
	if eerr != nil {
		logging.Logf("[sslcollector] nudge: cannot read %s start time (%v); proceeding to reload defensively", svc, eerr)
	} else if !edgeStart.IsZero() && edgeStart.After(socketReadyAt) {
		logging.Logf("[sslcollector] nudge: edge %s started after sslcollector ready (%s vs %s); skipping reload",
			svc, edgeStart.Format(time.RFC3339), socketReadyAt.Format(time.RFC3339))
		return
	}

	rctx, cancel := context.WithTimeout(ctx, 30*time.Second)
	defer cancel()
	out, err := systemctlRunner(rctx, "reload", svc)
	if err != nil {
		logging.Logf("[sslcollector] nudge: systemctl reload %s failed: %v (%s)", svc, err, strings.TrimSpace(string(out)))
		return
	}
	logging.Logf("[sslcollector] nudge: reloaded %s after first sslcollector-ready (edge predated socket+cert readiness; workers now re-init against ready state)", svc)
}

// activeEdgeService returns the first edge service systemd reports as
// active. Returns ok=false when none are active. When both angie and
// openresty are active simultaneously (rare; manual switchover), it
// logs and returns the first match — reloading both is wasteful and the
// usual case is one of them in flight.
func activeEdgeService(ctx context.Context) (svc string, ok bool) {
	var actives []string
	for _, candidate := range edgeServiceNames {
		actCtx, cancel := context.WithTimeout(ctx, 3*time.Second)
		_, err := systemctlRunner(actCtx, "is-active", "--quiet", candidate)
		cancel()
		if err != nil {
			continue
		}
		actives = append(actives, candidate)
	}
	if len(actives) == 0 {
		return "", false
	}
	if len(actives) > 1 {
		logging.Logf("[sslcollector] nudge: multiple edge services active (%s); reloading %s only",
			strings.Join(actives, ","), actives[0])
	}
	return actives[0], true
}

// edgeStartTime returns the wall-clock start time of the given edge
// service's main process. Uses systemctl's MainPID property (a plain
// integer, no timezone) and then reads /proc/<pid>/stat.
func edgeStartTime(ctx context.Context, svc string) (time.Time, error) {
	pidCtx, cancel := context.WithTimeout(ctx, 3*time.Second)
	defer cancel()
	out, err := systemctlRunner(pidCtx, "show", "-p", "MainPID", "--value", svc)
	if err != nil {
		return time.Time{}, err
	}
	v := strings.TrimSpace(string(out))
	if v == "" || v == "0" {
		return time.Time{}, nil // service active but no main pid yet — treat as unknown
	}
	pid, perr := strconv.Atoi(v)
	if perr != nil {
		return time.Time{}, perr
	}
	return processStartTimeFn(pid)
}

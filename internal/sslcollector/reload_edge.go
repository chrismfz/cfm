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
// openresty) was started before the cfm daemon itself, it issues one
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
// The "edge started before us" comparison uses /proc/<pid>/stat
// starttimes (timezone-free) so the gate works on hosts running in any
// local timezone. An older version that parsed `systemctl show
// ActiveEnterTimestamp` silently failed on named zones like EEST/MSK
// and always fell through to a reload, defeating the gate on a normal
// `systemctl restart cfm`.
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

func nudgeEdge(ctx context.Context, col *Collector) {
	deadline := time.Now().Add(nudgeTotalBudget)

	// Phase 1: wait for the socket to accept connections + at least one
	// cert in the index. Until both are true, an edge reload would just
	// hit the same not-ready state.
	for {
		if ctx.Err() != nil {
			return
		}
		if time.Now().After(deadline) {
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

	// Find our own start time once. If /proc parsing fails (extremely
	// unusual on Linux), fall back to the safe-but-noisy "always reload"
	// behaviour.
	ourStart, ourErr := processStartTimeFn(os.Getpid())
	if ourErr != nil {
		logging.Logf("[sslcollector] nudge: cannot read own start time (%v); reload-gate disabled, proceeding to reload", ourErr)
	}

	svc, ok := activeEdgeService(ctx)
	if !ok {
		logging.Logf("[sslcollector] nudge: no active edge service detected; nothing to reload")
		return
	}

	// Only reload if the edge was running before this cfm daemon
	// process started. On `systemctl restart cfm` after a long uptime
	// the edge has been alive for hours; an earlier version compared
	// edge start to "moment certs first loaded" which always tripped
	// "edge predates us" on a healthy restart and reloaded
	// unnecessarily. The correct anchor is cfm's own pid start time.
	if ourErr == nil {
		edgeStart, eerr := edgeStartTime(ctx, svc)
		if eerr != nil {
			logging.Logf("[sslcollector] nudge: cannot read %s start time (%v); proceeding to reload defensively", svc, eerr)
		} else if !edgeStart.IsZero() && edgeStart.After(ourStart) {
			logging.Logf("[sslcollector] nudge: edge %s started after cfm (%s vs %s); skipping reload",
				svc, edgeStart.Format(time.RFC3339), ourStart.Format(time.RFC3339))
			return
		}
	}

	rctx, cancel := context.WithTimeout(ctx, 30*time.Second)
	defer cancel()
	out, err := systemctlRunner(rctx, "reload", svc)
	if err != nil {
		logging.Logf("[sslcollector] nudge: systemctl reload %s failed: %v (%s)", svc, err, strings.TrimSpace(string(out)))
		return
	}
	logging.Logf("[sslcollector] nudge: reloaded %s after first sslcollector-ready (edge started before cfm; workers now re-init against ready socket+snapshot)", svc)
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

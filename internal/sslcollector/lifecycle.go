package sslcollector

import (
	"context"
	"fmt"
	"os"
	"os/user"
	"strconv"
	"sync"
	"time"

	cfgpkg "cfm/internal/config"
	"cfm/internal/logging"
)

const sharedLuaTokenPath = "/var/lib/cfm/lua/cfm_token.lua"
const sharedLuaConfigPath = "/var/lib/cfm/lua/cfm_sslcollector_config.lua"

// Respawn backoff bounds for a socket server that keeps exiting unexpectedly
// (a persistently unbindable path: stale socket, missing parent dir, EADDRINUSE).
// A single transient failure self-heals on the next tick (5s < the default 20s
// tick); sustained failure settles to one attempt per sockRetryCap.
const (
	sockRetryBase = 5 * time.Second
	sockRetryCap  = 5 * time.Minute
)

// sockBackoff returns the delay before the fail-th consecutive respawn attempt:
// 5s, 10s, 20s, … doubling, capped at sockRetryCap.
func sockBackoff(fail int) time.Duration {
	if fail < 1 {
		fail = 1
	}
	shift := fail - 1
	if shift > 20 { // guard against overflow before the cap clamps it
		shift = 20
	}
	d := sockRetryBase << uint(shift)
	if d <= 0 || d > sockRetryCap {
		d = sockRetryCap
	}
	return d
}

// SockLifecycle owns the start/stop/restart state of the SSLCollector
// unix socket server. Create once with NewSockLifecycle (passing the shared
// Collector), then call ApplyConfig on every daemon tick after config is
// parsed. It is a no-op when nothing relevant has changed.
//
// Concurrency: ApplyConfig and Stop are called only from the daemon's single
// runDaemon goroutine, but the ServeSock goroutine spawned by ApplyConfig runs
// concurrently and writes `running`/`failCount`/`nextAttempt` when it exits. The
// mutex guards every field below so the state machine is race-free regardless of
// how many goroutines ever call in — audit F27/F28.
type SockLifecycle struct {
	col     *Collector
	cfgPath string // path to cfm.conf, used by ValidateOrGenerateToken to patch the token in place

	// Shared-Lua output paths. Default to the fixed sharedLua*Path consts in
	// NewSockLifecycle; overridable so tests never write the LIVE token file that
	// running edge workers read (which would break socket auth on a root host).
	luaTokenPath  string
	luaConfigPath string

	mu          sync.Mutex
	cancel      context.CancelFunc
	cfgKey      string
	sockPath    string    // last bound path; unlinked on disable/Stop (Close no longer unlinks — F27)
	gen         uint64    // monotonic generation; each spawn bumps it. Guards a stale goroutine's exit.
	running     bool      // true while the current-generation ServeSock goroutine is believed live
	failCount   int       // consecutive unexpected exits; drives sockBackoff
	nextAttempt time.Time // earliest wall-clock time to respawn after a failure
	stopped     bool      // Stop() called — ApplyConfig becomes a no-op (no respawn after shutdown)
}

// NewSockLifecycle returns a ready-to-use SockLifecycle.
// col is the shared Collector instance created once at daemon startup.
// cfgPath is the path to cfm.conf; pass an empty string if not available.
func NewSockLifecycle(col *Collector, cfgPath string) *SockLifecycle {
	return &SockLifecycle{
		col:           col,
		cfgPath:       cfgPath,
		luaTokenPath:  sharedLuaTokenPath,
		luaConfigPath: sharedLuaConfigPath,
	}
}

// CfmGroupID returns the numeric GID of the "cfm" OS group, or 0 if not found.
// Returns 0 without error when the group does not exist; callers that receive 0
// should skip chown and log a warning rather than treating it as fatal.
func CfmGroupID() int {
	g, err := user.LookupGroup("cfm")
	if err != nil {
		return 0
	}
	gid, _ := strconv.Atoi(g.Gid)
	return gid
}

// ApplyConfig starts, stops, or restarts the socket server based on cfg.
// Safe to call on every tick — it only acts when something relevant changed.
//
// On every call where the socket is enabled, the token is validated and a new
// one is auto-generated if the existing value is absent or a known placeholder.
// The new token is patched into cfm.conf (l.cfgPath) and written to
// /var/lib/cfm/lua/cfm_token.lua so both OpenResty and Angie can read it.
func (l *SockLifecycle) ApplyConfig(ctx context.Context, cfg *cfgpkg.SSLCollectorSockConfig) {
	// Fast exit after Stop() — don't do token I/O or (re)spawn a shut-down server.
	l.mu.Lock()
	stopped := l.stopped
	l.mu.Unlock()
	if stopped {
		return
	}

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
	// Validate or rotate the token before anything else.
	// ValidateOrGenerateToken is a no-op when the token is already strong.
	if cfg.Enabled {
		tok, err := ValidateOrGenerateToken(l.cfgPath, cfg.Token)
		if err != nil {
			logging.Logf("[sslcollector] token generation failed: %v", err)
		} else {
			if tok != cfg.Token {
				logging.Logf("[sslcollector] weak/missing token replaced with generated token")
				cfg.Token = tok
			}
			// Write (or refresh) cfm_token.lua whenever the token is confirmed good.
			// WriteLuaToken is atomic (write-tmp + rename) so partial writes cannot
			// leave the Lua file in a broken state.
			gid := CfmGroupID()

			if cfg.LuaTokenPath != "" && cfg.LuaTokenPath != sharedLuaTokenPath {
				logging.Logf("[sslcollector] ignoring SSLCOLLECTOR_LUA_TOKEN_PATH=%s; using fixed shared path=%s", cfg.LuaTokenPath, sharedLuaTokenPath)
			}
			if werr := WriteLuaTokenWithMkdir(l.luaTokenPath, tok, gid); werr != nil {
				logging.Logf("[sslcollector] failed to write lua token path=%s: %v", l.luaTokenPath, werr)
			} else {
				logging.Logf("[sslcollector] wrote lua token path=%s", l.luaTokenPath)
			}
			// Write per-daemon runtime flags so Lua workers pick them up at init.
			offlineCache := cfg.OfflineCache == nil || *cfg.OfflineCache
			if werr := WriteLuaConfig(l.luaConfigPath, offlineCache, gid); werr != nil {
				logging.Logf("[sslcollector] failed to write lua config path=%s: %v", l.luaConfigPath, werr)
			}
		}
	}

	key := fmt.Sprintf("%t|%s|%s|%s|%d", cfg.Enabled, sp, cfg.Token, ttl, max)

	l.mu.Lock()
	defer l.mu.Unlock()

	// Stop() may have raced in between the fast check above and here.
	if l.stopped {
		return
	}

	if !cfg.Enabled {
		if l.cancel != nil {
			l.cancel()
			l.cancel = nil
			l.cfgKey = ""
			// Close() no longer unlinks (SetUnlinkOnClose(false), F27), so remove
			// the socket name ourselves — a disabled daemon must not leave a live-
			// looking socket file that yields ECONNREFUSED instead of ENOENT.
			_ = os.Remove(l.sockPath)
			logging.Logf("[sslcollector] sock server stopped (disabled)")
			// running is cleared by the cancelled goroutine's own exit (its gen
			// still matches — only a respawn bumps gen).
		}
		l.failCount = 0
		l.nextAttempt = time.Time{}
		return
	}

	// Same config and the server goroutine is still alive: nothing to do. A
	// healthy tick clears any accumulated backoff.
	if key == l.cfgKey && l.running {
		l.failCount = 0
		l.nextAttempt = time.Time{}
		return
	}

	if key == l.cfgKey && !l.running {
		// F28: the server exited unexpectedly — a mid-life Serve error OR (the
		// realistic case) a transient bind failure at startup: a stale socket,
		// a not-yet-ready parent dir, EADDRINUSE. Respawn it, but rate-bound so a
		// permanently unbindable path can't thrash os.Remove+net.Listen every tick.
		if time.Now().Before(l.nextAttempt) {
			return // cooling down; a later tick retries
		}
	} else {
		// Config changed, or first start: act immediately and reset backoff.
		l.failCount = 0
		l.nextAttempt = time.Time{}
	}

	// (Re)spawn. Cancel any prior generation (running, or already-dead-and-cancelled).
	if l.cancel != nil {
		l.cancel()
		l.cancel = nil
	}
	c, cancel := context.WithCancel(ctx)
	l.cancel = cancel
	l.cfgKey = key
	l.sockPath = sp
	l.gen++
	myGen := l.gen
	l.running = true

	gid := CfmGroupID()
	if gid == 0 {
		logging.Logf("[sslcollector] WARNING: 'cfm' OS group not found — socket will be root:root 0660 and OpenResty workers will not be able to connect. Run install-openresty.sh to create the cfm user/group.")
	}
	// All inputs passed BY VALUE so the goroutine can never observe a later
	// mutation of cfg. The goroutine touches only lifecycle state under l.mu.
	go func(myGen uint64, sockPath, token string, gid int, ttl time.Duration, max int) {
		err := ServeSock(c, l.col, SockServerConfig{
			Enabled:  true,
			SockPath: sockPath,
			Token:    token,
			SockGID:  gid,
			PEMTTL:   ttl,
			PEMMax:   max,
		})
		unexpected := err != nil && c.Err() == nil
		l.mu.Lock()
		if l.gen == myGen { // still the current generation — we own the liveness flag
			l.running = false
			if unexpected {
				l.failCount++
				l.nextAttempt = time.Now().Add(sockBackoff(l.failCount))
			}
		}
		l.mu.Unlock()
		if unexpected {
			logging.Logf("[sslcollector] sock server stopped: %v", err)
		}
	}(myGen, sp, cfg.Token, gid, ttl, max)

	logging.Logf("[sslcollector] sock server enabled path=%s ttl=%s max=%d", sp, ttl, max)
}

// Stop cleanly shuts down the socket server. Call on daemon exit.
// After Stop, ApplyConfig is a no-op — the server is never respawned.
func (l *SockLifecycle) Stop() {
	l.mu.Lock()
	defer l.mu.Unlock()
	l.stopped = true
	if l.cancel != nil {
		l.cancel()
		l.cancel = nil
	}
	l.cfgKey = ""
	// Close() no longer unlinks (SetUnlinkOnClose(false), F27), so remove the
	// socket name here on clean shutdown.
	_ = os.Remove(l.sockPath)
	// running is cleared by the cancelled goroutine's own exit (its gen still
	// matches — only a respawn bumps gen); l.stopped already blocks any respawn.
}

package sslcollector

import (
	"context"
	"fmt"
	"os/user"
	"strconv"
	"time"

	cfgpkg "cfm/internal/config"
	"cfm/internal/logging"
)

// SockLifecycle owns the start/stop/restart state of the SSLCollector
// unix socket server. Create once with NewSockLifecycle (passing the shared
// Collector), then call ApplyConfig on every daemon tick after config is
// parsed. It is a no-op when nothing relevant has changed.
type SockLifecycle struct {
	col     *Collector
	cfgPath string // path to cfm.conf, used by ValidateOrGenerateToken to patch the token in place
	cancel  context.CancelFunc
	cfgKey  string
}

// NewSockLifecycle returns a ready-to-use SockLifecycle.
// col is the shared Collector instance created once at daemon startup.
// cfgPath is the path to cfm.conf; pass an empty string if not available.
func NewSockLifecycle(col *Collector, cfgPath string) *SockLifecycle {
	return &SockLifecycle{col: col, cfgPath: cfgPath}
}

// cfmGroupID returns the numeric GID of the "cfm" OS group, or 0 if not found.
func cfmGroupID() int {
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
// cfg.LuaTokenPath so OpenResty can read it without embedding it in Lua source.
func (l *SockLifecycle) ApplyConfig(ctx context.Context, cfg *cfgpkg.SSLCollectorSockConfig) {
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
	luaPath := cfg.LuaTokenPath
	if luaPath == "" {
		luaPath = "/usr/local/openresty/nginx/lua/cfm_token.lua"
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
			if werr := WriteLuaToken(luaPath, tok, cfmGroupID()); werr != nil {
				logging.Logf("[sslcollector] failed to write lua token: %v", werr)
			}
		}
	}

	key := fmt.Sprintf("%t|%s|%s|%s|%d", cfg.Enabled, sp, cfg.Token, ttl, max)

	if !cfg.Enabled {
		if l.cancel != nil {
			l.cancel()
			l.cancel = nil
			l.cfgKey = ""
			logging.Logf("[sslcollector] sock server stopped (disabled)")
		}
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

	go func(sockPath string) {
		err := ServeSock(c, l.col, SockServerConfig{
			Enabled:  true,
			SockPath: sockPath,
			Token:    cfg.Token,
			PEMTTL:   ttl,
			PEMMax:   max,
		})
		if err != nil && c.Err() == nil {
			logging.Logf("[sslcollector] sock server stopped: %v", err)
		}
	}(sp)

	logging.Logf("[sslcollector] sock server enabled path=%s ttl=%s max=%d", sp, ttl, max)
}

// Stop cleanly shuts down the socket server. Call on daemon exit.
func (l *SockLifecycle) Stop() {
	if l.cancel != nil {
		l.cancel()
		l.cancel = nil
	}
}

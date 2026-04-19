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
			var candidates []string
			if cfg.LuaTokenPath != "" {
				candidates = append(candidates, cfg.LuaTokenPath)
			}
			candidates = append(candidates,
				"/usr/local/openresty/nginx/lua/cfm_token.lua",
				"/etc/angie/lua/cfm_token.lua",
			)

			seen := make(map[string]struct{}, len(candidates))
			deduped := make([]string, 0, len(candidates))
			for _, p := range candidates {
				if p == "" {
					continue
				}
				if _, ok := seen[p]; ok {
					continue
				}
				seen[p] = struct{}{}
				deduped = append(deduped, p)
			}

			attemptedCount := 0
			writtenCount := 0
			gid := CfmGroupID()
			for _, p := range deduped {
				attemptedCount++
				allowMkdir := cfg.LuaTokenPath != "" && p == cfg.LuaTokenPath
				if werr := writeLuaToken(p, tok, gid, allowMkdir); werr != nil {
					logging.Logf("[sslcollector] failed to write lua token path=%s: %v", p, werr)
					continue
				}
				writtenCount++
				logging.Logf("[sslcollector] wrote lua token path=%s", p)
			}
			logging.Logf("[sslcollector] lua token refresh summary: wrote=%d attempted=%d candidates=%d", writtenCount, attemptedCount, len(deduped))
			if attemptedCount == 0 {
				logging.Logf("[sslcollector] WARNING: SSL collector token file was not refreshed anywhere (no writable lua token target directories found)")
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

	gid := CfmGroupID()
	if gid == 0 {
		logging.Logf("[sslcollector] WARNING: 'cfm' OS group not found — socket will be root:root 0660 and OpenResty workers will not be able to connect. Run install-openresty.sh to create the cfm user/group.")
	}
	go func(sockPath string, gid int) {
		err := ServeSock(c, l.col, SockServerConfig{
			Enabled:  true,
			SockPath: sockPath,
			Token:    cfg.Token,
			SockGID:  gid,
			PEMTTL:   ttl,
			PEMMax:   max,
		})
		if err != nil && c.Err() == nil {
			logging.Logf("[sslcollector] sock server stopped: %v", err)
		}
	}(sp, gid)

	logging.Logf("[sslcollector] sock server enabled path=%s ttl=%s max=%d", sp, ttl, max)
}

// Stop cleanly shuts down the socket server. Call on daemon exit.
func (l *SockLifecycle) Stop() {
	if l.cancel != nil {
		l.cancel()
		l.cancel = nil
	}
}

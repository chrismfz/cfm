package main

import (
	"context"
	"path/filepath"
	"time"

	"cfm/internal/logging"
	"cfm/internal/wafconfig"
)

// startWAFConfigSync mirrors <cfgDir>/cfm_waf_config.lua (the operator's WAF
// rule-mode overrides) to /var/lib/cfm/lua/cfm_waf_config.lua, where the edge
// can read it (internal/wafconfig). Once at start, then every 5 s. The edge
// loads the file once per worker, so the log line says to reload it. An error
// is logged when it first appears or changes, not on every poll.
func startWAFConfigSync(ctx context.Context, cfgDir string) {
	if cfgDir == "" {
		// A relative source would never be found, and the sync would then
		// remove a good copy.
		logging.Logf("[wafconfig] no config dir; WAF override sync disabled")
		return
	}
	wafconfig.SourcePath = filepath.Join(cfgDir, "cfm_waf_config.lua")
	lastErr := ""
	run := func() {
		res, err := wafconfig.Sync()
		if err != nil {
			if msg := err.Error(); msg != lastErr {
				logging.Logf("[wafconfig] %s", msg)
				lastErr = msg
			}
			return
		}
		if lastErr != "" {
			logging.Logf("[wafconfig] %s readable again", wafconfig.SourcePath)
			lastErr = ""
		}
		switch res {
		case wafconfig.Written:
			logging.Logf("[wafconfig] %s copied to %s; reload the edge to apply it", wafconfig.SourcePath, wafconfig.LuaPath)
		case wafconfig.Removed:
			logging.Logf("[wafconfig] %s is gone; removed %s; reload the edge to drop the overrides", wafconfig.SourcePath, wafconfig.LuaPath)
		}
	}
	run()
	go func() {
		t := time.NewTicker(5 * time.Second)
		defer t.Stop()
		for {
			select {
			case <-ctx.Done():
				return
			case <-t.C:
				run()
			}
		}
	}()
}

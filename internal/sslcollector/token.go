package sslcollector

import (
	"crypto/rand"
	"encoding/hex"
	"fmt"
	"os"
	"path/filepath"
	"regexp"
	"strings"

	"cfm/internal/logging"
)

// badTokens matches well-known placeholder values that must not be used in
// production. The check is case-insensitive and requires a full-string match.
var badTokens = regexp.MustCompile(`(?i)^(supersecret|changeme|secret|password|default|token|test|demo|placeholder)$`)

// confTokenLine patches the SSLCOLLECTOR_SOCK_TOKEN line in a cfm.conf file.
var confTokenLine = regexp.MustCompile(`(?m)^(SSLCOLLECTOR_SOCK_TOKEN\s*=\s*).*$`)

// tokenIsLuaSafe reports whether s can be emitted verbatim into a generated Lua
// file via Go %q AND round-tripped through cfm.conf. It requires every byte to be
// a graphical ASCII char (0x21..0x7e): no whitespace, no control bytes, and no
// non-ASCII runes (audit F55). Go's %q renders a non-printable non-ASCII rune as
// \uXXXX / \UXXXXXXXX, which LuaJIT cannot parse (it expects \xHH or \u{...}), so
// a token containing e.g. a zero-width space would produce a cfm_token.lua /
// cfm_bridge_token.lua that fails to compile — taking edge<->collector (and
// edge<->bridge) auth down. An operator token that fails this is treated as weak
// and regenerated (the generated 48-hex token is always safe). Byte iteration is
// deliberate: any multi-byte UTF-8 rune has bytes >= 0x80 and is rejected.
func tokenIsLuaSafe(s string) bool {
	for i := 0; i < len(s); i++ {
		if c := s[i]; c < 0x21 || c > 0x7e {
			return false
		}
	}
	return true
}

// ValidateOrGenerateToken returns current unchanged if it is strong (≥32 chars,
// not a known placeholder). Otherwise it generates a new 48-hex-char token,
// patches the SSLCOLLECTOR_SOCK_TOKEN line in cfgPath in place, and returns the
// new token.
//
// cfgPath may be empty; in that case the file-patch step is skipped (non-fatal)
// and the new token is still returned so the caller can update in-memory config.
func ValidateOrGenerateToken(cfgPath, current string) (string, error) {
	cur := strings.TrimSpace(current)
	if len(cur) >= 32 && !badTokens.MatchString(cur) && tokenIsLuaSafe(cur) {
		return cur, nil
	}

	b := make([]byte, 24)
	if _, err := rand.Read(b); err != nil {
		return "", fmt.Errorf("sslcollector: token generation failed: %w", err)
	}
	token := hex.EncodeToString(b) // 48 hex chars

	if cfgPath != "" {
		// cfgPath is set at daemon startup from filepath.Join(cfgDir, "cfm.conf")
		// where cfgDir comes from a CLI flag or well-known path — never from
		// network input. Require an absolute path as a sanity guard.
		// #nosec G304 -- path is daemon-internal, not derived from user input
		if !filepath.IsAbs(cfgPath) {
			return token, fmt.Errorf("sslcollector: cfgPath must be absolute, got %q", cfgPath)
		}
		if data, err := os.ReadFile(cfgPath); err == nil { // #nosec G304
			updated := confTokenLine.ReplaceAllString(string(data), "${1}"+token)
			// Preserve the file's existing permissions (best-effort).
			info, statErr := os.Stat(cfgPath)
			mode := os.FileMode(0640)
			if statErr == nil {
				mode = info.Mode()
			}
			// #nosec G304 -- cfgPath is an absolute, daemon-internal config path
			_ = os.WriteFile(cfgPath, []byte(updated), mode)
		}
	}

	return token, nil
}

// ValidateOrGenerateTokenKey is the generic form of ValidateOrGenerateToken.
// Instead of patching the fixed SSLCOLLECTOR_SOCK_TOKEN key it patches keyName
// in cfgPath.  The function appends "keyName = <token>" if the key is not already
// present, so it works for keys that are absent on first install.
//
// cfgPath may be empty; in that case the file-patch step is skipped (non-fatal)
// and the new token is still returned so the caller can update in-memory config.
func ValidateOrGenerateTokenKey(cfgPath, keyName, current string) (string, error) {
	cur := strings.TrimSpace(current)
	if len(cur) >= 32 && !badTokens.MatchString(cur) && tokenIsLuaSafe(cur) {
		return cur, nil
	}

	b := make([]byte, 24)
	if _, err := rand.Read(b); err != nil {
		return "", fmt.Errorf("sslcollector: token generation failed: %w", err)
	}
	token := hex.EncodeToString(b) // 48 hex chars

	if cfgPath != "" {
		// Require an absolute path as a sanity guard.
		if !filepath.IsAbs(cfgPath) {
			return token, fmt.Errorf("sslcollector: cfgPath must be absolute, got %q", cfgPath)
		}
		// Build a per-key regexp. keyName only contains [A-Z0-9_] so QuoteMeta is a no-op,
		// but we use it anyway for correctness.
		re := regexp.MustCompile(`(?mi)^(` + regexp.QuoteMeta(keyName) + `\s*=\s*).*$`)
		// #nosec G304 -- cfgPath is daemon-internal, not derived from user input
		if data, err := os.ReadFile(cfgPath); err == nil { // #nosec G304
			info, statErr := os.Stat(cfgPath)
			mode := os.FileMode(0640)
			if statErr == nil {
				mode = info.Mode()
			}
			var updated string
			if re.Match(data) {
				// Replace the existing key's value.
				updated = re.ReplaceAllString(string(data), "${1}"+token)
			} else {
				// Key absent: append it so it persists across restarts.
				s := string(data)
				if len(s) > 0 && s[len(s)-1] != '\n' {
					s += "\n"
				}
				updated = s + keyName + " = " + token + "\n"
			}
			// #nosec G304 -- cfgPath is an absolute, daemon-internal config path
			_ = os.WriteFile(cfgPath, []byte(updated), mode) // #nosec G306 -- preserve existing permissions
		}
	}

	return token, nil
}

// WriteLuaToken atomically writes a Lua module that returns the token string to
// luaPath. The file is created with mode 0640 (root:cfm) so that OpenResty
// workers running as the cfm group can read it, but world cannot.
// If cfmGID > 0 the file is chowned to root:cfmGID after the write.
//
// The generated file looks like:
//
//	-- AUTO-GENERATED by CFM — do not edit
//	return "deadbeef..."
func WriteLuaToken(luaPath, token string, cfmGID int) error {
	return writeLuaToken(luaPath, token, cfmGID, false)
}

// WriteLuaTokenWithMkdir is like WriteLuaToken, but it will create the parent
// directory (0750) when it does not already exist.
func WriteLuaTokenWithMkdir(luaPath, token string, cfmGID int) error {
	return writeLuaToken(luaPath, token, cfmGID, true)
}

// LuaTokenWriteResult describes the outcome of attempting to write a token file
// at a candidate path.
type LuaTokenWriteResult struct {
	Path    string
	Written bool
	Skipped bool
	Err     error
}

// WriteLuaTokenToExistingParents writes a Lua token module to each candidate
// path whose parent directory already exists. Missing parent directories are
// skipped so mixed OpenResty/Angie migrations can refresh whichever layout is
// present on disk without creating extra trees.
func WriteLuaTokenToExistingParents(token string, cfmGID int, candidates ...string) []LuaTokenWriteResult {
	seen := make(map[string]struct{}, len(candidates))
	results := make([]LuaTokenWriteResult, 0, len(candidates))
	for _, p := range candidates {
		p = strings.TrimSpace(p)
		if p == "" {
			continue
		}
		if _, ok := seen[p]; ok {
			continue
		}
		seen[p] = struct{}{}

		res := LuaTokenWriteResult{Path: p}
		dir := filepath.Dir(p)
		st, err := os.Stat(dir)
		if err != nil {
			if os.IsNotExist(err) {
				res.Skipped = true
				results = append(results, res)
				continue
			}
			res.Err = fmt.Errorf("sslcollector: stat parent directory %q for lua token target %q: %w", dir, p, err)
			results = append(results, res)
			continue
		}
		if !st.IsDir() {
			res.Err = fmt.Errorf("sslcollector: parent path %q for lua token target %q is not a directory", dir, p)
			results = append(results, res)
			continue
		}
		if err := writeLuaToken(p, token, cfmGID, false); err != nil {
			res.Err = err
			results = append(results, res)
			continue
		}
		res.Written = true
		results = append(results, res)
	}
	return results
}

func writeLuaToken(luaPath, token string, cfmGID int, mkdirParent bool) error {
	if !filepath.IsAbs(luaPath) {
		return fmt.Errorf("sslcollector: luaPath must be absolute, got %q", luaPath)
	}
	dir := filepath.Dir(luaPath)
	st, err := os.Stat(dir)
	if err != nil {
		if os.IsNotExist(err) {
			if !mkdirParent {
				return fmt.Errorf("sslcollector: missing parent directory %q for lua token target %q: %w", dir, luaPath, err)
			}
			if mkErr := os.MkdirAll(dir, 0750); mkErr != nil {
				return fmt.Errorf("sslcollector: create parent directory %q for lua token target %q: %w", dir, luaPath, mkErr)
			}
		} else {
			return fmt.Errorf("sslcollector: stat parent directory %q for lua token target %q: %w", dir, luaPath, err)
		}
	} else if !st.IsDir() {
		return fmt.Errorf("sslcollector: parent path %q for lua token target %q is not a directory", dir, luaPath)
	}

	content := fmt.Sprintf(
		"-- AUTO-GENERATED by CFM \xe2\x80\x94 do not edit\nreturn %q\n",
		token,
	)
	return writeLuaFileAtomic(luaPath, content, cfmGID, "sslcollector", "[sslcollector]", "lua token")
}

// writeLuaFileAtomic writes a generated Lua file via tmp-file + rename with
// the enforced ownership/mode for generated Lua (0640 root:cfm — post-deploy
// checks assert this; see CLAUDE.md §5). Single implementation shared by all
// four Lua-file writers in this package so a future fix (fsync before
// rename, umask handling, a permission tweak) cannot land in three writers
// and miss the fourth. errPrefix/logTag/what preserve each caller's
// historical error strings and log identity.
//
// Durability (audit F54): the tmp file's DATA is fsync'd BEFORE the rename, so a
// crash or power loss can't make the rename durable while the bytes are still
// only in the page cache — which would leave a present-but-empty/truncated file
// (e.g. a zero-length cfm_token.lua that 403s every /cert and /dumpall). Mirrors
// writeSnapshotAtomic in snapshot.go.
//
// 0640: root owns, cfm group reads (required for OpenResty/Angie workers).
// World has no access. gosec G306 flags anything above 0600 but group-read
// is intentional here — 0600 would prevent the workers from reading it.
func writeLuaFileAtomic(luaPath, content string, cfmGID int, errPrefix, logTag, what string) error {
	tmp := luaPath + ".tmp"
	// #nosec G302 G304 -- 0640 group-read intentional (cfm group = nginx workers
	// only); tmp is derived from a daemon-internal, absolute luaPath.
	f, err := os.OpenFile(tmp, os.O_WRONLY|os.O_CREATE|os.O_TRUNC, 0640)
	if err != nil {
		return fmt.Errorf("%s: open %s tmp: %w", errPrefix, what, err)
	}
	if _, werr := f.Write([]byte(content)); werr != nil {
		_ = f.Close()
		_ = os.Remove(tmp)
		return fmt.Errorf("%s: write %s tmp: %w", errPrefix, what, werr)
	}
	if serr := f.Sync(); serr != nil {
		_ = f.Close()
		_ = os.Remove(tmp)
		return fmt.Errorf("%s: fsync %s tmp: %w", errPrefix, what, serr)
	}
	if cerr := f.Close(); cerr != nil {
		_ = os.Remove(tmp)
		return fmt.Errorf("%s: close %s tmp: %w", errPrefix, what, cerr)
	}
	if err := os.Chmod(tmp, 0640); err != nil {
		logging.Logf("%s WARNING: failed chmod on tmp %s %s: %v", logTag, what, tmp, err)
	}
	if cfmGID > 0 {
		if err := os.Chown(tmp, 0, cfmGID); err != nil {
			logging.Logf("%s WARNING: failed chown on tmp %s %s to root:%d: %v", logTag, what, tmp, cfmGID, err)
		}
	}
	if err := os.Rename(tmp, luaPath); err != nil {
		_ = os.Remove(tmp)
		return fmt.Errorf("%s: rename %s: %w", errPrefix, what, err)
	}
	if err := os.Chmod(luaPath, 0640); err != nil {
		logging.Logf("%s WARNING: failed chmod on final %s %s: %v", logTag, what, luaPath, err)
	}
	if cfmGID > 0 {
		if err := os.Chown(luaPath, 0, cfmGID); err != nil {
			logging.Logf("%s WARNING: failed chown on final %s %s to root:%d: %v", logTag, what, luaPath, cfmGID, err)
		}
	}
	return nil
}

// WriteLuaConfig atomically writes a Lua module with sslcollector runtime flags
// to luaPath (typically /var/lib/cfm/lua/cfm_sslcollector_config.lua).
// The file is created 0640 (root:cfm) so OpenResty workers can read it.
// sslcollector.lua loads this file at init_worker time to apply per-daemon config.
func WriteLuaConfig(luaPath string, offlineCache bool, cfmGID int) error {
	if !filepath.IsAbs(luaPath) {
		return fmt.Errorf("sslcollector: luaPath must be absolute, got %q", luaPath)
	}
	offlineCacheStr := "true"
	if !offlineCache {
		offlineCacheStr = "false"
	}
	content := fmt.Sprintf(
		"-- AUTO-GENERATED by CFM \xe2\x80\x94 do not edit\nreturn {\n  offline_cache = %s,\n}\n",
		offlineCacheStr,
	)
	return writeLuaFileAtomic(luaPath, content, cfmGID, "sslcollector", "[sslcollector]", "lua config")
}

// WriteClamavLuaConfig atomically writes a Lua module exposing the clamav
// Lua-hook on/off switch (typically /var/lib/cfm/lua/cfm_clamav_config.lua).
// The file is created 0640 (root:cfm) so OpenResty workers can read it.
// cfm.lua loadfile()s it at init_worker time and forwards `enabled` into
// cfm_clamav.init({...}); cfm_clamav.notify() short-circuits when
// CFG.enabled is false, sparing the multipart parse + bridge socket trip
// on every upload while keeping the on-demand `cfm clam scan` path alive.
//
// The file also carries a stable header sentinel line
//
//	-- CFM_HOOK_ENABLED=true|false
//
// that the CLI parses with a tight regex in `cfm clam status` /
// `cfm clam hook status`. Lua-table grammar can drift (spacing, trailing
// commas, comment styles) and a substring match against
// `"enabled = true"` would silently start lying as soon as a future
// editor reformats this file. The sentinel is grep-cheap, format-stable,
// and decoupled from the Lua surface — change one, change the other.
// scanDefault is the global scanning POLICY (CLAM_SCAN_DEFAULT). The edge
// (cfm_clamav.lua) computes should-scan(host) = scan_default XOR host-in-override.
// The deploy default is ON (async notify-only scanner, unchanged for months), so
// a listed override host is an opt-OUT; a scan-off server (scan_default=false)
// with no overrides does zero upload work.
//
// scanMode is the global CLAM_SCAN_MODE ("async"|"inline"); the edge flips it
// per vhost via the mode-override set and, when inline, calls the blocking
// bridge endpoint bounded by inlineTimeoutMs (fail-open on expiry). Anything
// other than the exact string "inline" renders as async — blocking must never
// arm through a corrupt value.
func WriteClamavLuaConfig(luaPath string, enabled bool, scanDefault bool, scanMode string, inlineTimeoutMs int, cfmGID int) error {
	if !filepath.IsAbs(luaPath) {
		return fmt.Errorf("clam: luaPath must be absolute, got %q", luaPath)
	}
	enabledStr := "true"
	if !enabled {
		enabledStr = "false"
	}
	scanDefaultStr := "true"
	if !scanDefault {
		scanDefaultStr = "false"
	}
	modeStr := "async"
	if scanMode == "inline" {
		modeStr = "inline"
	}
	if inlineTimeoutMs <= 0 {
		inlineTimeoutMs = 3000
	}
	content := fmt.Sprintf(
		"-- AUTO-GENERATED by CFM \xe2\x80\x94 do not edit\n"+
			"-- CFM_HOOK_ENABLED=%s\n"+
			"return {\n  enabled = %s,\n  scan_default = %s,\n  scan_mode = %q,\n  inline_timeout_ms = %d,\n}\n",
		enabledStr, enabledStr, scanDefaultStr, modeStr, inlineTimeoutMs,
	)
	return writeLuaFileAtomic(luaPath, content, cfmGID, "clam", "[clam]", "clamav lua config")
}

// WebdetectorBridgeConfig carries the webdetector → edge-Lua runtime knobs
// published via cfm_bridge_config.lua. Fields map 1:1 to the Lua table the
// edge reads (configs/lua/cfm_bridge_cfg.lua is the canonical consumer).
type WebdetectorBridgeConfig struct {
	// ClearanceRefresh: when true, accepted requests re-mint cfm_clearance
	// with exp = now + cookie_life so active panel/webmail users don't get
	// re-challenged mid-session ([webdetector] CHALLENGE_COOKIE_REFRESH).
	ClearanceRefresh bool
	// OriginKeepalive routes edge allow-traffic through the pooled
	// cfm_origin_* upstreams instead of a fresh backend connection per
	// request ([webdetector] ORIGIN_KEEPALIVE, default off). See
	// docs/proxy-performance.md.
	OriginKeepalive bool
	// OriginKAIdleSec / OriginKAMaxReqs tune the pool
	// ([webdetector] ORIGIN_KEEPALIVE_IDLE_SEC / ORIGIN_KEEPALIVE_MAX_REQS).
	OriginKAIdleSec int
	OriginKAMaxReqs int
	// CookieLifeSec is the authoritative clearance-cookie lifetime in seconds
	// (the challenge server's CHALLENGE_COOKIE_LIFE → CHALLENGE_COOLDOWN → 60m
	// chain). Published so the edge Lua re-mint/refresh paths (cfm.lua
	// ok_ttl_sec, cfm_panel.lua clearance_cookie_ttl) use the SAME lifetime the
	// daemon mints tokens with, instead of their own hardcoded fallbacks.
	CookieLifeSec int
	// PanelWAFMode / PanelDecisionMode are the panel enforce modes
	// ("off"|"logonly"|"enforce") sourced from detectors.conf [webdetector]
	// PANEL_WAF_MODE / PANEL_DECISION_MODE. cfm_panel.lua reads them via
	// cfm_bridge_cfg and resolves env-override → this value → default "enforce".
	// Empty is rendered as "enforce" so a caller that never set them still
	// publishes the fleet default rather than a blank the Lua would treat as
	// "absent → enforce" anyway.
	PanelWAFMode      string
	PanelDecisionMode string
	// PanelFPPolicyMode is the panel-port consult mode for the fleet-armed
	// fingerprint policy ("off"|"logonly"|"enforce"), sourced from
	// detectors.conf [webdetector] PANEL_FP_POLICY_MODE — the master plan's
	// "panel-port fp-policy consult": an operator-armed fingerprint `deny`
	// covers :2083/:2087/:2096 too. Same resolution chain and "empty →
	// enforce" rendering as the other panel modes; the global FPPolicy=false
	// still kills the consult regardless of this mode.
	PanelFPPolicyMode string
	// PostClearanceCadence enables the edge post-clearance nav-cadence shadow
	// (cfm_pcw, Track-2 B2 — cfm.lua Step 2b). Log-only measurement, default on;
	// detectors.conf [webdetector] POST_CLEARANCE_CADENCE. This replaces the former
	// CFM_PCW env kill-switch so the toggle lives in config like the others and
	// applies within ~10s without a proxy reload.
	PostClearanceCadence bool
	// FPPolicy mirrors [webdetector] FP_POLICY to the edge (default on). The
	// daemon-side knob already makes every /nginx/fppolicy lookup answer "no
	// action"; publishing it here lets cfm.lua skip Step 0c ENTIRELY — no
	// tlsfp tuple build, no md5, no shared-dict traffic on the pre-clearance
	// hot path — so FP_POLICY=0 removes the feature's whole per-request cost
	// within ~10s, not just its answers (whats_wrong-side review finding on
	// PR #1438).
	FPPolicy bool
	// SiteCache mirrors [webdetector] SITE_CACHE to the edge — the master KILL
	// SWITCH for per-vhost edge caching (default ON). It is not a second opt-in:
	// the per-vhost policy store (default empty) is what arms a vhost, so nothing
	// caches until one is armed regardless of this flag. false stops Site Cache on
	// this node's edge (no feed poll, no cache gate, no stamp, no stats push;
	// the log phase still counts) so an operator can kill its caching in ~10s
	// without disarming vhosts.
	SiteCache bool
	// MicroCacheEnforce mirrors [webdetector] MICRO_CACHE_ENFORCE to the edge —
	// the Tier B (micro-cache of anonymous HTML) ENFORCE gate. Default OFF: unlike
	// SiteCache this is an explicit OPT-IN, so a binary/config upgrade never turns
	// HTML micro-caching on by itself even for a vhost whose micro tier is armed
	// (the CLAUDE.md §6 "adding X silently arms it" lesson). While false, Tier B
	// runs in DRY-RUN — the X-CFM-Cache observe header still shows the would-cache
	// verdict, but cfm.lua's micro gate never ngx.exec's to a cache location, so
	// nothing is stored. true lets an armed+anonymous+cacheable request route to
	// its @cfm_micro_<n>s bucket. Flips within ~10s, no proxy reload.
	MicroCacheEnforce bool
}

// WriteWebdetectorBridgeConfig atomically writes a Lua module exposing
// webdetector → OpenResty/Angie runtime knobs (typically
// /var/lib/cfm/lua/cfm_bridge_config.lua). The file is created 0640 (root:cfm)
// so OpenResty workers can read it. Both edge entrypoints (cfm.lua and
// cfm_panel.lua) consume it through configs/lua/cfm_bridge_cfg.lua, whose
// 10s TTL cache means knob changes apply without a proxy reload — only a
// cfm daemon reload to rewrite this file.
func WriteWebdetectorBridgeConfig(luaPath string, cfg WebdetectorBridgeConfig, cfmGID int) error {
	if !filepath.IsAbs(luaPath) {
		return fmt.Errorf("sslcollector: luaPath must be absolute, got %q", luaPath)
	}
	luaBool := func(b bool) string {
		if b {
			return "true"
		}
		return "false"
	}
	// Panel modes: normalise to one of the three tokens; empty/unknown → the
	// fleet default "enforce" (same fallback the Lua applies for an absent field).
	panelMode := func(s string) string {
		switch strings.ToLower(strings.TrimSpace(s)) {
		case "off", "0":
			return "off"
		case "logonly", "1":
			return "logonly"
		default:
			return "enforce"
		}
	}
	content := fmt.Sprintf(
		"-- AUTO-GENERATED by CFM \xe2\x80\x94 do not edit\nreturn {\n"+
			"  clearance_refresh = %s,\n"+
			"  origin_keepalive = %s,\n"+
			"  origin_ka_idle_sec = %d,\n"+
			"  origin_ka_max_reqs = %d,\n"+
			"  cookie_life_sec = %d,\n"+
			"  panel_waf_mode = %q,\n"+
			"  panel_decision_mode = %q,\n"+
			"  panel_fp_policy_mode = %q,\n"+
			"  post_clearance_cadence = %s,\n"+
			"  fp_policy = %s,\n"+
			"  site_cache = %s,\n"+
			"  micro_cache_enforce = %s,\n"+
			"}\n",
		luaBool(cfg.ClearanceRefresh),
		luaBool(cfg.OriginKeepalive),
		cfg.OriginKAIdleSec,
		cfg.OriginKAMaxReqs,
		cfg.CookieLifeSec,
		panelMode(cfg.PanelWAFMode),
		panelMode(cfg.PanelDecisionMode),
		panelMode(cfg.PanelFPPolicyMode),
		luaBool(cfg.PostClearanceCadence),
		luaBool(cfg.FPPolicy),
		luaBool(cfg.SiteCache),
		luaBool(cfg.MicroCacheEnforce),
	)
	return writeLuaFileAtomic(luaPath, content, cfmGID, "sslcollector", "[sslcollector]", "webdetector bridge config")
}

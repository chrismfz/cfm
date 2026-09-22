-- /var/lib/cfm/lua/cfm_bridge_cfg.lua
--
-- Canonical accessor for the webdetector → edge-Lua runtime knobs published
-- by the cfm daemon in /var/lib/cfm/lua/cfm_bridge_config.lua (written by
-- sslcollector.WriteWebdetectorBridgeConfig on daemon start / config reload,
-- sourced from detectors.conf [webdetector]).
--
-- WHY A MODULE: both cfm.lua (origin_keepalive on/off, clearance_refresh)
-- and cfm_origin_ka.lua (pool idle/max-requests tuning) need this file, and
-- cfm_filecache keys its cache by path — two call sites with different
-- transforms on the same path would fight over the cached shape. This module
-- owns the one canonical transform; everyone else calls get().
--
-- Freshness: 10s TTL via cfm_filecache — a `cfm` daemon reload (which
-- rewrites the file) propagates to every worker within ~10s, no proxy
-- reload needed.
--
-- Returned table (fields absent when the daemon predates them — callers
-- must keep their own defaults/env fallbacks):
--   clearance_refresh   boolean (default true when file missing/invalid)
--   origin_keepalive    boolean or nil
--   origin_ka_idle_sec  number  or nil
--   origin_ka_max_reqs  number  or nil
--   cookie_life_sec     number  or nil (authoritative clearance-cookie TTL;
--                       consumers honor it only when > 0)
--   panel_waf_mode      string  or nil ("off"|"logonly"|"enforce"; nil when the
--                       daemon predates the field → cfm_panel.lua defaults it to
--                       "enforce")
--   panel_decision_mode string  or nil (same shape as panel_waf_mode)
--   panel_fp_policy_mode string or nil (same shape; the panel-port consult of
--                       the fleet-armed fingerprint policy — cfm_panel step 2f)
--   post_clearance_cadence boolean (default true when file/field missing; the
--                       cfm_pcw B2 shadow toggle — [webdetector] POST_CLEARANCE_CADENCE)
--   fp_policy           boolean (default true when file/field missing; the
--                       fingerprint-policy edge gate — [webdetector] FP_POLICY.
--                       false = cfm.lua skips Step 0c entirely: no tlsfp tuple,
--                       no md5, no dict, no /nginx/fppolicy lookups)
--   site_cache          boolean (default TRUE when file/field missing; the
--                       Site Cache master KILL SWITCH — [webdetector] SITE_CACHE.
--                       Not an opt-in (the per-vhost policy store arms vhosts);
--                       false = cfm_cache.lua is a full no-op: no feed poll, no
--                       lookup, no X-CFM-Cache header)

local fc = require "cfm_filecache"

local _M = {}

local PATH = "/var/lib/cfm/lua/cfm_bridge_config.lua"

-- Served when the file is missing or unloadable (fresh install, upgrade
-- lag). clearance_refresh=true mirrors the historical fail-safe default;
-- the origin_* fields stay nil so callers fall back to their defaults.
local FALLBACK = { clearance_refresh = true }

-- Hoisted to module scope: this module's state persists across requests
-- (unlike cfm.lua's chunk), and fc.get only consults opts on a cache
-- miss — building the table + closure per call would be pure garbage on
-- the ~10s-TTL hit path, which runs at least once per request.
local OPTS = {
  ttl = 10,
  transform = function(val)
    if type(val) ~= "table" then error("did not return a table") end
    local out = { clearance_refresh = (val.clearance_refresh ~= false) }
    if val.origin_keepalive ~= nil then
      out.origin_keepalive = (val.origin_keepalive == true)
    end
    out.origin_ka_idle_sec = tonumber(val.origin_ka_idle_sec)
    out.origin_ka_max_reqs = tonumber(val.origin_ka_max_reqs)
    -- Authoritative clearance-cookie lifetime (seconds) — the daemon's
    -- CHALLENGE_COOKIE_LIFE chain. nil on an older daemon's file; consumers
    -- (cfm.lua ok_ttl_sec, cfm_panel.lua clearance_cookie_ttl) fall back.
    out.cookie_life_sec = tonumber(val.cookie_life_sec)
    -- Panel enforce modes (off|logonly|enforce). Kept as-is when a string;
    -- nil on an older daemon's file → cfm_panel.lua's resolver defaults to
    -- "enforce" (the fleet posture). The Lua re-normalises, so an unexpected
    -- token here is harmless.
    if type(val.panel_waf_mode) == "string" then
      out.panel_waf_mode = val.panel_waf_mode
    end
    if type(val.panel_decision_mode) == "string" then
      out.panel_decision_mode = val.panel_decision_mode
    end
    if type(val.panel_fp_policy_mode) == "string" then
      out.panel_fp_policy_mode = val.panel_fp_policy_mode
    end
    -- Post-clearance nav-cadence shadow (cfm_pcw, B2). Default TRUE (nil on an
    -- older daemon's file → on), off only when explicitly published false — same
    -- fail-safe idiom as clearance_refresh.
    out.post_clearance_cadence = (val.post_clearance_cadence ~= false)
    -- Fingerprint-policy edge gate (Step 0c). Fail-safe default TRUE like the
    -- other booleans: an older daemon's file simply lacks the field and the
    -- feature stays available; only an explicit false removes it.
    out.fp_policy = (val.fp_policy ~= false)
    -- Site Cache master KILL SWITCH ([webdetector] SITE_CACHE). Default TRUE like
    -- the other booleans (absent field / older daemon → on); it is not an opt-in,
    -- since the per-vhost policy store must still arm a vhost before anything
    -- caches. Only an EXPLICIT false disarms it (cfm_cache.lua → full no-op).
    out.site_cache = (val.site_cache ~= false)
    return out
  end,
}

function _M.get()
  return fc.get(PATH, OPTS) or FALLBACK
end

-- ── Bridge token ─────────────────────────────────────────────────────────────
-- Canonical accessor for the bridge auth token (sibling file to the bridge
-- config, written by the daemon on start — internal/detectors/manager.go).
-- One load+validate implementation for every edge consumer (cfm.lua,
-- cfm_panel.lua, cfm_purge.lua, cfm_h3_config.lua) so the validity rule
-- (string, ≥32 chars) and the freshness policy live in exactly one place.
-- 10s TTL: a daemon-side token rotation converges everywhere within 10s
-- without an nginx reload; a missing file (daemon not started yet) is
-- retried every 2s. Returns (token) or (nil, err).

local TOKEN_PATH = "/var/lib/cfm/lua/cfm_bridge_token.lua"

local TOKEN_OPTS = {
  ttl = 10,
  missing_ttl = 2,
  transform = function(val)
    if type(val) ~= "string" or #val < 32 then
      error("invalid or too short token")
    end
    return val
  end,
}

function _M.token()
  return fc.get(TOKEN_PATH, TOKEN_OPTS)
end

-- Exported so consumers can name the canonical file in operator-facing
-- error messages without keeping their own copy of the path.
_M.TOKEN_PATH = TOKEN_PATH

-- refresh_token drops the cached entry and re-reads the file NOW.
-- For inbound-credential validators only (cfm_purge.check_token): they
-- compare a caller-presented token against ours, and the daemon may purge
-- immediately after rotating a weak token at startup — serving the 10s-old
-- cached value there would 403 a perfectly fresh credential. Outbound
-- consumers (cfm.lua, cfm_panel, cfm_h3_config) must keep using token();
-- calling this per request would reintroduce the loadfile-per-request cost
-- the cache exists to remove.
function _M.refresh_token()
  fc.entries[TOKEN_PATH] = nil
  return _M.token()
end

-- refresh_token_throttled re-reads the token file NOW, but at most once per
-- `min_interval` seconds PER WORKER (module state persists across requests).
-- For the OUTBOUND decision path (cfm.lua): when the bridge 403s an RPC the
-- daemon may have just rotated the token and our ~10s-cached copy is stale, so
-- refreshing lets the request retry with the fresh token instead of failing open
-- (audit F45). A legit rotation converges the per-worker cache in ONE refresh, so
-- the throttle only bites a PERSISTENT 403 (misconfigured/wrong token, file
-- unchanged) — bounding the loadfile cost so it can't become a re-read on every
-- request. Returns (token, nil) on a fresh read, or (nil, "throttled") when
-- called again within the window (the caller must NOT retry — fail per policy).
local _last_forced_refresh = -math.huge
function _M.refresh_token_throttled(min_interval)
  min_interval = tonumber(min_interval) or 2
  local now = (ngx and ngx.now and ngx.now()) or 0
  if (now - _last_forced_refresh) < min_interval then
    return nil, "throttled"
  end
  _last_forced_refresh = now
  fc.entries[TOKEN_PATH] = nil
  return _M.token()
end

return _M

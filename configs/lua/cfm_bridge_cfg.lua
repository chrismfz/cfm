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

local fc = require "cfm_filecache"

local _M = {}

local PATH = "/var/lib/cfm/lua/cfm_bridge_config.lua"

-- Served when the file is missing or unloadable (fresh install, upgrade
-- lag). clearance_refresh=true mirrors the historical fail-safe default;
-- the origin_* fields stay nil so callers fall back to env/defaults.
local FALLBACK = { clearance_refresh = true }

function _M.get()
  local cfg = fc.get(PATH, {
    ttl = 10,
    transform = function(val)
      if type(val) ~= "table" then error("did not return a table") end
      local out = { clearance_refresh = (val.clearance_refresh ~= false) }
      if val.origin_keepalive ~= nil then
        out.origin_keepalive = (val.origin_keepalive == true)
      end
      out.origin_ka_idle_sec = tonumber(val.origin_ka_idle_sec)
      out.origin_ka_max_reqs = tonumber(val.origin_ka_max_reqs)
      return out
    end,
  })
  return cfg or FALLBACK
end

return _M

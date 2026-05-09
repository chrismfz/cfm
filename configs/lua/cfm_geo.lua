-- /var/lib/cfm/lua/cfm_geo.lua
--
-- Per-worker singleton MaxMind GeoIP lookup.
--
-- WHY THIS IS A MODULE
--
-- See the long-form pitfall block at the top of cfm.lua under
-- "PITFALL: access_by_lua_file top-level locals". Short version:
-- cfm.lua's chunk re-executes on every request, so a top-level
-- `local _geo_init_done = false` reset to false on every request and
-- `mmdb.init(path)` was called repeatedly. lua-resty-maxminddb's init
-- opens a fresh ~60 MB FFI mmap of the .mmdb file each call, and Lua's
-- GC doesn't release it (no `__gc` metamethod calls MMDB_close).
-- Mappings accumulated ~1/min until each worker had 200+ duplicate
-- maps of the same file (~13 GB virtual / ~0.5 GB resident per
-- worker). Confirmed on virgo via /proc/<pid>/maps captured by
-- `cfm debug` on 2026-05-09; bundle filed under
-- /var/lib/cfm/debug/20260509T143131Z/.
--
-- By living in `package.loaded["cfm_geo"]`, this module is initialised
-- exactly once per worker. The init flag and any mmdb handle are
-- module-scope locals — they survive across requests.
--
-- Sister-fix: cfm_waf_excl.lua holds the WAF-excludes cache state for
-- the same reason. Both modules document the rule "state that must
-- persist across requests goes in a `require`d module, never in a
-- top-level local of an access_by_lua_file body".
--
-- API: `local geo = require "cfm_geo"; local cc = geo.country(ip_str)`.

local _M = {}

local mmdb_ok, mmdb = pcall(require, "resty.maxminddb")

local _geo_db        = nil
local _geo_api_mode  = "disabled"
local _geo_init_done = false
local _geo_warned    = false

local GEO_DB_PATH = os.getenv("CFM_GEO_DB") or "/var/lib/cfm/maxmind/GeoLite2-City.mmdb"

if mmdb_ok and type(mmdb) == "table" then
  if type(mmdb.init) == "function" and type(mmdb.lookup) == "function" then
    _geo_api_mode = "init_lookup"
  elseif type(mmdb.new) == "function" then
    _geo_api_mode = "new_object"
  else
    _geo_api_mode = "disabled"
  end
end

local function geo_warn_once(...)
  if _geo_warned then return end
  _geo_warned = true
  ngx.log(ngx.WARN, ...)
end

-- country returns the ISO country code for ip_str, or "" if the lookup
-- failed or geo is disabled. Safe to call concurrently — the underlying
-- mmdb handle is read-only after init.
function _M.country(ip_str)
  if _geo_api_mode == "disabled" then
    if not mmdb_ok then
      geo_warn_once("[cfm_geo] lua-resty-maxminddb unavailable: ", tostring(mmdb), " — geo disabled")
    else
      geo_warn_once("[cfm_geo] lua-resty-maxminddb loaded but unsupported API — geo disabled")
    end
    return ""
  end

  if _geo_api_mode == "init_lookup" then
    if not _geo_init_done then
      -- pcall guards against FFI/library load errors (e.g. libmaxminddb.so missing).
      local call_ok, ok, err = pcall(mmdb.init, GEO_DB_PATH)
      if not call_ok then
        geo_warn_once("[cfm_geo] mmdb init error: ", tostring(ok), " — geo disabled")
        _geo_api_mode = "disabled"
        return ""
      end
      if not ok then
        geo_warn_once("[cfm_geo] mmdb init failed: ", tostring(err), " path=", GEO_DB_PATH)
        _geo_api_mode = "disabled"
        return ""
      end
      _geo_init_done = true
    end
    local call_ok, res, err = pcall(mmdb.lookup, ip_str)
    if not call_ok or not res then
      if not call_ok and res then
        geo_warn_once("[cfm_geo] mmdb lookup error: ", tostring(res))
      elseif err then
        geo_warn_once("[cfm_geo] mmdb lookup failed: ", tostring(err))
      end
      return ""
    end
    return (res.country and res.country.iso_code) or ""
  end

  if _geo_api_mode == "new_object" then
    if not _geo_db then
      -- pcall guards against FFI/library load errors.
      local call_ok, db, err = pcall(mmdb.new, GEO_DB_PATH)
      if not call_ok then
        geo_warn_once("[cfm_geo] mmdb new error: ", tostring(db), " — geo disabled")
        _geo_api_mode = "disabled"
        return ""
      end
      if not db then
        geo_warn_once("[cfm_geo] mmdb open failed: ", tostring(err), " path=", GEO_DB_PATH)
        _geo_api_mode = "disabled"
        return ""
      end
      _geo_db = db
    end
    local call_ok, res, err = pcall(_geo_db.lookup, _geo_db, ip_str)
    if not call_ok or not res then
      if not call_ok and res then
        geo_warn_once("[cfm_geo] mmdb lookup error: ", tostring(res))
      elseif err then
        geo_warn_once("[cfm_geo] mmdb lookup failed: ", tostring(err))
      end
      return ""
    end
    return (res.country and res.country.iso_code) or ""
  end

  return ""
end

-- mode returns the active backend ("init_lookup", "new_object",
-- "disabled"). Diagnostic only; not on the hot path.
function _M.mode() return _geo_api_mode end

-- initialised reports whether the backend has actually opened the DB.
-- Useful for tests and the diagnostics bundle.
function _M.initialised()
  return (_geo_api_mode == "init_lookup" and _geo_init_done) or
         (_geo_api_mode == "new_object"  and _geo_db ~= nil)
end

return _M

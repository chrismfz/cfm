-- /var/lib/cfm/lua/cfm_filecache.lua
--
-- Per-worker TTL cache for the small Lua data files consulted on the
-- request hot path (bridge token, bridge runtime config, self-ips,
-- ignore-nets, clamav hook config).
--
-- WHY THIS FILE EXISTS
--
-- cfm.lua is loaded via `access_by_lua_file`, so its top-level locals
-- re-initialise on EVERY request (see the "PITFALL: access_by_lua_file
-- top-level locals" block at the top of cfm.lua). That reset silently
-- defeated the in-file caches that were supposed to throttle disk reads:
--
--   * `_self_ip_cache` / `_ignore_cache` carried `expires_at` TTL fields,
--     but the tables re-initialised to `expires_at = 0` on every request,
--     so the "still fresh?" check was a permanent miss and both files were
--     loadfile()'d + parsed on every single request.
--   * The bridge token, bridge config and clamav hook config were
--     loadfile()'d unconditionally at chunk top-level — once per request
--     by construction.
--
-- Net effect: 4-5 open/read/compile round-trips per request that were all
-- designed to happen once per TTL window. Module state survives across
-- requests via package.loaded, so the TTLs actually hold here.
--
-- API
--
--   local fc = require "cfm_filecache"
--   local val, err = fc.get(path, opts)
--
--     opts.ttl          REQUIRED. Seconds a successfully loaded value is
--                       served from cache before the file is re-read.
--     opts.missing_ttl  Seconds a failed load (missing file, chunk error,
--                       transform error) is cached before retrying.
--                       Defaults to opts.ttl.
--     opts.transform    Optional function(raw) -> derived. Runs once per
--                       (re)load; its return value is what get() serves.
--                       Raise (error()) inside it to reject an unexpected
--                       payload shape — the failure is cached like a
--                       missing file, and err carries the message.
--
-- Failure semantics intentionally match the previous per-request
-- behaviour: a missing or invalid file yields (nil, <err string>) and the
-- caller keeps its existing fallback. The only change is that the disk
-- probe happens at most once per TTL window instead of once per request.
--
-- ACCEPTED TRADE-OFF: callers living in access_by_lua_file chunks
-- (cfm.lua) re-build their opts table + transform closure on every
-- request, even on cache hits, because chunk top-levels re-execute per
-- request. That is a few hundred bytes of LuaJIT nursery garbage per
-- request — noise next to the WAF/shdict work on the same path. Callers
-- in real modules (cfm_bridge_cfg) hoist their opts to module scope
-- instead. Don't restructure cfm.lua's call sites around this without a
-- measurement showing access-phase GC pressure; see
-- docs/edge-unification-plan.md §10 ("Explicitly NOT planned").
--
-- NOT for files that must be re-read with sub-second freshness. Every
-- current consumer tolerates seconds of staleness: the bridge token is
-- persisted in detectors.conf and only rotates when weak (see
-- internal/detectors/manager.go), and self-ips/ignore-nets already had
-- 30s TTLs by design.

local _M = { entries = {} }

function _M.get(path, opts)
  local now = ngx.now()
  local e = _M.entries[path]
  if e and now < e.expires_at then
    return e.value, e.err
  end

  local value, err
  local ok_load, chunk_or_err = pcall(loadfile, path)
  if not ok_load then
    err = "loadfile panic: " .. tostring(chunk_or_err)
  elseif not chunk_or_err then
    -- Missing/unreadable file. Deliberately NOT logged here: for several
    -- consumers (self-ips on a fresh install, clamav config during an
    -- upgrade lag) absence is a normal state with a defined fallback.
    err = "missing or unreadable"
  else
    local ok_run, raw = pcall(chunk_or_err)
    if not ok_run then
      err = "chunk error: " .. tostring(raw)
    else
      value = raw
      if opts.transform then
        local ok_t, derived = pcall(opts.transform, raw)
        if ok_t then
          value = derived
        else
          value, err = nil, "transform error: " .. tostring(derived)
        end
      end
    end
  end

  -- Log real failures (present-but-broken file) once per TTL window —
  -- bounded noise, unlike the old per-request WARN spam.
  if err and err ~= "missing or unreadable" then
    ngx.log(ngx.WARN, "[cfm_filecache] ", path, ": ", err)
  end

  local ttl = err and (opts.missing_ttl or opts.ttl) or opts.ttl
  _M.entries[path] = { value = value, err = err, expires_at = now + ttl }
  return value, err
end

return _M

-- /var/lib/cfm/lua/cfm_cache_log.lua (CFM-managed canonical location)
--
-- Lightweight cache status counters for dashboard use.
-- Intended for log_by_lua_block only.
-- No external I/O.

local _M = {}

local VALID = {
  HIT = true,
  MISS = true,
  BYPASS = true,
  EXPIRED = true,
  STALE = true,
  UPDATING = true,
  REVALIDATED = true,
}

local function incr(dict, key, n)
  local ok, err = dict:incr(key, n or 1, 0)
  if not ok and err ~= "not found" then
    -- ignore quietly
  end
end

function _M.log(zone, status)
  if not zone or zone == "" then return end
  if not status or status == "" then return end
  if not VALID[status] then return end

  local d = ngx.shared.cfm_cache_stats
  if not d then return end

  incr(d, "cache:total")
  incr(d, "cache:zone:" .. zone .. ":total")
  incr(d, "cache:zone:" .. zone .. ":status:" .. status)

  d:set("cache:last_seen_ts", ngx.time())
end

function _M.log_throttle(is_meta, is_throttled, limit_status, status)
  if is_meta ~= "1" then return end

  local d = ngx.shared.cfm_cache_stats
  if not d then return end

  local function incr(k)
    local ok, err = d:incr(k, 1, 0)
    if not ok and err ~= "not found" then
      -- ignore
    end
  end

  incr("throttle:meta:total")

  if is_throttled == "1" then
    incr("throttle:meta:throttled")
  end

  if limit_status == "REJECTED" then
    incr("throttle:meta:rejected")
  elseif limit_status == "DELAYED" then
    incr("throttle:meta:delayed")
  end

  if status == "429" then
    incr("throttle:meta:http_429")
  end
end

return _M

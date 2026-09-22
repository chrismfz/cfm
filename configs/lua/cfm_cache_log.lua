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

-- log(zone, status[, host]): count one cache verdict. `host` is optional and,
-- when present, adds a PER-VHOST breakdown (cache:vhost:<host>:...). The caller
-- (log_by_lua) passes host ONLY for an armed vhost, so per-vhost key cardinality
-- stays bounded. Backward-compatible: host omitted → zone/global totals only.
function _M.log(zone, status, host)
  if not zone or zone == "" then return end
  if not status or status == "" then return end
  if not VALID[status] then return end

  local d = ngx.shared.cfm_cache_stats
  if not d then return end

  incr(d, "cache:total")
  incr(d, "cache:zone:" .. zone .. ":total")
  incr(d, "cache:zone:" .. zone .. ":status:" .. status)

  if host and host ~= "" then
    incr(d, "cache:vhost:" .. host .. ":total")
    incr(d, "cache:vhost:" .. host .. ":status:" .. status)
  end

  d:set("cache:last_seen_ts", ngx.time())
end

-- snapshot_vhosts: read side for the daemon /nginx/cache/stats push. Returns
--   { ["<host>"] = { total = N, HIT = n, MISS = n, ... }, ... }
-- by scanning the per-vhost keys. Absolute counts (the daemon hook is
-- UPSERT-idempotent, like the WAF-stats push). Bounded — only armed vhosts are
-- ever keyed, each with ~1 + #statuses entries.
function _M.snapshot_vhosts()
  local d = ngx.shared.cfm_cache_stats
  if not d then return {} end
  local out = {}
  local keys = d:get_keys(4000)   -- 0 would warn+cap at 1024; armed vhosts are few
  for _, k in ipairs(keys) do
    local host = k:match("^cache:vhost:(.+):total$")
    if host then
      out[host] = out[host] or {}
      out[host].total = tonumber(d:get(k) or 0) or 0
    else
      local h, st = k:match("^cache:vhost:(.+):status:([A-Z]+)$")
      if h then
        out[h] = out[h] or {}
        out[h][st] = tonumber(d:get(k) or 0) or 0
      end
    end
  end
  return out
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

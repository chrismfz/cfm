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

  -- Per-vhost breakdown: status keys ONLY (no per-vhost :total). The daemon
  -- derives a vhost's total by summing its statuses, so there is no separate
  -- total key that could survive a get_keys() truncation while its status keys
  -- are dropped — which would push a misleading "total>0, zero hits" row.
  if host and host ~= "" then
    incr(d, "cache:vhost:" .. host .. ":status:" .. status)
  end

  d:set("cache:last_seen_ts", ngx.time())
end

-- snapshot_vhosts: read side for the daemon /nginx/cache/stats push. Returns
--   { ["<host>"] = { HIT = n, MISS = n, ... }, ... }
-- (status keys only; the daemon sums them) by scanning the per-vhost keys.
-- Absolute counts (the daemon hook is UPSERT-idempotent, like the WAF-stats
-- push). A vhost is keyed only while armed, but its keys stay in the dict after
-- it is disarmed (until an edge reload); the daemon drops such rows.
function _M.snapshot_vhosts()
  local d = ngx.shared.cfm_cache_stats
  if not d then return {} end
  local out = {}
  -- 0 would warn + cap at 1024. A KEY bound, not a vhost bound: each armed
  -- vhost uses up to #statuses keys and the budget also holds zone/throttle
  -- keys and the stale keys of disarmed vhosts, so past roughly 1000-2600
  -- armed vhosts some vhosts are left out — and a cut can fall inside one
  -- vhost's keys, pushing it with PARTIAL counts (docs/site-cache-design.md
  -- §11 "Bounds").
  local keys = d:get_keys(8000)
  for _, k in ipairs(keys) do
    local h, st = k:match("^cache:vhost:(.+):status:([A-Z]+)$")
    if h then
      out[h] = out[h] or {}
      out[h][st] = tonumber(d:get(k) or 0) or 0
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

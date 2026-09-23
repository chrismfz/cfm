-- /var/lib/cfm/lua/cfm_cache_log.lua (CFM-managed canonical location)
--
-- Lightweight cache status counters for dashboard use.
-- Intended for log_by_lua_block only.
-- No external I/O.

local _M = {}

-- The cache statuses counted (nginx $upstream_cache_status values). One list:
-- the log-side gate (VALID) and the read side (snapshot_vhosts) both come from it.
local STATUSES = { "HIT", "MISS", "BYPASS", "EXPIRED", "STALE", "UPDATING", "REVALIDATED" }
local VALID = {}
for _, st in ipairs(STATUSES) do VALID[st] = true end

-- Per-vhost counter key: "cvh:" .. md5(policy key) .. ":" .. status — 48 bytes
-- at most whatever the host's length, so every counter takes the same (small)
-- shared-dict slot and the dict's capacity is a fixed number of counters (a
-- 253-byte host used to take a slot twice as large, and two of them could not
-- reuse the slot of an evicted short one). Only this module writes and reads
-- these keys (log / snapshot_vhosts). The per-worker memo is keyed on the
-- policy key — bounded by the armed policies — and reset if it ever grows past
-- VKEY_MEMO_MAX.
local VKEY_MEMO, VKEY_MEMO_N, VKEY_MEMO_MAX = {}, 0, 20000
local function vhost_prefix(host)
  local p = VKEY_MEMO[host]
  if p then return p end
  p = "cvh:" .. ngx.md5(host) .. ":"
  if VKEY_MEMO_N >= VKEY_MEMO_MAX then VKEY_MEMO, VKEY_MEMO_N = {}, 0 end
  VKEY_MEMO[host] = p
  VKEY_MEMO_N = VKEY_MEMO_N + 1
  return p
end

local function incr(dict, key, n)
  local ok, err = dict:incr(key, n or 1, 0)
  if not ok and err ~= "not found" then
    -- ignore quietly
  end
end

-- log(zone, status[, host]): count one cache verdict. `host` is optional and,
-- when present, adds a PER-VHOST breakdown (vhost_prefix(host) .. status). The caller
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
  -- total key that could disagree with them (an LRU eviction of one status key
  -- would otherwise push a misleading "total>0, zero hits" row).
  if host and host ~= "" then
    incr(d, vhost_prefix(host) .. status)
  end

  d:set("cache:last_seen_ts", ngx.time())
end

-- snapshot_vhosts(keys): read side for the daemon /nginx/cache/stats push.
-- `keys` is the list of ARMED policy keys (cfm_cache.lua builds it from the
-- feed: every value policy_key_for can return). Returns
--   { ["<key>"] = { HIT = n, MISS = n, ... }, ... }
-- (status keys only; the daemon sums them), reading each key's status counters
-- by name, so every armed vhost is read in full however many keys the dict
-- holds (it used to scan get_keys(8000): past a few thousand vhosts some were
-- left out, or pushed with a partial set of statuses). A key with no counter
-- yet is left out. Absolute counts (the daemon hook is UPSERT-idempotent, like
-- the WAF-stats push). A disarmed vhost's counters stay in the dict until the
-- edge restarts (a reload keeps a lua_shared_dict of the same size) or LRU
-- evicts them — no longer read, they are the least recently touched — and if
-- it is re-armed first, its counts resume from them.
function _M.snapshot_vhosts(keys)
  local d = ngx.shared.cfm_cache_stats
  if not d or type(keys) ~= "table" then return {} end
  local out = {}
  for _, h in ipairs(keys) do
    if type(h) == "string" and h ~= "" and out[h] == nil then
      local pre = vhost_prefix(h)
      local counts
      for _, st in ipairs(STATUSES) do
        local v = d:get(pre .. st)
        if v ~= nil then
          counts = counts or {}
          counts[st] = tonumber(v) or 0
        end
      end
      if counts then out[h] = counts end
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

-- Exposed for unit tests (scripts/tests/cfm_cache_log_test.lua).
_M._vhost_prefix = vhost_prefix

return _M

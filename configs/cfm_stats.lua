-- /usr/local/openresty/nginx/lua/cfm_stats.lua
--
-- CFM shared-dict introspection module.
-- Called exclusively by the /cfm-admin/lua-stats endpoint.
-- No I/O, no yields, no side effects — read-only snapshots only.

local cjson = require "cjson.safe"
local math  = math

local _M = {}

local function age_s(ts)
  if not ts or ts == 0 then return nil end
  local n = tonumber(ts)
  if not n then return nil end
  return math.floor(ngx.time() - n)
end

local function fmt_nginx_version(v)
  if not v then return "-" end
  local major = math.floor(v / 1000000)
  local minor = math.floor((v % 1000000) / 1000)
  local patch = v % 1000
  return string.format("%d.%d.%d", major, minor, patch)
end

local function ngx_num_var(name)
  local v = ngx.var[name]
  if not v or v == "" then return nil end
  local n = tonumber(v)
  return n
end

local function pct(part, total)
  part = tonumber(part) or 0
  total = tonumber(total) or 0
  if total <= 0 then return 0 end
  return math.floor((part / total) * 1000) / 10
end

local function nginx_worker_info()
  local nv = ngx.config.nginx_version
  return {
    version     = nv,
    version_str = fmt_nginx_version(nv),
    prefix      = ngx.config.prefix(),
    subsystem   = ngx.config.subsystem,
    worker = {
      pid     = ngx.worker.pid(),
      id      = ngx.worker.id(),
      count   = ngx.worker.count(),
      exiting = ngx.worker.exiting(),
    },
    connections = {
      active    = ngx_num_var("connections_active"),
      reading   = ngx_num_var("connections_reading"),
      writing   = ngx_num_var("connections_writing"),
      waiting   = ngx_num_var("connections_waiting"),
      accepted  = ngx_num_var("connections_accepted"),
      handled   = ngx_num_var("connections_handled"),
      requests  = ngx_num_var("connections_requests"),
    },
  }
end

local function sslcache_stats(d)
  if not d then return { error = "dict_not_found" } end

  local cap  = d:capacity()
  local free = d:free_space()
  local used = cap - free

  local all_keys = d:get_keys(8000)
  local total    = #all_keys
  local capped   = (total >= 8000)

  -- Cert/key PEM strings are stored in the worker-local _store table inside
  -- sslcollector.lua (not in shared dict) so other Lua code cannot enumerate
  -- them via dict:get_keys(). Ask the module directly for counts.
  local sc_ok, sc = pcall(require, "sslcollector")
  local exact_hosts, wild_hosts = 0, 0
  if sc_ok and sc and sc.cert_counts then
    exact_hosts, wild_hosts = sc.cert_counts()
  end

  local meta_count, lock_count  = 0, 0
  for _, k in ipairs(all_keys) do
    if     k:sub(1, 5) == "meta:" then meta_count = meta_count + 1
    elseif k == "lock:dumpall"    then lock_count  = lock_count  + 1
    end
  end

  local function g(k) return d:get(k) end

  local last_dumpall_ts = tonumber(g("meta:last_dumpall_at"))
  local last_attempt_ts = tonumber(g("meta:last_dumpall_attempt_at"))
  local snapshot_ts     = tonumber(g("meta:snapshot_written_at"))
  local last_stats_ts   = tonumber(g("meta:last_stats_at"))
  local last_error_ts   = tonumber(g("meta:last_error_at"))
  local poll_sec        = tonumber(g("meta:poll_interval"))

  return {
    capacity_bytes    = cap,
    free_bytes        = free,
    used_bytes        = used,
    used_pct          = cap > 0 and math.floor(used / cap * 1000) / 10 or 0,
    total_keys        = total,
    keys_capped       = capped,
    exact_hosts       = exact_hosts,
    wild_hosts        = wild_hosts,
    meta_count        = meta_count,
    ingest_lock       = (lock_count > 0),
    ready             = g("meta:ready"),
    version           = g("meta:version"),
    generated_at      = g("meta:generated_at"),
    last_dumpall_src  = g("meta:last_dumpall_src"),
    poll_interval_s   = poll_sec,
    last_dumpall_age_s = age_s(last_dumpall_ts),
    last_attempt_age_s = age_s(last_attempt_ts),
    snapshot_age_s     = age_s(snapshot_ts),
    last_stats_age_s   = age_s(last_stats_ts),
    last_error         = g("meta:last_error"),
    last_error_age_s   = age_s(last_error_ts),
  }
end

local function decisions_stats(d)
  if not d then return { error = "dict_not_found" } end

  local cap  = d:capacity()
  local free = d:free_space()
  local used = cap - free

  local all_keys = d:get_keys(25000)
  local total    = #all_keys
  local capped   = (total >= 25000)

  local cnt_snap_ips  = 0
  local cnt_snap_vhosts = 0
  local cnt_snap_rules = 0
  local cnt_snap_waf_excludes = 0
  local cnt_snap_ts = 0
  local cnt_snap_lock = 0
  local cnt_resume    = 0
  local cnt_ok_touch  = 0
  local cnt_waf_push  = 0
  local cnt_other     = 0

  for _, k in ipairs(all_keys) do
    if     k == "snap_ips"            then cnt_snap_ips  = cnt_snap_ips + 1
    elseif k == "snap_vhosts"         then cnt_snap_vhosts = cnt_snap_vhosts + 1
    elseif k == "snap_rules"          then cnt_snap_rules = cnt_snap_rules + 1
    elseif k == "snap_waf_excludes"   then cnt_snap_waf_excludes = cnt_snap_waf_excludes + 1
    elseif k == "snap_ts"             then cnt_snap_ts = cnt_snap_ts + 1
    elseif k == "snap_lock"           then cnt_snap_lock = cnt_snap_lock + 1
    elseif k:sub(1, 3) == "pr|"       then cnt_resume    = cnt_resume    + 1
    elseif k:sub(1, 9) == "ok_touch|" then cnt_ok_touch  = cnt_ok_touch  + 1
    elseif k:sub(1, 8) == "wafpush|"  then cnt_waf_push  = cnt_waf_push  + 1
    else                                    cnt_other     = cnt_other     + 1
    end
  end

  local snap_ts = tonumber(d:get("snap_ts") or "0") or 0
  local snap_waf_excludes = cjson.decode(d:get("snap_waf_excludes") or "[]") or {}
  local wx_hosts, wx_paths = {}, {}
  if type(snap_waf_excludes) == "table" then
    for _, e in ipairs(snap_waf_excludes) do
      local t = tostring(e.type or ""):lower()
      local v = tostring(e.value or ""):lower()
      if v ~= "" then
        if t == "host" then
          wx_hosts[#wx_hosts + 1] = v
        elseif t == "path" then
          wx_paths[#wx_paths + 1] = v
        end
      end
    end
  end

  return {
    capacity_bytes = cap,
    free_bytes     = free,
    used_bytes     = used,
    used_pct       = cap > 0 and math.floor(used / cap * 1000) / 10 or 0,
    total_keys     = total,
    keys_capped    = capped,
    key_breakdown = {
      snapshot_ips            = cnt_snap_ips,
      snapshot_vhosts         = cnt_snap_vhosts,
      snapshot_rules          = cnt_snap_rules,
      snapshot_waf_excludes   = cnt_snap_waf_excludes,
      snapshot_ts             = cnt_snap_ts,
      snapshot_lock           = cnt_snap_lock,
      post_resume_entries     = cnt_resume,
      solved_ip_touch_entries = cnt_ok_touch,
      waf_push_cooldowns      = cnt_waf_push,
      other                   = cnt_other,
    },
    waf_excludes = {
      refresh_age_s = snap_ts > 0 and math.floor(ngx.time() - snap_ts) or nil,
      host_rules    = wx_hosts,
      path_rules    = wx_paths,
    },
  }
end

local function waf_config()
  local ok, waf = pcall(require, "cfm_waf")
  if not ok or not waf then
    return { error = "module_load_failed" }
  end

  if waf.get_config then
    local cfg = waf.get_config()
    local rules, tuning = {}, {}
    for k, v in pairs(cfg) do
      if k:sub(1, 5) == "rule_" then
        rules[k] = v
      elseif type(v) == "number" or type(v) == "boolean" then
        tuning[k] = v
      end
    end
    return {
      enabled = waf.enabled and waf.enabled() or false,
      rules   = rules,
      tuning  = tuning,
    }
  end

  return {
    enabled = waf.enabled and waf.enabled() or false,
    note    = "Add _M.get_config() to cfm_waf.lua to expose rule modes here",
  }
end

local function cache_zone_stats(d, zone)
  local function g(k)
    return tonumber(d:get("cache:zone:" .. zone .. ":" .. k) or 0) or 0
  end

  local total       = g("total")
  local hit         = g("status:HIT")
  local miss        = g("status:MISS")
  local bypass      = g("status:BYPASS")
  local expired     = g("status:EXPIRED")
  local stale       = g("status:STALE")
  local updating    = g("status:UPDATING")
  local revalidated = g("status:REVALIDATED")

  local cacheable_total = hit + miss + expired + stale + updating + revalidated

  return {
    total              = total,
    hit                = hit,
    miss               = miss,
    bypass             = bypass,
    expired            = expired,
    stale              = stale,
    updating           = updating,
    revalidated        = revalidated,
    cacheable_total    = cacheable_total,
    hit_pct            = pct(hit, cacheable_total),
    miss_pct           = pct(miss, cacheable_total),
    bypass_pct         = pct(bypass, total),
    stale_pct          = pct(stale, cacheable_total),
    revalidated_pct    = pct(revalidated, cacheable_total),
  }
end

local function cache_stats(d)
  if not d then return { error = "dict_not_found" } end

  local cap  = d:capacity()
  local free = d:free_space()
  local used = cap - free

  local total_all = tonumber(d:get("cache:total") or 0) or 0
  local last_seen_ts = tonumber(d:get("cache:last_seen_ts") or 0) or 0

  return {
    capacity_bytes   = cap,
    free_bytes       = free,
    used_bytes       = used,
    used_pct         = cap > 0 and math.floor(used / cap * 1000) / 10 or 0,
    total            = total_all,
    last_seen_age_s  = age_s(last_seen_ts),
    zones = {
      cfm_static = cache_zone_stats(d, "cfm_static"),
      cfm_micro  = cache_zone_stats(d, "cfm_micro"),
    },
  }
end

local function throttle_stats(d)
  if not d then return { error = "dict_not_found" } end

  local function g(k)
    return tonumber(d:get(k) or 0) or 0
  end

  local total     = g("throttle:meta:total")
  local throttled = g("throttle:meta:throttled")
  local rejected  = g("throttle:meta:rejected")
  local delayed   = g("throttle:meta:delayed")
  local http429   = g("throttle:meta:http_429")

  return {
    meta = {
      total         = total,
      throttled     = throttled,
      rejected      = rejected,
      delayed       = delayed,
      http_429      = http429,
      throttled_pct = total > 0 and math.floor(throttled / total * 1000) / 10 or 0,
      rejected_pct  = total > 0 and math.floor(rejected / total * 1000) / 10 or 0,
      delayed_pct   = total > 0 and math.floor(delayed / total * 1000) / 10 or 0,
      http_429_pct  = total > 0 and math.floor(http429 / total * 1000) / 10 or 0,
    }
  }
end

function _M.stats()
  return {
    ts        = ngx.now(),
    nginx     = nginx_worker_info(),
    sslcache  = sslcache_stats(ngx.shared.sslcache),
    decisions = decisions_stats(ngx.shared.cfm_decisions),
    cache     = cache_stats(ngx.shared.cfm_cache_stats),
    throttle  = throttle_stats(ngx.shared.cfm_cache_stats),
    waf       = waf_config(),
  }
end


return _M

-- /usr/local/openresty/nginx/lua/cfm_stats.lua
--
-- CFM shared-dict introspection module.
-- Called exclusively by the /cfm-admin/lua-stats endpoint.
-- No I/O, no yields, no side effects — read-only snapshots only.
--
-- Sources:
--   ngx.shared.cfm_decisions  (cfm.lua + cfm_waf.lua)
--   ngx.shared.sslcache       (sslcollector.lua)
--   ngx.config / ngx.worker   (nginx built-ins)
--   cfm_waf module             (rule config, requires _M.get_config export)

local cjson = require "cjson.safe"
local math  = math

local _M = {}

-- ── Helpers ───────────────────────────────────────────────────────────────────

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

-- ── nginx / worker ────────────────────────────────────────────────────────────

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
  }
end

-- ── sslcache ──────────────────────────────────────────────────────────────────
--
-- Key schema (from sslcollector.lua):
--   e:pemcert:<hostname>  exact cert PEM  (TTL 0 = never expire)
--   e:pemkey:<hostname>   exact key PEM
--   w:pemcert:<suffix>    wildcard cert PEM
--   w:pemkey:<suffix>     wildcard key PEM
--   meta:ready            "1" once certs loaded
--   meta:version          last upstream version string
--   meta:generated_at     upstream generation ts
--   meta:last_dumpall_at  unix ts of last successful ingest
--   meta:last_dumpall_src "dumpall" | "snapshot"
--   meta:last_dumpall_attempt_at  unix ts of last do_dumpall() attempt
--   meta:snapshot_written_at      unix ts of last disk snapshot write
--   meta:last_stats_at    unix ts of last successful /stats poll
--   meta:poll_interval    current backoff seconds (doubles on /stats failure)
--   meta:last_error       last error message string
--   meta:last_error_at    unix ts of last error
--   lock:dumpall          transient lock key (present only during active ingest)

local function sslcache_stats(d)
  if not d then return { error = "dict_not_found" } end

  local cap  = d:capacity()
  local free = d:free_space()
  local used = cap - free

  -- Enumerate keys (values are NOT fetched — only key strings, so this is cheap
  -- even for large cert blobs). Cap at 8000 to stay safe on very large deployments.
  local all_keys = d:get_keys(8000)
  local total    = #all_keys
  local capped   = (total >= 8000)

  local exact_hosts, wild_hosts = 0, 0
  local meta_count, lock_count  = 0, 0
  for _, k in ipairs(all_keys) do
    local p = k:sub(1, 10)
    if     p == "e:pemcert:" then exact_hosts = exact_hosts + 1
    elseif p == "w:pemcert:" then wild_hosts  = wild_hosts  + 1
    elseif k:sub(1, 5) == "meta:" then meta_count = meta_count + 1
    elseif k == "lock:dumpall"    then lock_count  = lock_count  + 1
    end
    -- e:pemkey: / w:pemkey: are skipped to avoid double-counting
  end

  local function g(k) return d:get(k) end

  local last_dumpall_ts    = tonumber(g("meta:last_dumpall_at"))
  local last_attempt_ts    = tonumber(g("meta:last_dumpall_attempt_at"))
  local snapshot_ts        = tonumber(g("meta:snapshot_written_at"))
  local last_stats_ts      = tonumber(g("meta:last_stats_at"))
  local last_error_ts      = tonumber(g("meta:last_error_at"))
  local poll_sec           = tonumber(g("meta:poll_interval"))

  return {
    -- Memory
    capacity_bytes = cap,
    free_bytes     = free,
    used_bytes     = used,
    used_pct       = cap > 0 and math.floor(used / cap * 1000) / 10 or 0,

    -- Key breakdown (by prefix)
    total_keys   = total,
    keys_capped  = capped,
    exact_hosts  = exact_hosts,   -- unique exact-match hostnames
    wild_hosts   = wild_hosts,    -- unique wildcard suffixes
    meta_count   = meta_count,
    ingest_lock  = (lock_count > 0),  -- true if a worker is actively ingesting right now

    -- sslcollector health (all meta:* keys)
    ready                 = g("meta:ready"),
    version               = g("meta:version"),
    generated_at          = g("meta:generated_at"),
    last_dumpall_src      = g("meta:last_dumpall_src"),
    poll_interval_s       = poll_sec,

    -- Ages in seconds (nil = never happened)
    last_dumpall_age_s    = age_s(last_dumpall_ts),
    last_attempt_age_s    = age_s(last_attempt_ts),
    snapshot_age_s        = age_s(snapshot_ts),
    last_stats_age_s      = age_s(last_stats_ts),

    -- Last error
    last_error            = g("meta:last_error"),
    last_error_age_s      = age_s(last_error_ts),
  }
end

-- ── cfm_decisions ─────────────────────────────────────────────────────────────
--
-- Key schema (from cfm.lua + cfm_waf.lua):
--   d|<ip>|<host>|<method>|<scheme>|<uri_part>  bridge decision cache (allow-only)
--   pr|<md5token>                                POST resume stash (90s TTL)
--   ok_touch|<ip>                                ok-touch rate-limit token (120s TTL)
--   wafpush|<reason>|<ip>                        WAF push cooldown (60s TTL)
--   wxhosts                                      WAF exclude host patterns (JSON array)
--   wxpaths                                      WAF exclude path patterns (JSON array)
--   wxsnap_ts                                    WAF exclude last-refresh timestamp
--   wxsnap_lock                                  transient refresh lock (1s TTL)

local function decisions_stats(d)
  if not d then return { error = "dict_not_found" } end

  local cap  = d:capacity()
  local free = d:free_space()
  local used = cap - free

  -- Safe to enumerate all keys: 64MB with short string keys (IPs, tokens) =
  -- at most tens of thousands. Cap at 25000.
  local all_keys = d:get_keys(25000)
  local total    = #all_keys
  local capped   = (total >= 25000)

  local cnt_decision  = 0
  local cnt_resume    = 0
  local cnt_ok_touch  = 0
  local cnt_waf_push  = 0
  local cnt_waf_excl  = 0
  local cnt_other     = 0

  for _, k in ipairs(all_keys) do
    if     k:sub(1, 2) == "d|"        then cnt_decision  = cnt_decision  + 1
    elseif k:sub(1, 3) == "pr|"       then cnt_resume    = cnt_resume    + 1
    elseif k:sub(1, 9) == "ok_touch|" then cnt_ok_touch  = cnt_ok_touch  + 1
    elseif k:sub(1, 8) == "wafpush|"  then cnt_waf_push  = cnt_waf_push  + 1
    elseif k == "wxhosts" or k == "wxpaths"
        or k == "wxsnap_ts" or k == "wxsnap_lock"
                                       then cnt_waf_excl  = cnt_waf_excl  + 1
    else                                    cnt_other     = cnt_other     + 1
    end
  end

  -- WAF exclude lists (stored as JSON arrays in the dict)
  local wx_ts_raw   = d:get("wxsnap_ts")
  local wx_ts       = tonumber(wx_ts_raw or "0") or 0
  local wx_hosts    = cjson.decode(d:get("wxhosts") or "[]") or {}
  local wx_paths    = cjson.decode(d:get("wxpaths") or "[]") or {}

  return {
    -- Memory
    capacity_bytes = cap,
    free_bytes     = free,
    used_bytes     = used,
    used_pct       = cap > 0 and math.floor(used / cap * 1000) / 10 or 0,
    total_keys     = total,
    keys_capped    = capped,

    -- Key breakdown by type
    key_breakdown = {
      decisions     = cnt_decision,   -- cached bridge allow-decisions
      post_resumes  = cnt_resume,     -- pending POST resume stash entries
      ok_touches    = cnt_ok_touch,   -- active solved-IP rate-limit tokens
      waf_push_cool = cnt_waf_push,   -- WAF push cooldown entries (≈ recent WAF hits)
      waf_excl_meta = cnt_waf_excl,   -- WAF exclude snapshot meta keys
      other         = cnt_other,
    },

    -- WAF exclude snapshot (pulled directly from dict, no Go call needed)
    waf_excludes = {
      refresh_age_s = wx_ts > 0 and math.floor(ngx.time() - wx_ts) or nil,
      host_rules    = wx_hosts,
      path_rules    = wx_paths,
    },
  }
end

-- ── WAF config ────────────────────────────────────────────────────────────────
--
-- Requires adding to cfm_waf.lua (before `return _M`):
--   function _M.get_config()
--     local s = {}
--     for k, v in pairs(CFG) do s[k] = v end
--     return s
--   end
--
-- Without that export, returns a minimal fallback (enabled flag only).

local function waf_config()
  local ok, waf = pcall(require, "cfm_waf")
  if not ok or not waf then
    return { error = "module_load_failed" }
  end

  if waf.get_config then
    local cfg = waf.get_config()
    -- Split out rule modes vs numeric tuning for cleaner UI rendering
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

  -- Fallback if get_config not yet added to cfm_waf.lua
  return {
    enabled = waf.enabled and waf.enabled() or false,
    note    = "Add _M.get_config() to cfm_waf.lua to expose rule modes here",
  }
end

-- ── Public API ────────────────────────────────────────────────────────────────

function _M.stats()
  return {
    ts        = ngx.now(),
    nginx     = nginx_worker_info(),
    sslcache  = sslcache_stats(ngx.shared.sslcache),
    decisions = decisions_stats(ngx.shared.cfm_decisions),
    waf       = waf_config(),
  }
end

return _M

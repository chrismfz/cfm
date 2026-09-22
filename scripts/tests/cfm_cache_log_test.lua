-- Tests for cfm_cache_log.lua — per-vhost + zone cache-status counters (Site
-- Cache 3c). Pure luajit: ngx.shared.cfm_cache_stats is a mock dict. Drives
-- _M.log(zone, status[, host]) and asserts the key schema + _M.snapshot_vhosts.

package.path = "configs/lua/?.lua;" .. package.path

-- Minimal ngx.shared dict: incr(key,n,init) / get / set / get_keys.
local function new_dict()
  local store = {}
  return {
    incr = function(_, k, n, init)
      if store[k] == nil then
        if init == nil then return nil, "not found" end
        store[k] = init
      end
      store[k] = store[k] + (n or 1)
      return store[k]
    end,
    get      = function(_, k) return store[k] end,
    set      = function(_, k, v) store[k] = v end,
    get_keys = function(_, _n)
      local ks = {}; for k in pairs(store) do ks[#ks + 1] = k end; return ks
    end,
    _store = store,
  }
end

local fails = 0
local function check(c, m) if c then return end; fails = fails + 1; io.stderr:write("FAIL: " .. m .. "\n") end

local dict = new_dict()
_G.ngx = { shared = { cfm_cache_stats = dict }, time = function() return 12345 end }

local cl = require("cfm_cache_log")

-- ── valid HIT for an armed vhost: zone + vhost + global keys all move ──────────
cl.log("cfm_static", "HIT", "myip.gr")
check(dict:get("cache:total") == 1,                                "global total incremented")
check(dict:get("cache:zone:cfm_static:total") == 1,               "zone total incremented")
check(dict:get("cache:zone:cfm_static:status:HIT") == 1,          "zone HIT incremented")
check(dict:get("cache:vhost:myip.gr:total") == 1,                 "vhost total incremented")
check(dict:get("cache:vhost:myip.gr:status:HIT") == 1,            "vhost HIT incremented")
check(dict:get("cache:last_seen_ts") == 12345,                    "last_seen_ts set")

-- ── a MISS accumulates ────────────────────────────────────────────────────────
cl.log("cfm_static", "MISS", "myip.gr")
check(dict:get("cache:vhost:myip.gr:total") == 2,                 "vhost total = 2 after HIT+MISS")
check(dict:get("cache:vhost:myip.gr:status:MISS") == 1,           "vhost MISS = 1")

-- ── an UNKNOWN status is ignored (VALID gate) ─────────────────────────────────
cl.log("cfm_static", "TELEPORTED", "myip.gr")
check(dict:get("cache:vhost:myip.gr:status:TELEPORTED") == nil,   "unknown status never keyed")
check(dict:get("cache:vhost:myip.gr:total") == 2,                 "unknown status did not bump total")

-- ── host omitted → zone/global only, no vhost key ─────────────────────────────
cl.log("cfm_static", "HIT")
check(dict:get("cache:zone:cfm_static:status:HIT") == 2,          "zone HIT = 2 after host-less HIT")
check(dict:get("cache:vhost::total") == nil,                      "no empty-host vhost key")

-- ── a second armed vhost keeps its own keys ───────────────────────────────────
cl.log("cfm_static", "BYPASS", "www.example.com")
check(dict:get("cache:vhost:www.example.com:status:BYPASS") == 1, "second vhost keyed independently")

-- ── snapshot_vhosts returns per-host absolute counts ──────────────────────────
local snap = cl.snapshot_vhosts()
check(snap["myip.gr"] and snap["myip.gr"].total == 2,             "snapshot myip.gr total = 2")
check(snap["myip.gr"].HIT == 1 and snap["myip.gr"].MISS == 1,     "snapshot myip.gr HIT/MISS split")
check(snap["www.example.com"] and snap["www.example.com"].BYPASS == 1, "snapshot second vhost BYPASS")

-- ── no dict declared → full no-op / empty snapshot (fail-safe) ────────────────
_G.ngx.shared.cfm_cache_stats = nil
cl.log("cfm_static", "HIT", "x.com")             -- must not raise
local empty = cl.snapshot_vhosts()
check(type(empty) == "table" and next(empty) == nil, "snapshot with no dict → empty table")

if fails > 0 then io.stderr:write(fails .. " failure(s)\n"); os.exit(1) end
print("OK cfm_cache_log_test")

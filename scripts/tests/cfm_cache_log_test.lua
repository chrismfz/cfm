-- Tests for cfm_cache_log.lua — per-vhost + zone cache-status counters (Site
-- Cache 3c). Pure luajit: ngx.shared.cfm_cache_stats is a mock dict. Drives
-- _M.log(zone, status[, host]) and asserts the key schema + _M.snapshot_vhosts(keys).

package.path = "configs/lua/?.lua;" .. package.path

-- Minimal ngx.shared dict: incr (no init) / add / get / set (get_keys refuses).
local function new_dict()
  local store = {}
  return {
    -- incr with init loses counters on a crc32 collision (lua-nginx-module
    -- 0.10.26, see cfm_cache_log.lua incr): this stand-in refuses it
    incr = function(_, k, n, init)
      if init ~= nil then error("incr with init: loses counters on a key hash collision; use incr, then add") end
      if store[k] == nil then return nil, "not found" end
      store[k] = store[k] + (n or 1)
      return store[k]
    end,
    add = function(_, k, v)
      if store[k] ~= nil then return false, "exists" end
      store[k] = v
      return true
    end,
    get      = function(_, k) return store[k] end,
    set      = function(_, k, v) store[k] = v end,
    -- snapshot_vhosts must read the armed keys by name: a get_keys scan is
    -- bounded (and locks the dict), so this stand-in refuses to be one
    get_keys = function() error("get_keys: snapshot_vhosts must not scan the dict") end,
    _store = store,
  }
end

local fails = 0
local function check(c, m) if c then return end; fails = fails + 1; io.stderr:write("FAIL: " .. m .. "\n") end

local dict = new_dict()
-- ngx.md5 stand-in: 32 hex chars, distinct for the hosts below (the real one
-- is exercised on nginx; only the key's shape matters here).
local function fake_md5(s)
  return (s:gsub(".", function(c) return string.format("%02x", c:byte()) end) .. string.rep("0", 32)):sub(1, 32)
end
_G.ngx = { shared = { cfm_cache_stats = dict }, time = function() return 12345 end, md5 = fake_md5 }

local cl = require("cfm_cache_log")
local function vk(host, st) return cl._vhost_prefix(host) .. st end

-- ── the per-vhost key is fixed-length whatever the host (one dict slot size) ──
check(vk("myip.gr", "HIT") == "cvh:" .. fake_md5("myip.gr") .. ":HIT", "per-vhost key = cvh:<md5(policy key)>:<status>")
check(#vk(string.rep("a", 240) .. ".example", "REVALIDATED") == 48, "a 253-byte host's key is 48 bytes, like any other")
check(#vk("*.example.com", "REVALIDATED") == 48, "a wildcard key is 48 bytes")

-- ── valid HIT for an armed vhost: zone + vhost + global keys all move ──────────
cl.log("cfm_static", "HIT", "myip.gr")
check(dict:get("cache:total") == 1,                                "global total incremented")
check(dict:get("cache:zone:cfm_static:total") == 1,               "zone total incremented")
check(dict:get("cache:zone:cfm_static:status:HIT") == 1,          "zone HIT incremented")
check(dict:get(vk("myip.gr", "HIT")) == 1,                        "vhost HIT incremented")
check(dict:get(vk("myip.gr", "total")) == nil,                    "no per-vhost :total key (statuses only, avoids a total that disagrees with them)")
check(dict:get("cache:last_seen_ts") == 12345,                    "last_seen_ts set")

-- ── a MISS accumulates ────────────────────────────────────────────────────────
cl.log("cfm_static", "MISS", "myip.gr")
check(dict:get(vk("myip.gr", "MISS")) == 1,                       "vhost MISS = 1")

-- ── an UNKNOWN status is ignored (VALID gate) ─────────────────────────────────
cl.log("cfm_static", "TELEPORTED", "myip.gr")
check(dict:get(vk("myip.gr", "TELEPORTED")) == nil,               "unknown status never keyed")

-- ── host omitted → zone/global only, no vhost key ─────────────────────────────
cl.log("cfm_static", "HIT")
check(dict:get("cache:zone:cfm_static:status:HIT") == 2,          "zone HIT = 2 after host-less HIT")
local nv = 0; for k in pairs(dict._store) do if k:sub(1, 4) == "cvh:" then nv = nv + 1 end end
check(nv == 2,                                                     "no vhost key for a host-less verdict (only myip.gr's HIT + MISS): " .. nv)

-- ── a second armed vhost keeps its own keys ───────────────────────────────────
cl.log("cfm_static", "BYPASS", "www.example.com")
check(dict:get(vk("www.example.com", "BYPASS")) == 1,             "second vhost keyed independently")

-- ── snapshot_vhosts(keys) reads the named (armed) keys, nothing else ────────
-- a disarmed vhost's counters stay in the dict but are no longer read
cl.log("cfm_static", "HIT", "disarmed.example")
local snap = cl.snapshot_vhosts({ "myip.gr", "www.example.com", "armed-no-traffic.example", "myip.gr", "", 7 })
check(snap["myip.gr"] and snap["myip.gr"].HIT == 1 and snap["myip.gr"].MISS == 1, "snapshot myip.gr HIT/MISS split")
check(snap["myip.gr"].total == nil,                               "snapshot carries no :total (daemon derives it)")
check(snap["myip.gr"].BYPASS == nil,                              "a status never counted is absent, not a fabricated 0")
check(snap["www.example.com"] and snap["www.example.com"].BYPASS == 1, "snapshot second vhost BYPASS")
check(snap["disarmed.example"] == nil,                            "a key not in the list is never read")
check(snap["armed-no-traffic.example"] == nil,                    "an armed key with no counter yet is left out")
check(snap[""] == nil,                                            "an empty key is skipped")
local nrows = 0; for _ in pairs(snap) do nrows = nrows + 1 end
check(nrows == 2, "exactly the two counted armed keys (a duplicate / non-string entry adds nothing): " .. nrows)
check(next(cl.snapshot_vhosts(nil)) == nil and next(cl.snapshot_vhosts({})) == nil, "no key list → empty snapshot")

-- every counted status is read back (all seven): the read is by name (the
-- dict refuses a scan, see new_dict), so it cannot be cut short
for _, st in ipairs({ "HIT", "MISS", "BYPASS", "EXPIRED", "STALE", "UPDATING", "REVALIDATED" }) do
  cl.log("cfm_micro", st, "all.example")
end
local all = cl.snapshot_vhosts({ "all.example" })["all.example"]
local nst = 0; for _ in pairs(all or {}) do nst = nst + 1 end
check(nst == 7, "all seven statuses of an armed key are read: " .. nst)
dict:set(vk("all.example", "TELEPORTED"), 9)
check(cl.snapshot_vhosts({ "all.example" })["all.example"].TELEPORTED == nil, "only the counted statuses are read")

-- ── another worker's add wins the race: the count still lands (incr again) ───
do
  local real_add = dict.add
  dict.add = function(self, k, v) real_add(self, k, 5); return false, "exists" end
  cl.log("cfm_static", "HIT", "race.example")
  dict.add = real_add
  check(dict:get(vk("race.example", "HIT")) == 6, "add lost to another worker's add: incr again (5 + 1)")
end

-- ── throttle counters use the same incr ───────────────────────────────────────
cl.log_throttle("1", "1", "REJECTED", "429")
cl.log_throttle("1", "0", "DELAYED", "200")
check(dict:get("throttle:meta:total") == 2 and dict:get("throttle:meta:throttled") == 1
      and dict:get("throttle:meta:rejected") == 1 and dict:get("throttle:meta:delayed") == 1
      and dict:get("throttle:meta:http_429") == 1, "throttle counters counted")

-- ── no dict declared → full no-op / empty snapshot (fail-safe) ────────────────
_G.ngx.shared.cfm_cache_stats = nil
cl.log("cfm_static", "HIT", "x.com")             -- must not raise
local empty = cl.snapshot_vhosts({ "x.com" })
check(type(empty) == "table" and next(empty) == nil, "snapshot with no dict → empty table")

if fails > 0 then io.stderr:write(fails .. " failure(s)\n"); os.exit(1) end
print("OK cfm_cache_log_test")

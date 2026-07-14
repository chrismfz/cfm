-- Tests for the geo cache relocation to its own shared dict (audit F25).
--
-- geo_country_cached() used to cache per-IP country codes in cfm_decisions with a
-- 300s TTL, so under a high-distinct-IP flood the geo entries LRU-evicted the 90s
-- decision allows and the abuse counters sharing that dict. It now writes to a
-- dedicated cfm_geocache dict with a 90s TTL, keeping eviction pressure off the
-- security state.
--
-- cfm.lua is an access_by_lua_file; extract geo_country_cached() from source and
-- load() it with its free names (ngx, geo_country) provided as globals.

local path = "configs/lua/cfm.lua"
local f = assert(io.open(path, "r"), "cannot open " .. path)
local src = f:read("*a"); f:close()

local start = src:find("local function geo_country_cached%(")
assert(start, "geo_country_cached() not found (renamed/moved?)")
local body = src:sub(start)
local stop = body:find("\nend\n")
assert(stop, "could not delimit geo_country_cached() body")
local fnsrc = body:sub(1, stop + 4)

local fails = 0
local function check(cond, msg)
  if not cond then fails = fails + 1; io.stderr:write("FAIL: " .. msg .. "\n") end
end

-- Per-dict capture. geo_store/geo_writes are reassigned by reset(); the stub
-- closures read the current upvalue, so a reset swaps in fresh tables.
local geo_store, geo_writes, decisions_writes
local function reset() geo_store, geo_writes, decisions_writes = {}, {}, 0 end
reset()

local geocache_stub = {
  get = function(_, k) return geo_store[k] end,
  set = function(_, k, v, ttl) geo_store[k] = v; geo_writes[#geo_writes + 1] = { k = k, v = v, ttl = ttl } end,
}
_G.ngx = {
  shared = {
    cfm_geocache = geocache_stub,
    -- If geo is ever written to cfm_decisions again, flag it.
    cfm_decisions = { get = function() return nil end, set = function() decisions_writes = decisions_writes + 1 end },
  },
}

-- Controllable geo backend (the local upvalue geo_country resolves to this global
-- once the function is load()ed out of its chunk).
local geo_ret, geo_calls = "US", 0
_G.geo_country = function(_) geo_calls = geo_calls + 1; return geo_ret end

local geo_country_cached = assert(load(fnsrc .. "\nreturn geo_country_cached"))()
assert(type(geo_country_cached) == "function", "extracted geo_country_cached is not a function")

-- ── miss → looks up, caches in cfm_geocache (TTL 90), returns value ───────────
do
  reset(); geo_ret = "US"; geo_calls = 0
  local cc = geo_country_cached("1.2.3.4")
  check(cc == "US", "returns the looked-up country")
  check(geo_calls == 1, "cache miss performs exactly one lookup")
  check(#geo_writes == 1, "cache miss writes exactly one geocache entry")
  check(geo_writes[1] and geo_writes[1].k == "geo|1.2.3.4", "key is geo|<ip>")
  check(geo_writes[1] and geo_writes[1].v == "US", "value is the country code")
  check(geo_writes[1] and geo_writes[1].ttl == 90, "F25: TTL is 90s (was 300), got " .. tostring(geo_writes[1] and geo_writes[1].ttl))
  check(decisions_writes == 0, "F25: geo is NOT written to cfm_decisions")
end

-- ── hit → returns cached, no lookup, no write ────────────────────────────────
do
  reset(); geo_store["geo|9.9.9.9"] = "DE"; geo_ret = "US"; geo_calls = 0
  local cc = geo_country_cached("9.9.9.9")
  check(cc == "DE", "cache hit returns the cached value")
  check(geo_calls == 0, "cache hit performs no lookup")
  check(#geo_writes == 0, "cache hit writes nothing")
end

-- ── cached "" is a hit (nil is the only miss sentinel) ───────────────────────
do
  reset(); geo_store["geo|8.8.8.8"] = ""; geo_calls = 0
  local cc = geo_country_cached("8.8.8.8")
  check(cc == "", "cached empty string is a hit")
  check(geo_calls == 0, "cached '' is not re-looked-up")
end

-- ── dict absent (conf not yet reloaded) → uncached fallback still works ───────
do
  reset(); geo_ret = "FR"; geo_calls = 0
  _G.ngx.shared.cfm_geocache = nil
  local cc = geo_country_cached("2.2.2.2")
  check(cc == "FR", "absent geocache dict → uncached lookup still returns the country")
  check(geo_calls == 1, "absent dict → one direct lookup, no crash")
  _G.ngx.shared.cfm_geocache = geocache_stub
end

-- ── sentinel ips (-, '', nil) never key the dict ─────────────────────────────
do
  reset(); geo_ret = "US"; geo_calls = 0
  geo_country_cached("-"); geo_country_cached(""); geo_country_cached(nil)
  check(#geo_writes == 0, "sentinel ips (-, '', nil) never write the geocache")
end

if fails > 0 then
  io.stderr:write("\n" .. fails .. " test(s) failed in cfm_geo_cache_dict_test.lua\n")
  os.exit(1)
end
io.stdout:write("ok: geo cache uses its own cfm_geocache dict at 90s TTL (F25)\n")

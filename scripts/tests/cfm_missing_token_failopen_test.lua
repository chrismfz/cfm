-- Tests for the missing-bridge-token policy (audit F47).
--
-- Before: a nil bridge token raised error() at cfm.lua chunk top level, and
-- because access_by_lua_file re-runs the chunk per request, that returned HTTP
-- 500 for EVERY request while the token was absent (e.g. a reboot where nginx
-- starts before the cfm daemon writes the token) — while a present-but-dead
-- daemon fails OPEN. Operator decision: make the two uniform and never interrupt
-- service. The fatal error() is gone, and the decision path now treats a missing
-- token exactly like an unreachable daemon: Client:fail() under cfg.fail_open,
-- WITHOUT the pointless auth-less RPC, logged (throttled).
--
-- The decision path now lives in cfm_decision.lua as Client:get (extracted from
-- cfm.lua in edge-unification Phase 2). We require the module and exercise the
-- PRODUCTION method, stubbing the transport (Client:rpc) and cache key.

-- 1) The fatal error() on a missing token must be GONE from the production
--    source (else it 500s per request).
local dsrc = assert(io.open("configs/lua/cfm_decision.lua", "r")):read("*a")
assert(not dsrc:find('error%("%[cfm%] bridge token unavailable'),
  "the fatal error() on a missing bridge token is still present — F47 not applied")

package.loaded["cjson.safe"] = {
  decode = function(s) return (s == nil or s == "") and nil or { ip_action = "allow", vhost_action = "allow" } end,
  encode = function(_) return "{}" end,
}
package.path = package.path .. ";configs/lua/?.lua;./?.lua"

local rpc_calls, log_lines
local function reset() rpc_calls, log_lines = 0, {} end
reset()

_G.ngx = {
  ERR = 1, WARN = 2, INFO = 3,
  ctx = {}, header = {},
  now = function() return 1000 end,
  md5 = function(s) return tostring(s) end,
  escape_uri = function(s) return tostring(s or "") end,
  log = function(_, ...)
    local parts = {}
    for i = 1, select("#", ...) do parts[i] = tostring((select(i, ...))) end
    log_lines[#log_lines + 1] = table.concat(parts)
  end,
}

local cfm_decision = require("cfm_decision")

-- mk builds a production client with the transport + cache-key stubbed. cfg is
-- held by reference (as in production); fail() and the token/cache/throttle
-- logic under test are the REAL module code.
local function mk(cfg, sh)
  local c = cfm_decision.new(cfg, {
    shdict     = sh,
    token_path = "/var/lib/cfm/lua/cfm_bridge_token.lua",
    token_err  = function() return "no token file at path" end,
    on_token_403 = function() return nil end,
  })
  c.cache_key = function() return "testkey" end
  c.rpc = function() rpc_calls = rpc_calls + 1; return '{"ok":1}', nil end
  return c
end

local fails = 0
local function check(cond, msg)
  if cond then return end
  fails = fails + 1
  io.stderr:write("FAIL: " .. msg .. "\n")
end
local function callon(c) return c:get("1.2.3.4", "h", "/u", "", "GET", "https", "ua", "US", "web") end

-- ── Missing token + fail_open (default): allow, NO rpc, logged ────────────────
do
  reset()
  local d = callon(mk({ token = nil, fail_open = true }, nil))
  check(d.ip_action == "allow" and d.vhost_action == "allow", "missing token + fail_open -> allow")
  check(d.err == "bridge_token_missing", "missing token -> err=bridge_token_missing (got " .. tostring(d.err) .. ")")
  check(rpc_calls == 0, "missing token -> the bridge RPC is NOT attempted (got " .. rpc_calls .. " calls)")
  check(#log_lines == 1, "missing token -> logged once (got " .. #log_lines .. ")")
  check(log_lines[1]:find("FAILING OPEN", 1, true) ~= nil, "log says FAILING OPEN")
  check(log_lines[1]:find("cfm_bridge_token.lua", 1, true) ~= nil, "log includes the token path")
end

-- ── Missing token + fail_closed: block, NO rpc ───────────────────────────────
do
  reset()
  local d = callon(mk({ token = nil, fail_open = false }, nil))
  check(d.ip_action == "block" and d.vhost_action == "block", "missing token + fail_closed -> block")
  check(rpc_calls == 0, "missing token (fail_closed) -> no RPC")
  check(log_lines[1]:find("FAILING CLOSED", 1, true) ~= nil, "fail_closed log says FAILING CLOSED")
end

-- ── Empty-string token behaves like missing ──────────────────────────────────
do
  reset()
  local d = callon(mk({ token = "", fail_open = true }, nil))
  check(rpc_calls == 0 and d.err == "bridge_token_missing", "empty-string token -> fail-open, no RPC")
end

-- ── Present token: the normal RPC path runs ──────────────────────────────────
do
  reset()
  local d = callon(mk({ token = "realtoken", fail_open = true, decision_cache_ttl_ms = 90000 }, nil))
  check(rpc_calls == 1, "present token -> the bridge RPC IS attempted (got " .. rpc_calls .. ")")
  check(d.err == nil, "present token + clean bridge allow -> no fail-open err")
  check(#log_lines == 0, "present token -> no missing-token log")
end

-- ── Cache-first: a cached clean-allow is served even with a missing token ─────
-- (proves the token check sits AFTER the cache lookup — uniform with a dead
-- daemon, which also serves cached allows.)
do
  reset()
  local store = { testkey = '{"cached":1}' }
  local sh = { get = function(_, k) return store[k] end,
               set = function() end,
               add = function() return true end }
  local d = callon(mk({ token = nil, fail_open = true }, sh))
  check(d._cache == true, "cached clean-allow is served even when the token is missing")
  check(rpc_calls == 0, "cache hit -> no RPC")
  check(#log_lines == 0, "cache hit -> no fail-open log (token check not reached)")
end

-- ── Log throttle: only the first of two misses logs within the window ─────────
do
  reset()
  local added = {}
  local sh = { get = function() return nil end,
               set = function() end,
               add = function(_, k, _v, _ttl) if added[k] then return false, "exists" end added[k] = true; return true end }
  local c = mk({ token = nil, fail_open = true }, sh)
  callon(c); callon(c)
  check(#log_lines == 1, "two missing-token requests within the window log ONCE (got " .. #log_lines .. ")")
end

if fails > 0 then
  io.stderr:write("\n" .. fails .. " test(s) failed in cfm_missing_token_failopen_test.lua\n")
  os.exit(1)
end
io.stdout:write("ok: missing bridge token fails open (uniform, throttled, cache-first) (F47)\n")

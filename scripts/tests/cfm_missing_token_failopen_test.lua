-- Tests for the missing-bridge-token policy (audit F47).
--
-- Before: a nil bridge token raised error() at cfm.lua chunk top level, and
-- because access_by_lua_file re-runs the chunk per request, that returned HTTP
-- 500 for EVERY request while the token was absent (e.g. a reboot where nginx
-- starts before the cfm daemon writes the token) — while a present-but-dead
-- daemon fails OPEN. Operator decision: make the two uniform and never interrupt
-- service. The fatal error() is gone, and get_decision() now treats a missing
-- token exactly like an unreachable daemon: fail_decision() under CFG.fail_open,
-- WITHOUT the pointless auth-less RPC, logged (throttled).
--
-- cfm.lua is an access_by_lua_file (runs main() on require), so we extract the
-- real get_decision() from source and load() it, providing its free names as
-- globals — exercising the PRODUCTION function.

local path = "configs/lua/cfm.lua"
local f = assert(io.open(path, "r"), "cannot open " .. path)
local src = f:read("*a"); f:close()

-- 1) The fatal error() on a missing token must be GONE (else it 500s per request).
assert(not src:find('error%("%[cfm%] bridge token unavailable'),
  "the fatal error() on a missing bridge token is still present — F47 not applied")

-- 2) Extract get_decision() and load it.
local start = src:find("local function get_decision%(")
assert(start, "get_decision() not found (renamed/moved?)")
local body = src:sub(start)
local stop = body:find("\nend\n")
assert(stop, "could not delimit get_decision() body")
local fnsrc = body:sub(1, stop + 4)

-- ── Test harness: stubs for get_decision's free names ────────────────────────
local rpc_calls, log_lines
local function reset() rpc_calls, log_lines = 0, {} end
reset()

_G.ngx = {
  ERR = 1, WARN = 2, INFO = 3,
  ctx = {}, header = {},
  now = function() return 1000 end,
  log = function(_, ...)
    local parts = {}
    for i = 1, select("#", ...) do parts[i] = tostring((select(i, ...))) end
    log_lines[#log_lines + 1] = table.concat(parts)
  end,
}
_G.cjson = {
  decode = function(s) return s == "" and nil or { ip_action = "allow", vhost_action = "allow" } end,
  encode = function(_) return "{}" end,
}
_G.esc = function(x) return tostring(x) end
_G.log_route = function() end
_G._bridge = { TOKEN_PATH = "/var/lib/cfm/lua/cfm_bridge_token.lua" }
_G._bridge_token_err = "no token file at path"
_G.decision_cache_key = function() return "testkey" end
-- Mirror of the real fail_decision (cfm.lua): honours CFG.fail_open.
_G.fail_decision = function(err)
  if _G.CFG.fail_open then
    return { ip_action = "allow", vhost_action = "allow", err = err }
  end
  return { ip_action = "block", vhost_action = "block", err = err }
end
-- rpc_call records that it ran and returns a clean bridge "allow".
_G.rpc_call = function() rpc_calls = rpc_calls + 1; return '{"ok":1}', nil end

local get_decision = assert(load(fnsrc .. "\nreturn get_decision"))()
assert(type(get_decision) == "function", "extracted get_decision is not a function")

local fails = 0
local function check(cond, msg)
  if cond then return end
  fails = fails + 1
  io.stderr:write("FAIL: " .. msg .. "\n")
end
local function call() return get_decision("1.2.3.4", "h", "/u", "GET", "https", "ua", "US", "web") end

-- ── Missing token + fail_open (default): allow, NO rpc, logged ────────────────
do
  reset()
  _G.SH = nil
  _G.CFG = { token = nil, fail_open = true }
  local d = call()
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
  _G.SH = nil
  _G.CFG = { token = nil, fail_open = false }
  local d = call()
  check(d.ip_action == "block" and d.vhost_action == "block", "missing token + fail_closed -> block")
  check(rpc_calls == 0, "missing token (fail_closed) -> no RPC")
  check(log_lines[1]:find("FAILING CLOSED", 1, true) ~= nil, "fail_closed log says FAILING CLOSED")
end

-- ── Empty-string token behaves like missing ──────────────────────────────────
do
  reset()
  _G.SH = nil
  _G.CFG = { token = "", fail_open = true }
  local d = call()
  check(rpc_calls == 0 and d.err == "bridge_token_missing", "empty-string token -> fail-open, no RPC")
end

-- ── Present token: the normal RPC path runs ──────────────────────────────────
do
  reset()
  _G.SH = nil
  _G.CFG = { token = "realtoken", fail_open = true, decision_cache_ttl_ms = 90000 }
  local d = call()
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
  _G.SH = { get = function(_, k) return store[k] end,
            set = function() end,
            add = function() return true end }
  _G.CFG = { token = nil, fail_open = true }
  local d = call()
  check(d._cache == true, "cached clean-allow is served even when the token is missing")
  check(rpc_calls == 0, "cache hit -> no RPC")
  check(#log_lines == 0, "cache hit -> no fail-open log (token check not reached)")
end

-- ── Log throttle: only the first of two misses logs within the window ─────────
do
  reset()
  local added = {}
  _G.SH = { get = function() return nil end,
            set = function() end,
            add = function(_, k, _v, _ttl) if added[k] then return false, "exists" end added[k] = true; return true end }
  _G.CFG = { token = nil, fail_open = true }
  call(); call()
  check(#log_lines == 1, "two missing-token requests within the window log ONCE (got " .. #log_lines .. ")")
end

if fails > 0 then
  io.stderr:write("\n" .. fails .. " test(s) failed in cfm_missing_token_failopen_test.lua\n")
  os.exit(1)
end
io.stdout:write("ok: missing bridge token fails open (uniform, throttled, cache-first) (F47)\n")

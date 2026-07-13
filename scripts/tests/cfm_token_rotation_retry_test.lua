-- Tests the get_decision retry-on-403 that closes the token-rotation fail-open
-- window (audit F45).
--
-- When the bridge 403s a decision RPC (stale cached token after a daemon
-- rotation), get_decision force-refreshes the token once (throttled) and — only
-- if the token actually CHANGED — retries with the fresh token before failing
-- open. A persistent 403 (token unchanged / throttled) does NOT retry.
--
-- cfm.lua is an access_by_lua_file; we extract the real get_decision and load()
-- it with its free names as globals.

local path = "configs/lua/cfm.lua"
local f = assert(io.open(path, "r")); local src = f:read("*a"); f:close()
local start = src:find("local function get_decision%(")
assert(start, "get_decision not found")
local body = src:sub(start)
local stop = body:find("\nend\n")
local fnsrc = body:sub(1, stop + 4)

-- ── Harness state ────────────────────────────────────────────────────────────
local rpc_responses, rpc_calls, refresh_calls, refresh_result
local function reset(responses, refresh)
  rpc_responses, rpc_calls, refresh_calls, refresh_result = responses, 0, 0, refresh
end

_G.ngx = { WARN = 1, ERR = 2, INFO = 3, ctx = {}, header = {},
           now = function() return 1000 end, log = function() end }
_G.SH = nil
_G.esc = function(x) return tostring(x) end
_G.log_route = function() end
_G.decision_cache_key = function() return "k" end
_G.cjson = { decode = function(s) return s and { ip_action = "allow", vhost_action = "allow" } or nil end }
_G.fail_decision = function(err)
  if _G.CFG.fail_open then return { ip_action = "allow", vhost_action = "allow", err = err } end
  return { ip_action = "block", vhost_action = "block", err = err }
end
-- Real classify_bridge_err logic (copied from cfm.lua — parses "http NNN").
_G.classify_bridge_err = function(err)
  local msg = string.lower(tostring(err or ""))
  if msg == "" then return "unknown" end
  if msg:find("timeout", 1, true) then return "timeout" end
  if msg:find("connect:", 1, true) then return "connect" end
  local code = msg:match("http%s+(%d%d%d)")
  if code then return "http_" .. code end
  return "unknown"
end
_G._bridge = {
  TOKEN_PATH = "/var/lib/cfm/lua/cfm_bridge_token.lua",
  refresh_token_throttled = function(_) refresh_calls = refresh_calls + 1; return refresh_result end,
}
_G.rpc_call = function() rpc_calls = rpc_calls + 1; local r = rpc_responses[rpc_calls] or { nil, "http 403 body=x" }; return r[1], r[2] end

local get_decision = assert(load(fnsrc .. "\nreturn get_decision"))()

local fails = 0
local function check(cond, msg) if cond then return end fails = fails + 1; io.stderr:write("FAIL: " .. msg .. "\n") end
local function call() return get_decision("1.2.3.4", "h", "/u", "GET", "https", "ua", "US", "web") end

-- 1) 403 then token ROTATED: refresh returns a NEW token -> retry -> success ────
do
  _G.CFG = { token = "OLD" .. string.rep("a", 32), fail_open = true }
  reset({ { nil, "http 403 body=forbidden" }, { '{"ok":1}', nil } }, "NEW" .. string.rep("b", 32))
  local d = call()
  check(rpc_calls == 2, "rotation: the RPC is retried after refresh (got " .. rpc_calls .. " calls)")
  check(refresh_calls == 1, "rotation: refresh_token_throttled called once")
  check(_G.CFG.token == "NEW" .. string.rep("b", 32), "rotation: CFG.token switched to the fresh token")
  check(d.ip_action == "allow" and d.err == nil, "rotation: retry succeeds -> real allow, no fail-open err")
end

-- 2) 403 but token UNCHANGED: refresh returns the SAME token -> no retry ────────
do
  local TOK = "SAME" .. string.rep("c", 32)
  _G.CFG = { token = TOK, fail_open = true }
  reset({ { nil, "http 403 body=forbidden" } }, TOK)   -- refresh returns the same value
  local d = call()
  check(rpc_calls == 1, "persistent 403 (unchanged token): NO retry (got " .. rpc_calls .. ")")
  check(refresh_calls == 1, "unchanged token: refresh attempted once")
  check(d.err ~= nil and d.ip_action == "allow", "unchanged token: fails open (fail_decision)")
end

-- 3) 403 but refresh THROTTLED (nil): no retry ─────────────────────────────────
do
  _G.CFG = { token = "TOK" .. string.rep("d", 32), fail_open = true }
  reset({ { nil, "http 403 body=forbidden" } }, nil)   -- refresh throttled -> nil
  local d = call()
  check(rpc_calls == 1, "throttled refresh: NO retry")
  check(d.err ~= nil, "throttled refresh: fails open")
end

-- 4) Non-403 error (connect): no refresh, no retry ─────────────────────────────
do
  _G.CFG = { token = "TOK" .. string.rep("e", 32), fail_open = true }
  reset({ { nil, "connect: connection refused" } }, "NEW" .. string.rep("f", 32))
  local d = call()
  check(refresh_calls == 0, "non-403 error: refresh is NOT attempted (got " .. refresh_calls .. ")")
  check(rpc_calls == 1, "non-403 error: no retry")
  check(d.err ~= nil, "non-403 error: fails open")
end

-- 5) Normal 200: no refresh, no retry ──────────────────────────────────────────
do
  _G.CFG = { token = "TOK" .. string.rep("g", 32), fail_open = true }
  reset({ { '{"ok":1}', nil } }, "NEW")
  local d = call()
  check(rpc_calls == 1 and refresh_calls == 0, "success: one RPC, no refresh")
  check(d.ip_action == "allow" and d.err == nil, "success: real allow")
end

-- 6) Empty token (F47 path, not F45): 403-retry guard requires a present token ──
-- (A missing token short-circuits earlier; here we assert the retry block's
-- `CFG.token ~= ""` guard doesn't fire a refresh when there's no token.)
do
  _G.CFG = { token = "", fail_open = true }
  reset({ { nil, "http 403 body=forbidden" } }, "NEW")
  -- With an empty token the earlier missing-token branch returns first; refresh
  -- for rotation must not run.
  call()
  check(refresh_calls == 0, "empty token: rotation-refresh not attempted")
end

-- 7) Retry ALSO 403s (rotation raced, or the fresh token is also rejected):
-- bounded — exactly 2 RPCs then fail open, no loop / no third call. ────────────
do
  _G.CFG = { token = "OLD" .. string.rep("h", 32), fail_open = true }
  reset({ { nil, "http 403 body=x" }, { nil, "http 403 body=x" } }, "NEW" .. string.rep("i", 32))
  local d = call()
  check(rpc_calls == 2, "retry-also-403: exactly 2 RPCs (single retry, no loop) (got " .. rpc_calls .. ")")
  check(refresh_calls == 1, "retry-also-403: refresh attempted once")
  check(d.err ~= nil and d.ip_action == "allow", "retry-also-403: fails open after the single retry")
end

if fails > 0 then
  io.stderr:write("\n" .. fails .. " test(s) failed in cfm_token_rotation_retry_test.lua\n")
  os.exit(1)
end
io.stdout:write("ok: get_decision retries once on a 403 after a token rotation, fails open otherwise (F45)\n")

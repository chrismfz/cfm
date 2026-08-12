-- Tests the decision retry-on-403 that closes the token-rotation fail-open
-- window (audit F45).
--
-- When the bridge 403s a decision RPC (stale cached token after a daemon
-- rotation), the decision path force-refreshes the token once (throttled) and —
-- only if the token actually CHANGED — retries with the fresh token before
-- failing open. A persistent 403 (token unchanged / throttled) does NOT retry.
--
-- The decision path now lives in cfm_decision.lua as Client:get (extracted from
-- cfm.lua in edge-unification Phase 2). We require the module and exercise the
-- PRODUCTION method; the throttled refresh is the injected on_token_403 hook and
-- the transport is a stubbed Client:rpc. classify_bridge_err is the module's own.

package.loaded["cjson.safe"] = {
  decode = function(s) return s and { ip_action = "allow", vhost_action = "allow" } or nil end,
  encode = function(_) return "{}" end,
}
package.path = package.path .. ";configs/lua/?.lua;./?.lua"

_G.ngx = { WARN = 1, ERR = 2, INFO = 3, ctx = {}, header = {},
           now = function() return 1000 end, log = function() end,
           md5 = function(s) return tostring(s) end,
           escape_uri = function(s) return tostring(s or "") end }

local cfm_decision = require("cfm_decision")

-- ── Harness state ────────────────────────────────────────────────────────────
local rpc_responses, rpc_calls, refresh_calls, refresh_result
local function reset(responses, refresh)
  rpc_responses, rpc_calls, refresh_calls, refresh_result = responses, 0, 0, refresh
end

-- mk builds a production client with SH off, the transport stubbed to replay
-- `rpc_responses`, and on_token_403 recording + returning `refresh_result`.
local function mk(cfg)
  local c = cfm_decision.new(cfg, {
    shdict       = nil,
    token_path   = "/var/lib/cfm/lua/cfm_bridge_token.lua",
    on_token_403 = function() refresh_calls = refresh_calls + 1; return refresh_result end,
  })
  c.cache_key = function() return "k" end
  c.rpc = function()
    rpc_calls = rpc_calls + 1
    local r = rpc_responses[rpc_calls] or { nil, "http 403 body=x" }
    return r[1], r[2]
  end
  return c
end

local fails = 0
local function check(cond, msg) if cond then return end fails = fails + 1; io.stderr:write("FAIL: " .. msg .. "\n") end
local function callon(c) return c:get("1.2.3.4", "h", "/u", "", "GET", "https", "ua", "US", "web") end

-- 1) 403 then token ROTATED: refresh returns a NEW token -> retry -> success ────
do
  local c = mk({ token = "OLD" .. string.rep("a", 32), fail_open = true })
  reset({ { nil, "http 403 body=forbidden" }, { '{"ok":1}', nil } }, "NEW" .. string.rep("b", 32))
  local d = callon(c)
  check(rpc_calls == 2, "rotation: the RPC is retried after refresh (got " .. rpc_calls .. " calls)")
  check(refresh_calls == 1, "rotation: on_token_403 called once")
  check(c.cfg.token == "NEW" .. string.rep("b", 32), "rotation: cfg.token switched to the fresh token")
  check(d.ip_action == "allow" and d.err == nil, "rotation: retry succeeds -> real allow, no fail-open err")
end

-- 2) 403 but token UNCHANGED: refresh returns the SAME token -> no retry ────────
do
  local TOK = "SAME" .. string.rep("c", 32)
  local c = mk({ token = TOK, fail_open = true })
  reset({ { nil, "http 403 body=forbidden" } }, TOK)   -- refresh returns the same value
  local d = callon(c)
  check(rpc_calls == 1, "persistent 403 (unchanged token): NO retry (got " .. rpc_calls .. ")")
  check(refresh_calls == 1, "unchanged token: refresh attempted once")
  check(d.err ~= nil and d.ip_action == "allow", "unchanged token: fails open (Client:fail)")
end

-- 3) 403 but refresh THROTTLED (nil): no retry ─────────────────────────────────
do
  local c = mk({ token = "TOK" .. string.rep("d", 32), fail_open = true })
  reset({ { nil, "http 403 body=forbidden" } }, nil)   -- refresh throttled -> nil
  local d = callon(c)
  check(rpc_calls == 1, "throttled refresh: NO retry")
  check(d.err ~= nil, "throttled refresh: fails open")
end

-- 4) Non-403 error (connect): no refresh, no retry ─────────────────────────────
do
  local c = mk({ token = "TOK" .. string.rep("e", 32), fail_open = true })
  reset({ { nil, "connect: connection refused" } }, "NEW" .. string.rep("f", 32))
  local d = callon(c)
  check(refresh_calls == 0, "non-403 error: refresh is NOT attempted (got " .. refresh_calls .. ")")
  check(rpc_calls == 1, "non-403 error: no retry")
  check(d.err ~= nil, "non-403 error: fails open")
end

-- 5) Normal 200: no refresh, no retry ──────────────────────────────────────────
do
  local c = mk({ token = "TOK" .. string.rep("g", 32), fail_open = true })
  reset({ { '{"ok":1}', nil } }, "NEW")
  local d = callon(c)
  check(rpc_calls == 1 and refresh_calls == 0, "success: one RPC, no refresh")
  check(d.ip_action == "allow" and d.err == nil, "success: real allow")
end

-- 6) Empty token (F47 path, not F45): 403-retry guard requires a present token ──
do
  local c = mk({ token = "", fail_open = true })
  reset({ { nil, "http 403 body=forbidden" } }, "NEW")
  callon(c)
  check(refresh_calls == 0, "empty token: rotation-refresh not attempted")
end

-- 7) Retry ALSO 403s (rotation raced, or the fresh token is also rejected):
-- bounded — exactly 2 RPCs then fail open, no loop / no third call. ────────────
do
  local c = mk({ token = "OLD" .. string.rep("h", 32), fail_open = true })
  reset({ { nil, "http 403 body=x" }, { nil, "http 403 body=x" } }, "NEW" .. string.rep("i", 32))
  local d = callon(c)
  check(rpc_calls == 2, "retry-also-403: exactly 2 RPCs (single retry, no loop) (got " .. rpc_calls .. ")")
  check(refresh_calls == 1, "retry-also-403: refresh attempted once")
  check(d.err ~= nil and d.ip_action == "allow", "retry-also-403: fails open after the single retry")
end

if fails > 0 then
  io.stderr:write("\n" .. fails .. " test(s) failed in cfm_token_rotation_retry_test.lua\n")
  os.exit(1)
end
io.stdout:write("ok: decision retries once on a 403 after a token rotation, fails open otherwise (F45)\n")

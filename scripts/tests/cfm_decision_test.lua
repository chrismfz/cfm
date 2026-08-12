-- Tests for cfm_decision.lua invariants not covered by the F38/F45/F47 tests:
--   * classify_bridge_err maps transport errors to stable classes, and
--   * Client:get caches ONLY clean allows — never a challenge/block/throttle
--     verdict (a currently-flagged IP hitting a NEW url must miss and see the
--     flag; caching a non-allow would let it be served for the cache TTL).
--
-- Extracted from cfm.lua in edge-unification Phase 2; exercised via require.

package.loaded["cjson.safe"] = {
  _decoded = nil,
  decode = function(s) return package.loaded["cjson.safe"]._decoded end,
  encode = function(_) return "{}" end,
}
package.path = package.path .. ";configs/lua/?.lua;./?.lua"

_G.ngx = { WARN = 1, ERR = 2, INFO = 3, ctx = {}, header = {},
           now = function() return 1000 end, log = function() end,
           md5 = function(s) return tostring(s) end,
           escape_uri = function(s) return tostring(s or "") end }

local cfm_decision = require("cfm_decision")

local fails = 0
local function check(cond, msg) if cond then return end fails = fails + 1; io.stderr:write("FAIL: " .. msg .. "\n") end

-- ── classify_bridge_err ──────────────────────────────────────────────────────
local ce = cfm_decision.classify_bridge_err
check(ce("") == "unknown", "empty -> unknown")
check(ce("connect: connection refused") == "connect", "connect -> connect")
check(ce("timeout") == "timeout", "timeout -> timeout")
check(ce("http 403 body=forbidden") == "http_403", "http 403 -> http_403")
check(ce("http 500 body=oops") == "http_500", "http 500 -> http_500")
check(ce("decode failed") == "json", "decode -> json")
check(ce("weird") == "unknown", "unrecognised -> unknown")

-- ── cache-write guard: only clean allows are stored ──────────────────────────
local function client_with_store(store)
  local sh = { get = function(_, k) return store[k] end,
               set = function(_, k, v) store[k] = v end,
               add = function() return true end }
  local c = cfm_decision.new({ token = "t" .. string.rep("x", 32), fail_open = true, decision_cache_ttl_ms = 90000 }, { shdict = sh })
  c.cache_key = function() return "K" end
  c.rpc = function() return "BODY", nil end   -- non-nil body -> decode path
  return c, store
end

local function run_verdict(verdict)
  package.loaded["cjson.safe"]._decoded = verdict
  local store = {}
  local c = client_with_store(store)
  local d = c:get("1.2.3.4", "h", "/u", "", "GET", "https", "ua", "US", "web")
  return d, store["K"]
end

-- clean allow: cached
do
  local d, cached = run_verdict({ ip_action = "allow", vhost_action = "allow" })
  check(d.ip_action == "allow", "clean allow returned")
  check(cached == "BODY", "clean allow IS cached")
end
-- ip block: NOT cached
do
  local _, cached = run_verdict({ ip_action = "block", vhost_action = "allow" })
  check(cached == nil, "ip block is NOT cached")
end
-- vhost challenge: NOT cached
do
  local _, cached = run_verdict({ ip_action = "allow", vhost_action = "challenge" })
  check(cached == nil, "vhost challenge is NOT cached")
end
-- allow/allow but a rule_action pending (challenge/block/throttle): NOT cached
do
  local _, cached = run_verdict({ ip_action = "allow", vhost_action = "allow", rule_action = "challenge" })
  check(cached == nil, "allow+allow with a pending rule_action is NOT cached")
end

if fails > 0 then
  io.stderr:write("\n" .. fails .. " test(s) failed in cfm_decision_test.lua\n")
  os.exit(1)
end
io.stdout:write("ok: cfm_decision classify + clean-allow-only caching\n")

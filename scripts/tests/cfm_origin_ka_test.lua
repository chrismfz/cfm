-- Standalone smoke + behaviour test for cfm_origin_ka (the balancer_by_lua
-- helper behind the opt-in origin keepalive pools). Run with:
--   luajit scripts/tests/cfm_origin_ka_test.lua
--
-- Also serves as the load-executes gate for the module: `make lua` only
-- parses (`luajit -bl`), so without this file a top-level error in
-- cfm_origin_ka.lua would pass every CI gate and only explode in the
-- balancer phase of production workers with ORIGIN_KEEPALIVE=1.
--
-- Stubs ngx + ngx.balancer. The fake balancer records calls so we can
-- assert: SNI-keyed pooling on 3-param cores, keepalive-race retry via
-- set_more_tries(1) on first attempt only, the per-worker latch when the
-- 3-arg call fails, and the keepalive_broken latch when enable_keepalive
-- raises (missing FFI shim, e.g. some Angie module builds).

package.path = package.path .. ";configs/lua/?.lua;./?.lua"

local logs = {}
local fake_now = 1000
_G.ngx = {
  now = function() return fake_now end,
  log = function(_, ...)
    local parts = {}
    for _, v in ipairs({ ... }) do parts[#parts + 1] = tostring(v) end
    logs[#logs + 1] = table.concat(parts)
  end,
  exit = function(code) return code end,
  var = { server_addr = "203.0.113.7", host = "example.com" },
  WARN = 1, ERR = 2, INFO = 3, NOTICE = 4,
  ERROR = -1,
}

local failures = 0
local function check(cond, msg)
  if cond then
    print("ok   - " .. msg)
  else
    failures = failures + 1
    print("FAIL - " .. msg)
  end
end

local function log_matching(pat)
  local n = 0
  for _, l in ipairs(logs) do
    if l:find(pat, 1, true) then n = n + 1 end
  end
  return n
end

-- Fake bridge config: no origin_ka fields → built-in defaults (3, 1000).
package.loaded["cfm_bridge_cfg"] = {
  get = function() return { clearance_refresh = true } end,
}

-- ── Scenario 1: modern core (3-param set_current_peer, keepalive OK) ────────
local calls = { set_peer = {}, keepalive = {}, more_tries = {} }
local last_failure = nil
package.loaded["ngx.balancer"] = {
  -- 3 declared params → nparams=3 → SNI pools detected as supported
  set_current_peer = function(addr, port, host)
    calls.set_peer[#calls.set_peer + 1] = { addr = addr, port = port, host = host }
    return true
  end,
  enable_keepalive = function(idle, reqs)
    calls.keepalive[#calls.keepalive + 1] = { idle = idle, reqs = reqs }
    return true
  end,
  set_more_tries = function(n)
    calls.more_tries[#calls.more_tries + 1] = n
    return true
  end,
  get_last_failure = function() return last_failure end,
}

local ka = require "cfm_origin_ka"
check(ka.sni_pool_supported() == true, "3-param core detected as SNI-pool capable")

ka.balance(443)
check(#calls.set_peer == 1 and calls.set_peer[1].host == "example.com"
      and calls.set_peer[1].port == 443,
      "443: peer set with SNI host (pool keyed per vhost)")
check(#calls.keepalive == 1 and calls.keepalive[1].idle == 3 and calls.keepalive[1].reqs == 1000,
      "443: keepalive enabled with built-in defaults when bridge fields absent")
check(#calls.more_tries == 1 and calls.more_tries[1] == 1,
      "first attempt arms exactly one keepalive-race retry (set_more_tries(1))")

-- Retry attempt: get_last_failure ~= nil → no additional tries stacked.
last_failure = "failed"
ka.balance(443)
check(#calls.more_tries == 1, "retry attempt does not stack more tries")
last_failure = nil

ka.balance(80)
check(calls.set_peer[#calls.set_peer].host == nil and calls.set_peer[#calls.set_peer].port == 80,
      "80: peer set without SNI arg")
check(#calls.keepalive >= 3, "80: pooling enabled")

-- Bridge-config knob override + memoisation on table identity.
local cfg_tbl = { clearance_refresh = true, origin_ka_idle_sec = 2, origin_ka_max_reqs = 500 }
package.loaded["cfm_bridge_cfg"].get = function() return cfg_tbl end
ka.balance(80)
local last_ka = calls.keepalive[#calls.keepalive]
check(last_ka.idle == 2 and last_ka.reqs == 500,
      "bridge-config idle/max-reqs override the built-in defaults")

-- ── Scenario 2: 3-arg call raises → per-worker latch, no per-request spam ──
package.loaded["cfm_origin_ka"] = nil
local raise_count = 0
package.loaded["ngx.balancer"] = {
  set_current_peer = function(addr, port, host)
    if host ~= nil then
      raise_count = raise_count + 1
      error("bad argument: opts table expected")
    end
    return true
  end,
  enable_keepalive = function() return true end,
  set_more_tries = function() return true end,
  get_last_failure = function() return nil end,
}
local ka2 = require "cfm_origin_ka"
logs = {}
ka2.balance(443)
ka2.balance(443)
ka2.balance(443)
check(raise_count == 1, "3-arg failure latches: raised once, then 2-arg only")
check(ka2.sni_pool_supported() == false, "latch demotes sni_pool_supported()")
check(log_matching("disabling HTTPS pooling") == 1, "latch warns exactly once")

-- ── Scenario 3: 2-param core → HTTPS unpooled, HTTP pooled, NOTICE once ────
package.loaded["cfm_origin_ka"] = nil
local ka_calls = 0
package.loaded["ngx.balancer"] = {
  set_current_peer = function(addr, port) return true end, -- nparams=2
  enable_keepalive = function() ka_calls = ka_calls + 1; return true end,
  set_more_tries = function() return true end,
  get_last_failure = function() return nil end,
}
local ka3 = require "cfm_origin_ka"
check(ka3.sni_pool_supported() == false, "2-param core detected as unsupported")
logs = {}
ka3.balance(443)
ka3.balance(443)
check(ka_calls == 0, "443 on 2-param core: never pooled (no cross-SNI reuse)")
check(log_matching("lacks SNI-keyed") == 1, "no-SNI NOTICE logged exactly once")
ka3.balance(80)
check(ka_calls == 1, "80 on 2-param core: still pooled")

-- ── Scenario 4: enable_keepalive raises → keepalive_broken latch ───────────
package.loaded["cfm_origin_ka"] = nil
local ek_raises = 0
package.loaded["ngx.balancer"] = {
  set_current_peer = function(addr, port, host) return true end,
  enable_keepalive = function()
    ek_raises = ek_raises + 1
    error("missing FFI symbol ngx_http_lua_ffi_balancer_enable_keepalive")
  end,
  set_more_tries = function() return true end,
  get_last_failure = function() return nil end,
}
local ka4 = require "cfm_origin_ka"
logs = {}
ka4.balance(80)
ka4.balance(80)
ka4.balance(80)
check(ek_raises == 1, "enable_keepalive raise latches after first attempt")
check(log_matching("degrading to per-request connections") == 1,
      "keepalive_broken warns exactly once")

if failures > 0 then
  print(string.format("%d failure(s)", failures))
  os.exit(1)
end
print("OK: cfm_origin_ka capability detection, pooling, retry arming and failure latches behave as specified")

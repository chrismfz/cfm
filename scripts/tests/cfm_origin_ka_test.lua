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
-- assert the module's invariants after the 2026-08 421 fix:
--
--   * port 443 is NEVER pooled and NEVER passes a 3rd (SNI host) argument to
--     set_current_peer — this is what makes cross-SNI reuse (Apache 421
--     Misdirected Request) impossible. SNI on 443 comes from
--     proxy_ssl_name $host at the location level, not from the balancer.
--   * port 80 IS pooled (enable_keepalive) with the bridge-config idle/
--     max_reqs knobs (built-in defaults when absent).
--   * dispatch is fail-safe: ONLY port 80 pools; 443 and any other port
--     default to unpooled (correctness-first), so a future balance(<port>)
--     can't silently pool a TLS origin.
--   * the keepalive-race retry arms set_more_tries(1) on the first POOLED
--     (port 80) attempt only — never on any unpooled path.
--   * each path reports its TRUE effective state once per worker at WARN
--     (visible at the default error_log level): unpooled ports "origin port
--     <n>: per-request", 80 "origin pooling active" (or a degraded WARN when
--     the engine lacks enable_keepalive, or a tier-2 WARN when it pools but
--     can't arm the retry).

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

-- ── Scenario 1: modern core (set_current_peer + enable_keepalive OK) ────────
local calls = { set_peer = {}, keepalive = {}, more_tries = {} }
local peer_by_port = {}      -- port -> count of enable_keepalive calls at that port
local host_arg_seen = false  -- true if set_current_peer ever got a non-nil 3rd arg
local last_failure = nil
local cur_port = nil
package.loaded["ngx.balancer"] = {
  set_current_peer = function(addr, port, host)
    calls.set_peer[#calls.set_peer + 1] = { addr = addr, port = port, host = host }
    if host ~= nil then host_arg_seen = true end
    cur_port = port
    return true
  end,
  enable_keepalive = function(idle, reqs)
    calls.keepalive[#calls.keepalive + 1] = { idle = idle, reqs = reqs, port = cur_port }
    peer_by_port[cur_port] = (peer_by_port[cur_port] or 0) + 1
    return true
  end,
  set_more_tries = function(n)
    calls.more_tries[#calls.more_tries + 1] = n
    return true
  end,
  get_last_failure = function() return last_failure end,
}

local ka = require "cfm_origin_ka"

ka.balance(443)
check(#calls.set_peer == 1 and calls.set_peer[1].port == 443
      and calls.set_peer[1].host == nil,
      "443: peer set with the 2-arg form (no SNI host passed to the balancer)")
check(#calls.keepalive == 0,
      "443: NEVER pooled — enable_keepalive not called (no cross-SNI reuse)")
check(#calls.more_tries == 0,
      "443: keepalive-race retry NOT armed on the unpooled path")
check(log_matching("origin port 443: per-request") == 1,
      "visibility: 443 per-request policy WARN emitted once on first 443 balance")

ka.balance(80)
check(calls.set_peer[#calls.set_peer].host == nil and calls.set_peer[#calls.set_peer].port == 80,
      "80: peer set without SNI arg")
check((peer_by_port[80] or 0) == 1, "80: pooling enabled (enable_keepalive at port 80)")
check(#calls.more_tries == 1 and calls.more_tries[1] == 1,
      "80: first attempt arms exactly one keepalive-race retry (set_more_tries(1))")
check(log_matching("HTTP(80) origin pooling active") == 1,
      "visibility: 80 pooled-active WARN emitted once on first 80 balance")

-- Retry attempt on port 80: get_last_failure ~= nil → no additional tries.
last_failure = "failed"
ka.balance(80)
check(#calls.more_tries == 1, "80 retry attempt does not stack more tries")
check(log_matching("HTTP(80) origin pooling active") == 1,
      "80 pooled-active WARN stays once-per-worker across requests")
last_failure = nil

check((peer_by_port[443] or 0) == 0, "443 stayed unpooled across all calls")
check(host_arg_seen == false,
      "set_current_peer is NEVER called with a 3rd host arg (proxy_ssl_name owns SNI)")

-- Bridge-config knob override + memoisation on table identity (port-80 pool).
local cfg_tbl = { clearance_refresh = true, origin_ka_idle_sec = 2, origin_ka_max_reqs = 500 }
package.loaded["cfm_bridge_cfg"].get = function() return cfg_tbl end
ka.balance(80)
local last_ka = calls.keepalive[#calls.keepalive]
check(last_ka.idle == 2 and last_ka.reqs == 500,
      "bridge-config idle/max-reqs override the built-in defaults on the 80 pool")

-- ── Scenario 2: 2-arg-only core → identical behaviour (443 unpooled, 80 pooled)
-- With the capability probe removed, the module never passes a 3rd arg, so a
-- core whose set_current_peer takes only (addr, port) behaves identically. No
-- "lacks SNI-keyed" NOTICE exists anymore (that whole path is gone).
package.loaded["cfm_origin_ka"] = nil
local ka2_ek = 0
local ka2_host_seen = false
package.loaded["ngx.balancer"] = {
  -- Represents an older/plainer core (2 fixed params). The varargs capture
  -- lets us assert the module never passes a 3rd (SNI host) arg.
  set_current_peer = function(addr, port, ...)
    if select("#", ...) > 0 then ka2_host_seen = true end
    return true
  end,
  enable_keepalive = function() ka2_ek = ka2_ek + 1; return true end,
  set_more_tries = function() return true end,
  get_last_failure = function() return nil end,
}
local ka2 = require "cfm_origin_ka"
logs = {}
ka2.balance(443)
ka2.balance(443)
check(ka2_ek == 0, "443: never pooled regardless of core capability")
check(log_matching("lacks SNI-keyed") == 0,
      "the old 'lacks SNI-keyed' NOTICE path is gone")
ka2.balance(80)
check(ka2_ek == 1, "80: still pooled")
check(ka2_host_seen == false, "still never passes a 3rd host arg")

-- ── Scenario 3: enable_keepalive raises → keepalive_broken latch (port 80) ──
package.loaded["cfm_origin_ka"] = nil
local ek_raises = 0
local s3_more_tries = 0
package.loaded["ngx.balancer"] = {
  set_current_peer = function(addr, port) return true end,
  enable_keepalive = function()
    ek_raises = ek_raises + 1
    error("missing FFI symbol ngx_http_lua_ffi_balancer_enable_keepalive")
  end,
  set_more_tries = function() s3_more_tries = s3_more_tries + 1; return true end,
  get_last_failure = function() return nil end,
}
local ka3 = require "cfm_origin_ka"
logs = {}
ka3.balance(80)
ka3.balance(80)
ka3.balance(80)
check(ek_raises == 1, "enable_keepalive raise latches after first attempt")
check(log_matching("degrading to per-request connections") == 1,
      "keepalive_broken warns exactly once")
check(log_matching("HTTP(80) origin pooling active") == 0,
      "no false 'pooling active' claim when enable_keepalive raised")
-- The keepalive-race retry is armed only from enable_pool()'s success path,
-- so a worker that never pools (enable_keepalive raises) must NEVER arm
-- set_more_tries — not even on the first request. This is the connect-doubling
-- anti-pattern the 443 path avoids, now closed on the degraded-80 path too.
check(s3_more_tries == 0,
      "unpooled (raising) port-80 path never arms set_more_tries")

-- ── Scenario 4: enable_keepalive absent entirely → latch + one WARN ─────────
-- The no-enable_keepalive path must NOT be silent (it previously returned with
-- no log, so port 80 ran per-request while the logs claimed nothing).
package.loaded["cfm_origin_ka"] = nil
package.loaded["ngx.balancer"] = {
  set_current_peer = function(addr, port) return true end,
  -- enable_keepalive intentionally ABSENT (not a function)
  set_more_tries = function() return true end,
  get_last_failure = function() return nil end,
}
local ka4 = require "cfm_origin_ka"
logs = {}
ka4.balance(80)
ka4.balance(80)
check(log_matching("engine lacks balancer.enable_keepalive") == 1,
      "no-enable_keepalive path warns exactly once (not silent)")
check(log_matching("HTTP(80) origin pooling active") == 0,
      "no false 'pooling active' claim when enable_keepalive is absent")

-- ── Scenario 4b: enable_keepalive returns nil,err (non-raise) → warn once ───
-- A deterministic error RETURN (not a raise) must NOT latch (the next request
-- may pool fine) but must NOT flood: the WARN is throttled to once per worker,
-- and enable_keepalive keeps being attempted every request.
package.loaded["cfm_origin_ka"] = nil
local ek_calls_4b = 0
local s4b_more_tries = 0
package.loaded["ngx.balancer"] = {
  set_current_peer = function(addr, port) return true end,
  enable_keepalive = function() ek_calls_4b = ek_calls_4b + 1; return nil, "no memory" end,
  set_more_tries = function() s4b_more_tries = s4b_more_tries + 1; return true end,
  get_last_failure = function() return nil end,
}
local ka4b = require "cfm_origin_ka"
logs = {}
ka4b.balance(80)
ka4b.balance(80)
ka4b.balance(80)
check(ek_calls_4b == 3, "non-raise enable_keepalive failure does NOT latch (keeps attempting)")
check(log_matching("enable_keepalive failed") == 1,
      "non-raise enable_keepalive failure warns exactly once/worker (no flood)")
check(log_matching("HTTP(80) origin pooling active") == 0,
      "no false 'pooling active' claim while enable_keepalive keeps failing")
check(s4b_more_tries == 0,
      "unpooled (non-raise-failure) port-80 path never arms set_more_tries")

-- ── Scenario 5: hostless 443 request → unpooled 2-arg set_peer, no error ────
-- $host may be "" (server_name '_' didn't resolve a Host). 443 is unpooled
-- either way; the empty host is irrelevant because the balancer never keys or
-- SNIs on it.
package.loaded["cfm_origin_ka"] = nil
local s5 = { set_peer = {}, keepalive = 0 }
package.loaded["ngx.balancer"] = {
  set_current_peer = function(addr, port, host)
    s5.set_peer[#s5.set_peer + 1] = { addr = addr, port = port, host = host }
    return true
  end,
  enable_keepalive = function() s5.keepalive = s5.keepalive + 1; return true end,
  set_more_tries = function() return true end,
  get_last_failure = function() return nil end,
}
local ka5 = require "cfm_origin_ka"
ngx.var.host = ""
ka5.balance(443)
check(#s5.set_peer == 1 and s5.set_peer[1].port == 443 and s5.set_peer[1].host == nil,
      "hostless 443: 2-arg set_peer, no 3rd arg")
check(s5.keepalive == 0, "hostless 443: not pooled")
ngx.var.host = "example.com"

-- ── Scenario 6: set_current_peer fails on 443 → clean 502 (ngx.exit ERROR) ──
package.loaded["cfm_origin_ka"] = nil
local exited = nil
package.loaded["ngx.balancer"] = {
  set_current_peer = function() return nil, "connect refused" end,
  enable_keepalive = function() return true end,
  set_more_tries = function() return true end,
  get_last_failure = function() return nil end,
}
local prev_exit = ngx.exit
ngx.exit = function(code) exited = code; return code end
local ka6 = require "cfm_origin_ka"
logs = {}
ka6.balance(443)
ngx.exit = prev_exit
check(exited == ngx.ERROR, "443: a hard set_current_peer failure exits with ngx.ERROR (502)")
check(log_matching("set_current_peer(203.0.113.7:443) failed") == 1,
      "443: the set_current_peer failure is logged")

-- ── Scenario 7: fail-safe dispatch — only port 80 pools ─────────────────────
-- Dispatch is `if port == 80 then pool else unpooled`, NOT a `port == 443`
-- special case. So any OTHER port a future caller might pass (e.g. 8443) must
-- default to unpooled: never enable_keepalive, never set_more_tries. This
-- prevents a new balance(<port>) from silently pooling a TLS origin.
package.loaded["cfm_origin_ka"] = nil
local s7 = { keepalive = 0, more_tries = 0, set_peer = {} }
package.loaded["ngx.balancer"] = {
  set_current_peer = function(addr, port)
    s7.set_peer[#s7.set_peer + 1] = port; return true
  end,
  enable_keepalive = function() s7.keepalive = s7.keepalive + 1; return true end,
  set_more_tries = function() s7.more_tries = s7.more_tries + 1; return true end,
  get_last_failure = function() return nil end,
}
local ka7 = require "cfm_origin_ka"
logs = {}
ka7.balance(8443)   -- some future TLS port
check(s7.keepalive == 0, "fail-safe: a non-80 port is NEVER pooled (no enable_keepalive)")
check(s7.more_tries == 0, "fail-safe: a non-80 port never arms set_more_tries")
check(s7.set_peer[1] == 8443, "fail-safe: the peer is still set (request served, just unpooled)")
check(log_matching("origin port 8443: per-request") == 1,
      "fail-safe: the unpooled announce names the actual port")
-- Per-port announce: a worker that saw 8443 first still announces 443 when it
-- appears (announced_unpooled is keyed by port, not a single flag).
ka7.balance(443)
check(log_matching("origin port 443: per-request") == 1,
      "fail-safe: a second unpooled port (443) announces once on its own")
check(log_matching("origin port 8443: per-request") == 1,
      "fail-safe: the 8443 announce stayed once (not re-emitted)")
-- Port 80 through the SAME worker still pools (dispatch didn't break 80).
ka7.balance(80)
check(s7.keepalive == 1, "fail-safe: port 80 still pools alongside the unpooled default")

-- ── Scenario 8: pooled but keepalive-race retry capability missing (tier 2) ─
-- enable_keepalive works (port 80 pools) but the engine lacks get_last_failure/
-- set_more_tries. arm_keepalive_retry() can't arm, so a stale pooled connection
-- could 502 with no retry — a distinct middle tier that must be surfaced with
-- its own once-per-worker WARN, not hidden behind "pooling active".
package.loaded["cfm_origin_ka"] = nil
package.loaded["ngx.balancer"] = {
  set_current_peer = function(addr, port) return true end,
  enable_keepalive = function() return true end,
  -- get_last_failure / set_more_tries intentionally ABSENT
}
local ka8 = require "cfm_origin_ka"
logs = {}
ka8.balance(80)
ka8.balance(80)
check(log_matching("keepalive-race retry is unavailable") == 1,
      "tier 2: pooled-without-retry warns exactly once/worker")
check(log_matching("HTTP(80) origin pooling active") == 1,
      "tier 2: pooling-active is still reported (it IS pooled, just no retry)")

if failures > 0 then
  print(string.format("%d failure(s)", failures))
  os.exit(1)
end
print("OK: cfm_origin_ka pools ONLY port 80 (fail-safe default), never pools 443/other, arms retries only on a real pool, latches/throttles keepalive failures, and reports each path's true state")

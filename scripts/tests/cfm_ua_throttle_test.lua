-- Tests for the lock-free UA-emergency throttle (audit F22).
--
-- The throttle was a per-UA spin-lock + read-modify-write token bucket on the
-- shared cfm_decisions dict (add-lock + up to 10x ngx.sleep(1ms) + get + set +
-- delete per request). Under a same-UA bot wave that thundered on one lock and
-- churned the hot decision dict. It is now a LOCK-FREE fixed-window counter in
-- its OWN dict (cfm_ua_throttle): ONE atomic incr per request, no lock, no sleep.
--
-- We require the real module and drive _M.throttle against a controllable clock
-- and a stub cfm_ua_throttle dict, reading LIMIT/WINDOW from source so the test
-- tracks the real constants.

package.path = package.path .. ";configs/lua/?.lua;./?.lua"

local fails = 0
local function check(cond, msg)
  if not cond then fails = fails + 1; io.stderr:write("FAIL: " .. tostring(msg) .. "\n") end
end

-- Read the rate constants from source so this test can't silently drift.
local BOX_RATE, BOX_BURST
do
  local f = assert(io.open("configs/lua/cfm_ua_emergency.lua", "r"))
  local src = f:read("*a"); f:close()
  BOX_RATE  = tonumber(src:match("BOX_RATE%s*=%s*([%d%.]+)"))
  BOX_BURST = tonumber(src:match("BOX_BURST%s*=%s*(%d+)"))
  assert(BOX_RATE and BOX_BURST, "could not read BOX_RATE/BOX_BURST from cfm_ua_emergency.lua")
end
local WINDOW = math.max(1, math.floor(BOX_BURST / BOX_RATE))
local LIMIT  = BOX_BURST

-- Stub shared dict: incr models a window-keyed counter; add models the log dedup.
local store, incr_fail
local function reset_store() store, incr_fail = {}, false end
reset_store()
local throttle_dict = {
  incr = function(_, k, v, init, _ttl)
    if incr_fail then return nil, "no memory" end
    store[k] = (store[k] or init or 0) + v
    return store[k]
  end,
  add = function(_, k, val, _ttl)
    if store[k] ~= nil then return false end
    store[k] = val; return true
  end,
}

local _now = 1000.0
_G.ngx = {
  now    = function() return _now end,
  time   = function() return math.floor(_now) end,
  log    = function(_, _) end,
  shared = { cfm_ua_throttle = throttle_dict },
  sleep  = function(_) error("throttle must be LOCK-FREE: ngx.sleep must not be called") end,
  timer  = { at = function() return true end },
  WARN = 1, ERR = 2, INFO = 3,
  var  = {},
}
package.loaded["cjson.safe"] = { decode = function() return nil end }

local m = require "cfm_ua_emergency"
assert(type(m.throttle) == "function", "cfm_ua_emergency.throttle missing")

-- ── Exactly LIMIT requests pass per window; the next is throttled ────────────
do
  reset_store(); _now = 1000.0   -- fixed within the window so win is constant
  for i = 1, LIMIT do
    local hit = m.throttle("badbot")
    check(hit == false, "request " .. i .. "/" .. LIMIT .. " within budget must pass (got hit=" .. tostring(hit) .. ")")
  end
  local hit, retry = m.throttle("badbot")
  check(hit == true, "request LIMIT+1 must be throttled")
  check(type(retry) == "number" and retry >= 1 and retry == math.floor(retry),
    "retry_after must be an integer >= 1 (Retry-After header), got " .. tostring(retry))
end

-- ── The next window resets the budget (fresh key) ────────────────────────────
do
  -- still in the SAME store; advancing by WINDOW moves to the next window index.
  _now = 1000.0 + WINDOW
  local hit = m.throttle("badbot")
  check(hit == false, "a new window resets the per-UA budget")
end

-- ── Distinct UAs have independent budgets ────────────────────────────────────
do
  reset_store(); _now = 2000.0
  for _ = 1, LIMIT do m.throttle("bot-a") end
  check(m.throttle("bot-a") == true, "bot-a is throttled after LIMIT in the window")
  check(m.throttle("bot-b") == false, "bot-b has its own independent budget")
end

-- ── incr failure (shdict full) fails OPEN by default (admit) ─────────────────
do
  reset_store(); _now = 3000.0; incr_fail = true
  local hit = m.throttle("anybot")
  check(hit == false, "an incr failure fails open by default (admit, not 429)")
  incr_fail = false
end

-- ── sentinel UAs are never throttled and never touch the dict ────────────────
do
  reset_store(); _now = 4000.0
  check(m.throttle(nil) == false, "nil ua is not throttled")
  check(m.throttle("") == false, "empty ua is not throttled")
  check(m.throttle("-") == false, "'-' ua is not throttled")
  check(next(store) == nil, "sentinel uas never write the dict")
end

-- ── missing dict → fail OPEN + a single diagnostic log (F22 review) ──────────
-- The dedicated dict can genuinely be absent (a hand-edited /etc/cfm conf that
-- didn't pick up the new lua_shared_dict line). That silently disables the
-- throttle, so it must fail open AND warn once per worker rather than no-op.
do
  package.loaded["cfm_ua_emergency"] = nil
  local logs = {}
  local saved_log = _G.ngx.log
  _G.ngx.log = function(_, ...)
    local p = {}
    for i = 1, select("#", ...) do p[i] = tostring((select(i, ...))) end
    logs[#logs + 1] = table.concat(p)
  end
  _G.ngx.shared = { cfm_ua_throttle = nil }   -- dict not declared

  local m2 = require "cfm_ua_emergency"
  local hit1 = m2.throttle("badbot")
  local hit2 = m2.throttle("badbot")
  check(hit1 == false and hit2 == false, "missing dict → throttle fails OPEN (admit, not 429)")

  local warned = 0
  for _, l in ipairs(logs) do
    if l:find("cfm_ua_throttle", 1, true) and l:find("DISABLED", 1, true) then warned = warned + 1 end
  end
  check(warned == 1, "missing dict logs the disabled-throttle warning exactly once per worker, got " .. warned)

  _G.ngx.log = saved_log
  _G.ngx.shared = { cfm_ua_throttle = throttle_dict }
  package.loaded["cfm_ua_emergency"] = nil   -- leave cache clean
end

if fails > 0 then
  io.stderr:write("\n" .. fails .. " test(s) failed in cfm_ua_throttle_test.lua\n")
  os.exit(1)
end
io.stdout:write(string.format("ok: lock-free UA throttle — %d req/%ds window, atomic incr, own dict (F22)\n", LIMIT, WINDOW))

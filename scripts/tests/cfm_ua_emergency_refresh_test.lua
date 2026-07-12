-- Tests for cfm_ua_emergency's refresh scheduling (audit F48).
--
-- refresh_if_needed() used to do a blocking io.open + full read of the rule file
-- in the access phase every REFRESH_INTERVAL_SEC. It now reads synchronously only
-- on the FIRST load per worker (so the very first request is checked), and
-- schedules every later refresh on a background ngx.timer.at(0) (the cfm_h3
-- pattern), serving the current in-memory rules meanwhile.

-- ── Mocks (installed before the module is required) ──────────────────────────
local _now = 1000
local timer_fns = {}
_G.ngx = {
  now   = function() return _now end,
  time  = function() return _now end, -- unix seconds; rule expiry compares against this
  timer = { at = function(_, fn) timer_fns[#timer_fns + 1] = fn; return true end },
  log   = function() end,
  WARN  = 1, ERR = 2, INFO = 3,
  -- The throttle path (unused by these tests) reads ngx.shared.cfm_decisions at load.
  shared = { cfm_decisions = setmetatable({}, { __index = function() return function() end end }) },
}

-- io.open spy over the rule file: returns _file_content (nil => file missing).
local PATH = "/var/lib/cfm/ua_emergency.json"
local _file_content = nil
local _open_count = 0
local _real_open = io.open
io.open = function(path, mode)
  if path == PATH then
    _open_count = _open_count + 1
    if _file_content == nil then return nil end
    return { read = function() return _file_content end, close = function() end }
  end
  return _real_open(path, mode)
end

-- cjson.safe.decode: map known content strings to decoded tables.
local DECODE = {}
package.loaded["cjson.safe"] = { decode = function(s) return DECODE[s] end }

package.path = "configs/lua/?.lua;" .. package.path
local mod = require("cfm_ua_emergency")

local fails = 0
local function check(cond, msg)
  if cond then return end
  fails = fails + 1
  io.stderr:write("FAIL: " .. msg .. "\n")
end

-- Install a rule keyed by the normalized form of our probe UA.
local UA  = "EvilScraper/2.0 (bot)"
local KEY = mod.normalize_ua(UA)
DECODE["RULESET_A"] = { { ua = KEY, action = "block", expires_at_unix = _now + 100000, reason = "t" } }
_file_content = "RULESET_A"

-- ── Cold start: synchronous read, no timer, rule applied to the first request ─
local r = mod.check(UA)
check(_open_count == 1, "cold start: exactly one synchronous read (got " .. _open_count .. ")")
check(#timer_fns == 0, "cold start: no async timer scheduled")
check(r ~= nil and r.action == "block", "cold start: rule loaded and matched on the first request")

-- ── Within the interval: no work ─────────────────────────────────────────────
mod.check(UA)
check(_open_count == 1, "within REFRESH_INTERVAL: no re-read")
check(#timer_fns == 0, "within REFRESH_INTERVAL: no timer")

-- ── After the interval: refresh is DEFERRED to a timer, NOT read synchronously ─
_now = _now + 4
mod.check(UA)
check(_open_count == 1, "F48: after the interval the read is NOT synchronous (deferred) (got " .. _open_count .. ")")
check(#timer_fns == 1, "F48: after the interval an async refresh timer is scheduled")

-- The request still sees the current rules while the refresh is pending.
check(mod.check(UA) ~= nil, "F48: current rules still served while refresh is pending")
-- ...and the dedupe flag prevents stacking a second timer.
check(#timer_fns == 1, "F48: concurrent requests do not stack timers (dedupe)")

-- ── Running the scheduled timer performs the read AND applies a changed file ──
-- Swap in a different ruleset before the timer fires: this proves the async timer
-- actually re-reads + re-parses + swaps _rules (not just that a read was deferred).
-- UA still matches the FIRST ruleset until the timer runs.
check(mod.check(UA) ~= nil, "F48: old rule still matches before the deferred timer runs")
local UA2  = "OtherEvil/9 (spider)"
local KEY2 = mod.normalize_ua(UA2)
DECODE["RULESET_B"] = { { ua = KEY2, action = "block", expires_at_unix = _now + 100000, reason = "t2" } }
_file_content = "RULESET_B"

if timer_fns[1] then timer_fns[1](false) end -- premature = false
check(_open_count == 2, "F48: the scheduled timer performs the deferred read (got " .. _open_count .. ")")
check(mod.check(UA2) ~= nil and mod.check(UA2).action == "block",
      "F48: the async timer applied the changed file (new rule now matches)")
check(mod.check(UA) == nil, "F48: the async timer swapped out the old ruleset (old rule no longer matches)")

-- After the timer ran, a fresh window can schedule again.
_now = _now + 4
mod.check(UA2)
check(#timer_fns == 2, "F48: a later window schedules the next background refresh")

if fails > 0 then
  io.stderr:write("\n" .. fails .. " test(s) failed in cfm_ua_emergency_refresh_test.lua\n")
  os.exit(1)
end
io.stdout:write("ok: cfm_ua_emergency async refresh scheduling (F48)\n")

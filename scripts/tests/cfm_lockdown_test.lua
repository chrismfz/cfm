-- Vhost LOCKDOWN at the edge (internal/webdetector/vhost_lockdown.go):
--   * cfm.lua Step 0 withdraws the crawler ("1") bypass on a locked vhost, so
--     the client meets the vhost challenge; a CDN ("2") keeps its bypass;
--   * any failure of the lockdown module leaves the bypass as it always was;
--   * cfm_lockdown.lua keeps the daemon's host -> expiry set, honours each
--     expiry on its own, and refreshes out of band.

package.path = "configs/lua/?.lua;" .. package.path

local fails = 0
local function check(cond, msg)
  if cond then return end
  fails = fails + 1
  io.stderr:write("FAIL: " .. msg .. "\n")
end

local H = dofile("scripts/tests/cfm_lua_harness.lua")
local function desc(r)
  return ("ok=%s up=%s exit=%s rpcs=%s err=%s"):format(tostring(r.ok), tostring(r.upstream),
    tostring(r.exited), r.rpcs, tostring(r.err))
end
local function bypassed(r) return r.ok and r.upstream == "cfm_apache" and r.rpcs == "" end
local CHAL = { ip_action = "allow", vhost_action = "challenge" }

-- ── Step 0 ────────────────────────────────────────────────────────────────────
do
  local locked = { ["shop.gr"] = true }
  local cases = {
    { name = "crawler, no lockdown",            bp = "1", lock = {},     want = "bypass" },
    { name = "crawler, locked vhost",           bp = "1", lock = locked, want = "held" },
    { name = "CDN, locked vhost",               bp = "2", lock = locked, want = "bypass" },
    { name = "crawler, another vhost locked",   bp = "1", lock = { ["other.gr"] = true }, want = "bypass" },
    { name = "crawler, module fails to load",   bp = "1", lock = nil,    want = "bypass" },
    { name = "crawler, module check raises",    bp = "1", lock = "raise", want = "bypass" },
    { name = "not on the list, locked vhost",   bp = "0", lock = locked, want = "held" },
  }
  for _, c in ipairs(cases) do
    local r = H.run{ host = "shop.gr", vars = { cfm_bypass_ip = c.bp }, lockdown = c.lock, verdict = CHAL }
    if c.want == "bypass" then
      check(bypassed(r), c.name .. ": must keep the Step 0 bypass: " .. desc(r))
    else
      check(r.ok and not bypassed(r) and r.rpcs:find("decision", 1, true) ~= nil,
            c.name .. ": must go on to the bridge decision (the vhost challenge): " .. desc(r))
    end
  end
  -- The lockdown is asked about the request's own host.
  local asked
  H.run{ host = "www.shop.gr", vars = { cfm_bypass_ip = "1" }, verdict = CHAL,
         lockdown = function(h) asked = h; return false end }
  check(asked == "www.shop.gr", "Step 0 asks about the request host, got " .. tostring(asked))
  -- A CDN client never even asks (no lookup on the 2 prefixes).
  asked = nil
  H.run{ host = "shop.gr", vars = { cfm_bypass_ip = "2" }, verdict = CHAL,
         lockdown = function(h) asked = h; return true end }
  check(asked == nil, "a CDN client must not consult the lockdown set")
end

-- ── cfm_lockdown.lua ──────────────────────────────────────────────────────────
do
  local now, timers = 1000, {}
  _G.ngx = {
    now = function() return now end,
    time = function() return now end,
    log = function() end, WARN = 1, ERR = 0,
    timer = { at = function(_, fn) timers[#timers + 1] = fn; return true end },
    socket = { tcp = function() return nil, "no socket in test" end },
  }
  package.loaded["cjson.safe"] = nil
  package.loaded["cfm_lockdown"] = nil
  package.preload["cfm_lockdown"] = nil -- the harness leaves a failing stub
  package.loaded["cfm_hostmatch"] = nil
  package.preload["cjson.safe"] = function() return { decode = function() return nil end } end
  local L = require("cfm_lockdown")

  check(L.active("shop.gr") == false, "empty set: nothing locked")
  check(#timers == 1, "the first lookup schedules a refresh, got " .. #timers)
  L.active("shop.gr")
  check(#timers == 1, "a refresh in flight is not scheduled twice")

  L._rebuild({ ["Shop.GR"] = 1600, ["gone.gr"] = 900, [5] = 2000, ["bad.gr"] = "x" })
  check(L.active("shop.gr") == true, "a host with a future expiry is locked (case-normalized)")
  check(L.active("SHOP.gr.") == true, "the lookup normalizes the request host too (case, trailing dot)")
  check(L.active("gone.gr") == false, "an expired entry is not locked")
  check(L.active("bad.gr") == false, "a non-numeric expiry is dropped")
  check(L.active("other.gr") == false, "an absent host is not locked")
  check(L.active("") == false, "an empty host is not locked")
  now = 1700
  check(L.active("shop.gr") == false, "the entry's own expiry ends the lockdown without a refresh")

  -- The scheduled refresh runs out of band; a failed fetch keeps the last list.
  now = 1000
  L._rebuild({ ["shop.gr"] = 1600 })
  for _, fn in ipairs(timers) do fn(false) end
  check(L.active("shop.gr") == true, "a failed refresh keeps the last list")
end

if fails > 0 then
  io.stderr:write("\n" .. fails .. " test(s) failed in cfm_lockdown_test.lua\n")
  os.exit(1)
end
io.stdout:write("ok: vhost lockdown — Step 0 withdraws the crawler bypass on a locked vhost, CDN keeps it, fail-open; module set/expiry/refresh\n")

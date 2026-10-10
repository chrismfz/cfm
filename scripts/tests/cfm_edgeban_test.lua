-- Tests for cfm_edgeban.lua — the edge's copy of the daemon's edge bans
-- (clients behind a trusted proxy, which the nft drop never sees). Pure
-- luajit: ngx is mocked with a settable clock, the shared dict honours TTLs
-- against that clock, and the bridge RPC is a scripted stub.

package.path = "configs/lua/?.lua;" .. package.path

local unpack = unpack or table.unpack
local clock = 1000
local exited, timers = nil, {}
local function new_dict()
  local store = {}
  local d = {}
  function d:get(k)
    local e = store[k]
    if not e then return nil end
    if e.exp and e.exp <= clock then store[k] = nil; return nil end
    return e.v
  end
  function d:set(k, v, ttl)
    store[k] = { v = v, exp = (ttl and ttl > 0) and (clock + ttl) or nil }
    return true
  end
  function d:add(k, v, ttl)
    if self:get(k) ~= nil then return false, "exists" end
    return self:set(k, v, ttl)
  end
  d._store = store
  return d
end

_G.ngx = {
  shared = {},
  now = function() return clock end,
  var = { remote_addr = "203.0.113.5", realip_remote_addr = "173.245.48.1" },
  header = {},
  escape_uri = function(s) return s end,
  exit = function(code) exited = code; return code end,
  timer = { at = function(delay, cb, ...) timers[#timers + 1] = { cb = cb, args = { ... } }; return true end },
}

local eb = require("cfm_edgeban")

local fails = 0
local function check(c, m)
  if c then return end
  fails = fails + 1
  io.stderr:write("FAIL: " .. m .. "\n")
end

local function reset()
  ngx.shared = { cfm_edgeban = new_dict() }
  ngx.var = { remote_addr = "203.0.113.5", realip_remote_addr = "173.245.48.1" }
  ngx.header = {}
  exited, timers = nil, {}
  clock = 1000
end

-- ── No list yet: nothing is banned (fail open) ──────────────────────────────
reset()
check(eb.check("203.0.113.5") == false, "no list: not banned")

-- ── A list: permanent and timed bans, proxied requests only ─────────────────
reset()
local d = ngx.shared.cfm_edgeban
check(eb.apply(d, { gen = "g1", ips = { ["203.0.113.5"] = 0, ["198.51.100.7"] = clock + 100 } }, clock),
  "apply a new list")
check(eb.check("203.0.113.5"), "permanent ban, proxied: banned")
check(eb.check("198.51.100.7"), "timed ban, proxied: banned")
check(not eb.check("192.0.2.1"), "an address not on the list: not banned")
ngx.var.realip_remote_addr = ngx.var.remote_addr
check(not eb.check("203.0.113.5"), "a direct client is nft's: not banned at the edge")
ngx.var.realip_remote_addr = nil
check(not eb.check("203.0.113.5"), "no realip variable: not banned")

-- ── A timed ban ends at its expiry; every entry fades after ENTRY_TTL_MAX ────
ngx.var.realip_remote_addr = "173.245.48.1"
clock = clock + 101
check(not eb.check("198.51.100.7"), "a timed ban ends at its expiry")
check(eb.check("203.0.113.5"), "a permanent one still holds within ENTRY_TTL_MAX")
clock = 1000 + eb.ENTRY_TTL_MAX + 1
check(not eb.check("203.0.113.5"), "without a refresh the copy fades (daemon unreachable: fail open)")

-- ── A new list switches atomically; an unbanned address stops at once ───────
reset()
d = ngx.shared.cfm_edgeban
eb.apply(d, { gen = "g1", ips = { ["203.0.113.5"] = 0, ["198.51.100.7"] = 0 } }, clock)
local slot1 = eb._current(d)
eb.apply(d, { gen = "g2", ips = { ["203.0.113.5"] = 0 } }, clock)
local slot2, gen2 = eb._current(d)
check(slot1 ~= slot2 and gen2 == "g2", "a new generation goes to the other slot")
check(eb.check("203.0.113.5"), "still banned under the new list")
check(not eb.check("198.51.100.7"), "unbanned in the new list: no longer banned")
-- The live slot is untouched while the next list is written: an address on
-- both lists answers banned throughout.
local live_key = "eb|" .. slot2 .. "|203.0.113.5"
check(d:get(live_key) == "g2", "live slot holds the live generation")
eb.apply(d, { gen = "g3", ips = { ["203.0.113.5"] = 0, ["192.0.2.9"] = 0 } }, clock)
check(d:get(live_key) == "g2", "writing g3 did not touch the slot g2 lives in")
check(eb.check("192.0.2.9") and eb.check("203.0.113.5"), "g3 live")
-- An address left in a reused slot from an older list never matches.
eb.apply(d, { gen = "g4", ips = {} }, clock)
check(not eb.check("203.0.113.5") and not eb.check("192.0.2.9"), "an empty list unbans everyone")
check(not eb.check("198.51.100.7"), "a g1 leftover in the reused slot does not match g4")

-- ── Same generation (periodic full fetch) refreshes in place ────────────────
reset()
d = ngx.shared.cfm_edgeban
eb.apply(d, { gen = "g1", ips = { ["203.0.113.5"] = 0 } }, clock)
local s1 = eb._current(d)
clock = clock + eb.ENTRY_TTL_MAX - 10
eb.apply(d, { gen = "g1", ips = { ["203.0.113.5"] = 0 } }, clock)
check(eb._current(d) == s1, "same generation stays in its slot")
clock = clock + 20
check(eb.check("203.0.113.5"), "the refresh extended the entry's TTL")

-- ── Replies that change nothing ─────────────────────────────────────────────
reset()
d = ngx.shared.cfm_edgeban
eb.apply(d, { gen = "g1", ips = { ["203.0.113.5"] = 0 } }, clock)
for _, r in ipairs({ { gen = "g1", unchanged = true }, { gen = "g9", unchanged = true },
                     { gen = "", ips = {} }, { ips = {} }, { gen = "g9" }, { gen = "g9", ips = "x" } }) do
  check(eb.apply(d, r, clock) == false, "a reply without a usable list changes nothing")
end
check(eb.apply(d, nil, clock) == false, "nil reply changes nothing")
check(eb.check("203.0.113.5"), "the list survives bad replies")
-- An already-expired ban is not written.
eb.apply(d, { gen = "g2", ips = { ["198.51.100.8"] = clock - 1 } }, clock)
check(not eb.check("198.51.100.8"), "an expired ban in the list is not written")

-- ── tick: one poll per POLL_SEC node-wide, a full fetch every FULL_SEC ───────
reset()
d = ngx.shared.cfm_edgeban
local calls = {}
local dec = { rpc = function(_, kind, method, path) calls[#calls + 1] = path; return "BODY" end }
local function decode(body)
  if body ~= "BODY" then return nil end
  return { gen = "g1", ips = { ["203.0.113.5"] = 0 } }
end
eb.tick(dec, decode)
eb.tick(dec, decode)
check(#timers == 1, "two requests in one window schedule one poll")
check(timers[1].args[1] == dec and timers[1].args[2] == decode and timers[1].args[3] == true,
  "the first poll is a full fetch, its state passed as timer arguments")
timers[1].cb(false, unpack(timers[1].args))
check(calls[1] == "/nginx/edgeban", "full fetch carries no ?gen=")
check(eb.check("203.0.113.5"), "the polled list answers")
clock = clock + eb.POLL_SEC
eb.tick(dec, decode)
check(#timers == 2 and timers[2].args[3] == false, "next window: an incremental poll")
timers[2].cb(false, unpack(timers[2].args))
check(calls[2] == "/nginx/edgeban?gen=g1", "incremental poll sends the held generation")
clock = clock + eb.FULL_SEC
eb.tick(dec, decode)
check(timers[3].args[3] == true, "every FULL_SEC a full fetch again (refreshes the entry TTLs)")
-- A premature (worker exiting) or failed poll leaves the list.
timers[3].cb(true, unpack(timers[3].args))
check(#calls == 2, "a premature timer does no RPC")
local bad = { rpc = function() return nil, "timeout" end }
eb._poll_cb(false, bad, decode, true)
check(eb.check("203.0.113.5"), "a failed RPC keeps the list")
-- No dict at all: tick and check do nothing.
ngx.shared = {}
eb.tick(dec, decode)
check(not eb.check("203.0.113.5"), "no dict: not banned")

-- ── Upgrade lag: the conf without cfm_edgeban uses cfm_decisions ────────────
reset()
ngx.shared = { cfm_decisions = new_dict() }
eb.apply(eb._dict(), { gen = "g1", ips = { ["203.0.113.5"] = 0 } }, clock)
check(eb.check("203.0.113.5"), "falls back to cfm_decisions before the conf reload")

-- ── static_gate: 403 for a banned proxied client, nothing otherwise ─────────
reset()
d = ngx.shared.cfm_edgeban
eb.apply(d, { gen = "g1", ips = { ["203.0.113.5"] = 0 } }, clock)
eb.static_gate()
check(exited == 403 and ngx.var.cfm_upstream == "cfm_block" and ngx.header["X-CFM-Edge-Ban"] == "1",
  "static gate blocks a banned proxied client")
exited = nil
ngx.var.remote_addr = "192.0.2.1"
eb.static_gate()
check(exited == nil, "static gate lets anyone else through")

-- ── Placement: where cfm.lua and the confs call it ──────────────────────────
local function read(p) local f = assert(io.open(p)); local t = f:read("*a"); f:close(); return t end
local src = read("configs/lua/cfm.lua")
local function at(pat) return src:find(pat, 1, true) end
local step = at("-- ── Step 0e: Edge ban")
check(step ~= nil, "cfm.lua has the edge-ban step")
if step then
  check(at("decision = require(\"cfm_decision\").new(") < step, "the step comes after the bridge client it polls with")
  check(at("-- ── Step 0: Static IP/CIDR bypass") < step, "after the static IP/CIDR bypass only")
  for _, later in ipairs({ "-- ── Step 0: cPanel / webmail targeted bypass", "-- ── Step 0a: Local-origin hard bypass",
                           "-- ── Step 0a1: /.well-known/ carve-out", "-- ── Step 0d: cPanel proxy-subdomain",
                           "-- ── Step 2b: Honour clearance allow", "-- ── Step 3: Bridge Decision" }) do
    local pos = at(later)
    check(pos ~= nil and step < pos, "the edge-ban step runs before: " .. later)
  end
end
for _, conf in ipairs({ "configs/openresty.conf", "configs/angie.conf" }) do
  local c = read(conf)
  check(c:find("lua_shared_dict cfm_edgeban", 1, true) ~= nil, conf .. ": declares the cfm_edgeban dict")
  local n, pos = 0, 1
  while true do
    local a = c:find('pcall(require, "cfm_edgeban")', pos, true)
    if not a then break end
    n = n + 1
    local g = c:find("eb.static_gate()", a, true)
    local cache = c:find('pcall(require, "cfm_cache")', a, true)
    check(g and cache and g < cache, conf .. ": the edge-ban gate runs before the Site Cache gate")
    pos = a + 1
  end
  check(n == 2, conf .. ": both static-asset locations call the edge-ban gate (got " .. n .. ")")
end

if fails > 0 then
  io.stderr:write(fails .. " failure(s)\n")
  os.exit(1)
end
print("cfm_edgeban_test: OK")

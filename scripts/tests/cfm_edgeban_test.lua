-- Tests for cfm_edgeban.lua — the edge's copy of the daemon's edge bans
-- (clients behind a trusted proxy, which the nft drop never sees). Pure
-- luajit: ngx is mocked with a settable clock, the shared dict honours TTLs
-- against that clock (and can be made to refuse writes, as a full dict
-- does), and the bridge RPC is a scripted stub.

package.path = "configs/lua/?.lua;" .. package.path

local unpack = unpack or table.unpack
local clock = 1000
local exited, timers, logs = nil, {}, {}
local function new_dict()
  local store, d = {}, { full = false }
  function d:get(k)
    local e = store[k]
    if not e then return nil end
    if e.exp and e.exp <= clock then store[k] = nil; return nil end
    return e.v
  end
  function d:set(k, v, ttl)
    if self.full and k:sub(1, 3) == "eb|" then return false, "no memory" end
    if self.failcur and k == "eb:cur" then return false, "no memory" end
    store[k] = { v = v, exp = (ttl and ttl > 0) and (clock + ttl) or nil }
    return true
  end
  function d:delete(k) store[k] = nil end
  function d:add(k, v, ttl)
    if self:get(k) ~= nil then return false, "exists" end
    return self:set(k, v, ttl)
  end
  function d:incr(k, n)
    local v = self:get(k)
    if v == nil then return nil, "not found" end
    store[k].v = v + n
    return v + n
  end
  d._store = store
  return d
end

_G.ngx = {
  shared = {}, header = {}, WARN = 1,
  now = function() return clock end,
  var = {},
  escape_uri = function(s) return s end,
  exit = function(code) exited = code; return code end,
  log = function(_, ...) logs[#logs + 1] = table.concat({ ... }) end,
  timer = { at = function(_, cb, ...) timers[#timers + 1] = { cb = cb, args = { ... } }; return true end },
}

local eb = require("cfm_edgeban")

local fails = 0
local function check(c, m)
  if c then return end
  fails = fails + 1
  io.stderr:write("FAIL: " .. m .. "\n")
end

local d
local function reset()
  d = new_dict()
  ngx.shared = { cfm_edgeban = d }
  ngx.var = { remote_addr = "203.0.113.5", realip_remote_addr = "173.245.48.1" }
  ngx.header = {}
  exited, timers, logs = nil, {}, {}
  clock = 1000
  eb._reset()
end
local function full(epoch, seq, ips, mode)
  return { epoch = epoch, seq = seq, full = true, ips = ips, mode = mode or "enforce" }
end
local function delta(epoch, seq, set, del, mode)
  return { epoch = epoch, seq = seq, set = set or {}, del = del or {}, mode = mode or "enforce" }
end
local function as(ip) ngx.var.remote_addr = ip; return eb.verdict(ip) end

-- ── No list yet: nothing is banned (fail open) ──────────────────────────────
reset()
check(eb.verdict("203.0.113.5") == nil, "no list: not banned")

-- ── A full list: permanent and timed bans, proxied requests only ────────────
reset()
check(eb.apply(d, full("e1", 10, { ["203.0.113.5"] = 0, ["198.51.100.7"] = clock + 100 }), clock), "apply a full list")
check(as("203.0.113.5") == "block", "permanent ban, proxied, enforce: block")
check(as("198.51.100.7") == "block", "timed ban: block")
check(as("192.0.2.1") == nil, "an address not on the list: nothing")
ngx.var.remote_addr = "203.0.113.5"
ngx.var.realip_remote_addr = "203.0.113.5"
check(eb.verdict("203.0.113.5") == nil, "a direct client is nft's: nothing at the edge")
ngx.var.realip_remote_addr = nil
check(eb.verdict("203.0.113.5") == nil, "no realip variable: nothing")
ngx.var.realip_remote_addr = "173.245.48.1"
check(eb.verdict("::ffff:203.0.113.5") == "block", "an IPv4-mapped address matches its IPv4 entry")
clock = clock + 101
check(eb.verdict("198.51.100.7") == nil, "a timed ban ends at its expiry")
clock = clock + 100000
check(eb.verdict("203.0.113.5") == "block", "a permanent ban has no TTL (the daemon down: still enforced, as nft)")

-- ── Mode: log counts and logs, enforce blocks; one log line per minute ─────
reset()
eb.apply(d, full("e1", 1, { ["203.0.113.5"] = 0 }, "log"), clock)
check(eb.verdict("203.0.113.5") == "log", "log mode: would block, not block")
check(not eb.check("203.0.113.5"), "log mode: check is false")
eb.verdict("203.0.113.5")
check(d:get("eb:n:would") == 3, "every would-block counted (got " .. tostring(d:get("eb:n:would")) .. ")")
check(#logs == 1 and logs[1]:find("would_block edge_ban ip=203.0.113.5", 1, true), "one log line per address per minute")
clock = clock + eb.LOG_SEC
eb.verdict("203.0.113.5")
check(#logs == 2, "a minute later: logged again")
eb.apply(d, delta("e1", 1, {}, {}, "enforce"), clock)
check(eb.verdict("203.0.113.5") == "block" and d:get("eb:n:block") == 1, "enforce mode from the next reply")
eb.apply(d, { epoch = "e1", seq = 1, set = {}, del = {}, mode = "bogus" }, clock)
check(eb.verdict("203.0.113.5") == "block", "an unknown mode leaves the mode as it was")
reset()
eb.apply(d, { epoch = "e1", seq = 1, full = true, ips = { ["203.0.113.5"] = 0 } }, clock)
check(eb.verdict("203.0.113.5") == "log", "no mode yet: log (the safe default)")

-- ── Changes onto the live list ──────────────────────────────────────────────
reset()
eb.apply(d, full("e1", 10, { ["203.0.113.5"] = 0, ["198.51.100.7"] = 0 }), clock)
local slot1 = eb._current(d)
check(eb.apply(d, delta("e1", 12, { ["192.0.2.9"] = clock + 60 }, { "198.51.100.7" }), clock), "apply changes")
check(eb._current(d) == slot1, "changes go into the live slot (no flip)")
check(as("192.0.2.9") == "block", "a new ban from the changes")
check(as("198.51.100.7") == nil, "an unban from the changes, at once")
check(as("203.0.113.5") == "block", "untouched entries stay")
check(d:get("eb:pos") == "e1:12", "position advanced")
eb.apply(d, delta("e1", 13, { ["192.0.2.9"] = clock - 1 }), clock)
check(as("192.0.2.9") == nil, "a change to an expired ban removes it")
-- Changes for another epoch (a daemon restart) are not applied.
check(not eb.apply(d, delta("e2", 1, { ["192.0.2.50"] = 0 })), "changes of another epoch are refused")
check(as("192.0.2.50") == nil, "nothing written from them")
-- Changes with no list at all are not applied.
reset()
check(not eb.apply(d, delta("e1", 3, { ["192.0.2.50"] = 0 }), clock), "changes before any full list are refused")

-- ── A new full list flips atomically; leftovers never match ─────────────────
reset()
eb.apply(d, full("e1", 10, { ["203.0.113.5"] = 0, ["198.51.100.7"] = 0 }), clock)
local s1 = eb._current(d)
local live_key = "eb|" .. s1 .. "|203.0.113.5"
eb.apply(d, full("e1", 20, { ["203.0.113.5"] = 0, ["192.0.2.9"] = 0 }), clock)
check(eb._current(d) ~= s1, "a full list goes to the other slot")
check(d:get(live_key) == "e1:10", "writing it did not touch the slot that was live")
check(as("198.51.100.7") == nil and as("192.0.2.9") == "block", "the new list is live")
eb.apply(d, full("e2", 1, {}), clock)
check(as("203.0.113.5") == nil and as("198.51.100.7") == nil, "an empty list: nothing banned, old leftovers never match")

-- ── A refused write keeps the old list and the old position ────────────────
-- (A real dict evicts rather than refuse when full; a refusal is the rare
-- case, e.g. an entry larger than a slab. The live list's protection is the
-- dict size: two copies of the daemon's cap.)
reset()
eb.apply(d, full("e1", 10, { ["203.0.113.5"] = 0 }), clock)
d.full = true
check(not eb.apply(d, full("e1", 20, { ["192.0.2.9"] = 0 }), clock), "a full list that does not fit is not switched to")
check(as("203.0.113.5") == "block" and d:get("eb:pos") == "e1:10", "the old list and position stay")
check(not eb.apply(d, delta("e1", 21, { ["192.0.2.9"] = 0 }), clock), "changes that do not fit")
check(d:get("eb:pos") == "e1:10", "do not advance the position (they come again)")
d.full = false

-- A whole list whose eb:cur write fails does not move the position (changes
-- would go onto the old list from the new position).
reset()
eb.apply(d, full("e1", 10, { ["203.0.113.5"] = 0 }), clock)
d.failcur = true
check(not eb.apply(d, full("e1", 20, { ["192.0.2.9"] = 0 }), clock) and d:get("eb:pos") == "e1:10",
  "a whole list that cannot become live keeps the old position")
d.failcur = false
-- A null / missing expiry is skipped, never made permanent.
eb.apply(d, delta("e1", 11, { ["192.0.2.60"] = "x" }), clock)
check(as("192.0.2.60") == nil, "a non-numeric expiry is skipped")
-- The mode of a "not ready" reply still applies.
eb.apply(d, { ready = false, mode = "log" }, clock)
check(as("203.0.113.5") == "log", "a not-ready reply carries the mode")

-- ── Replies that change nothing ─────────────────────────────────────────────
for _, r in ipairs({ { ready = false }, { epoch = "", seq = 1, full = true, ips = {} }, { seq = 1, full = true, ips = {} },
                     { epoch = "e1", full = true, ips = {} }, { epoch = "e1", seq = 30, full = true, ips = "x" } }) do
  check(eb.apply(d, r, clock) == false, "a reply without a usable list changes nothing")
end
check(eb.apply(d, nil, clock) == false, "nil reply changes nothing")
check(as("203.0.113.5") ~= nil, "the list survives bad replies")

-- ── tick / poll: one poller, a position, counters, a full every FULL_SEC ────
reset()
local calls, replies = {}, {}
local dec = { rpc = function(_, _, _, path) calls[#calls + 1] = path; return table.remove(replies, 1) end }
local function decode(b) return b end -- the stub returns tables already
replies[1] = full("e1", 5, { ["203.0.113.5"] = 0 })
eb.tick(dec, decode)
eb.tick(dec, decode)
check(#timers == 1, "two requests in one window: one poll")
check(timers[1].args[3] == true, "the first poll is a full one")
timers[1].cb(false, unpack(timers[1].args))
check(calls[1]:find("&full=1", 1, true), "full poll asks for the whole list: " .. calls[1])
check(as("203.0.113.5") == "block", "the polled list answers")
check(d:get("eb:n:block") == 1, "a block counted")
clock = clock + eb.POLL_SEC
replies[1] = delta("e1", 6, {}, { "203.0.113.5" })
eb.tick(dec, decode)
check(#timers == 2 and timers[2].args[3] == false, "next window: a poll for the changes (the lock was released)")
timers[2].cb(false, unpack(timers[2].args))
check(calls[2]:find("epoch=e1&seq=5", 1, true) and calls[2]:find("blocked=1", 1, true), "sends position and counters: " .. calls[2])
check(d:get("eb:n:block") == 0, "reported counters are taken off")
check(as("203.0.113.5") == nil, "the unban arrived")
-- A poll in flight holds the lock.
clock = clock + eb.POLL_SEC
eb.tick(dec, decode)
clock = clock + eb.POLL_SEC
eb.tick(dec, decode)
check(#timers == 3, "while a poll is in flight no other starts")
-- A failed RPC keeps everything and reports nothing.

timers[3].cb(false, unpack(timers[3].args)) -- replies is empty: rpc returns nil
check(d:get("eb:pos") == "e1:6", "a failed poll keeps the position")
-- Premature (worker exiting): no RPC, lock released.
clock = clock + eb.POLL_SEC
eb.tick(dec, decode)
local n = #calls
timers[4].cb(true, unpack(timers[4].args))
check(#calls == n and d:get("eb:lock") == nil, "a premature timer does no RPC and releases the lock")
clock = clock + eb.FULL_SEC
eb.tick(dec, decode)
check(timers[5].args[3] == true, "every FULL_SEC a full list again (the consistency check)")
-- eb:cur lost (evicted) while eb:pos survives: the next poll asks for the
-- whole list instead of changes that have nothing to go onto.
d:delete("eb:cur")
d:delete("eb:lock")
clock = clock + eb.POLL_SEC
eb.tick(dec, decode)
timers[#timers].cb(false, unpack(timers[#timers].args))
check(calls[#calls]:find("&full=1", 1, true), "no live list: ask for the whole list: " .. calls[#calls])
-- An invalid expiry in the changes leaves an existing entry alone.
reset()
eb.apply(d, full("e1", 1, { ["203.0.113.5"] = 0 }), clock)
eb.apply(d, delta("e1", 2, { ["203.0.113.5"] = "x" }), clock)
check(as("203.0.113.5") == "block", "a non-numeric expiry in the changes is skipped, not a delete")
-- No dict at all.
ngx.shared = {}
eb.tick(dec, decode)
check(eb.verdict("203.0.113.5") == nil, "no dict: nothing")

-- ── Upgrade lag: the conf without cfm_edgeban uses cfm_decisions ────────────
reset()
ngx.shared = { cfm_decisions = d }
eb.apply(eb._dict(), full("e1", 1, { ["203.0.113.5"] = 0 }), clock)
check(as("203.0.113.5") == "block", "falls back to cfm_decisions before the conf reload")

-- ── step and static_gate ────────────────────────────────────────────────────
reset()
eb.apply(d, full("e1", 1, { ["203.0.113.5"] = 0 }), clock)
check(eb.step("203.0.113.5", nil, decode) == "block", "step without a client still answers")
eb.static_gate()
check(exited == 403 and ngx.var.cfm_upstream == "cfm_block" and ngx.header["X-CFM-Edge-Ban"] == "1",
  "static gate blocks a banned proxied client in enforce mode")
exited = nil
ngx.var.remote_addr = "192.0.2.1"
eb.static_gate()
check(exited == nil, "static gate lets anyone else through")
reset()
eb.apply(d, full("e1", 1, { ["203.0.113.5"] = 0 }, "log"), clock)
eb.static_gate()
check(exited == nil and d:get("eb:n:would") == 1, "static gate in log mode: counts, does not block")
-- A raising ngx.var never escapes.
ngx.var = setmetatable({}, { __index = function() error("API disabled") end })
check(eb.step("203.0.113.5", nil, decode) == nil, "step never raises")

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
  check(src:find('eb.step(ip, decision, cjson.decode) == "block"', step, true) ~= nil, "Step 0e blocks on step()'s block verdict only")
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

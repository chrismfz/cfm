-- A crawler of the bypass list (cfm.lua Step 0, kind "1") on a micro-armed
-- vhost is served from the micro-cache, in its own keyspace (the class the
-- gate gets is "crawler"); a CDN ("2") keeps its plain bypass; a visitor keeps
-- the visitor keyspace at Step 4; a crawler a vhost lockdown holds keeps the
-- crawler keyspace when it reaches Step 4; and a cache module that fails
-- leaves every bypass as it was.

package.path = "configs/lua/?.lua;" .. package.path

local fails = 0
local function check(cond, msg)
  if cond then return end
  fails = fails + 1
  io.stderr:write("FAIL: " .. msg .. "\n")
end

local H = dofile("scripts/tests/cfm_lua_harness.lua")
local function desc(r)
  return ("ok=%s up=%s exec=%s rpcs=%s err=%s"):format(tostring(r.ok), tostring(r.upstream),
    tostring(r.execd), r.rpcs, tostring(r.err))
end

-- a fake gate recording each call's class, answering `target`
local function gate(target)
  local g = { calls = {}, skips = {} }
  g.micro = {
    gate = function(class) g.calls[#g.calls + 1] = tostring(class); return target end,
    skip = function(why) g.skips[#g.skips + 1] = why end,
  }
  return g
end
local ALLOW = { ip_action = "allow", vhost_action = "allow" }
local CHAL = { ip_action = "allow", vhost_action = "challenge" }

-- crawler, armed vhost: served from micro, crawler keyspace, no decision RPC
do
  local g = gate("@cfm_micro_30s")
  local r = H.run{ host = "shop.gr", vars = { cfm_bypass_ip = "1" }, verdict = CHAL, micro = g.micro }
  check(r.ok and r.execd == "@cfm_micro_30s", "crawler on an armed vhost → micro exec: " .. desc(r))
  check(g.calls[1] == "crawler" and #g.calls == 1, "the gate is asked once, with class crawler: " .. table.concat(g.calls, ","))
  check(r.rpcs == "", "the crawler bypass still makes no decision RPC: " .. r.rpcs)
  check(r.upstream == "cfm_apache" and r.pass ~= "", "the origin pass is set before the exec: " .. desc(r))
end

-- crawler, vhost not armed (the gate says no): the plain bypass
do
  local g = gate(nil)
  local r = H.run{ host = "shop.gr", vars = { cfm_bypass_ip = "1" }, verdict = CHAL, micro = g.micro }
  check(r.ok and r.execd == nil and r.upstream == "cfm_apache" and r.rpcs == "", "unarmed: plain bypass: " .. desc(r))
end

-- CDN: never micro-cached at Step 0, the gate is not even asked; mwhy=cdn
do
  local g = gate("@cfm_micro_30s")
  local r = H.run{ host = "shop.gr", vars = { cfm_bypass_ip = "2" }, verdict = CHAL, micro = g.micro }
  check(r.ok and r.execd == nil and r.upstream == "cfm_apache" and r.rpcs == "", "CDN keeps its plain bypass: " .. desc(r))
  check(#g.calls == 0, "the gate is not asked for a CDN client")
  check(g.skips[1] == "cdn", "a CDN client is logged mwhy=cdn: " .. tostring(g.skips[1]))
end

-- a visitor (not on the list): Step 4, visitor keyspace
do
  local g = gate("@cfm_micro_30s")
  local r = H.run{ host = "shop.gr", vars = { cfm_bypass_ip = "0" }, verdict = ALLOW, micro = g.micro }
  check(r.ok and r.execd == "@cfm_micro_30s", "a visitor reaches micro at Step 4: " .. desc(r))
  check(g.calls[1] == "nil", "a visitor gets the visitor keyspace (no class): " .. tostring(g.calls[1]))
end

-- a crawler a lockdown holds: through the steps, crawler keyspace at Step 4
do
  local g = gate("@cfm_micro_30s")
  local r = H.run{ host = "shop.gr", vars = { cfm_bypass_ip = "1" }, lockdown = { ["shop.gr"] = true },
                   verdict = ALLOW, micro = g.micro }
  check(r.ok and r.execd == "@cfm_micro_30s" and r.rpcs ~= "", "a held crawler goes through the decision to Step 4: " .. desc(r))
  check(g.calls[1] == "crawler", "a held crawler keeps the crawler keyspace: " .. tostring(g.calls[1]))
end

-- the gate raises: the bypass stays (the pcall), no exec
do
  local r = H.run{ host = "shop.gr", vars = { cfm_bypass_ip = "1" }, verdict = CHAL,
                   micro = { gate = function() error("boom") end } }
  check(r.ok and r.execd == nil and r.upstream == "cfm_apache" and r.rpcs == "", "a raising gate keeps the bypass: " .. desc(r))
end

-- no cache module at all: the bypass as before
do
  local r = H.run{ host = "shop.gr", vars = { cfm_bypass_ip = "1" }, verdict = CHAL }
  check(r.ok and r.execd == nil and r.upstream == "cfm_apache" and r.rpcs == "", "no cache module: plain bypass: " .. desc(r))
end

if fails > 0 then io.stderr:write(fails .. " failure(s)\n"); os.exit(1) end
io.stdout:write("ok: crawler micro — Step 0 crawler served from micro in its own keyspace, CDN plain bypass, held crawler keeps the class, fail-open\n")

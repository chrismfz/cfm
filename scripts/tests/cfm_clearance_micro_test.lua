-- The clearance fast path (cfm.lua Step 2b) is a Tier B micro entry, in the
-- visitor keyspace, on a conf that declares $cfm_edge_sc: the refreshed
-- cfm_clearance line is set and recorded there before the exec (so the
-- micro location's header filter leaves exactly it out of the store
-- decision). An older conf keeps the old path (origin, mwhy=clearance); a WAF
-- logonly hit still keeps the request out of micro; an unarmed vhost goes to
-- the origin.

package.path = "configs/lua/?.lua;" .. package.path

local fails = 0
local function check(cond, msg)
  if cond then return end
  fails = fails + 1
  io.stderr:write("FAIL: " .. msg .. "\n")
end

local H = dofile("scripts/tests/cfm_lua_harness.lua")
local function desc(r)
  return ("ok=%s up=%s exec=%s action=%s rpcs=%s err=%s"):format(tostring(r.ok), tostring(r.upstream),
    tostring(r.execd), tostring(r.action), r.rpcs, tostring(r.err))
end
local function gate(target)
  local g = { calls = {}, skips = {} }
  g.micro = {
    gate = function(class) g.calls[#g.calls + 1] = tostring(class); return target end,
    skip = function(why) g.skips[#g.skips + 1] = why end,
  }
  return g
end
local CLEARED = { cookie_cfm_clearance = "good" }
local function with(t, extra) local o = {} for k, v in pairs(t) do o[k] = v end for k, v in pairs(extra or {}) do o[k] = v end return o end
local CHAL = { ip_action = "allow", vhost_action = "challenge" }

-- a cleared visitor on an armed vhost, new conf: micro, visitor keyspace, no decision RPC
do
  local g = gate("@cfm_micro_30s")
  local vars = with(CLEARED, { cfm_edge_sc = "" })
  local r = H.run{ clearance = true, vars = vars, verdict = CHAL, micro = g.micro }
  check(r.ok and r.execd == "@cfm_micro_30s", "cleared visitor → micro exec: " .. desc(r))
  check(g.calls[1] == "nil" and #g.calls == 1, "visitor keyspace (no class), asked once: " .. table.concat(g.calls, ","))
  check(not r.rpcs:find("decision", 1, true), "the fast path still makes no decision RPC: " .. r.rpcs)
  check(r.action == "allow_cookie", "reported allow_cookie as before: " .. tostring(r.action))
  local rec = r.vars.cfm_edge_sc
  check(type(rec) == "string" and rec:find("^cfm_clearance=minted;") ~= nil,
        "the refreshed clearance line is recorded in $cfm_edge_sc before the exec: " .. tostring(rec))
  local sc = r.headers["Set-Cookie"]
  check(sc == rec, "the recorded line is exactly the Set-Cookie line on the response: " .. tostring(sc))
end

-- a second edge line in the same request is appended "\n"-joined: the
-- filter's exact-line set reads both (cfm_cache.micro_setcookie_filter)
do
  local g = gate("@cfm_micro_30s")
  local r = H.run{ clearance = true, vars = with(CLEARED, { cfm_edge_sc = "cfm_prev=1; Path=/" }), verdict = CHAL, micro = g.micro }
  local rec = r.vars.cfm_edge_sc
  check(r.ok and r.execd == "@cfm_micro_30s", "cleared visitor with a prior edge line → micro exec: " .. desc(r))
  local lines = {}
  for l in (rec or ""):gmatch("[^\n]+") do lines[#lines + 1] = l end
  check(#lines == 2 and lines[1] == "cfm_prev=1; Path=/" and lines[2]:find("^cfm_clearance=minted;") ~= nil,
        "two edge lines recorded, newline-joined, in order: " .. tostring(rec))
end

-- the same, gate says no (vhost not armed, or a request rail): the origin
do
  local g = gate(nil)
  local r = H.run{ clearance = true, vars = with(CLEARED, { cfm_edge_sc = "" }), verdict = CHAL, micro = g.micro }
  check(r.ok and r.execd == nil and r.upstream == "cfm_apache", "unarmed: the origin: " .. desc(r))
end

-- an older conf (no $cfm_edge_sc): the old path, mwhy=clearance, gate not asked
do
  local g = gate("@cfm_micro_30s")
  local r = H.run{ clearance = true, vars = CLEARED, verdict = CHAL, micro = g.micro }
  check(r.ok and r.execd == nil and r.upstream == "cfm_apache", "older conf: the origin: " .. desc(r))
  check(#g.calls == 0 and g.skips[1] == "clearance", "older conf: gate not asked, mwhy=clearance: " ..
        table.concat(g.calls, ",") .. " / " .. tostring(g.skips[1]))
end

-- a WAF logonly hit on a cleared request: never micro (mwhy=waf)
do
  local g = gate("@cfm_micro_30s")
  local logonly = {
    enabled = function() return true end,
    check = function() return true, "WAF_X:T", 600, "logonly", {}, 999 end,
    should_push = function() return false end,
    also_rule_ids = function() return {} end,
    post_clearance_action = function(a) return a, false end,
  }
  local r = H.run{ waf_fake = logonly, clearance = true, vars = with(CLEARED, { cfm_edge_sc = "" }), verdict = CHAL, micro = g.micro }
  check(r.ok and r.execd == nil and r.upstream == "cfm_apache", "logonly hit: the origin: " .. desc(r))
  check(#g.calls == 0 and g.skips[1] == "waf", "logonly hit: gate not asked, mwhy=waf: " .. tostring(g.skips[1]))
end

-- the gate raises: the origin (pcall), nothing breaks
do
  local r = H.run{ clearance = true, vars = with(CLEARED, { cfm_edge_sc = "" }), verdict = CHAL,
                   micro = { gate = function() error("boom") end } }
  check(r.ok and r.execd == nil and r.upstream == "cfm_apache", "a raising gate: the origin: " .. desc(r))
end

if fails > 0 then io.stderr:write(fails .. " failure(s)\n"); os.exit(1) end
io.stdout:write("ok: clearance micro — Step 2b cleared visitor served from micro (visitor keyspace), refresh recorded first; old conf / logonly / unarmed / raising gate keep the origin\n")

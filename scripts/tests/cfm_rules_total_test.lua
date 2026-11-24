-- Tests for the throttle_total traffic rule at the edge (cfm_rules.lua
-- total_hit): ONE budget for every matching request, per vhost or per node,
-- keyed on the rule id, never on the client. A bot spread over hundreds of IPs
-- (titan, 2026-11-24: Meta, a Chrome/152 scraper) gets one budget, not one each.

local store = {}
local dict = {}
function dict:get(key) local e = store[key]; return e and e.v or nil end
function dict:add(key, v, ttl)
  if store[key] ~= nil then return false, "exists" end
  store[key] = { v = v, ttl = ttl }; return true
end
function dict:incr(key, value, init, ttl)
  local e = store[key]
  if not e then
    if init == nil then return nil, "not found" end
    store[key] = { v = init + value, ttl = ttl }
    return init + value
  end
  e.v = e.v + value
  return e.v
end

local now = 1000.0
_G.ngx = {
  now = function() return now end,
  sleep = function() error("must be lock-free") end,
  log = function() end,
  ERR = 2, WARN = 1, INFO = 3,
  shared = { cfm_decisions = dict },
}
package.path = "configs/lua/?.lua;" .. package.path
package.loaded["cfm_filecache"] = { get = function() return nil end }
local rules = dofile("configs/lua/cfm_rules.lua")
rules.init({})

local fails = 0
local function check(cond, msg)
  if cond then print("ok   - " .. msg) else fails = fails + 1; print("FAIL - " .. msg) end
end

local function total(rule_id, rate, per, host, ip)
  return rules.apply({ rule_action = "throttle", rule_id = rule_id, throttle_rate = rate, throttle_per = per },
    { host = host, ip = ip })
end

-- Node-wide 0.5 r/s = 5 per 10 s window, across clients AND vhosts.
do
  local allowed = 0
  for i = 1, 5 do
    local r = total("r-node", 0.5, "node", "h" .. (i % 2) .. ".example", "203.0.113." .. i)
    if r.action == "allow" then allowed = allowed + 1 end
  end
  check(allowed == 5, "node: the first 5 requests (5 IPs, 2 vhosts) pass")
  local r = total("r-node", 0.5, "node", "h9.example", "198.51.100.77")
  check(r.action == "throttle" and r.retry_after >= 1, "node: the 6th, from a NEW IP on a NEW vhost, gets 429 (one budget)")
end

-- Per vhost: each vhost has its own budget.
do
  local a, b = 0, 0
  for i = 1, 6 do
    if total("r-vh", 0.5, "vhost", "a.example", "203.0.113." .. i).action == "allow" then a = a + 1 end
    if total("r-vh", 0.5, "vhost", "b.example", "203.0.113." .. i).action == "allow" then b = b + 1 end
  end
  check(a == 5 and b == 5, "vhost: 5 pass on each vhost, the 6th of each is refused")
end

-- Two rules never share a budget.
do
  local r = total("r-other", 0.5, "node", "h9.example", "198.51.100.77")
  check(r.action == "allow", "another rule has its own budget")
end

-- A new window refills.
do
  now = now + 10
  check(total("r-node", 0.5, "node", "h1.example", "203.0.113.1").action == "allow", "the next 10 s window refills")
end

-- Malformed or old-daemon decisions fall back to the per-client profile throttle.
do
  local r1 = rules.apply({ rule_action = "throttle", throttle_profile = "hard_bot", throttle_rate = 5, throttle_per = "bogus", rule_id = "x" }, { host = "c.example", ip = "192.0.2.1" })
  check(r1.action == "allow", "an unknown per falls back to the per-client throttle (first request passes)")
  local before = 0
  for k in pairs(store) do if k:match("^tr|hard_bot|c%.example|") then before = before + 1 end end
  check(before == 1, "...and that fallback counted on the per-client key")
  local r2 = rules.apply({ rule_action = "throttle", throttle_rate = 5, throttle_per = "node" }, { host = "d.example", ip = "192.0.2.2" })
  check(r2.action == "allow", "no rule_id falls back to the per-client throttle")
end

-- Keys carry no client (cfm_purge.purge_ip matches a trailing client).
do
  local bad = false
  for k in pairs(store) do
    if k:match("^trt|") and (k:match("203%.0%.113") or k:match("198%.51")) then bad = true end
  end
  check(not bad, "throttle_total keys never name a client")
end

if fails > 0 then print(fails .. " failure(s)"); os.exit(1) end
print("OK: cfm_rules throttle_total")

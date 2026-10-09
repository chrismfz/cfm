-- Tests for cfm_waf.also_rule_ids: the OTHER rules that matched a request
-- behind the headline, which cfm.lua ships on the ip_push so a rule that never
-- owns the headline (a logonly scanner after a stronger rule) is measurable.

_G.ngx = {
  now           = function() return 1000 end,
  decode_base64 = function(_) return nil end,
  log           = function(_, _) end,
  ERR           = 0, WARN = 1, INFO = 2,
}

package.path = "configs/lua/?.lua;" .. package.path
local waf = require("cfm_waf")

local fails = 0
local function check(cond, msg)
  if cond then return end
  fails = fails + 1
  io.stderr:write("FAIL: " .. msg .. "\n")
end
local function same(a, b)
  if #a ~= #b then return false end
  for i = 1, #a do if a[i] ~= b[i] then return false end end
  return true
end
local function show(t) local o = {} for i, v in ipairs(t) do o[i] = tostring(v) end return "{" .. table.concat(o, ",") .. "}" end

-- ── The pure helper ─────────────────────────────────────────────────────────
local function h(id) return { waf_rule_id = id } end
local r = waf.also_rule_ids({ h(404), h(612), h(422), h(612), h(nil), h(0) }, 404)
check(same(r, { 422, 612 }), "drops the headline / nil / 0, de-duplicates, sorts (got " .. show(r) .. ")")
check(#waf.also_rule_ids({ h(404) }, 404) == 0, "only the headline → empty")
check(#waf.also_rule_ids(nil, 404) == 0, "nil hits → empty")
local many = { h(10014) }
for i = 1, 30 do many[#many + 1] = h(100 + i) end
local capped = waf.also_rule_ids(many, 0)
check(#capped == 16, "capped at 16")
-- First 16 in evaluation order, then sorted: a high id that matched early is
-- kept (capping after a sort would drop the 10xxx CVE band first).
check(capped[16] == 10014 and capped[1] == 101, "cap keeps evaluation order, then sorts (got " .. show(capped) .. ")")

-- ── From a real check(): a challenge headline with the 612 tell behind it ───
-- Enable only the XSS rule (challenge_v2) and the 612 tell (logonly). A
-- header-poor Chrome GET with an XSS payload in the query trips both; the XSS
-- rule owns the headline, and 612 is what also_rule_ids must surface.
local snap = waf.get_config()
for k, _ in pairs(snap) do
  if k:sub(1, 5) == "rule_" then waf.set_rule(k, "disabled") end
end
waf.set_rule("rule_xss", "challenge_v2")
waf.set_rule("rule_fetch_metadata_missing", "logonly")
local hit, reason, _, action, hits, rule_id = waf.check({
  uri = "/search", raw_uri = "/search?q=%3Cscript%3Ealert(1)%3C%2Fscript%3E",
  args = "q=%3Cscript%3Ealert(1)%3C%2Fscript%3E", method = "GET", ip = "203.0.113.90", body = "",
  headers = { ["User-Agent"] = "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 " ..
              "(KHTML, like Gecko) Chrome/131.0.0.0 Safari/537.36", ["Accept"] = "text/html" },
})
check(hit == true and action == "challenge_v2", "XSS owns the headline (got " .. tostring(reason) .. "/" .. tostring(action) .. ")")
check(rule_id == 302, "headline rule id 302 (got " .. tostring(rule_id) .. ")")
local also = waf.also_rule_ids(hits, rule_id)
check(same(also, { 612 }), "612 surfaces behind the XSS headline (got " .. show(also) .. ")")

-- ── cfm.lua ships it on the ip_push (structural: cfm.lua needs nginx to run) ─
do
  local f = assert(io.open("configs/lua/cfm.lua", "r"))
  local src = f:read("*a"); f:close()
  check(src:find("local waf_ran, hit, reason, ttl, waf_action, waf_hits, waf_rule_id = xpcall(waf.check, debug.traceback,", 1, true) ~= nil,
        "cfm.lua keeps the check()'s hits list (waf_hits)")
  check(src:find("waf.also_rule_ids(waf_hits, waf_rule_id)", 1, true) ~= nil,
        "cfm.lua computes also_rule_ids from the hits and the headline id")
  check(src:find("push.also_rule_ids = also", 1, true) ~= nil,
        "cfm.lua puts also_rule_ids on the ip_push")
end

if fails > 0 then
  io.stderr:write(("cfm_waf also_rule_ids tests: %d FAILED\n"):format(fails))
  os.exit(1)
end
print("ok: cfm_waf also_rule_ids (behind-the-headline rule ids)")

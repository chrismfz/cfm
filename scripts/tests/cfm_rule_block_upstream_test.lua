-- A request that ONLY a traffic rule blocks is logged with
-- $cfm_upstream = "cfm_block_rule", so the daemon's 403 counters
-- (webdetector isRuleBlock403) skip it and a rule's block never grows into a
-- node-wide nft ban. Every other block (IP, vhost, both with a rule too)
-- stays "cfm_block" and keeps counting.
--
-- Runs the real configs/lua/cfm.lua under a mocked ngx (cfm_lua_harness.lua).

package.path = "configs/lua/?.lua;" .. package.path

local fails = 0
local function check(cond, msg)
  if cond then return end
  fails = fails + 1
  io.stderr:write("FAIL: " .. msg .. "\n")
end

local H = dofile("scripts/tests/cfm_lua_harness.lua")

local function desc(r)
  return ("ok=%s action=%s up=%s exit=%s err=%s"):format(tostring(r.ok), tostring(r.action),
    tostring(r.upstream), tostring(r.exited), tostring(r.err))
end

local cases = {
  { v = { ip_action = "allow", vhost_action = "allow", rule_action = "block", rule_id = "r1" }, up = "cfm_block_rule", what = "rule-only block" },
  { v = { ip_action = "block", vhost_action = "allow" }, up = "cfm_block", what = "IP block" },
  { v = { ip_action = "allow", vhost_action = "block" }, up = "cfm_block", what = "vhost block" },
  { v = { ip_action = "block", vhost_action = "allow", rule_action = "block", rule_id = "r1" }, up = "cfm_block", what = "IP block + rule block" },
  { v = { ip_action = "allow", vhost_action = "block", rule_action = "block", rule_id = "r1" }, up = "cfm_block", what = "vhost block + rule block" },
}
for _, c in ipairs(cases) do
  local r = H.run{ verdict = c.v }
  check(r.ok and r.exited == 403 and r.action == "block" and r.upstream == c.up,
        c.what .. ": 403 with up=" .. c.up .. " (" .. desc(r) .. ")")
end

-- The access-log map that routes blocks to the focused log must match the
-- new name in both confs.
for _, conf in ipairs({ "configs/openresty.conf", "configs/angie.conf" }) do
  local f = assert(io.open(conf, "r"))
  local s = f:read("*a"); f:close()
  check(s:find('"~^cfm_block(_rule)?\\|"', 1, true) ~= nil,
        conf .. ": $log_cfm map must match cfm_block_rule as well as cfm_block")
end

if fails > 0 then
  io.stderr:write(fails .. " failure(s)\n")
  os.exit(1)
end
print("cfm_rule_block_upstream_test: OK")

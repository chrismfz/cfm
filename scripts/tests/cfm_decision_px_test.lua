-- The decision RPC carries px=1 when the request reached the edge through a
-- trusted proxy (realip replaced the TCP peer): the bridge answers its edge
-- ban store only then (internal/edgeban, 2026-10-10). A direct client is
-- nft's alone, so it must never carry px.

package.loaded["cjson.safe"] = {
  decode = function() return { ip_action = "allow", vhost_action = "allow" } end,
  encode = function() return "{}" end,
}
package.path = package.path .. ";configs/lua/?.lua;./?.lua"

_G.ngx = { WARN = 1, ERR = 2, INFO = 3, ctx = {}, header = {}, var = {},
           now = function() return 1000 end, log = function() end,
           md5 = function(s) return tostring(s) end,
           escape_uri = function(s) return tostring(s or "") end }

local cfm_decision = require("cfm_decision")

local fails = 0
local function check(cond, msg) if cond then return end fails = fails + 1; io.stderr:write("FAIL: " .. msg .. "\n") end

local function path_for(var)
  ngx.var = var
  local seen
  local c = cfm_decision.new({ token = "t" .. string.rep("x", 32), fail_open = true, decision_cache_ttl_ms = 0 },
                             { shdict = { get = function() return nil end, set = function() end, add = function() return true end } })
  c.rpc = function(_, _, _, path) seen = path; return "BODY", nil end
  c:get("203.0.113.9", "h", "/u", "", "GET", "https", "ua", "US", "web")
  return seen or ""
end

check(path_for({ remote_addr = "203.0.113.9", realip_remote_addr = "172.70.1.1" }):find("&px=1", 1, true),
      "a request via a trusted proxy carries px=1")
check(not path_for({ remote_addr = "203.0.113.9", realip_remote_addr = "203.0.113.9" }):find("px=", 1, true),
      "a direct client carries no px")
check(not path_for({ remote_addr = "203.0.113.9" }):find("px=", 1, true),
      "no realip variable: no px (fail toward the nft-only path)")
ngx.var = setmetatable({}, { __index = function() error("API disabled") end })
local ok = pcall(path_for, ngx.var)
check(ok, "an unreadable ngx.var does not raise")

if fails > 0 then
  io.stderr:write(("decision px tests: %d FAILED\n"):format(fails))
  os.exit(1)
end
print("ok: the decision RPC marks proxied requests px=1")

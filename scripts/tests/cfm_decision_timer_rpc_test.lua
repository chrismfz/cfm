-- Client:rpc's error path read the request (ngx.var.host / request_uri,
-- real_ip, ngx.ctx / ngx.header, the log_route hook) whatever the caller. The
-- waf_insp flush calls it from a timer, where those raise "API disabled in the
-- current context": a waf_stats error (a daemon restart, a timeout) aborted
-- the timer (edge Lua sweep 2026-10-09). From a timer it now logs with
-- ngx.log and touches nothing of the request's.

package.loaded["cjson.safe"] = { decode = function() return nil end, encode = function() return "{}" end }
package.path = package.path .. ";configs/lua/?.lua;./?.lua"

local LOGS = {}
local function disabled() error("API disabled in the current context") end
_G.ngx = {
  WARN = 1, ERR = 2, INFO = 3,
  now = function() return 1000 end,
  log = function(_, ...) LOGS[#LOGS + 1] = table.concat({ ... }) end,
  escape_uri = function(s) return tostring(s or "") end,
  get_phase = function() return "timer" end,
  var = setmetatable({}, { __index = disabled }),
  ctx = setmetatable({}, { __index = disabled, __newindex = disabled }),
  header = setmetatable({}, { __index = disabled, __newindex = disabled }),
}
local cfm_decision = require("cfm_decision")

local fails = 0
local function check(cond, msg) if cond then return end fails = fails + 1; io.stderr:write("FAIL: " .. msg .. "\n") end

local sh = { get = function() return nil end, set = function() end, add = function() return true end,
             delete = function() end, incr = function() return nil, "not found" end }
for _, dbg in ipairs({ { debug = false, debug_headers = false }, { debug = true, debug_headers = true } }) do
  LOGS = {}
  local routed = false
  local c = cfm_decision.new(dbg, { shdict = sh, real_ip = disabled,
                                    log_route = function() routed = true end })
  c.http = function() return nil, "timeout" end
  local ok, resp, err = pcall(c.rpc, c, "waf_stats", "POST", "/nginx/waf/stats", "{}", { ip = "-", host = "-", uri = "/x" })
  check(ok and resp == nil and err == "timeout",
        "an RPC error from a timer returns the error (debug=" .. tostring(dbg.debug) .. ": " .. tostring(resp) .. ")")
  check(not routed, "the request's log_route hook is not called from a timer")
  if dbg.debug then
    local seen = false
    for _, l in ipairs(LOGS) do if l:find("rpc_err kind=waf_stats", 1, true) then seen = true end end
    check(seen, "debug: the error is logged with ngx.log")
  end
  -- Without the caller's context the error path must not read the request either.
  ok = pcall(c.rpc, c, "waf_stats", "POST", "/nginx/waf/stats", "{}")
  check(ok, "an RPC error from a timer without a req_ctx does not raise")
end

if fails > 0 then
  io.stderr:write(("decision timer rpc tests: %d FAILED\n"):format(fails))
  os.exit(1)
end
print("ok: an RPC error from a timer touches nothing of the request's")

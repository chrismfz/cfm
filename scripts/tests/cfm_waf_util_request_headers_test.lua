-- cfm_waf_util.waf_request_headers: ngx.req.get_headers() stops at 100 header
-- lines ("truncated") while nginx forwards them all. The WAF retries with up
-- to WAF_MAX_HEADER_LINES and reports a request with even more as too_many
-- (the callers refuse it), so no header hides past line 100.

_G.ngx = { log = function() end, ERR = 0, WARN = 1, INFO = 2 }
package.path = "configs/lua/?.lua;" .. package.path
local util = require("cfm_waf_util")

local fails = 0
local function check(c, m)
  if c then return end
  fails = fails + 1
  io.stderr:write("FAIL: " .. m .. "\n")
end

-- A fake request with `n` header lines: get_headers(max) (default 100) returns
-- the first `max` and "truncated" past it.
local function req(n)
  local calls = {}
  return {
    calls = calls,
    get_headers = function(max)
      max = max or 100
      calls[#calls + 1] = max
      local h = {}
      for i = 1, math.min(n, max) do h["x-h" .. i] = "v" end
      if n > max then return h, "truncated" end
      return h
    end,
  }
end

local r = req(30)
local h, too_many = util.waf_request_headers(r)
check(h["x-h30"] == "v" and not too_many and #r.calls == 1, "30 lines: one read, all headers, not too many")

r = req(150)
h, too_many = util.waf_request_headers(r)
check(h["x-h150"] == "v", "150 lines: the header on line 150 is read")
check(not too_many, "150 lines: not too many")
check(r.calls[2] == util.WAF_MAX_HEADER_LINES, "150 lines: re-read with the larger cap")

r = req(util.WAF_MAX_HEADER_LINES + 1)
h, too_many = util.waf_request_headers(r)
check(too_many, "more than WAF_MAX_HEADER_LINES lines: too_many")

if fails > 0 then
  io.stderr:write(("cfm_waf_util request headers tests: %d FAILED\n"):format(fails))
  os.exit(1)
end
print("ok: cfm_waf_util.waf_request_headers reads past 100 header lines, refuses past the cap")

-- cfm_waf_util.waf_request_headers: ngx.req.get_headers() alone stops at 100
-- header lines ("truncated") while nginx forwards them all. The WAF reads up to
-- CFG.max_header_lines (default 1000) in one call and reports a request with
-- more as too_many, and as to-be-refused under max_header_lines_mode = block;
-- 0 turns the check off.

_G.ngx = { log = function() end, ERR = 0, WARN = 1, INFO = 2 }
package.path = "configs/lua/?.lua;" .. package.path
local util = require("cfm_waf_util")

local fails = 0
local function check(c, m)
  if c then return end
  fails = fails + 1
  io.stderr:write("FAIL: " .. m .. "\n")
end

-- A fake request with `n` header lines: get_headers(max) (default 100)
-- returns the first `max` and "truncated" past it.
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

local cfg = { max_header_lines = 1000 }
util.init(cfg)

local r = req(150)
local h, too_many = util.waf_request_headers(r)
check(h["x-h150"] == "v", "150 lines: the header on line 150 is read")
check(not too_many, "150 lines: not too many")
check(#r.calls == 1 and r.calls[1] == 1000, "one read, capped at max_header_lines")

local blk
h, too_many, blk = util.waf_request_headers(req(1001))
check(too_many and not blk, "1001 lines: too_many, not refused under the default logonly mode")
cfg.max_header_lines_mode = "block"
h, too_many, blk = util.waf_request_headers(req(1001))
check(too_many and blk, "1001 lines under max_header_lines_mode = block: refused")
h, too_many, blk = util.waf_request_headers(req(999))
check(not too_many and not blk, "999 lines under block mode: passed")

cfg.max_header_lines = 0
h, too_many = util.waf_request_headers(req(5000))
check(not too_many and h["x-h1000"] == "v", "max_header_lines = 0: no refusal, the first 1000 lines read")

cfg.max_header_lines = 20
r = req(150)
h, too_many = util.waf_request_headers(r)
check(r.calls[1] == 100 and too_many, "a cap below 100 is raised to 100 (never fewer than before)")

if fails > 0 then
  io.stderr:write(("cfm_waf_util request headers tests: %d FAILED\n"):format(fails))
  os.exit(1)
end
print("ok: cfm_waf_util.waf_request_headers reads up to max_header_lines, refuses past it")

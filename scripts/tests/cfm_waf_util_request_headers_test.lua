-- cfm_waf_util.waf_request_headers: ngx.req.get_headers() stops at 100 header
-- lines ("truncated"); the body headers the WAF needs (Content-Type,
-- Content-Length, Transfer-Encoding) are then taken from nginx's own parse.

_G.ngx = { log = function() end, ERR = 0, WARN = 1, INFO = 2 }
package.path = "configs/lua/?.lua;" .. package.path
local util = require("cfm_waf_util")

local fails = 0
local function check(c, m)
  if c then return end
  fails = fails + 1
  io.stderr:write("FAIL: " .. m .. "\n")
end

local var = {
  http_content_type = "multipart/form-data; boundary=b",
  http_content_length = "123",
  http_transfer_encoding = nil,
}
local function req(h, err) return { get_headers = function() return h, err end } end

local h = util.waf_request_headers(req({ ["x-pad"] = { "1", "2" } }, "truncated"), var)
check(h["content-type"] == "multipart/form-data; boundary=b", "truncated: Content-Type backfilled from $http_content_type")
check(h["content-length"] == "123", "truncated: Content-Length backfilled")
check(h["transfer-encoding"] == nil, "truncated: an absent header stays absent")

h = util.waf_request_headers(req({ ["content-type"] = "application/x-www-form-urlencoded" }, "truncated"), var)
check(h["content-type"] == "application/x-www-form-urlencoded", "truncated: a header already seen is kept")

h = util.waf_request_headers(req({ ["x-a"] = "b" }, nil), var)
check(h["content-type"] == nil, "not truncated: nothing is added")

if fails > 0 then
  io.stderr:write(("cfm_waf_util request headers tests: %d FAILED\n"):format(fails))
  os.exit(1)
end
print("ok: cfm_waf_util.waf_request_headers backfills body headers past 100 lines")

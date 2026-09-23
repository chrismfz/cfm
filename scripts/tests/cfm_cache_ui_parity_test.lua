-- The edge side of scripts/tests/fixtures/site_cache_ui_parity.txt: every
-- `bucket` case is the micro TTL bucket cfm_cache.lua snaps a stored TTL to.
-- site-cache-model.test.js runs the same cases through the cfm-admin page's
-- microBucketSeconds, so the page shows the bucket the edge really uses.

package.path = "configs/lua/?.lua;" .. package.path

_G.ngx = nil
package.preload["cjson.safe"] = function()
  return { decode = function() return nil end, encode = function() return "{}" end }
end

local cache = require("cfm_cache")

local fails, n = 0, 0
local function check(c, m)
  if c then return end
  fails = fails + 1
  io.stderr:write("FAIL: " .. m .. "\n")
end

local f = assert(io.open("scripts/tests/fixtures/site_cache_ui_parity.txt", "r"))
local lineno = 0
for line in f:lines() do
  lineno = lineno + 1
  if line ~= "" and line:sub(1, 1) ~= "#" then
    local kind, input, want = line:match("^([^\t]*)\t([^\t]*)\t([^\t]*)$")
    check(kind ~= nil, "fixture line " .. lineno .. ": want 3 TAB-separated fields")
    if kind == "bucket" then
      n = n + 1
      if input == "<empty>" then input = "" end
      local got = cache._micro_bucket(input)
      check(got == tonumber(want),
        string.format("line %d: micro bucket for %q = %s, want %s", lineno, input, tostring(got), want))
    end
  end
end
f:close()
check(n > 0, "fixture has no bucket cases")

if fails > 0 then
  io.stderr:write(fails .. " failure(s)\n")
  os.exit(1)
end
print("cfm_cache_ui_parity_test: ok (" .. n .. " bucket cases)")

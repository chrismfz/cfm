-- cfm_waf_util.url_decode_once decodes %XX through the HEX_BYTE lookup table
-- (a gsub with a table replacement, no Lua call per escape). It must decode
-- exactly as the function form it replaced, string.char(tonumber(h, 16)):
-- every byte pair after a `%` (hex or not, either case), and random strings
-- with malformed escapes, a trailing `%`, `%%`, NULs and high bytes.

_G.ngx = { log = function() end, ERR = 0, WARN = 1, INFO = 2 }
package.path = "configs/lua/?.lua;" .. package.path
local util = require("cfm_waf_util")

local function reference(s)
  return (s:gsub("%%(%x%x)", function(h) return string.char(tonumber(h, 16)) end))
end

local fails = 0
local function check(cond, msg)
  if cond then return end
  fails = fails + 1
  if fails <= 10 then io.stderr:write("FAIL: " .. msg .. "\n") end
end

for a = 0, 255 do
  for b = 0, 255 do
    local s = "x%" .. string.char(a, b) .. "y"
    check(util.url_decode_once(s) == reference(s), ("pair %d,%d"):format(a, b))
  end
end

math.randomseed(19632)
local alphabet = { "%", "%%", "%2", "%2e", "%2E", "%aF", "%g1", "%0", "%00", "%ff", "a", "Z", "+", "\0", "\255", "&", "=" }
for _ = 1, 20000 do
  local parts = {}
  for i = 1, math.random(0, 24) do parts[i] = alphabet[math.random(#alphabet)] end
  local s = table.concat(parts)
  check(util.url_decode_once(s) == reference(s), "random " .. s:gsub("%c", "?"))
end

if fails > 0 then
  io.stderr:write(("cfm_waf hex decode tests: %d FAILED\n"):format(fails))
  os.exit(1)
end
print("ok: url_decode_once (HEX_BYTE table) decodes exactly as string.char(tonumber(h, 16))")

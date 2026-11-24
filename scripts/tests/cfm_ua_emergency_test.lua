-- Standalone parity test for cfm_ua_emergency.normalize_ua against the
-- Go-side NormalizeUA. Run with:
--   lua5.1 scripts/tests/cfm_ua_emergency_test.lua
--
-- This is a host-side smoke test, not loaded by nginx. It stubs out the
-- ngx APIs the module touches.

package.path = package.path .. ";configs/lua/?.lua;./?.lua"

-- Stub ngx surface enough to load the module.
_G.ngx = {
  now    = function() return os.time() end,
  time   = function() return os.time() end,
  log    = function(_, _) end,
  shared = { cfm_decisions = nil },
  sleep  = function(_) end,
  WARN   = 1, ERR = 2, INFO = 3,
  var    = {},
}

-- cjson.safe stub: real one isn't needed for the normalize_ua tests.
package.loaded["cjson.safe"] = {
  decode = function(s)
    if not s or s == "" then return nil end
    return nil  -- not exercised by these tests
  end,
}

local m = require "cfm_ua_emergency"

-- scripts/tests/fixtures/ua_norm.txt is shared with Go's ua_norm_test.go:
-- the edge and the daemon must key every UA the same way.
local ESC = { n = "\n", r = "\r", t = "\t", v = "\v", f = "\f", ["\\"] = "\\" }
-- unescape decodes \n \r \t \v \f \\ and \xHH, like Go's unescapeUAFixture.
local function unescape(s)
  local out, i = {}, 1
  while i <= #s do
    local c = s:sub(i, i)
    if c ~= "\\" or i == #s then
      out[#out + 1] = c
      i = i + 1
    else
      local e = s:sub(i + 1, i + 1)
      if e == "x" then
        local hex = s:sub(i + 2, i + 3)
        assert(hex:match("^%x%x$"), "bad \\x escape in " .. s)
        out[#out + 1] = string.char(tonumber(hex, 16))
        i = i + 4
      else
        assert(ESC[e], "unknown escape \\" .. e .. " in " .. s)
        out[#out + 1] = ESC[e]
        i = i + 2
      end
    end
  end
  return table.concat(out)
end

local cases = {}
for line in io.lines("scripts/tests/fixtures/ua_norm.txt") do
  if line ~= "" and line:sub(1, 1) ~= "#" then
    local tab = string.find(line, "\t", 1, true)
    assert(tab, "fixture line without a tab: " .. line)
    cases[#cases + 1] = { unescape(line:sub(1, tab - 1)), unescape(line:sub(tab + 1)) }
  end
end
assert(#cases >= 30, "fixture read only " .. #cases .. " cases")

local pass, fail = 0, 0
for _, c in ipairs(cases) do
  local got = m.normalize_ua(c[1])
  if got == c[2] then
    pass = pass + 1
  else
    fail = fail + 1
    io.stderr:write(string.format("FAIL  normalize_ua(%q) = %q, want %q\n", c[1], got, c[2]))
  end
end

io.stdout:write(string.format("pass=%d fail=%d\n", pass, fail))
os.exit(fail == 0 and 0 or 1)

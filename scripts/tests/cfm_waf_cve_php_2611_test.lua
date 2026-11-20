-- Tests for the logonly burn-in rules of the php-src advisories published
-- 2026-11-19 (WAF_CVE, all logonly):
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
local function fires(c, label, reason)
  local hit, got, _, act = waf.check(c)
  check(hit == true, label .. " — hit=true (got " .. tostring(hit) .. ")")
  check(got == reason, label .. " — reason=" .. reason .. " (got " .. tostring(got) .. ")")
  check(act == "logonly", label .. " — action=logonly (got " .. tostring(act) .. ")")
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
local function fcgi(rtype, content)
  local n = #content
  return string.char(1, rtype, 0, 1, math.floor(n / 256), n % 256, 0, 0) .. content
end
local function pair(name, value) return string.char(#name, #value) .. name .. value end
local BEGIN = fcgi(1, string.char(0, 1, 1, 0, 0, 0, 0, 0)) -- role RESPONDER, keep-conn
local PARAMS = fcgi(4, pair("SCRIPT_FILENAME", "/home/u/public_html/index.php") ..
                       pair("PHP_ADMIN_VALUE", "allow_url_include=1\nauto_prepend_file=php://input"))

-- ── 10031 ───────────────────────────────────────────────────────────────────
set_only({ rule_cve_php_fpm_smuggle = "logonly" })
fires(req("POST", field("a", "1") .. GARBLED .. BEGIN .. PARAMS),
      "garbled multipart + FastCGI request in the body", "WAF_CVE:CVE_2026_129289:PHP:FCGI_BEGIN_REQUEST")
fires(req("POST", field("a", "1") .. GARBLED .. PARAMS), "FastCGI PARAMS record alone", "WAF_CVE:CVE_2026_129289:PHP:FCGI_PARAMS")
-- a value over 127 bytes takes a four-byte length
local long = string.rep("x", 200)
fires(req("POST", "zz" .. string.char(15, 128, 0, 0, 200) .. "SCRIPT_FILENAME" .. long),
      "four-byte value length", "WAF_CVE:CVE_2026_129289:PHP:FCGI_PARAMS")
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
set_only({ rule_cve_php_oversized_auth = "logonly" })
local limit = 8192 - #"Authorization: "
fires(req("GET", "", { Authorization = "Basic " .. string.rep("A", limit) }),
      "Basic over 8 KB", "WAF_CVE:CVE_2026_129496:PHP:BASIC_OVERSIZE")
fires(req("GET", "", { authorization = "Bearer " .. string.rep("A", limit) }),
      "Bearer over 8 KB", "WAF_CVE:CVE_2026_129496:PHP:OVERSIZE")
clean(req("GET", "", { Authorization = string.rep("A", limit) }), "exactly at the 8 KB line")
clean(req("GET", "", { Authorization = "Basic dXNlcjpwYXNz" }), "a normal Basic header")
clean(req("GET", "", { Authorization = "Bearer " .. string.rep("A", 4000) }), "a 4 KB JWT")
-- a repeated header: each line on its own
fires(req("GET", "", { Authorization = { "Basic YQ==", "Basic " .. string.rep("A", limit) } }),
      "oversized second Authorization line", "WAF_CVE:CVE_2026_129496:PHP:BASIC_OVERSIZE")

-- ── 10033 ───────────────────────────────────────────────────────────────────
set_only({ rule_cve_php_multipart_desync = "logonly" })
-- PHP 8.3.6 registers only "a" here: the garbled part ends the parse
fires(req("POST", field("a", "1") .. GARBLED .. "zz\r\n" .. field("b", "2") .. CLOSE),
      "garbled part mid-body", "WAF_CVE:CVE_2026_129289:PHP:GARBLED_STOP")
fires(req("POST", GARBLED .. "zz\r\n" .. CLOSE), "garbled first part", "WAF_CVE:CVE_2026_129289:PHP:GARBLED_STOP")
fires(req("POST", field("a", "1") .. CLOSE, { ["Content-Type"] = "multipart/form-data" }),
      "no boundary parameter", "WAF_CVE:CVE_2026_129289:PHP:NO_BOUNDARY")
fires(req("POST", "hello world, no parts here\r\n"), "no boundary line at all", "WAF_CVE:CVE_2026_129289:PHP:NO_PART")
-- PHP reads on in all of these (8.3.6): no stop, no hit
clean(req("POST", field("a", "1") .. field("b", "2") .. CLOSE), "a normal form")
clean(req("POST", field("a", "1") .. "--XB\r\nX-Foo: y\r\n\r\nzz\r\n" .. field("b", "2") .. CLOSE),
      "a part with no Content-Disposition (PHP skips it)")
clean(req("POST", field("a", "1") .. CLOSE .. field("b", "2") .. CLOSE), "bytes after the closing boundary")
clean(req("POST", field("a", "1") .. GARBLED .. "\r\n"), "garbled part with only whitespace after")
clean(req("POST", "   \r\n"), "a blank body")
clean(req("POST", "a=1", { ["Content-Type"] = "application/x-www-form-urlencoded" }), "urlencoded")

if fails > 0 then
  io.stderr:write(fails .. " failure(s)\n")
  os.exit(1)
end
print("cfm_waf_cve_php_2611_test: OK")

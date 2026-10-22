-- Tests for rule 330 rule_xss_body (WAF_XSS_BODY, logonly): explicit XSS
-- markup in a POST body, which rule 302 (path + query) never read. On
-- 2026-10-22 a stored-XSS payload posted in Live Helper Chat's chat-start
-- email field (`x" onmouseover="alert(document.domain)" data-x="`) ran in the
-- operator's browser with no WAF line at all.
--
-- Driven through the real cfm_waf.check with every other rule disabled.

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

local snap = waf.get_config()
for k, _ in pairs(snap) do
  if k:sub(1, 5) == "rule_" then waf.set_rule(k, "disabled") end
end
check(snap.rule_xss_body == "logonly", "rule_xss_body ships logonly (got " .. tostring(snap.rule_xss_body) .. ")")
waf.set_rule("rule_xss_body", "logonly")

local function post(body, opts)
  opts = opts or {}
  return {
    uri = opts.uri or "/index.php/chat/chatwidget/(department)/1",
    args = opts.args or "",
    method = "POST",
    ip = "203.0.113.91",
    cookie = opts.cookie or "",
    headers = { ["content-type"] = opts.ct or "application/x-www-form-urlencoded" },
    body = body,
  }
end

local function fires(ctx, tag, label)
  local hit, reason, _, action = waf.check(ctx)
  check(hit == true, label .. " — hit (got " .. tostring(hit) .. ")")
  check(reason == "WAF_XSS_BODY:" .. tag, label .. " — reason WAF_XSS_BODY:" .. tag .. " (got " .. tostring(reason) .. ")")
  check(action == "logonly", label .. " — logonly (got " .. tostring(action) .. ")")
end
local function clean(ctx, label)
  local hit, reason = waf.check(ctx)
  check(hit ~= true, label .. " — must not fire (got " .. tostring(reason) .. ")")
end

-- ── The LHC payload, as the widget posts it (urlencoded, `+` for blanks) ─────
fires(post("Email=x%22+onmouseover%3D%22alert(document.domain)%22+data-x%3D%22&Question=hi"),
  "ATTR_BREAKOUT", "LHC email field, urlencoded")
fires(post("Email=x\" onmouseover=\"alert(1)\" data-x=\""), "ATTR_BREAKOUT", "raw quotes")
fires(post("name=a'onfocus=alert(1) autofocus x='"), "ATTR_BREAKOUT", "single quote, no blank")
fires(post("q=%2522%2520onerror%253Dalert(1)"), "ATTR_BREAKOUT", "double-encoded")
fires(post('{"email":"x\\" onmouseover=\\"alert(1)"}', { ct = "application/json" }),
  "ATTR_BREAKOUT", "JSON body, escaped quote")
fires(post("comment=%3Cscript%3Ealert(1)%3C%2Fscript%3E"), "SCRIPT_TAG", "<script> in a comment")
fires(post("comment=<SCRIPT src=//evil/x.js>"), "SCRIPT_TAG", "<SCRIPT src=")
fires(post("url=%22+href%3D%22javascript:alert(1)"), "JS_URI", "javascript: href")
fires(post("--b\r\nContent-Disposition: form-data; name=\"email\"\r\n\r\nx\" onclick=\"alert(1)\r\n--b--\r\n",
  { ct = "multipart/form-data; boundary=b" }), "ATTR_BREAKOUT", "multipart field")

fires(post("comment=%3Cscript+src%3D%2F%2Fevil%2Fx.js%3E%3C%2Fscript%3E"), "SCRIPT_TAG",
  "<script src=…> as a form posts it (blank as +)")
fires(post("Email=x%22+autofocus+onfocus%3D%22alert(1)"), "ATTR_BREAKOUT",
  "breakout with an attribute before the handler")
fires(post("Email=x%22+onmouseover+%3Dalert(1)"), "ATTR_BREAKOUT", "`+` before the =")
fires(post("Email=x%22+onclick%3D1", { uri = "/wp-admin/admin-post.php" }), "ATTR_BREAKOUT",
  "anonymous admin-post (front-end forms post there) is scanned")
clean(post("text=%22hi%22+then+online%3D1"), "a quoted word, then a non-handler on…=")

-- ── Not markup ──────────────────────────────────────────────────────────────
clean(post("Email=user%40example.com&Question=Hello%2C+I+need+help"), "an ordinary form")
clean(post('{"onclick":"track","online":true}', { ct = "application/json" }), "a JSON key named like a handler")
clean(post("text=he said \"online=yes\" and left"), "on…= that is not a handler")
clean(post("text=the scripture says"), "<script needs a tag")
clean(post("text=see <scripts/> folder"), "<scripts is not <script")
clean(post("note=I+like+javascript:+the+good+parts"), "javascript: in prose")
fires(post("website=javascript:alert(1)"), "JS_URI", "a field that is a javascript: URL")
fires(post("comment=%3Cimg+src%3Dx+onerror%3Dalert(1)%3E"), "TAG_HANDLER", "<img onerror=>")
fires(post("comment=<svg/onload=alert(1)>"), "TAG_HANDLER", "<svg/onload=>")
clean(post("comment=a+<b>bold</b>+and+<i>online=1</i>"), "plain tags, no handler")
clean({ uri = "/x", args = "", method = "GET", ip = "203.0.113.91", headers = {},
        body = "" }, "a GET has no body")
-- The query is rule 302's: a GET payload does not fire 330.
clean({ uri = "/x", args = "q=%22+onmouseover%3D1", method = "GET", ip = "203.0.113.91",
        headers = {}, body = "" }, "a query payload is not 330's")

-- ── Editors and admins ──────────────────────────────────────────────────────
local markup = "content=%3Cp+onclick%3D%22x()%22%3E%3Cscript%3Ea()%3C%2Fscript%3E"
clean(post(markup, { uri = "/wp-admin/admin-ajax.php", cookie = "wordpress_logged_in_abc=admin%7C1" }),
  "a logged-in WordPress user (page builder via admin-ajax)")
clean(post(markup, { uri = "/wp-json/wp/v2/posts/12", cookie = "wordpress_logged_in_abc=x" }),
  "a logged-in WordPress user (REST editor)")
clean(post(markup, { uri = "/wp-admin/post.php" }), "WordPress admin page")
clean(post(markup, { uri = "/administrator/index.php" }), "Joomla administrator")
do
  local c = post(markup, { uri = "/wp-json/wc/v3/products" })
  c.headers.authorization = "Basic Y2tfeDpjc195"
  clean(c, "an API client (Authorization)")
end
fires(post(markup, { uri = "/wp-admin/admin-ajax.php" }), "TAG_HANDLER",
  "anonymous admin-ajax (front-end forms post there) is scanned")

-- ── Unit: the detector and the gate directly ────────────────────────────────
local det = require("cfm_waf_detectors")
check(det.detect_xss_body(nil) == nil and det.detect_xss_body("") == nil, "empty input")
check(det.detect_xss_body("x\"+/onload=1") == "ATTR_BREAKOUT", "`+` and `/` between quote and handler")
check(det.xss_body_admin_request("/wp-admin/admin-ajax.php", "") == false, "admin-ajax alone is not admin")
check(det.xss_body_admin_request("/x", "a=1; WordPress_Logged_In_x=y") == true, "cookie name, any case")

-- ── 330 runs late: among logonly hits the first recorded owns the headline,
-- so it must follow the dropper / backdoor scanners (421-439) ──────────────
do
  local f = assert(io.open("configs/lua/cfm_waf.lua"))
  local src = f:read("*a"); f:close()
  local at = src:find("RULE_IDS.rule_xss_body", 1, true)
  local s60 = src:find("── 60) Generic phpfuck", 1, true)
  local last = src:find("── LAST) Fetch-metadata missing", 1, true)
  check(at and s60 and last and s60 < at and at < last, "rule 330 sits after step 60 and before 612")
end

if fails > 0 then
  io.stderr:write(fails .. " failure(s)\n")
  os.exit(1)
end
print("OK: cfm_waf xss_body tests passed")

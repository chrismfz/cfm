-- Rule 501 (auth endpoint burst), edge Lua sweep 2026-10-09, PR 10c:
--   * it skipped every client whose IP is its TCP peer, so it never ran for
--     a direct client, only behind a trusted proxy (Cloudflare);
--   * it counted every request to a login-ish path, GETs and admin
--     navigation included (OpenCart /admin/index.php?route=…, Joomla
--     POST /administrator/index.php saves).
-- It now counts credential submissions only (a POST carrying a password
-- field, read like PHP), for every client; a direct client is capped at
-- auth_burst_direct_mode (logonly) for a burn-in.

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

-- A dict with the ngx.shared calls cfm_shdict makes (incr without init, add).
local function new_dict()
  local d = { v = {} }
  function d:get(k) return self.v[k] end
  function d:incr(k, n)
    if self.v[k] == nil then return nil, "not found" end
    self.v[k] = self.v[k] + n; return self.v[k]
  end
  function d:add(k, val)
    if self.v[k] ~= nil then return false, "exists" end
    self.v[k] = val; return true
  end
  function d:set(k, val) self.v[k] = val; return true end
  return d
end

local CHROME = "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/131.0.0.0 Safari/537.36"
local FORM = "application/x-www-form-urlencoded"

-- n requests from one IP; returns the last one's 501 action (or nil).
local function burst(n, t)
  local dict = new_dict()
  local peer = t.peer
  if peer == nil then peer = "203.0.113.20" elseif peer == false then peer = nil end
  local act
  for _ = 1, n do
    local _, _, _, _, hits = waf.check({
      uri = t.uri, args = t.args or "", raw_uri = t.uri .. (t.args and ("?" .. t.args) or ""),
      method = t.method or "POST", ip = "203.0.113.20", peer = peer,
      body = t.body or "", shdict = dict,
      headers = { ["user-agent"] = CHROME, accept = "text/html", referer = "https://example.com/",
                  ["accept-language"] = "en", ["content-type"] = t.ct or FORM, ["content-length"] = t.clen },
    })
    act = nil
    for _, h in ipairs(hits or {}) do if h.waf_rule_id == 501 then act = h.action end end
  end
  return act
end

-- ── Credential submissions count, direct clients included (logonly) ────────
do
  local cases = {
    { "WordPress",   { uri = "/wp-login.php", body = "log=admin&pwd=guess&wp-submit=Log+In" } },
    { "Drupal",      { uri = "/user/login", body = "name=admin&pass=guess&form_id=user_login_form" } },
    { "Joomla",      { uri = "/administrator/index.php", body = "username=admin&passwd=guess&option=com_login&task=login" } },
    { "OpenCart",    { uri = "/admin/index.php", args = "route=common/login", body = "username=admin&password=guess" } },
    { "Magento",     { uri = "/admin/admin/index/index/", body = "form_key=x&login%5Busername%5D=admin&login%5Bpassword%5D=guess" } },
    { "generic",     { uri = "/account/login", body = "email=a%40b.c&password=guess" } },
  }
  for _, c in ipairs(cases) do
    local a = burst(9, c[2])
    check(a == "logonly", c[1] .. ": 9 direct credential POSTs → 501 logonly (got " .. tostring(a) .. ")")
    local p = {}
    for k, v in pairs(c[2]) do p[k] = v end
    p.peer = "172.70.1.1"  -- a Cloudflare edge relayed it: the rule's own mode
    a = burst(9, p)
    check(a == "challenge_v2", c[1] .. ": 9 proxied credential POSTs → 501 challenge_v2 (got " .. tostring(a) .. ")")
  end
  check(burst(7, { uri = "/wp-login.php", body = "log=admin&pwd=guess" }) == nil, "7 submissions: under the threshold")
  -- No peer at all reads as direct.
  check(burst(9, { uri = "/wp-login.php", body = "log=admin&pwd=guess", peer = false }) == "logonly", "no peer: direct, logonly")
  -- Drupal's JSON login.
  check(burst(9, { uri = "/user/login", args = "_format=json", ct = "application/json",
                   body = '{"name":"admin","pass":"guess"}', peer = "172.70.1.1" }) == "challenge_v2", "Drupal JSON login counts")
  -- Padding past the 32 KB the WAF reads: PHP still reads the password there.
  local pad = "x=" .. ("a"):rep(33000) .. "&log=admin&pwd=guess"
  check(burst(9, { uri = "/wp-login.php", body = pad:sub(1, 32768), clen = tostring(#pad), peer = "172.70.1.1" }) == "challenge_v2",
        "a login padded past the WAF's 32 KB still counts")
  check(burst(9, { uri = "/wp-login.php", body = "", clen = "40000", peer = "172.70.1.1" }) == "challenge_v2",
        "an unread login body (Content-Length only) counts")
  -- Cut at 32 KB with no Content-Length (chunked, HTTP/2).
  check(burst(9, { uri = "/wp-login.php", body = pad:sub(1, 32768), peer = "172.70.1.1" }) == "challenge_v2",
        "a chunked login cut at 32 KB counts")
  -- Unread, no Content-Length (HTTP/3).
  check(burst(9, { uri = "/wp-login.php", body = "", peer = "172.70.1.1" }) == "challenge_v2",
        "an unread login body without Content-Length counts")
  -- Drupal's REST login decodes by _format, whatever the Content-Type.
  check(burst(9, { uri = "/user/login", args = "_format=json", ct = "text/plain",
                   body = '{"name":"admin","pass":"guess"}', peer = "172.70.1.1" }) == "challenge_v2",
        "Drupal _format login under text/plain counts")
  -- A JSON key spelled with escapes, past 2 KB, no JSON media type.
  check(burst(9, { uri = "/account/login", ct = "text/plain", peer = "172.70.1.1",
                   body = '{"a":"' .. ("x"):rep(3000) .. '","user":"admin","p\\u0061ss":"guess"}' }) == "challenge_v2",
        "an escaped JSON password key past 2 KB counts")
  -- Drupal's _format branch on its own: an XML login, not JSON-shaped, and
  -- an encoded `%5Fformat`.
  check(burst(9, { uri = "/user/login", args = "%5Fformat=xml", ct = "text/plain",
                   body = "<r><name>a</name><pass>x</pass></r>", peer = "172.70.1.1" }) == "challenge_v2",
        "Drupal _format=xml login counts")
  -- Magento's storefront login (a /login path: login[username] + login[password]).
  check(burst(9, { uri = "/customer/account/loginPost/", body = "form_key=x&login%5Busername%5D=a%40b.c&login%5Bpassword%5D=g",
                   peer = "172.70.1.1" }) == "challenge_v2", "Magento storefront loginPost counts")
  -- OpenCart's login route encoded, padded.
  check(burst(9, { uri = "/admin/index.php", args = "route=common%2Flogin", body = pad:sub(1, 32768), clen = tostring(#pad),
                   peer = "172.70.1.1" }) == "challenge_v2", "OpenCart encoded login route padded counts")
  -- Magento on the bare /admin route.
  check(burst(9, { uri = "/admin", body = "form_key=x&login%5Busername%5D=a&login%5Bpassword%5D=b", peer = "172.70.1.1" }) == "challenge_v2",
        "Magento login on bare /admin counts")
  -- OpenCart's login route padded past the cut.
  check(burst(9, { uri = "/admin/index.php", args = "route=common/login", body = pad:sub(1, 32768), clen = tostring(#pad),
                   peer = "172.70.1.1" }) == "challenge_v2", "OpenCart login route padded counts")
end

-- ── Not credential submissions: never counted ───────────────────────────────
do
  local P = "172.70.1.1"
  local cases = {
    { "GET of wp-login.php",           { uri = "/wp-login.php", method = "GET", peer = P } },
    { "wp-login lost password",        { uri = "/wp-login.php", args = "action=lostpassword", body = "user_login=admin", peer = P } },
    { "password only in the query",    { uri = "/wp-login.php", args = "log=a&pwd=b", method = "GET", peer = P } },
    { "OpenCart admin navigation",     { uri = "/admin/index.php", args = "route=catalog/product&user_token=abc", method = "GET", peer = P } },
    { "OpenCart admin save",           { uri = "/admin/index.php", args = "route=catalog/product.save", body = "product_description%5B1%5D%5Bname%5D=x&model=y", peer = P } },
    { "Joomla admin save",             { uri = "/administrator/index.php", body = "option=com_content&task=article.save&jform%5Btitle%5D=x", peer = P } },
    { "Magento admin save",            { uri = "/admin/catalog/product/save/", body = "form_key=x&product%5Bname%5D=y", peer = P } },
    { "password only in the query",    { uri = "/wp-login.php", args = "pwd=x", body = "foo=bar", peer = P } },
    { "PUT with a form pwd",           { uri = "/wp-login.php", method = "PUT", body = "log=a&pwd=b", peer = P } },
    { "admin save with one login",     { uri = "/admin/customer/save/", body = "form_key=x&login=jdoe", peer = P } },
    { "wp-admin admin-ajax login[]",   { uri = "/wp-admin/admin-ajax.php", body = "action=x&login%5Ba%5D=1&login%5Bb%5D=2", peer = P } },
    { "padded admin save (Magento)",   { uri = "/admin/catalog/product/save/", body = ("a"):rep(32768), clen = "50000", peer = P } },
    { "Joomla media upload > 32 KB",   { uri = "/administrator/index.php", args = "option=com_media&format=json&task=api.files",
                                         ct = "application/json", body = '{"name":"a.jpg","content":"' .. ("A"):rep(40000) .. '"}', peer = P } },
    { "OpenCart filemanager upload",   { uri = "/admin/index.php", args = "route=common/filemanager.upload", body = ("B"):rep(32768), clen = "90000", peer = P } },
    { "xmlrpc wp.uploadFile 40 KB",    { uri = "/xmlrpc.php", ct = "text/xml", body = ("C"):rep(32768), clen = "40000", peer = P } },
    { "username-only login field",     { uri = "/account/login", body = "login=jdoe&remember=1", peer = P } },
    { "xmlrpc (510-512's job)",        { uri = "/xmlrpc.php", ct = "text/xml", peer = P,
                                         body = "<?xml version=\"1.0\"?><methodCall><methodName>wp.getUsersBlogs</methodName><params><param><value>admin</value></param><param><value>x</value></param></params></methodCall>" } },
  }
  for _, c in ipairs(cases) do
    local a = burst(12, c[2])
    check(a == nil, c[1] .. ": 12 requests never count for 501 (got " .. tostring(a) .. ")")
  end
end

-- ── The direct cap never raises a weaker rule mode; a typo reads as logonly ─
do
  local function reload(rule, capv)
    package.loaded["cfm_waf_config"] = { rule_auth_burst = rule, auth_burst_direct_mode = capv }
    package.loaded["cfm_waf"] = nil
    waf = require("cfm_waf")
  end
  reload("logonly", "challenge")
  check(burst(9, { uri = "/wp-login.php", body = "log=a&pwd=b" }) == "logonly", "rule logonly + cap challenge: stays logonly")
  reload("challenge_v2", "challenge")
  check(burst(9, { uri = "/wp-login.php", body = "log=a&pwd=b" }) == "challenge", "the cap applies when set (challenge)")
  reload("challenge_v2", "chalenge")
  check(burst(9, { uri = "/wp-login.php", body = "log=a&pwd=b" }) == "logonly", "a misspelled cap reads as logonly")
  package.loaded["cfm_waf_config"] = nil
  package.loaded["cfm_waf"] = nil
end

-- ── The panel ports read no body: never counted there ──────────────────────
do
  local dict, act = new_dict(), nil
  for _ = 1, 12 do
    local _, _, _, _, hits = waf.check({
      uri = "/login/", args = "login_only=1", raw_uri = "/login/?login_only=1", method = "POST",
      ip = "203.0.113.30", peer = "203.0.113.30", body = "", body_unread = true, shdict = dict,
      headers = { ["user-agent"] = CHROME, ["content-length"] = "40", ["content-type"] = FORM },
    })
    act = nil
    for _, h in ipairs(hits or {}) do if h.waf_rule_id == 501 then act = h.action end end
  end
  check(act == nil, "a panel login (body_unread) is not counted (got " .. tostring(act) .. ")")
end

if fails > 0 then
  io.stderr:write(("auth burst tests: %d FAILED\n"):format(fails))
  os.exit(1)
end
print("ok: rule 501 counts credential submissions, direct clients at logonly")

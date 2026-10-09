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
  local act
  for _ = 1, n do
    local _, _, _, _, hits = waf.check({
      uri = t.uri, args = t.args or "", raw_uri = t.uri .. (t.args and ("?" .. t.args) or ""),
      method = t.method or "POST", ip = "203.0.113.20", peer = t.peer or "203.0.113.20",
      body = t.body or "", shdict = dict,
      headers = { ["user-agent"] = CHROME, accept = "text/html", referer = "https://example.com/",
                  ["accept-language"] = "en", ["content-type"] = t.ct or FORM },
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
    { "xmlrpc (510-512's job)",        { uri = "/xmlrpc.php", ct = "text/xml", peer = P,
                                         body = "<?xml version=\"1.0\"?><methodCall><methodName>wp.getUsersBlogs</methodName><params><param><value>admin</value></param><param><value>x</value></param></params></methodCall>" } },
  }
  for _, c in ipairs(cases) do
    local a = burst(12, c[2])
    check(a == nil, c[1] .. ": 12 requests never count for 501 (got " .. tostring(a) .. ")")
  end
end

if fails > 0 then
  io.stderr:write(("auth burst tests: %d FAILED\n"):format(fails))
  os.exit(1)
end
print("ok: rule 501 counts credential submissions, direct clients at logonly")

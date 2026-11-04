-- Tests for log-cfm.lua's login-facts column (idx 14, login POSTs only;
-- docs/webdetector-signals-v2.md §2; the daemon decides the outcome). Status alone cannot tell a login's
-- outcome (glaveris.gr: a hide-login plugin answered a failed wp-login.php
-- post with 302 → ?login=failed); the wordpress_logged_in_* cookie can.

package.path = "configs/lua/?.lua;" .. package.path

local fails = 0
local function check(cond, msg)
  if cond then return end
  fails = fails + 1
  io.stderr:write("FAIL: " .. tostring(msg) .. "\n")
end

local sent, timers
_G.ngx = {
  now    = function() return 1000 end,
  log    = function() end,
  WARN   = 1, ERR = 0, INFO = 2,
  var    = {},
  header = {},
  shared = {},
  timer  = { at = function(delay, cb, kind) timers[#timers + 1] = { cb = cb, kind = kind }; return true end },
  socket = { tcp = function()
    return {
      settimeouts = function() end, connect = function() return true end,
      send = function(_, p) sent[#sent + 1] = p; return true end,
      setkeepalive = function() return true end, close = function() end,
    }
  end },
}

local m = require("log-cfm")
local af = m._auth_field

-- A tiny query decoder standing in for ngx.req.get_uri_args: exact-case
-- names, %XX decoded, a repeated name becomes a list (as OpenResty does).
local function uri_args(uri)
  local out = {}
  local q = uri:match("%?(.*)$") or ""
  for kv in q:gmatch("[^&]+") do
    local k, v = kv:match("^([^=]*)=?(.*)$")
    local function dec(x) return (x:gsub("%%(%x%x)", function(h) return string.char(tonumber(h, 16)) end)) end
    k, v = dec(k), dec(v)
    if out[k] == nil then out[k] = v
    elseif type(out[k]) == "table" then table.insert(out[k], v)
    else out[k] = { out[k], v } end
  end
  return out
end
ngx.req = { get_uri_args = function() return ngx._args or {} end }
ngx.unescape_uri = function(x) return (x:gsub("%%(%x%x)", function(h) return string.char(tonumber(h, 16)) end)) end

local function req(method, uri, status, hdr, extra)
  local v = { request_method = method, request_uri = uri, status = tostring(status or 200) }
  for k, x in pairs(extra or {}) do v[k] = x end
  ngx.header = hdr or {}
  ngx._args = uri_args(uri)
  return v
end

local LI = "wordpress_logged_in_0123abcd=admin%7C1790000000%7CtOkEn%7Chm4c; path=/; secure; HttpOnly"
local SEC = "wordpress_sec_0123abcd=admin%7C1790000000%7CtOkEn%7Chm4c; path=/wp-admin; secure; HttpOnly"

-- ── The facts (the daemon decides the outcome: auth_corpus.go) ──────────────
check(af(req("POST", "/wp-login.php", 302, { ["Set-Cookie"] = { SEC, LI }, Location = "https://x.gr/wp-admin/" }))
  == "WP_LOGIN;li=1;l=/wp-admin/;c=wordpress_sec_0123abcd,wordpress_logged_in_0123abcd",
  "a success: li=1, the host-stripped Location path, the cookie NAMES only")
check(af(req("POST", "/wp-login.php", 200, {})) == "WP_LOGIN;li=0;l=;c=", "the form shown again")
check(af(req("POST", "/wp-login.php", 302, { Location = "https://x.gr/wp-login.php?login=failed" }))
  == "WP_LOGIN;li=0;l=/wp-login.php;c=",
  "the glaveris.gr case: a 302 back to the login page, its query dropped")
check(af(req("POST", "/wp-login.php", 302, { Location = "//other.example/wp-admin/" })) == "WP_LOGIN;li=0;l=/wp-admin/;c=",
  "a protocol-relative Location loses its host")
check(af(req("POST", "/wp-login.php", 302, { ["Set-Cookie"] = "wordpress_logged_in_0123abcd=+; expires=Thu, 01-Jan-1970 00:00:01 GMT; path=/",
  Location = "/wp-login.php?loggedout=true" })) == "WP_LOGIN;li=0;l=/wp-login.php;c=wordpress_logged_in_0123abcd",
  "an expired logged-in cookie (blank value) is not li=1")
check(af(req("POST", "/wp-login.php?action=lostpassword", 302, { ["Set-Cookie"] = LI, Location = "/wp-admin/" }))
  == "WP_LOGIN;li=1;a=lostpassword;l=/wp-admin/;c=wordpress_logged_in_0123abcd",
  "a query action is reported beside li, never instead of it (a body action=login overrides it in PHP)")
check(af(req("POST", "/wp-login.php?action=re%09g%3Bi%3D1", 200, {})) == "WP_LOGIN;li=0;a=re_g_i_1;l=;c=",
  "the action is decoded, then reduced to a safe charset")
check(af(req("POST", "/wp-login.php?action=log%69n", 200, {})) == "WP_LOGIN;li=0;a=login;l=;c=",
  "an encoded action is decoded as PHP does (log%69n is login)")
check(af(req("POST", "/wp-login.php?action=lostpassword&action=login", 200, {})) == "WP_LOGIN;li=0;a=login;l=;c=",
  "a repeated action: the last, as PHP takes it")
check(af(req("POST", "/wp-login.php?ACTION=lostpassword", 200, {})) == "WP_LOGIN;li=0;l=;c=",
  "ACTION is another name to PHP: no action")
check(af(req("POST", "/wp-login.php?action", 200, {})) == "WP_LOGIN;li=0;l=;c=", "an action with no value")
check(af(req("POST", "/wp-login.php", 200, { ["Set-Cookie"] = { LI, "wordpress_logged_in_0123abcd=+; expires=Thu, 01-Jan-1970 00:00:01 GMT; path=/" } }))
  :find(";li=0;", 1, true),
  "a 2FA plugin clears the cookie wp_signon set in the same answer: the last one decides (li=0)")
check(af(req("POST", "/wp-login.php", 200, { ["Set-Cookie"] = { "wordpress_logged_in_0123abcd=+", LI } }))
  :find(";li=1;", 1, true), "cleared then set: li=1")
check(af(req("POST", "/wp-login.php", 302, { Location = "https:\\\\evil.example/a" })) == "WP_LOGIN;li=0;l=/a;c=",
  "a backslash host is dropped too")
check(af(req("POST", "/wp-login.php", 302, { Location = "\\\\evil.example/a" })) == "WP_LOGIN;li=0;l=/a;c=",
  "a backslash protocol-relative host is dropped too")
check(af(req("POST", "/blog/wp-login.php", 200, {})) == "WP_LOGIN;li=0;l=;c=", "WordPress in a subdirectory")
check(af(req("POST", "/WP-LOGIN.PHP", 200, {})) == "WP_LOGIN;li=0;l=;c=", "the pre-check is case-insensitive")

-- ── Other CMSes: the same facts ──────────────────────────────────────────────
check(af(req("POST", "/administrator/index.php", 303, { ["Set-Cookie"] = "a1b2c3d4e5f6a1b2c3d4e5f6a1b2c3d4=sess; path=/", Location = "/administrator/index.php" }))
  == "JOOMLA_ADMIN;li=0;l=/administrator/index.php;c=a1b2c3d4e5f6a1b2c3d4e5f6a1b2c3d4", "Joomla admin")
check(af(req("POST", "/user/login", 200, {})) == "DRUPAL_LOGIN;li=0;l=;c=", "Drupal")
check(af(req("POST", "/login", 302, { Location = "/dashboard" })) == "LOGIN_POST;li=0;l=/dashboard;c=", "a generic /login")

-- Every auth_endpoint_tag leg gets past auth_field's login/admin pre-check
-- (a new leg keyed on neither word must change the pre-check too).
do
  local legs = {
    ["/wp-login.php"] = "WP_LOGIN", ["/phpmyadmin/index.php"] = "PHPMYADMIN", ["/user/login"] = "DRUPAL_LOGIN",
    ["/administrator/index.php"] = "JOOMLA_ADMIN", ["/admin/auth/x"] = "MAGENTO_ADMIN",
    ["/admin/index.php"] = "OPENCART_ADMIN", ["/admin/login"] = "MAGENTO_ADMIN", ["/login"] = "LOGIN_POST",
  }
  for uri, want in pairs(legs) do
    local v = af(req("POST", uri, 200, {}))
    check(v and v:match("^([%u_]+);") == want, "leg " .. uri .. " → " .. want .. " (got " .. tostring(v) .. ")")
  end
  -- Every tag the real function can return is in `legs` above (xmlrpc
  -- aside, and ADMIN_LOGIN, which the Magento leg always takes first), so a
  -- new leg fails here until it is added there, and checked against the
  -- login/admin pre-check.
  local f = assert(io.open("configs/lua/cfm_waf_detectors.lua", "r"))
  local src = f:read("*a"); f:close()
  local body = src:match("local function auth_endpoint_tag%(.-\nend\n")
  check(body ~= nil, "auth_endpoint_tag found in cfm_waf_detectors.lua")
  local covered = {}
  for _, t in pairs(legs) do covered[t] = true end
  for t in (body or ""):gmatch('return "AUTH_([%u_]+)"') do
    check(covered[t] or t == "WP_XMLRPC" or t == "ADMIN_LOGIN",
      "auth_endpoint_tag returns AUTH_" .. t .. ", which this test's legs do not cover")
  end
  for lit in (body or ""):gmatch('has%(uri, "([^"]+)"%)') do
    check(lit:find("login") or lit:find("admin") or lit == "/xmlrpc.php" or lit == "index.php" or lit == "auth"
      or lit:find("option=com_login") or lit == "view=login",
      "an auth_endpoint_tag literal the pre-check may not cover: " .. lit)
  end
end

-- ── The tag is decided on the decoded PATH, never the query (third review) ──
check(af(req("POST", "/wp-l%6Fgin.php", 200, {})) == "WP_LOGIN;li=0;l=;c=",
  "an encoded login path is still a login (Apache decodes it before WordPress runs)")
check(af(req("POST", "/wp-login%2ephp", 200, {})) == "WP_LOGIN;li=0;l=;c=", "an encoded dot")
check(af(req("POST", "/contact/?redirect_to=/wp-login.php", 200, {})) == nil,
  "a form post with a login URL in its query is not a login")
check(af(req("POST", "/wp-admin/admin-ajax.php?action=nsl_login", 200, {})) == nil,
  "admin-ajax with a login-ish action is not a Magento login")
check(af(req("POST", "/wp-admin/admin-post.php?action=oauth_cb", 200, {})) == nil, "admin-post oauth")
check(af(req("POST", "/x?" .. string.rep("login=admin&", 500), 200, {})) == nil,
  "a long query with login/admin in it is never scanned or tagged")
check(af(req("POST", "/wp-login.php", 302, { Location = "https:/evil.example/a" })) == "WP_LOGIN;li=0;l=/a;c=",
  "a one-slash host is dropped")
check(af(req("POST", "/wp-login.php", 302, { Location = "https:evil.example/a" })) == "WP_LOGIN;li=0;l=/a;c=",
  "a no-slash host is dropped")

-- ── Not login lines ──────────────────────────────────────────────────────────
check(af(req("GET", "/wp-login.php", 200, {})) == nil, "a GET of the login page")
check(af(req("POST", "/xmlrpc.php", 200, {})) == nil, "xmlrpc is rule 510's")
check(af(req("POST", "/wp-admin/admin-ajax.php?action=heartbeat", 200, {})) == nil,
  "admin-ajax: past the admin pre-check, and no tag leg matches its path")
check(af(req("POST", "/wp-json/wp/v2/posts", 200, {})) == nil, "a POST without login/admin")
check(af(req("POST", "/secret-login/", 302, { Location = "/secret-login/?err=1" })) == nil,
  "a hide-login path auth_endpoint_tag does not know")
check(af(req("POST", "", 200, {})) == nil, "no URI")

-- ── Bounds and sanitising ────────────────────────────────────────────────────
do
  local many = {}
  for i = 1, 20 do many[i] = "c" .. i .. "=v" end
  local v = af(req("POST", "/wp-login.php", 200, { ["Set-Cookie"] = many }))
  local names = v:match(";c=([^;]*)")
  local n = 0
  for _ in names:gmatch("[^,]+") do n = n + 1 end
  check(n == 8, "at most 8 cookie names (got " .. n .. ")")
  v = af(req("POST", "/wp-login.php", 302, { Location = "/wp-login.php/" .. string.rep("a", 300) .. "\t\n<x>" }))
  local l = v:match(";l=([^;]*)")
  check(#l == 96, "the Location path is capped (got " .. #l .. ")")
  check(not v:find("[\t\n<>]"), "no TAB, newline or markup in the field")
  v = af(req("POST", "/wp-login.php", 302, { Location = { "/wp-login.php?x", "/other" } }))
  check(v == "WP_LOGIN;li=0;l=/wp-login.php;c=", "a repeated Location: the first")
  v = af(req("POST", "/wp-login.php", 200, { ["Set-Cookie"] = "we!rd\"name=1" }))
  check(v == "WP_LOGIN;li=0;l=;c=we_rd_name", "a cookie name reduced to a safe charset")
  v = af(req("POST", "/wp-login.php", 200, { ["Set-Cookie"] = { "x=1", LI } }))
  check(v:find(";li=1;", 1, true), "li=1 even when the logged-in cookie is not the first")
end

-- ── The line: 15 columns on a login POST, 14 otherwise ──────────────────────
local function line_for(method, uri, status, hdr, extra)
  sent, timers = {}, {}
  package.loaded["log-cfm"] = nil
  local mm = require("log-cfm")
  local v = { msec = "1000.0", remote_addr = "1.2.3.4", host = "h", request_method = method,
    request_uri = uri, server_protocol = "HTTP/1.1", status = tostring(status), body_bytes_sent = "10",
    request_time = "0.001", upstream_response_time = "0.001", http_referer = "", http_user_agent = "ua",
    cfm_upstream = "cfm_apache", cfm_bypass_ip = "0" }
  for k, x in pairs(extra or {}) do v[k] = x end
  ngx.var = v
  ngx.header = hdr or {}
  ngx._args = {}
  mm.log()
  for _, t in ipairs(timers) do t.cb(false, t.kind) end
  return sent[1] or ""
end
local function ncols(l)
  local n = 1
  for _ in l:gsub("\n$", ""):gmatch("\t") do n = n + 1 end
  return n
end
do
  local l = line_for("POST", "/wp-login.php", 302, { ["Set-Cookie"] = LI, Location = "/wp-admin/" })
  check(ncols(l) == 15, "a login POST line has 15 columns (got " .. ncols(l) .. ")")
  check(l:find("\tWP_LOGIN;li=1;l=/wp-admin/;c=wordpress_logged_in_0123abcd\n", 1, true), "…ending in the auth field")
  check(not l:find("tOkEn", 1, true), "no cookie VALUE reaches the line")
  l = line_for("GET", "/", 200, { ["Set-Cookie"] = LI })
  check(ncols(l) == 14, "any other line keeps 14 columns (got " .. ncols(l) .. ")")
  check(l:sub(-3) == "\t0\n", "…ending in the bypass flag, byte-identical to before")
end

-- ── The tag list unavailable: no column, the line still sent ────────────────
do
  package.loaded["cfm_waf_detectors"] = {}
  local l = line_for("POST", "/wp-login.php", 200, {})
  check(ncols(l) == 14, "no auth_endpoint_tag → no column, line intact")
  package.loaded["cfm_waf_detectors"] = { auth_endpoint_tag = function() error("boom") end }
  l = line_for("POST", "/wp-login.php", 200, {})
  check(ncols(l) == 14, "a failing auth_endpoint_tag → no column, line intact")
  package.loaded["cfm_waf_detectors"] = nil
end

if fails > 0 then
  io.stderr:write(fails .. " failure(s)\n")
  os.exit(1)
end
print("cfm_log_auth_test: OK")

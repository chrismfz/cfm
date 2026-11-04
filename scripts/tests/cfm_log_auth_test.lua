-- Tests for log-cfm.lua's login-outcome column (idx 14, login POSTs only;
-- docs/webdetector-signals-v2.md §2). Status alone cannot tell a login's
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

local function req(method, uri, status, hdr, extra)
  local v = { request_method = method, request_uri = uri, status = tostring(status or 200) }
  for k, x in pairs(extra or {}) do v[k] = x end
  ngx.header = hdr or {}
  return v
end

local LI = "wordpress_logged_in_0123abcd=admin%7C1790000000%7CtOkEn%7Chm4c; path=/; secure; HttpOnly"
local SEC = "wordpress_sec_0123abcd=admin%7C1790000000%7CtOkEn%7Chm4c; path=/wp-admin; secure; HttpOnly"

-- ── WordPress outcomes ──────────────────────────────────────────────────────
check(af(req("POST", "/wp-login.php", 302, { ["Set-Cookie"] = { SEC, LI }, Location = "https://x.gr/wp-admin/" }))
  == "WP_LOGIN:ok;l=/wp-admin/;c=wordpress_sec_0123abcd,wordpress_logged_in_0123abcd",
  "a success: the logged-in cookie, the host-stripped Location path, the cookie NAMES only")
check(af(req("POST", "/wp-login.php", 200, {})) == "WP_LOGIN:fail;l=;c=",
  "a failure: the form shown again (200), no cookie")
check(af(req("POST", "/wp-login.php", 302, { Location = "https://x.gr/wp-login.php?login=failed" }))
  == "WP_LOGIN:fail;l=/wp-login.php;c=",
  "the glaveris.gr case: a 302 back to the login page is a failure, its query dropped")
check(af(req("POST", "/secret-login/", 302, { Location = "/secret-login/?err=1" })) == nil,
  "a hide-login path auth_endpoint_tag does not know is not a login line")
check(af(req("POST", "/wp-login.php", 302, { Location = "/2fa-step/" })):sub(1, 11) == "WP_LOGIN:?;",
  "a redirect elsewhere without the cookie (a 2FA step) is unknown, not a failure")
check(af(req("POST", "/wp-login.php", 302, { ["Set-Cookie"] = "wordpress_logged_in_0123abcd=+; expires=Thu, 01-Jan-1970 00:00:01 GMT; path=/",
  Location = "/wp-login.php?loggedout=true" })) == "WP_LOGIN:fail;l=/wp-login.php;c=wordpress_logged_in_0123abcd",
  "an expired logged-in cookie (blank value) is not a success")
check(af(req("POST", "/wp-login.php?action=lostpassword", 302, { Location = "/wp-login.php?checkemail=confirm" }, { arg_action = "lostpassword" }))
  == "WP_LOGIN:na;l=/wp-login.php;c=;a=lostpassword",
  "another wp-login action is na, with the action")
check(af(req("POST", "/wp-login.php?action=login", 200, {}, { arg_action = "LOGIN" })) == "WP_LOGIN:fail;l=;c=",
  "action=login is the login")
check(af(req("POST", "/wp-login.php?action=x%09y", 200, {}, { arg_action = "re\tg;i=1" })) == "WP_LOGIN:na;l=;c=;a=re_g_i_1",
  "the action is reduced to a safe charset")
check(af(req("POST", "/blog/wp-login.php", 200, {})) == "WP_LOGIN:fail;l=;c=", "WordPress in a subdirectory")

-- ── Other CMSes: corpus only, no outcome yet ─────────────────────────────────
check(af(req("POST", "/administrator/index.php", 303, { ["Set-Cookie"] = "a1b2c3d4e5f6a1b2c3d4e5f6a1b2c3d4=sess; path=/", Location = "/administrator/index.php" }))
  == "JOOMLA_ADMIN:?;l=/administrator/index.php;c=a1b2c3d4e5f6a1b2c3d4e5f6a1b2c3d4",
  "Joomla admin: unknown outcome, the corpus fields")
check(af(req("POST", "/user/login", 200, {})) == "DRUPAL_LOGIN:?;l=;c=", "Drupal")
check(af(req("POST", "/login", 302, { Location = "/dashboard" })) == "LOGIN_POST:?;l=/dashboard;c=", "a generic /login")

-- ── Not login lines ──────────────────────────────────────────────────────────
check(af(req("GET", "/wp-login.php", 200, {})) == nil, "a GET of the login page")
check(af(req("POST", "/xmlrpc.php", 200, {})) == nil, "xmlrpc is rule 510's")
check(af(req("POST", "/wp-admin/admin-ajax.php?action=heartbeat", 200, {})) == nil, "an ordinary POST")
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
  check(v == "WP_LOGIN:fail;l=/wp-login.php;c=", "a repeated Location: the first")
  v = af(req("POST", "/wp-login.php", 200, { ["Set-Cookie"] = "we!rd\"name=1" }))
  check(v == "WP_LOGIN:fail;l=;c=we_rd_name", "a cookie name reduced to a safe charset")
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
  check(l:find("\tWP_LOGIN:ok;l=/wp-admin/;c=wordpress_logged_in_0123abcd\n", 1, true), "…ending in the auth field")
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

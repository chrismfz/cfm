-- Tests for cfm_panel.lua forced-mode dispatch decisions.
--
-- The script issues redirects/exits via side effects on ngx.redirect/ngx.exit;
-- the chunk's top-level return value is intentionally discarded by the
-- xpcall fail-open wrapper added in 0715c4f. Capture the side effects via
-- ngx.actions[] in the fakes and assert on those instead of the chunk's
-- return value.

local panel_path = "configs/lua/cfm_panel.lua"

local function run_case(c)
  local uri_args = c.uri_args or {}
  local actions = {}
  local ngx = {
    INFO = 1, WARN = 2, DEBUG = 3, ERR = 0, NOTICE = 5,
    header = {},
    ctx    = {},
    HTTP_TEMPORARY_REDIRECT = 307,
    HTTP_FORBIDDEN = 403,
    HTTP_NOT_FOUND = 404,
    HTTP_INTERNAL_SERVER_ERROR = 500,
    var = {
      uri = c.uri or "/",
      request_uri = c.request_uri or c.uri or "/",
      host = c.host or "example.test",
      remote_addr = c.ip or "203.0.113.9",
      http_authorization = c.auth or "",
      http_user_agent = c.ua or "Mozilla/5.0",
      http_cookie = c.cookie or "",
      cookie_cfm_ok = "",
      cookie_cfm_clearance = "",
      cfm_panel_origin = "http://origin",
      cfm_panel_challenge_mode = "forced",
      cfm_panel_challenge_location = "/__cfm_challenge",
    },
    req = {
      get_method = function() return c.method or "GET" end,
      get_uri_args = function() return uri_args end,
      is_internal = function() return c.internal or false end,
    },
    shared = {
      cfm_decisions = { get=function() return nil end, set=function() end, add=function() return true end, delete=function() end },
      cfm_stats     = { get=function() return nil end, set=function() end },
    },
    now      = function() return 1000 end,
    time     = function() return 1000 end,
    log      = function(...) end,
    location = { capture = c.capture or function() return { status = 200, body = "challenge", header = { Location = "/__cfm_challenge" } } end },
    -- Capture side effects rather than return them. cfm_panel.lua's main()
    -- is called inside xpcall(); top-level return is discarded.
    redirect = function(loc, code) actions[#actions+1] = { action = "redirect", location = loc, code = code } end,
    exit     = function(code)      actions[#actions+1] = { action = "exit",     code = code } end,
    decode_base64 = function(s) return s end,
    unescape_uri  = function(v) return v end,
    escape_uri    = function(v) return tostring(v):gsub("/","%%2F") end,
  }
  ngx.actions = actions
  ngx.var.cookie_cfm_ok = ((";"..ngx.var.http_cookie):match(";%s*cfm_ok=([^;]+)")) or ""
  _G.ngx = ngx
  assert(loadfile(panel_path))()
  -- last_action: most recent redirect/exit captured (nil if none).
  return ngx, actions[#actions]
end

local function assert_eq(a,b,m) if a~=b then error((m or "assert")..": got="..tostring(a).." expected="..tostring(b),2) end end

for _,u in ipairs({"/json-api/create_user_session","/json-api/listaccts","/json-api/batch","/execute/SomeModule/function","/xml-api/listaccts","/cpanelwebcall","/openid_connect/cpanelid","/cpsess1234567890/login/abc","/cpsess1234567890/json-api/listaccts","/api","/api/"}) do
  local ngx = run_case({uri=u, ua="-"})
  assert_eq(ngx.var.cfm_upstream, "cfm_panel_passthrough", "API/SSO should passthrough: "..u)
end

local _, r1 = run_case({uri="/", host="cpanel.example.com", ua="Mozilla/5.0"})
assert_eq(r1 and r1.action, "redirect", "cpanel / should challenge")
assert_eq(r1.code, 307, "challenge must be 307")

local _, r2 = run_case({uri="/login", host="whm.example.com", ua="Mozilla/5.0"})
assert_eq(r2 and r2.action, "redirect", "whm /login should challenge")

local _, r3 = run_case({uri="/", host="1.2.3.4", ua="Mozilla/5.0"})
assert_eq(r3 and r3.action, "redirect", "IP host / should challenge")

local ngx4, r4 = run_case({uri="/", host="cpanel.example.com", ua="python-requests"})
assert_eq(r4, nil, "non-browser on entry should not be denied")
assert_eq(ngx4.var.cfm_upstream, "cfm_panel_origin", "non-browser should pass origin")

local ngx5 = run_case({uri="/some/unknown", host="example.com", ua="-"})
assert_eq(ngx5.var.cfm_upstream, "cfm_panel_origin", "default passthrough")

local _, out6 = run_case({uri="/__cfm_panel_decide", internal=false})
assert_eq(out6 and out6.action, "exit", "external internal endpoint denied")

print("ok: cfm_panel forced-mode dispatch tests")

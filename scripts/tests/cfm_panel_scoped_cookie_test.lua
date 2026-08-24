-- Tests for cfm_panel.lua per-scope clearance cookie handling (Phase 2a).
--
-- The panel reads cfm_clearance_p<port> ONLY (the name the Go challenge
-- server mints for panel scopes) and re-mints under that scoped name. The
-- legacy shared cfm_clearance-name fallback was dropped in the Phase 3
-- cookie-net cleanup, so a legacy-only cookie now yields a one-time
-- re-challenge rather than being honoured.
--
-- Uses fake cfm_clearance / cfm_bridge_cfg modules injected via
-- package.loaded: tokens are "TOK_<scope>" and validate() succeeds only
-- when the token's scope suffix equals the scope being validated —
-- mirroring the real HMAC scope binding without crypto.

local panel_path = "configs/lua/cfm_panel.lua"
local canonical_secret = "canonical-bridge-secret-0123456789abcdef"
local real_getenv = os.getenv
os.getenv = function(name)
  if name == "CFM_CLEARANCE_HMAC_SECRET" then
    return "stale-environment-secret-0123456789abcdef"
  end
  return real_getenv(name)
end

local function run_case(c)
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
      request_uri = c.uri or "/",
      host = c.host or "cpanel.example.com",
      remote_addr = c.ip or "203.0.113.9",
      http_authorization = "",
      http_user_agent = c.ua or "Mozilla/5.0",
      http_cookie = "",
      cookie_cfm_ok = "",
      cookie_cfm_clearance = c.legacy_cookie or "",
      cfm_panel_origin = c.origin or "https://127.0.0.1:2087",
      cfm_panel_challenge_mode = "forced",
      cfm_panel_challenge_location = "/__cfm_challenge",
      server_port = c.server_port or "12087",
    },
    req = {
      get_method = function() return "GET" end,
      get_uri_args = function() return {} end,
      is_internal = function() return false end,
    },
    shared = {
      cfm_decisions = { get=function() return nil end, set=function() end, add=function() return true end, delete=function() end },
      cfm_stats     = { get=function() return nil end, set=function() end },
    },
    now      = function() return 1000 end,
    time     = function() return 1000 end,
    log      = function(...) end,
    location = { capture = function() return { status = 200, body = "challenge", header = {} } end },
    redirect = function(loc, code) actions[#actions+1] = { action = "redirect", location = loc, code = code } end,
    exit     = function(code)      actions[#actions+1] = { action = "exit",     code = code } end,
    decode_base64 = function(s) return s end,
    unescape_uri  = function(v) return v end,
    escape_uri    = function(v) return tostring(v):gsub("/","%%2F") end,
  }
  ngx.actions = actions
  for name, val in pairs(c.scoped_cookies or {}) do
    ngx.var["cookie_" .. name] = val
  end
  _G.ngx = ngx

  -- Fake modules: scope-bound token validation without crypto.
  package.loaded["cfm_clearance"] = {
    validate = function(token, ip, host, scope, secret)
      if secret ~= canonical_secret then return false, "wrong_secret" end
      if not token or token == "" then return false, "missing_cookie" end
      if token == ("TOK_" .. tostring(scope)) then return true, "ok" end
      return false, "scope_mismatch"
    end,
    mint = function(ip, host, scope, secret, ttl)
      if secret ~= canonical_secret then return nil, "wrong_secret" end
      return "MINTED_" .. tostring(scope), nil
    end,
    normalize_host = function(h) return tostring(h or ""):lower() end,
    panel_scope = function(panel_port, forwarded_port, panel_origin, server_port)
      local port = tostring(panel_origin or ""):match(":(%d+)") or tostring(server_port or "")
      if port == "" then port = "unknown" end
      return "panel:" .. port
    end,
  }
  package.loaded["cfm_bridge_cfg"] = {
    get = function() return { clearance_refresh = true, cookie_life_sec = 2700 } end,
    token = function() return canonical_secret end,
  }
  package.loaded["cfm_panel_hosts"] = nil -- let the inline fallback list run

  assert(loadfile(panel_path))()
  package.loaded["cfm_clearance"] = nil
  package.loaded["cfm_bridge_cfg"] = nil
  return ngx, actions[#actions]
end

local function assert_eq(a, b, m)
  if a ~= b then error((m or "assert") .. ": got=" .. tostring(a) .. " expected=" .. tostring(b), 2) end
end

local function set_cookie_values(ngx)
  local h = ngx.header["Set-Cookie"]
  if h == nil then return {} end
  if type(h) == "table" then return h end
  return { h }
end

local function find_cookie(ngx, name)
  for _, v in ipairs(set_cookie_values(ngx)) do
    local val = tostring(v):match("^" .. name .. "=([^;]*)")
    if val then return val end
  end
  return nil
end

-- 1) Scoped cookie valid → allow + re-mint under the scoped name.
local ngx1, r1 = run_case({
  scoped_cookies = { cfm_clearance_p2087 = "TOK_panel:2087" },
})
assert_eq(r1, nil, "valid scoped cookie must not redirect/exit")
assert_eq(ngx1.var.cfm_upstream, "cfm_panel_origin", "valid scoped cookie should pass to origin")
assert_eq(find_cookie(ngx1, "cfm_clearance_p2087"), "MINTED_panel:2087", "re-mint must use the scoped cookie name")
assert_eq(find_cookie(ngx1, "cfm_clearance"), nil, "re-mint must not touch the legacy shared name")

-- 2) Legacy shared-name cookie is NO LONGER honoured (Phase 3 cookie-net
--    cleanup): even a correctly panel-scoped token under the legacy name is
--    ignored, so the browser gets a one-time re-challenge and the legacy
--    cookie is left untouched (never rewritten under the scoped name).
local ngx2, r2 = run_case({
  legacy_cookie = "TOK_panel:2087",
})
assert_eq(r2 and r2.action, "redirect", "legacy-name cookie must no longer clear the panel")
assert_eq(r2.code, 307, "re-challenge must be 307")
assert_eq(find_cookie(ngx2, "cfm_clearance_p2087"), nil, "legacy cookie must not be migrated to the scoped name")
assert_eq(find_cookie(ngx2, "cfm_clearance"), nil, "the legacy cookie itself must be left alone")

-- 3) Legacy holding a WEB token (the old clobber shape) → also ignored →
--    browser gets the challenge; the web token itself is left alone.
local ngx3, r3 = run_case({
  legacy_cookie = "TOK_web",
})
assert_eq(r3 and r3.action, "redirect", "web-scoped legacy cookie must challenge on panel")
assert_eq(r3.code, 307, "challenge must be 307")
assert_eq(find_cookie(ngx3, "cfm_clearance"), nil, "the legacy web cookie must not be rewritten")

-- 4) Scoped cookie preferred over legacy when both exist.
local ngx4, r4 = run_case({
  scoped_cookies = { cfm_clearance_p2087 = "TOK_panel:2087" },
  legacy_cookie = "garbage",
})
assert_eq(r4, nil, "scoped cookie must win over legacy garbage")
assert_eq(ngx4.var.cfm_upstream, "cfm_panel_origin", "scoped cookie must win over legacy garbage")

-- 5) No cookies at all → challenge.
local _, r5 = run_case({})
assert_eq(r5 and r5.action, "redirect", "no cookie should challenge")

-- 6) A different listener's scoped cookie does not clear this port
--    (per-port isolation preserved: 2083's cookie is not read on 2087).
local _, r6 = run_case({
  scoped_cookies = { cfm_clearance_p2083 = "TOK_panel:2083" },
})
assert_eq(r6 and r6.action, "redirect", "another port's scoped cookie must not clear this port")

os.getenv = real_getenv
print("ok: cfm_panel per-scope clearance cookie tests")

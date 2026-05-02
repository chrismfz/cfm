local panel_path = "configs/cfm_panel.lua"

local function run_case(c)
  local shared = {}
  local function dict_get(k) return shared[k] end
  local function dict_set(k, v) shared[k] = v; return true end
  local ngx = {
    INFO = 1, WARN = 2, DEBUG = 3,
    HTTP_TEMPORARY_REDIRECT = 307,
    HTTP_FORBIDDEN = 403,
    var = {
      uri = c.uri or "/",
      request_uri = c.request_uri or c.uri or "/",
      host = "example.test",
      remote_addr = c.ip or "203.0.113.9",
      http_authorization = c.auth or "",
      http_user_agent = c.ua or "Mozilla/5.0",
      http_cookie = c.cookie or "",
      cfm_panel_origin = "http://origin",
      cfm_panel_challenge_mode = "forced",
      cfm_panel_fail_mode = "fail-open",
      cfm_challenge_cooldown = "45m",
      cfm_challenge_cookie_life = "45m",
      cfm_openresty_ok_ip_ttl = "45m",
      cfm_panel_challenge_location = "/__cfm_panel_decide",
    },
    req = { get_method = function() return c.method or "GET" end },
    shared = {
      cfm_decisions = { get = dict_get, set = dict_set },
      cfm_stats = { get = dict_get, set = dict_set },
    },
    now = function() return 1000 end,
    log = function(...) end,
    location = { capture = function() return { status = 200, body = "challenge", header = { Location = "/__cfm_challenge" } } end },
    redirect = function(loc, code) return { action = "redirect", location = loc, code = code } end,
    exit = function(code) return { action = "exit", code = code } end,
    decode_base64 = function(s) return s end,
    escape_uri = function(v)
      v = tostring(v or "")
      v = v:gsub("%%", "%%25"):gsub(" ", "%%20"):gsub("/", "%%2F"):gsub("%?", "%%3F"):gsub("=", "%%3D"):gsub("&", "%%26")
      return v
    end,
  }

  _G.ngx = ngx
  local out = assert(loadfile(panel_path))()
  return ngx, out, shared
end

local function assert_eq(actual, expected, msg)
  if actual ~= expected then
    error((msg or "assert_eq failed") .. ": got=" .. tostring(actual) .. " expected=" .. tostring(expected), 2)
  end
end

-- non-API browser request without cookie -> challenged
local ngx1, out1 = run_case({ uri = "/" })
assert_eq(out1.action, "redirect", "non-api without cookie should challenge")
assert_eq(ngx1.var.cfm_pass, nil, "should not pass origin when challenged")

-- same client with valid cookie -> pass
local ngx2 = run_case({ uri = "/", cookie = "cfm_clearance=ok" })
assert_eq(ngx2.var.cfm_upstream, "cfm_panel_origin", "cookie should allow origin pass")

-- authenticated API request -> pass without challenge
local ngx3 = run_case({ uri = "/json-api/listaccts", auth = "whm token" })
assert_eq(ngx3.var.cfm_upstream, "cfm_panel_api", "authenticated API should bypass challenge")


-- DirectAdmin-compatible API request with valid auth -> pass without challenge
local ngx4 = run_case({ uri = "/api/session", auth = "Basic dXNlcjpwYXNz" })
assert_eq(ngx4.var.cfm_upstream, "cfm_panel_api", "directadmin API with auth should bypass challenge")

-- DirectAdmin-compatible API request without auth -> not exempt, still challenged in forced mode
local _, out5 = run_case({ uri = "/api/session" })
assert_eq(out5.action, "redirect", "directadmin API without auth should not be exempt")

-- Non-API UI route with API auth but missing clearance cookie -> still challenged in forced mode
local _, out6 = run_case({ uri = "/", auth = "Basic dXNlcjpwYXNz" })
assert_eq(out6.action, "redirect", "non-api route with auth should still challenge in forced mode")


-- Forced mode /whm entrypoint should never redirect browser to internal decision URI.
local _, out7 = run_case({ uri = "/whm", request_uri = "/whm" })
assert_eq(out7.action, "redirect", "forced /whm should still challenge")
assert_eq(out7.location, "/__cfm_challenge", "forced /whm must redirect to public challenge endpoint")
if out7.location:find("/__cfm_panel_decide", 1, true) then
  error("forced /whm redirect chain leaked internal decision URI", 2)
end

print("ok")

-- Forced-mode loop prevention: exactly one hop to challenge endpoint with next target
local _, out8 = run_case({ uri = "/", request_uri = "/" })
assert_eq(out8.action, "redirect", "forced / should redirect to challenge")
assert_eq(out8.location, "/__cfm_challenge?next=%2F", "forced / should include single-hop challenge target")
if out8.location:find("/__cfm_challenge%?next=", 1, false) == nil then
  error("forced / redirect missing challenge next parameter", 2)
end

-- Challenge endpoint is exempt and must not re-challenge itself
local ngx9 = run_case({ uri = "/__cfm_challenge", request_uri = "/__cfm_challenge?next=%2F" })
assert_eq(ngx9.var.cfm_upstream, "cfm_panel_exempt", "challenge endpoint must be exempt from guard recursion")

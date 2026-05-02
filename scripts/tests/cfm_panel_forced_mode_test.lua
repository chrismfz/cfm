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

print("ok")

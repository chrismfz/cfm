local panel_path = "configs/cfm_panel.lua"
local CHALLENGE_COOLDOWN = "45m"
local CHALLENGE_COOKIE_LIFE = "45m"
local OPENRESTY_OK_IP_TTL = "45m"

local function parse_duration_seconds(raw, fallback)
  if raw == nil or raw == "" then return fallback end
  local n, unit = tostring(raw):match("^%s*(%d+)%s*([smhdSMHD]?)%s*$")
  n = tonumber(n)
  if not n then return fallback end
  unit = (unit or "s"):lower()
  if unit == "m" then return n * 60 end
  if unit == "h" then return n * 3600 end
  if unit == "d" then return n * 86400 end
  return n
end

local function run_case(c, shared)
  shared = shared or { kv = {}, now = 1000 }
  if not shared.kv then shared.kv = {} end
  if c.now then shared.now = c.now end
  local function dict_get(k)
    local row = shared.kv[k]
    if not row then return nil end
    if row.exp and row.exp <= shared.now then
      shared.kv[k] = nil
      return nil
    end
    return row.v
  end
  local function dict_set(k, v, ttl)
    local exp = nil
    if tonumber(ttl) and tonumber(ttl) > 0 then exp = shared.now + tonumber(ttl) end
    shared.kv[k] = { v = v, exp = exp }
    return true
  end
  local uri_args = c.uri_args or {}
  local function unescape_uri(v)
    v = tostring(v or "")
    return (v:gsub("%%(%x%x)", function(hex) return string.char(tonumber(hex, 16)) end))
  end
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
      CHALLENGE_COOLDOWN = CHALLENGE_COOLDOWN,
      CHALLENGE_COOKIE_LIFE = CHALLENGE_COOKIE_LIFE,
      OPENRESTY_OK_IP_TTL = OPENRESTY_OK_IP_TTL,
      cfm_panel_challenge_location = "/__cfm_panel_decide",
    },
    req = {
      get_method = function() return c.method or "GET" end,
      get_uri_args = function() return uri_args end,
      set_uri_args = function(args) uri_args = args end,
    },
    shared = {
      cfm_decisions = { get = dict_get, set = dict_set },
      cfm_stats = { get = dict_get, set = dict_set },
    },
    now = function() return shared.now end,
    log = function(...) end,
    location = { capture = c.capture or function() return { status = 200, body = "challenge", header = { Location = "/__cfm_challenge" } } end },
    redirect = function(loc, code) return { action = "redirect", location = loc, code = code } end,
    exit = function(code) return { action = "exit", code = code } end,
    decode_base64 = function(s) return s end,
    unescape_uri = unescape_uri,
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
local ngx2 = run_case({ uri = "/", cookie = "cfm_ok=ok" })
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


-- solve callback cookie should route subsequent request to origin (not challenge)
local shared_follow = {}
local _, out10 = run_case({ uri = "/" }, shared_follow)
assert_eq(out10.location, "/__cfm_challenge?next=%2F", "first hop must challenge")
local ngx11, out11 = run_case({ uri = "/", cookie = "cfm_ok=ok" }, shared_follow)
assert_eq(out11, nil, "solved follow-up should pass through without redirect")
assert_eq(ngx11.var.cfm_upstream, "cfm_panel_origin", "solved follow-up must route to panel origin")


-- End-to-end forced flow: single redirect to challenge, single redirect back, then origin pass without loops
local shared_e2e = {}
local _, first_hop = run_case({ uri = "/", request_uri = "/" }, shared_e2e)
assert_eq(first_hop.action, "redirect", "forced e2e first request should redirect")
assert_eq(first_hop.location, "/__cfm_challenge?next=%2F", "forced e2e first hop should go to challenge with next")

local ngx_challenge, challenge_hop = run_case({ uri = "/__cfm_challenge", request_uri = "/__cfm_challenge?next=%2F" }, shared_e2e)
assert_eq(challenge_hop, nil, "challenge endpoint should proxy directly")
assert_eq(ngx_challenge.var.cfm_upstream, "cfm_panel_origin", "challenge endpoint should be allowed to origin")

local ngx_final, final_hop = run_case({ uri = "/", request_uri = "/", cookie = "cfm_ok=ok" }, shared_e2e)
assert_eq(final_hop, nil, "forced e2e solved request should not redirect again")
assert_eq(ngx_final.var.cfm_upstream, "cfm_panel_origin", "forced e2e solved request should pass to origin")
local set_cookie = ngx_final.header and ngx_final.header["Set-Cookie"]
assert_eq(type(set_cookie), "string", "forced solved request should refresh clearance cookie")
if not set_cookie:find("cfm_ok=ok", 1, true) then
  error("forced solved request did not refresh cfm_ok cookie", 2)
end

-- Browser A solves challenge -> Browser B same IP bypasses within OPENRESTY_OK_IP_TTL
local shared_ip = { now = 2000 }
local _, out12 = run_case({ uri = "/", request_uri = "/", now = 2000 }, shared_ip)
assert_eq(out12.location, "/__cfm_challenge?next=%2F", "initial same-ip flow must challenge")
local ngx13 = run_case({ uri = "/__cfm_verify", request_uri = "/__cfm_verify?next=%2F", cookie = "cfm_ok=ok", now = 2001 }, shared_ip)
assert_eq(ngx13.var.cfm_upstream, "cfm_panel_origin", "verify must pass to origin")
local ngx14, out14 = run_case({ uri = "/", request_uri = "/", cookie = "", ua = "Mozilla/5.0 (Browser-B)", now = 2002 }, shared_ip)
assert_eq(out14, nil, "same IP second browser must bypass after verify")
assert_eq(ngx14.var.cfm_upstream, "cfm_panel_origin", "same IP bypass should route to origin")

-- Same browser with valid cookie bypasses within CHALLENGE_COOKIE_LIFE
local ngx15, out15 = run_case({ uri = "/", request_uri = "/", cookie = "cfm_ok=ok", now = 2100 }, { now = 2100 })
assert_eq(out15, nil, "valid cookie should bypass challenge")
assert_eq(ngx15.var.cfm_upstream, "cfm_panel_origin", "cookie bypass should route to origin")

-- After TTL expiry, challenge is required again
local shared_ttl = { now = 3000 }
run_case({ uri = "/__cfm_verify", request_uri = "/__cfm_verify?next=%2F", cookie = "cfm_ok=ok", now = 3000 }, shared_ttl)
local ip_ttl = parse_duration_seconds(OPENRESTY_OK_IP_TTL, 2700)
local _, out16 = run_case({ uri = "/", request_uri = "/", cookie = "", now = 3000 + ip_ttl + 1 }, shared_ttl)
assert_eq(out16.action, "redirect", "expired IP TTL should challenge again")
assert_eq(out16.location, "/__cfm_challenge?next=%2F", "expired IP TTL should redirect to challenge")


-- Forced mode should use shared decision backend path for panel routes.
local capture_calls = 0
local ngx17, out17 = run_case({ uri = "/", ip = "198.51.100.10", capture = function(uri)
  capture_calls = capture_calls + 1
  assert_eq(uri, "/__cfm_panel_decide", "forced panel route should query decision subrequest")
  return { status = 200, body = "allow", header = {} }
end })
assert_eq(out17, nil, "ignored IP decision allow should bypass challenge")
assert_eq(ngx17.var.cfm_upstream, "cfm_panel_origin", "ignored IP should pass to panel origin")
assert_eq(capture_calls, 1, "forced flow should call decision backend once")

local _, out18 = run_case({ uri = "/", ip = "198.51.100.11", capture = function(uri)
  assert_eq(uri, "/__cfm_panel_decide", "non-ignored IP should still query decision path")
  return { status = 200, body = "challenge", header = { Location = "/__cfm_challenge" } }
end })
assert_eq(out18.action, "redirect", "non-ignored IP should be challenged")
assert_eq(out18.location, "/__cfm_challenge?next=%2F", "non-ignored IP challenge should use panel redirect format")

local ngx19, out19 = run_case({ uri = "/", ip = "198.51.100.42", capture = function(uri)
  assert_eq(uri, "/__cfm_panel_decide", "ignored CIDR should use same decision path")
  return { status = 200, body = '{"decision":"allow","reason":"ignore_net_match"}', header = {} }
end })
assert_eq(out19, nil, "ignored CIDR decision allow should bypass challenge")
assert_eq(ngx19.var.cfm_upstream, "cfm_panel_origin", "ignored CIDR should route to panel origin")


-- Duplicate next params must not permit internal decision target.
local _, out20 = run_case({
  uri = "/",
  request_uri = "/?next=%2F__cfm_panel_decide&next=%2F",
  uri_args = { next = { "/__cfm_panel_decide", "/" } },
})
assert_eq(out20.action, "redirect", "duplicate next flow should still challenge")
assert_eq(out20.location, "/__cfm_challenge?next=%2F", "duplicate next flow should normalize to public path")
if out20.location:find("/__cfm_panel_decide", 1, true) then
  error("duplicate next flow leaked internal decision URI", 2)
end

-- Verify path with internal next must sanitize next to /.
local ngx21 = run_case({
  uri = "/__cfm_verify",
  request_uri = "/__cfm_verify?next=%2F__cfm_panel_decide",
  cookie = "cfm_ok=ok",
  uri_args = { next = "/__cfm_panel_decide" },
})
assert_eq(ngx21.var.cfm_upstream, "cfm_panel_origin", "verify with internal next should still pass to origin")

-- Decision-provided internal next must be rewritten to public path.
local _, out22 = run_case({
  uri = "/",
  request_uri = "/",
  capture = function(uri)
    assert_eq(uri, "/__cfm_panel_decide", "decision capture uri mismatch")
    return { status = 200, body = "challenge", header = { Location = "/__cfm_challenge?next=/__cfm_panel_decide" } }
  end
})
assert_eq(out22.action, "redirect", "internal next decision flow should challenge")
assert_eq(out22.location, "/__cfm_challenge?next=%2F", "internal decision next should be rewritten to /")
if out22.location:find("/__cfm_panel_decide", 1, true) then
  error("decision flow leaked internal decision URI", 2)
end

print("ok")

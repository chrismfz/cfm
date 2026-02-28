-- /usr/local/openresty/nginx/lua/cfm.lua
--
-- CFM OpenResty in-path enforcement (route-by-variable version).
--
-- Flow:
--   1) Determine client IP (realip_remote_addr if available, else remote_addr)
--   2) Call CFM bridge over UNIX socket (HTTP) to get decision:
--        GET /nginx/decision?ip=...&host=...&uri=...&method=...&scheme=...
--        -> {"ip_action":"allow|challenge|block","vhost_action":"allow|challenge|block"}
--      Header: X-CFM-Token: <token>
--   3) Enforce:
--      - block     -> ngx.exit(403 by default)
--      - challenge -> ngx.var.cfm_pass = "http://cfm_challenge"
--      - allow     -> ngx.var.cfm_pass = "http(s)://$server_addr:80|443"
--
-- IMPORTANT:
--   Nginx must define: set $cfm_pass "";
--   and use:          proxy_pass $cfm_pass;
--
-- Notes:
--   - If bridge fails, fail-open by default (availability first).
--   - Optional debug headers available via env flags.

local cjson = require "cjson.safe"

-- ─────────────────────────────────────────────────────────────────────────────
-- CONFIG
-- ─────────────────────────────────────────────────────────────────────────────
local CFG = {
  sock_path = "/var/run/cfm/cfm_nginx.sock",

  token = "cfm",
  token_header = "X-CFM-Token",

  decision_timeout_ms   = 80,
  decision_cache_ttl_ms = 1500,

  block_code = 403,

  -- Fail-open vs fail-closed when bridge is unreachable/forbidden/etc.
  fail_open = true,

  -- Debugging (set env vars in systemd if needed)
  debug         = (os.getenv("CFM_DEBUG") == "1"),
  debug_headers = (os.getenv("CFM_DEBUG_HEADERS") == "1"),

  -- Log ALL allow decisions too (can be noisy on busy hosts)
  log_allows    = (os.getenv("CFM_LOG_ALLOWS") == "1"),

  -- Sliding OK TTL (cookie + bridge okState)
  ok_ttl_sec = tonumber(os.getenv("CFM_OK_TTL_SEC") or "1800"),
  -- Rate limit for /nginx/ok/touch per IP
  ok_touch_every_sec = tonumber(os.getenv("CFM_OK_TOUCH_EVERY_SEC") or "120"),
}
-- ─────────────────────────────────────────────────────────────────────────────

local SH = ngx.shared.cfm_decisions

local function log_route(level, msg)
  ngx.log(level or ngx.WARN, "[cfm] ", msg)
end

local function esc(s) return ngx.escape_uri(s or "") end

local function append_set_cookie(v)
  local h = ngx.header["Set-Cookie"]
  if not h then
    ngx.header["Set-Cookie"] = v
    return
  end
  if type(h) == "table" then
    table.insert(h, v)
    ngx.header["Set-Cookie"] = h
    return
  end
  ngx.header["Set-Cookie"] = { h, v }
end

local function real_ip()
  local rip = ngx.var.remote_addr
  if rip and rip ~= "" then return rip end
  local cf = ngx.var.http_cf_connecting_ip
  if cf and cf ~= "" then return cf end
  return "-"
end

-- ── Minimal HTTP GET over unix socket ────────────────────────────────────────

local function http_get_unix(path_qs)
  local s, err = ngx.socket.tcp()
  if not s then return nil, "socket.tcp: " .. (err or "unknown") end

  s:settimeouts(CFG.decision_timeout_ms, CFG.decision_timeout_ms, CFG.decision_timeout_ms)

  local ok, cerr = s:connect("unix:" .. CFG.sock_path)
  if not ok then
    s:close()
    return nil, "connect: " .. (cerr or "unknown")
  end

  local req =
    "GET " .. path_qs .. " HTTP/1.1\r\n" ..
    "Host: localhost\r\n" ..
    "Connection: close\r\n"

  if CFG.token and CFG.token ~= "" then
    req = req .. CFG.token_header .. ": " .. CFG.token .. "\r\n"
  end
  req = req .. "\r\n"

  local _, werr = s:send(req)
  if werr then s:close(); return nil, "send: " .. (werr or "unknown") end

  local status_line, rerr = s:receive("*l")
  if not status_line then s:close(); return nil, "recv status: " .. (rerr or "unknown") end

  local code = tonumber(status_line:match("%s(%d%d%d)%s"))
  if not code then s:close(); return nil, "bad status line: " .. status_line end

  local content_length
  while true do
    local line, herr = s:receive("*l")
    if not line then s:close(); return nil, "recv headers: " .. (herr or "unknown") end
    if line == "" then break end
    local k, v = line:match("^([^:]+):%s*(.*)$")
    if k and v and k:lower() == "content-length" then
      content_length = tonumber(v)
    end
  end

  local body
  if content_length and content_length > 0 then
    body = s:receive(content_length)
  else
    body = s:receive("*a")
  end
  s:close()

  if code ~= 200 then
    return nil, "http " .. tostring(code) .. " body=" .. tostring(body or "")
  end
  return body or "", nil
end

-- ── Minimal HTTP POST (JSON) over unix socket ─────────────────────────────────

local function http_post_unix(path, json_body)
  local s, err = ngx.socket.tcp()
  if not s then return nil, "socket.tcp: " .. (err or "unknown") end

  s:settimeouts(CFG.decision_timeout_ms, CFG.decision_timeout_ms, CFG.decision_timeout_ms)

  local ok, cerr = s:connect("unix:" .. CFG.sock_path)
  if not ok then s:close(); return nil, "connect: " .. (cerr or "unknown") end

  local body = json_body or ""
  local req =
    "POST " .. path .. " HTTP/1.1\r\n" ..
    "Host: localhost\r\n" ..
    "Connection: close\r\n" ..
    "Content-Type: application/json\r\n" ..
    "Content-Length: " .. tostring(#body) .. "\r\n"

  if CFG.token and CFG.token ~= "" then
    req = req .. CFG.token_header .. ": " .. CFG.token .. "\r\n"
  end
  req = req .. "\r\n" .. body

  local _, werr = s:send(req)
  if werr then s:close(); return nil, "send: " .. (werr or "unknown") end

  local status_line, rerr = s:receive("*l")
  if not status_line then s:close(); return nil, "recv status: " .. (rerr or "unknown") end

  local code = tonumber(status_line:match("%s(%d%d%d)%s"))
  if not code then s:close(); return nil, "bad status line: " .. status_line end

  while true do
    local line, herr = s:receive("*l")
    if not line then s:close(); return nil, "recv headers: " .. (herr or "unknown") end
    if line == "" then break end
  end
  local resp = s:receive("*a")
  s:close()

  if code ~= 200 then
    return nil, "http " .. tostring(code) .. " body=" .. tostring(resp or "")
  end
  return resp or "", nil
end

-- ── Helpers ───────────────────────────────────────────────────────────────────

local function touch_ok(ip)
  if not SH then return end
  local k = "ok_touch|" .. (ip or "-")
  local now = ngx.now()
  local last = SH:get(k)
  if last and (now - last) < CFG.ok_touch_every_sec then return end
  SH:set(k, now, CFG.ok_touch_every_sec)
  local payload = cjson.encode({ ip = ip, ttl_sec = CFG.ok_ttl_sec })
  http_post_unix("/nginx/ok/touch", payload)
end

local function refresh_ok_cookie(cookie_val)
  if not cookie_val or cookie_val == "" then return end
  local attrs = "Path=/; Max-Age=" .. tostring(CFG.ok_ttl_sec) .. "; HttpOnly; SameSite=Lax"
  if ngx.var.scheme == "https" then attrs = attrs .. "; Secure" end
  append_set_cookie("cfm_ok=" .. cookie_val .. "; " .. attrs)
end

local function fail_decision(errmsg)
  if CFG.fail_open then
    return { ip_action = "allow", vhost_action = "allow", err = errmsg }
  else
    return { ip_action = "block", vhost_action = "block", err = errmsg }
  end
end

local function cache_key(ip, host, uri, method, scheme)
  local uh = ngx.md5(uri or "-")
  return "d|" .. ip .. "|" .. host .. "|" .. (method or "-") .. "|" .. (scheme or "-") .. "|" .. uh
end

local function get_decision(ip, host, uri, method, scheme)
  local key = cache_key(ip, host, uri, method, scheme)

  if SH then
    local cached = SH:get(key)
    if cached then
      local obj = cjson.decode(cached)
      if obj then obj._cache = true; return obj end
    end
  end

  local path =
    "/nginx/decision?ip=" .. esc(ip) ..
    "&host=" .. esc(host) ..
    "&uri=" .. esc(uri) ..
    "&method=" .. esc(method) ..
    "&scheme=" .. esc(scheme)

  local body, err = http_get_unix(path)
  if not body then return fail_decision(err) end

  local obj = cjson.decode(body)
  if not obj then return fail_decision("decode_failed") end

  -- IMPORTANT: cache only ALLOW decisions (avoid solve→re-challenge loops)
  if SH then
    local ip_action    = obj.ip_action    or "allow"
    local vhost_action = obj.vhost_action or "allow"
    if ip_action == "allow" and vhost_action == "allow" then
      SH:set(key, body, CFG.decision_cache_ttl_ms / 1000)
    end
  end

  return obj
end

-- ─────────────────────────────────────────────────────────────────────────────
-- Main enforcement
-- ─────────────────────────────────────────────────────────────────────────────

local ip     = real_ip()
local peer_ip   = ngx.var.realip_remote_addr or ""
local cf_ip     = ngx.var.http_cf_connecting_ip or ""
local host   = ngx.var.host   or "-"
local uri    = ngx.var.uri    or "-"
local method = ngx.req.get_method() or "-"
local scheme = ngx.var.scheme or "http"

local function origin_pass_for(scheme_)
  local dst = ngx.var.server_addr or "127.0.0.1"
  if scheme_ == "https" then return "https://" .. dst .. ":443" end
  return "http://" .. dst .. ":80"
end

-- ── Fast-path: solved cookie ──────────────────────────────────────────────────
local cfm_ok_cookie = ngx.var.cookie_cfm_ok
if cfm_ok_cookie and cfm_ok_cookie ~= "" then
  refresh_ok_cookie(cfm_ok_cookie)
  touch_ok(ip)
  ngx.header["X-CFM-Action"] = "allow_cookie"
  ngx.var.cfm_upstream = "cfm_apache"
  ngx.var.cfm_pass = origin_pass_for(scheme)
  return
end

-- ── WAF (inline, before bridge query) ────────────────────────────────────────
local waf
do
  local ok, mod = pcall(require, "cfm_waf")
  if ok and mod then
    waf = mod
  elseif CFG.debug then
    log_route(ngx.WARN, "waf disabled: require cfm_waf failed: " .. tostring(mod))
  end
end

if waf and waf.enabled and waf.enabled() then
  -- Pass cookie + shdict so WAF can run the cookieless-RPS detector.
  local hit, reason, ttl, waf_action = waf.check({
    uri    = uri,
    args   = ngx.var.args or "",
    method = method,
    host   = host,
    ip     = ip,
    cookie = ngx.var.http_cookie or "",
    peer   = peer_ip,
    cf_ip  = cf_ip,
    shdict = SH,
  })

  if hit then
    waf_action = waf_action or "challenge"  -- safe default


    local push_host   = ngx.var.host or host or ""
    local push_uri    = ngx.var.request_uri or uri or "/"
    local push_method = ngx.req.get_method() or method or ""



-- log only dryrun logic --
    if waf_action == "logonly" then
      -- Dry-run audit mode:
      -- - Log to cfm.challenges.log (via nginx bridge trigger hook)
      -- - Do NOT challenge and do NOT block
      ngx.header["X-CFM-Action"] = "logonly"
      ngx.var.cfm_upstream = "cfm_apache"
      ngx.var.cfm_pass = origin_pass_for(scheme)

      if waf.should_push and waf.should_push(SH, ip, reason) then
        local payload = cjson.encode({
          ip      = ip,
          action  = "logonly",
          ttl_sec = ttl or 600,
          reason  = reason,
          host    = push_host,
          uri     = push_uri,
          method  = push_method,
        })
        local _, perr = http_post_unix("/nginx/ip", payload)
        if perr and CFG.debug then
          log_route(ngx.WARN, "waf logonly push failed: " .. tostring(perr))
        end
      end

      log_route(ngx.INFO, "waf_logonly ip=" .. ip .. " host=" .. host ..
        " uri=" .. uri .. " reason=" .. tostring(reason) ..
        " ttl=" .. tostring(ttl or 600))

      return
    end



    if waf_action == "block" then
      -- High-confidence rules: traversal, RCE, TRACE/TRACK/CONNECT.
      -- Hard 403 — no challenge page, no cookie dance.
      ngx.header["X-CFM-Action"] = "block"
      ngx.var.cfm_upstream = "cfm_block"
      ngx.var.cfm_pass = ""

      if waf.should_push and waf.should_push(SH, ip, reason) then
        local payload = cjson.encode({
          ip      = ip,
          action  = "block",
          ttl_sec = ttl or 3600,
          reason  = reason,
          host    = push_host,
          uri     = push_uri,
          method  = push_method,
        })
        local _, perr = http_post_unix("/nginx/ip", payload)
        if perr and CFG.debug then
          log_route(ngx.WARN, "waf block push failed: " .. tostring(perr))
        end
      end

      log_route(ngx.WARN, "waf_block ip=" .. ip .. " host=" .. host ..
        " uri=" .. uri .. " reason=" .. tostring(reason) ..
        " ttl=" .. tostring(ttl or 3600))

      return ngx.exit(CFG.block_code)

    else
      -- Lower-confidence rules: XSS, SQLi, PROPFIND, cookieless, etc.
      ngx.header["X-CFM-Action"] = "challenge"
      ngx.var.cfm_upstream = "cfm_challenge"
      ngx.var.cfm_pass = "http://cfm_challenge"

      if waf.should_push and waf.should_push(SH, ip, reason) then
        local payload = cjson.encode({
          ip      = ip,
          action  = "challenge",
          ttl_sec = ttl or 600,
          reason  = reason,
          host    = push_host,
          uri     = push_uri,
          method  = push_method,
        })
        local _, perr = http_post_unix("/nginx/ip", payload)
        if perr and CFG.debug then
          log_route(ngx.WARN, "waf push failed: " .. tostring(perr))
        end
      end

      log_route(ngx.INFO, "waf_challenge ip=" .. ip .. " host=" .. host ..
        " uri=" .. uri .. " reason=" .. tostring(reason) ..
        " ttl=" .. tostring(ttl or 600))

      return
    end
  end
end  -- ← closes: if waf and waf.enabled and waf.enabled() then

-- ── Bridge decision ───────────────────────────────────────────────────────────

local d = get_decision(ip, host, uri, method, scheme)

local ip_action    = d.ip_action    or "allow"
local vhost_action = d.vhost_action or "allow"
local cache_flag   = d._cache and " cache=1" or ""

if CFG.debug_headers then
  ngx.header["X-CFM-IP"]     = ip
  ngx.header["X-CFM-Host"]   = host
  ngx.header["X-CFM-Dec-IP"] = ip_action
  ngx.header["X-CFM-Dec-VH"] = vhost_action
  if d.err    then ngx.header["X-CFM-Err"]   = tostring(d.err) end
  if d._cache then ngx.header["X-CFM-Cache"] = "1" end
end

-- Block wins
if ip_action == "block" or vhost_action == "block" then
  ngx.header["X-CFM-Action"] = "block"
  ngx.var.cfm_upstream = "cfm_block"
  ngx.var.cfm_pass = ""
  log_route(ngx.WARN, "block ip=" .. ip .. " host=" .. host .. " uri=" .. uri ..
    " scheme=" .. scheme .. cache_flag ..
    (d.err and (" err=" .. tostring(d.err)) or ""))
  return ngx.exit(CFG.block_code)
end

-- Challenge if either says challenge
if ip_action == "challenge" or vhost_action == "challenge" then
  ngx.header["X-CFM-Action"] = "challenge"
  ngx.var.cfm_upstream = "cfm_challenge"
  ngx.var.cfm_pass = "http://cfm_challenge"
  log_route(ngx.INFO, "challenge ip=" .. ip .. " host=" .. host .. " uri=" .. uri ..
    " scheme=" .. scheme .. " pass=" .. ngx.var.cfm_pass .. cache_flag ..
    (d.err and (" err=" .. tostring(d.err)) or ""))
  return
end

-- Allow
ngx.header["X-CFM-Action"] = "allow"
ngx.var.cfm_upstream = "cfm_apache"
ngx.var.cfm_pass = origin_pass_for(scheme)

if CFG.log_allows or CFG.debug then
  log_route(ngx.INFO, "allow ip=" .. ip .. " host=" .. host .. " uri=" .. uri ..
    " scheme=" .. scheme .. " pass=" .. ngx.var.cfm_pass .. cache_flag)
end

return

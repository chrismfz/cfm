-- /usr/local/openresty/nginx/lua/cfm.lua
--
-- CFM OpenResty in-path enforcement (Unified & Efficient Version)
-- Optimized with Keepalive and Chunked Transfer Encoding support.
--
-- Fixes applied vs previous version:
--   [1] logonly WAF action now returns early — no longer falls through to bridge decision
--   [2] URI re-added to cache key (capped at 64 chars) — prevents allow-cache bypass on sensitive paths
--   [3] observe_waf reuses the keepalive pool via http_post_unix (no more rogue Connection: close)
--   [4] WAF caller now passes headers and a narrow request body (XML-RPC POST only)

local cjson = require "cjson.safe"

-- ─────────────────────────────────────────────────────────────────────────────
-- CONFIG
-- ─────────────────────────────────────────────────────────────────────────────
local CFG = {
  sock_path = "/var/run/cfm/cfm_nginx.sock",

  token        = "cfm",
  token_header = "X-CFM-Token",

  decision_timeout_ms   = 80,
  decision_cache_ttl_ms = 9000,

  block_code = 403,
  fail_open  = true,

  -- Debugging (set env vars in systemd/env if needed)
  debug         = (os.getenv("CFM_DEBUG") == "1"),
  debug_headers = (os.getenv("CFM_DEBUG_HEADERS") == "1"),
  log_allows    = (os.getenv("CFM_LOG_ALLOWS") == "1"),

  -- Sliding OK TTL (cookie + bridge okState)
  ok_ttl_sec         = tonumber(os.getenv("CFM_OK_TTL_SEC")         or "1800"),
  ok_touch_every_sec = tonumber(os.getenv("CFM_OK_TOUCH_EVERY_SEC") or "120"),

  -- Keepalive pool (per nginx worker)
  keepalive_idle_ms = tonumber(os.getenv("CFM_BRIDGE_KA_IDLE_MS") or "15000"),
  keepalive_pool    = tonumber(os.getenv("CFM_BRIDGE_KA_POOL")    or "128"),

  -- Narrow body read for inline WAF (only where needed)
  waf_body_max_len = tonumber(os.getenv("CFM_WAF_BODY_MAX_LEN") or "4096"),
}

local SH = ngx.shared.cfm_decisions

-- ─────────────────────────────────────────────────────────────────────────────
-- UTILS
-- ─────────────────────────────────────────────────────────────────────────────
local function log_route(level, msg)
  ngx.log(level or ngx.WARN, "[cfm] ", msg)
end

local function esc(s) return ngx.escape_uri(s or "") end

local function append_set_cookie(v)
  local h = ngx.header["Set-Cookie"]
  if not h then ngx.header["Set-Cookie"] = v; return end
  if type(h) == "table" then table.insert(h, v); ngx.header["Set-Cookie"] = h; return end
  ngx.header["Set-Cookie"] = { h, v }
end

local function real_ip()
  local rip = ngx.var.remote_addr
  if rip and rip ~= "" then return rip end
  local cf = ngx.var.http_cf_connecting_ip
  if cf and cf ~= "" then return cf end
  return "-"
end

local function lower(s)
  if not s then return "" end
  return string.lower(s)
end

local function has(s, pat)
  if not s or s == "" then return false end
  return string.find(s, pat, 1, true) ~= nil
end

-- Read request body only when really needed by inline WAF.
-- Decide whether a POST destination is risky enough to justify body inspection.
-- Goal:
--   1) cover common CMS/admin/plugin/theme exploit paths
--   2) stay generic across apps
--   3) avoid needing endless one-off endpoint additions
local function waf_should_read_body(uri, method)
  uri = lower(uri or "")
  method = lower(method or "")

  if method ~= "post" then
    return false
  end

  -- Root-level high-risk filenames / endpoints
  if has(uri, "/xmlrpc.php")        then return true end
  if has(uri, "/wp-login.php")      then return true end
  if has(uri, "/admin-ajax.php")    then return true end
  if has(uri, "/ajax")              then return true end
  if has(uri, "/api/")              then return true end
  if has(uri, "/graphql")           then return true end
  if has(uri, "/rest/")             then return true end

  -- WordPress / WooCommerce
  if has(uri, "/wp-admin/")                 then return true end
  if has(uri, "/wp-content/plugins/")       then return true end
  if has(uri, "/wp-content/themes/")        then return true end
  if has(uri, "/wp-content/uploads/")       then return true end
  if has(uri, "/wp-includes/")              then return true end
  if has(uri, "/wc-api/")                   then return true end
  if has(uri, "/wc-ajax=")                  then return true end
  if has(uri, "wc-ajax=")                   then return true end

  -- Joomla
  if has(uri, "/administrator/")  then return true end
  if has(uri, "/components/")     then return true end
  if has(uri, "/modules/")        then return true end
  if has(uri, "/plugins/")        then return true end
  if has(uri, "/templates/")      then return true end
  if has(uri, "/media/")          then return true end

  -- Drupal
  if has(uri, "/user/login")      then return true end
  if has(uri, "/admin/")          then return true end
  if has(uri, "/sites/default/")  then return true end
  if has(uri, "/modules/")        then return true end
  if has(uri, "/themes/")         then return true end

  -- PrestaShop
  if has(uri, "/admin")                   then return true end
  if has(uri, "/modules/")                then return true end
  if has(uri, "/themes/")                 then return true end
  if has(uri, "/upload/")                 then return true end
  if has(uri, "/filemanager/")            then return true end
  if has(uri, "/ajax-tab.php")            then return true end
  if has(uri, "/webservice/")             then return true end

  -- OpenCart
  if has(uri, "/admin/")                  then return true end
  if has(uri, "/catalog/")                then return true end
  if has(uri, "/system/")                 then return true end
  if has(uri, "/extension/")              then return true end
  if has(uri, "/index.php?route=")        then return true end

  -- CS-Cart
  if has(uri, "/admin.php")               then return true end
  if has(uri, "/backend/")                then return true end
  if has(uri, "/api/")                    then return true end
  if has(uri, "/addons/")                 then return true end
  if has(uri, "/var/themes_repository/")  then return true end

  -- Generic admin / installer / uploader / importer / tool paths
  if has(uri, "/admin")       then return true end
  if has(uri, "/administrator") then return true end
  if has(uri, "/login")       then return true end
  if has(uri, "/auth")        then return true end
  if has(uri, "/upload")      then return true end
  if has(uri, "/uploads")     then return true end
  if has(uri, "/import")      then return true end
  if has(uri, "/export")      then return true end
  if has(uri, "/restore")     then return true end
  if has(uri, "/backup")      then return true end
  if has(uri, "/install")     then return true end
  if has(uri, "/installer")   then return true end
  if has(uri, "/setup")       then return true end
  if has(uri, "/update")      then return true end
  if has(uri, "/upgrade")     then return true end
  if has(uri, "/filemanager") then return true end
  if has(uri, "/connector")   then return true end
  if has(uri, "/shell")       then return true end
  if has(uri, "/cmd")         then return true end

  -- Suspicious script extensions in risky places
  if uri:match("%.php[%?/].*") then return true end
  if uri:match("%.phtml[%?/].*") then return true end
  if uri:match("%.php$") then return true end
  if uri:match("%.phtml$") then return true end

  return false
end

-- Read request body only when justified by destination risk.
local function get_req_body_for_waf(uri, method, max_len)
  if not waf_should_read_body(uri, method) then
    return ""
  end

  ngx.req.read_body()

  local data = ngx.req.get_body_data()
  if data and data ~= "" then
    if #data > max_len then
      return string.sub(data, 1, max_len)
    end
    return data
  end

  local body_file = ngx.req.get_body_file()
  if body_file and body_file ~= "" then
    local f = io.open(body_file, "rb")
    if f then
      local chunk = f:read(max_len) or ""
      f:close()
      return chunk
    end
  end

  return ""
end



-- ─────────────────────────────────────────────────────────────────────────────
-- NETWORK LAYER (Keepalive + Chunked Support)
-- ─────────────────────────────────────────────────────────────────────────────

local function read_chunked(sock)
  local out = {}
  while true do
    local line, err = sock:receive("*l")
    if not line then return nil, "chunked size line: " .. (err or "?") end

    local hex = line:match("^%s*([0-9a-fA-F]+)")
    if not hex then return nil, "bad chunk size line: " .. tostring(line) end

    local n = tonumber(hex, 16)
    if not n then return nil, "bad chunk size hex: " .. tostring(hex) end

    if n == 0 then
      -- Drain trailers until blank line
      while true do
        local tline = sock:receive("*l")
        if not tline or tline == "" then break end
      end
      break
    end

    local data, derr = sock:receive(n)
    if not data then return nil, "chunk read: " .. (derr or "?") end
    table.insert(out, data)

    sock:receive(2) -- trailing CRLF
  end
  return table.concat(out), nil
end

local function http_unix(method, path, body)
  local s, err = ngx.socket.tcp()
  if not s then return nil, "socket.tcp: " .. (err or "unknown") end

  s:settimeouts(CFG.decision_timeout_ms, CFG.decision_timeout_ms, CFG.decision_timeout_ms)

  local ok, cerr = s:connect("unix:" .. CFG.sock_path)
  if not ok then s:close(); return nil, "connect: " .. (cerr or "unknown") end

  body = body or ""
  local req = method .. " " .. path .. " HTTP/1.1\r\n" ..
              "Host: localhost\r\n" ..
              "Connection: keep-alive\r\n"

  if CFG.token and CFG.token ~= "" then
    req = req .. CFG.token_header .. ": " .. CFG.token .. "\r\n"
  end

  if method == "POST" then
    req = req .. "Content-Type: application/json\r\n" ..
                 "Content-Length: " .. tostring(#body) .. "\r\n"
  end

  req = req .. "\r\n" .. body

  local _, werr = s:send(req)
  if werr then s:close(); return nil, "send: " .. (werr or "unknown") end

  local status_line, rerr = s:receive("*l")
  if not status_line then s:close(); return nil, "recv status: " .. (rerr or "unknown") end

  local code = tonumber(status_line:match("%s(%d%d%d)%s"))
  if not code then s:close(); return nil, "bad status line: " .. status_line end

  local content_length
  local is_chunked = false

  while true do
    local line, herr = s:receive("*l")
    if not line or line == "" then break end
    local k, v = line:match("^([^:]+):%s*(.*)$")
    if k and v then
      local kl = k:lower()
      if kl == "content-length" then
        content_length = tonumber(v)
      elseif kl == "transfer-encoding" and v:lower():find("chunked", 1, true) then
        is_chunked = true
      end
    end
  end

  local resp = ""
  if method == "HEAD" or code == 204 or code == 304 then
    resp = ""
  elseif content_length and content_length > 0 then
    resp = s:receive(content_length)
  elseif is_chunked then
    local b, berr = read_chunked(s)
    if not b then s:close(); return nil, berr end
    resp = b
  else
    resp = s:receive("*a") or ""
  end

  local ok_ka = s:setkeepalive(CFG.keepalive_idle_ms, CFG.keepalive_pool)
  if not ok_ka then s:close() end

  if code ~= 200 then
    return nil, "http " .. tostring(code) .. " body=" .. tostring(resp)
  end
  return resp, nil
end

local function http_get_unix(path_qs)  return http_unix("GET",  path_qs, nil) end
local function http_post_unix(path, b) return http_unix("POST", path,    b)   end

-- ─────────────────────────────────────────────────────────────────────────────
-- HELPERS
-- ─────────────────────────────────────────────────────────────────────────────

-- FIX [3]: reuse keepalive pool — removed the rogue raw socket + Connection: close
local function observe_waf(ip, host, uri, method, status, reason)
  if not ip or ip == "" then return end
  local payload = cjson.encode({
    ip     = ip,
    host   = host   or "",
    uri    = uri    or "/",
    method = method or "",
    status = status or 403,
    reason = reason or "",
  })
  -- Best-effort; ignore errors
  http_post_unix("/nginx/observe", payload)
end

local function touch_ok(ip)
  if not SH then return end
  local k   = "ok_touch|" .. (ip or "-")
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

-- FIX [2]: URI re-included in cache key (capped at 64 chars, no MD5 overhead)
-- Without URI, an "allow" cached for / would prevent the bridge from seeing
-- requests to /wp-admin, /xmlrpc.php etc. for the full 9-second TTL window.
local function get_decision(ip, host, uri, method, scheme)
  local uri_part = (uri or "-"):sub(1, 64)
  local key = "d|" .. ip .. "|" .. host .. "|" .. method .. "|" .. scheme .. "|" .. uri_part

  if SH then
    local cached = SH:get(key)
    if cached then
      local obj = cjson.decode(cached)
      if obj then obj._cache = true; return obj end
    end
  end

  local path = "/nginx/decision?ip=" .. esc(ip) ..
               "&host="   .. esc(host)   ..
               "&uri="    .. esc(uri)    ..
               "&method=" .. esc(method) ..
               "&scheme=" .. esc(scheme)

  local body, err = http_get_unix(path)
  if not body then return fail_decision(err) end

  local obj = cjson.decode(body)
  if not obj then return fail_decision("decode_failed") end

  -- Only cache clean allows — never cache challenge/block to avoid
  -- a brief allow window preventing a subsequent challenge from landing.
  if SH and obj.ip_action == "allow" and obj.vhost_action == "allow" then
    SH:set(key, body, CFG.decision_cache_ttl_ms / 1000)
  end
  return obj
end

-- ─────────────────────────────────────────────────────────────────────────────
-- MAIN ENFORCEMENT
-- ─────────────────────────────────────────────────────────────────────────────

local ip      = real_ip()
local peer_ip = ngx.var.realip_remote_addr or ""
local cf_ip   = ngx.var.http_cf_connecting_ip or ""
local host    = ngx.var.host or "-"
local uri     = ngx.var.uri or "-"
local method  = ngx.req.get_method() or "-"
local scheme  = ngx.var.scheme or "http"

local function origin_pass_for(s_in)
  local dst = ngx.var.server_addr or "127.0.0.1"
  return (s_in == "https" and "https://" or "http://") .. dst ..
         (s_in == "https" and ":443" or ":80")
end

-- ── Step 1: Fast-path — Solved Cookie ─────────────────────────────────────────
local cfm_ok_cookie = ngx.var.cookie_cfm_ok
if cfm_ok_cookie and cfm_ok_cookie ~= "" then
  refresh_ok_cookie(cfm_ok_cookie)
  touch_ok(ip)
  ngx.header["X-CFM-Action"] = "allow_cookie"
  ngx.var.cfm_upstream = "cfm_apache"
  ngx.var.cfm_pass     = origin_pass_for(scheme)
  return
end

-- ── Step 2: Inline WAF ────────────────────────────────────────────────────────
local waf_ok, waf = pcall(require, "cfm_waf")
if waf_ok and waf and waf.enabled and waf.enabled() then
  local req_headers = ngx.req.get_headers()
  local req_body    = get_req_body_for_waf(uri, method, CFG.waf_body_max_len)

  local hit, reason, ttl, waf_action = waf.check({
    uri     = uri,
    args    = ngx.var.args or "",
    method  = method,
    host    = host,
    ip      = ip,
    cookie  = ngx.var.http_cookie or "",
    peer    = peer_ip,
    cf_ip   = cf_ip,
    shdict  = SH,
    headers = req_headers,
    body    = req_body,
  })

  if hit then
    waf_action = waf_action or "challenge"
    local p_host = ngx.var.host        or host
    local p_uri  = ngx.var.request_uri or uri
    local p_meth = method

    if waf_action == "logonly" then
      ngx.header["X-CFM-Action"] = "logonly"
      ngx.var.cfm_upstream = "cfm_apache"
      ngx.var.cfm_pass     = origin_pass_for(scheme)

    elseif waf_action == "block" then
      ngx.header["X-CFM-Action"] = "block"
      ngx.var.cfm_upstream = "cfm_block"
      ngx.var.cfm_pass     = ""
      observe_waf(ip, host, p_uri, p_meth, 403, reason)

    else -- challenge
      ngx.header["X-CFM-Action"] = "challenge"
      ngx.var.cfm_upstream = "cfm_challenge"
      ngx.var.cfm_pass     = "http://cfm_challenge"
    end

    if waf.should_push and waf.should_push(SH, ip, reason) then
      local payload = cjson.encode({
        ip      = ip,
        action  = waf_action,
        ttl_sec = ttl or 600,
        reason  = reason,
        host    = p_host,
        uri     = p_uri,
        method  = p_meth,
      })
      http_post_unix("/nginx/ip", payload)
    end

    log_route(ngx.INFO, "waf_" .. waf_action .. " ip=" .. ip ..
      " host=" .. host .. " reason=" .. tostring(reason))

    if waf_action == "block" then
      return ngx.exit(CFG.block_code)
    end
    return
  end
end

-- ── Step 3: Bridge Decision ───────────────────────────────────────────────────
local d          = get_decision(ip, host, uri, method, scheme)
local ip_action  = d.ip_action    or "allow"
local vh_action  = d.vhost_action or "allow"
local cache_flag = d._cache and " cache=1" or ""

if CFG.debug_headers then
  ngx.header["X-CFM-IP"]     = ip
  ngx.header["X-CFM-Host"]   = host
  ngx.header["X-CFM-Dec-IP"] = ip_action
  ngx.header["X-CFM-Dec-VH"] = vh_action
  if d.err    then ngx.header["X-CFM-Err"]   = tostring(d.err) end
  if d._cache then ngx.header["X-CFM-Cache"] = "1" end
end

if ip_action == "block" or vh_action == "block" then
  ngx.header["X-CFM-Action"] = "block"
  ngx.var.cfm_upstream = "cfm_block"
  ngx.var.cfm_pass     = ""
  log_route(ngx.WARN, "block ip=" .. ip .. " host=" .. host .. cache_flag ..
    (d.err and (" err=" .. tostring(d.err)) or ""))
  return ngx.exit(CFG.block_code)
end

if ip_action == "challenge" or vh_action == "challenge" then
  ngx.header["X-CFM-Action"] = "challenge"
  ngx.var.cfm_upstream = "cfm_challenge"
  ngx.var.cfm_pass     = "http://cfm_challenge"
  log_route(ngx.INFO, "challenge ip=" .. ip .. " host=" .. host .. cache_flag)
  return
end

-- ── Step 4: Allow ─────────────────────────────────────────────────────────────
ngx.header["X-CFM-Action"] = "allow"
ngx.var.cfm_upstream = "cfm_apache"
ngx.var.cfm_pass     = origin_pass_for(scheme)

if CFG.log_allows or CFG.debug then
  log_route(ngx.INFO, "allow ip=" .. ip .. " host=" .. host ..
    " pass=" .. ngx.var.cfm_pass .. cache_flag)
end

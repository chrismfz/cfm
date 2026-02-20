-- /opt/openresty/nginx/lua/cfm.lua
--
-- CFM OpenResty in-path enforcement (single-file version).
--
-- Flow:
--   1) Determine client IP (realip_remote_addr if available, else remote_addr)
--   2) Call CFM bridge over UNIX socket (HTTP) to get decision:
--        GET /nginx/decision?ip=...&host=...&uri=...&method=...&scheme=...
--        -> {"ip_action":"allow|challenge|block","vhost_action":"allow|challenge|block"}
--      Header: X-CFM-Token: <token>
--   3) Enforce:
--      - block     -> ngx.exit(403 by default)
--      - challenge -> ngx.var.cfm_upstream = "cfm_challenge"
--      - allow     -> ngx.var.cfm_upstream = "cfm_apache"
--
-- Nginx requirements:
--   - In nginx.conf:
--       lua_shared_dict cfm_decisions 10m;
--       set $cfm_upstream "cfm_apache";
--       access_by_lua_file /opt/openresty/nginx/lua/cfm.lua;
--       location / { proxy_pass http://$cfm_upstream; ... }
--       location = /verify { bypass lua; proxy_pass http://cfm_challenge; ... }
--
-- Notes:
--   - This file does NOT define upstreams; it only sets ngx.var.cfm_upstream.
--   - Token can come from env (preferred) or fallback hardcoded.
--   - If the bridge call fails, we "fail-open" to allow (availability first).
--   - Change FAIL_OPEN=false if you want failures to block instead.

local cjson = require "cjson.safe"

-- ─────────────────────────────────────────────────────────────────────────────
-- CONFIG (edit here)
-- ─────────────────────────────────────────────────────────────────────────────
local CFG = {
  -- Bridge socket (CFM serves HTTP on this unix socket)
  sock_path = "/var/run/cfm/cfm_nginx.sock",

  -- Required auth token for bridge (header X-CFM-Token)
  -- Prefer setting OPENRESTY_TOKEN via systemd. Fallback is okay for testing.
  token = "cfm",
  token_header = "X-CFM-Token",

  -- Timeouts and cache
  decision_timeout_ms =  80,
  decision_cache_ttl_ms =  1500,

  -- Enforcement behavior
  upstream_allow = "cfm_apache",
  upstream_challenge = "cfm_challenge",
  block_code =  403,

  -- Fail-open vs fail-closed when bridge is unreachable/forbidden/etc.
  -- true  => if bridge errors, allow traffic (recommended initially)
  -- false => if bridge errors, block traffic (strict)
  fail_open = true,

  -- Debugging
  debug = (os.getenv("CFM_DEBUG") == "1"),
  debug_headers = (os.getenv("CFM_DEBUG_HEADERS") == "1"),
}
-- ─────────────────────────────────────────────────────────────────────────────

local SH = ngx.shared.cfm_decisions

local function dbg(msg)
  if CFG.debug then ngx.log(ngx.WARN, "[cfm] ", msg) end
end

local function esc(s) return ngx.escape_uri(s or "") end

local function real_ip()
  -- Works with realip module. If you trust Cloudflare/proxies properly,
  -- realip_remote_addr becomes the real visitor IP.
  return ngx.var.realip_remote_addr or ngx.var.remote_addr or "-"
end

-- Minimal HTTP GET over unix socket
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
  if werr then
    s:close()
    return nil, "send: " .. (werr or "unknown")
  end

  local status_line, rerr = s:receive("*l")
  if not status_line then
    s:close()
    return nil, "recv status: " .. (rerr or "unknown")
  end

  local code = tonumber(status_line:match("%s(%d%d%d)%s"))
  if not code then
    s:close()
    return nil, "bad status line: " .. status_line
  end

  local content_length
  while true do
    local line, herr = s:receive("*l")
    if not line then
      s:close()
      return nil, "recv headers: " .. (herr or "unknown")
    end
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

local function fail_decision(errmsg)
  if CFG.fail_open then
    return { ip_action = "allow", vhost_action = "allow", err = errmsg }
  else
    return { ip_action = "block", vhost_action = "block", err = errmsg }
  end
end

local function get_decision(ip, host, uri, method, scheme)
  local key = "d|" .. ip .. "|" .. host

  -- Read cache
  if SH then
    local cached = SH:get(key)
    if cached then
      local obj = cjson.decode(cached)
      if obj then
        obj._cache = true
        return obj
      end
    end
  end

  local path =
    "/nginx/decision?ip=" .. esc(ip) ..
    "&host=" .. esc(host) ..
    "&uri=" .. esc(uri) ..
    "&method=" .. esc(method) ..
    "&scheme=" .. esc(scheme)

  local body, err = http_get_unix(path)
  if not body then
    return fail_decision(err)
  end

  local obj = cjson.decode(body)
  if not obj then
    return fail_decision("decode_failed")
  end

  -- Store cache
  if SH then
    SH:set(key, body, CFG.decision_cache_ttl_ms / 1000)
  end

  return obj
end

-- ─────────────────────────────────────────────────────────────────────────────
-- Main enforcement
-- ─────────────────────────────────────────────────────────────────────────────

local ip = real_ip()
local host = ngx.var.host or "-"
local uri = ngx.var.request_uri or "-"
local method = ngx.req.get_method() or "-"
local scheme = ngx.var.scheme or "-"

local d = get_decision(ip, host, uri, method, scheme)
local ip_action = d.ip_action or "allow"
local vhost_action = d.vhost_action or "allow"

-- Optional debug headers (very useful while tuning)
if CFG.debug_headers then
  ngx.header["X-CFM-IP"] = ip
  ngx.header["X-CFM-Host"] = host
  ngx.header["X-CFM-Dec-IP"] = ip_action
  ngx.header["X-CFM-Dec-VH"] = vhost_action
  if d.err then ngx.header["X-CFM-Err"] = tostring(d.err) end
  if d._cache then ngx.header["X-CFM-Cache"] = "1" end
end

-- Block wins
if ip_action == "block" or vhost_action == "block" then
  ngx.header["X-CFM-Action"] = "block"
  dbg("block ip=" .. ip .. " host=" .. host .. " uri=" .. uri)
  return ngx.exit(CFG.block_code)
end

-- Challenge if either says challenge
if ip_action == "challenge" or vhost_action == "challenge" then
  ngx.header["X-CFM-Action"] = "challenge"
  dbg("challenge ip=" .. ip .. " host=" .. host .. " uri=" .. uri)

  ngx.var.cfm_upstream = CFG.upstream_challenge
  return
end

-- Allow
ngx.var.cfm_upstream = CFG.upstream_allow
return

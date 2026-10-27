-- configs/lua/cfm_lockdown.lua
--
-- Vhost LOCKDOWN at the edge: which vhosts withdraw the crawler bypass.
--
-- cfm.lua Step 0 passes every client on challenge_waf_bypass.conf straight to
-- the origin, before any other step: no challenge, no WAF, no rule reaches it.
-- A vhost in LOCKDOWN (a manual vhost challenge armed with lockdown, see
-- internal/webdetector/vhost_lockdown.go) withdraws that bypass for the
-- crawler ("1") prefixes, so they meet the vhost challenge like anyone else.
-- CDN prefixes ("2", QUIC.cloud) keep their bypass: they fetch for a site's
-- visitors. This module answers "is <host> locked down now?" for Step 0.
--
-- The daemon serves the set at GET /nginx/lockdown as
-- {"hosts": {"<host>": <expiry unix>}}. Each worker keeps its own copy and
-- refreshes it out of band (ngx.timer.at) every REFRESH_SEC, like
-- cfm_h3_config.lua. The expiry rides with each entry, so a lockdown ends on
-- time even while the bridge is unreachable; on a failed refresh the worker
-- keeps the last list it had.
--
-- Cost: called only for a bypass-listed request (the "1" prefixes): one table
-- lookup, plus a staleness check that may schedule a refresh. The refresh is
-- lazy: a worker that served no bypass request for a while serves its first
-- one after a new lockdown with the old table, then refreshes (one request
-- per worker, at most).
--
-- Failure is fail-OPEN to the old behaviour (bypass): a module that cannot
-- load or fetch never challenges a crawler the operator did not lock out.

local cjson = require "cjson.safe"
local hm    = require "cfm_hostmatch"

local _M = {}

local SOCK_PATH     = "/var/run/cfm/cfm_nginx.sock"
local BRIDGE_PATH   = "/nginx/lockdown"
local TOKEN_HEADER  = "X-CFM-Token"
local IO_TIMEOUT_MS = 200

local _hosts = {}            -- host -> expiry (unix seconds)
local _last_refresh_at = 0
local _refresh_in_progress = false
local _refresh_sec = tonumber(os.getenv("CFM_LOCKDOWN_REFRESH_SEC") or "5") or 5
if _refresh_sec < 1 then _refresh_sec = 1 end

local function load_bridge_token()
  local ok, bc = pcall(require, "cfm_bridge_cfg")
  if ok and type(bc) == "table" and bc.token then
    return (bc.token())
  end
  return nil
end

local function bridge_fetch()
  local token = load_bridge_token()
  if not token then return nil, "no bridge token yet" end
  local s, err = ngx.socket.tcp()
  if not s then return nil, "socket.tcp: " .. (err or "?") end
  s:settimeouts(IO_TIMEOUT_MS, IO_TIMEOUT_MS, IO_TIMEOUT_MS)
  local ok, cerr = s:connect("unix:" .. SOCK_PATH)
  if not ok then s:close(); return nil, "connect: " .. (cerr or "?") end
  local req = "GET " .. BRIDGE_PATH .. " HTTP/1.1\r\n" ..
              "Host: localhost\r\n" ..
              "Connection: close\r\n" ..
              TOKEN_HEADER .. ": " .. token .. "\r\n\r\n"
  local _, werr = s:send(req)
  if werr then s:close(); return nil, "send: " .. (werr or "?") end
  local status_line, rerr = s:receive("*l")
  if not status_line then s:close(); return nil, "recv status: " .. (rerr or "?") end
  local code = tonumber(status_line:match("%s(%d%d%d)%s"))
  if code ~= 200 then s:close(); return nil, "http " .. tostring(code) end
  while true do
    local line = s:receive("*l")
    if not line or line == "" then break end
  end
  local body = s:receive("*a") or ""
  s:close()
  return body, nil
end

-- rebuild replaces the table from a decoded feed: only string hosts with a
-- numeric expiry, normalized like every other host lookup at the edge.
local function rebuild(hosts)
  local t = {}
  if type(hosts) == "table" then
    for h, exp in pairs(hosts) do
      local n = tonumber(exp)
      if type(h) == "string" and n then
        local norm = hm.normalize_host(h)
        if norm ~= "" then t[norm] = n end
      end
    end
  end
  _hosts = t
end
_M._rebuild = rebuild -- tests

local function refresh_handler(premature)
  local ok, err = pcall(function()
    if premature then return end
    local body, ferr = bridge_fetch()
    _last_refresh_at = ngx.now()
    if body then
      local decoded = cjson.decode(body)
      if type(decoded) == "table" then
        rebuild(decoded.hosts)
      else
        ngx.log(ngx.WARN, "[cfm_lockdown] bad bridge response (not JSON)")
      end
    else
      ngx.log(ngx.WARN, "[cfm_lockdown] refresh failed: ", tostring(ferr), " (keeping last list)")
    end
  end)
  _refresh_in_progress = false
  if not ok then
    ngx.log(ngx.ERR, "[cfm_lockdown] refresh handler raised: ", tostring(err))
  end
end

local function schedule_refresh_if_needed()
  if _refresh_in_progress then return end
  if (ngx.now() - _last_refresh_at) < _refresh_sec then return end
  _refresh_in_progress = true
  local ok, err = ngx.timer.at(0, refresh_handler)
  if not ok then
    _refresh_in_progress = false
    ngx.log(ngx.WARN, "[cfm_lockdown] could not schedule refresh: ", tostring(err))
  end
end

-- active(host): true while host is locked down. Exact host only: the daemon
-- publishes the apex arm's www. variant itself and refuses wildcard lockdowns.
function _M.active(host)
  schedule_refresh_if_needed()
  local h = hm.normalize_host(host)
  if h == "" then return false end
  local exp = _hosts[h]
  return exp ~= nil and exp > ngx.time()
end

return _M

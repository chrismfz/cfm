-- /usr/local/openresty/nginx/lua/log-cfm.lua
--
-- CFM webdetector log ingestion via Unix socket.
--
-- Intended for use inside log_by_lua_block. ngx.socket.tcp() is DISABLED in
-- the log phase, so the build-the-line part runs inline (where ngx.var.* is
-- available) and the actual socket send is deferred into ngx.timer.at(0, ...)
-- which executes in a light-thread context where cosockets are allowed.
--
-- Emits one TSV record per request to /run/cfm/ingest.sock, matching the
-- exact column order and delimiters produced by the cfm_tsv access_log
-- format. The receiver (CFM socket listener) reuses the existing TSV
-- parser, so the contract MUST stay in sync with
-- internal/webdetector/engine.go::parseTSV.
--
-- Field order (TAB-separated, newline-terminated, 12 columns):
--
--   idx  field   ngx source               type / notes
--   ---  ------  -----------------------  ----------------------------------
--    0   ts      ngx.var.msec             seconds, fractional
--    1   ip      ngx.var.remote_addr      string
--    2   host    ngx.var.host             string (lowercased downstream)
--    3   method  ngx.var.request_method   string
--    4   uri     ngx.var.request_uri      full URI with query string
--    5   proto   ngx.var.server_protocol  "HTTP/1.1" etc.
--    6   status  ngx.var.status           int
--    7   bytes   ngx.var.body_bytes_sent  int64
--    8   rt      ngx.var.request_time     seconds (float)
--    9   urt     ngx.var.upstream_response_time  seconds or "-" (normalized to 0 downstream)
--   10   ref     ngx.var.http_referer     string (tabs/newlines stripped)
--   11   ua      ngx.var.http_user_agent  string (tabs/newlines stripped)
--
-- Connection reuse: setkeepalive(10000, 100) gives us up to 100 pooled
-- cosockets per worker, idle timeout 10s. First timer per worker pays
-- the connect cost (≤50ms), subsequent ones reuse the pool.
--
-- Failure policy: if the socket is missing or the send fails (CFM not
-- running, socket being rotated, etc.) we drop the line silently. The
-- request must NEVER be affected.

local _M = {}

local SOCK_PATH    = "/run/cfm/ingest.sock"
local CONNECT_MS   = 50
local SEND_MS      = 50
local KEEPALIVE_MS = 10000
local POOL_SIZE    = 100

-- Sanitize a field so it cannot break the TSV contract: strip \t, \r, \n.
local function clean(s)
  if s == nil then return "" end
  if type(s) ~= "string" then s = tostring(s) end
  s = s:gsub("[\t\r\n]", " ")
  return s
end

local function nz(s)
  if s == nil or s == "" then return "-" end
  return s
end

-- Timer callback: runs outside the log phase, so cosockets are permitted.
-- `line` is the fully-built TSV record captured in _M.log() below.
local function send_line(premature, line)
  if premature then return end

  local sock = ngx.socket.tcp()
  sock:settimeouts(CONNECT_MS, SEND_MS, SEND_MS)

  local ok, err = sock:connect("unix:" .. SOCK_PATH)
  if not ok then
    -- Socket absent / CFM down / permissions. Drop silently; a WARN here
    -- would hit every request and drown the error log.
    return
  end

  local _, serr = sock:send(line)
  if serr then
    sock:close()
    return
  end

  local kok, kerr = sock:setkeepalive(KEEPALIVE_MS, POOL_SIZE)
  if not kok then
    sock:close()
    if kerr and kerr ~= "closed" then
      ngx.log(ngx.WARN, "cfm log socket keepalive failed: ", kerr)
    end
  end
end

function _M.log()
  local var = ngx.var
  local line = table.concat({
    nz(var.msec),
    nz(var.remote_addr),
    nz(var.host),
    nz(var.request_method),
    clean(var.request_uri),
    nz(var.server_protocol),
    nz(var.status),
    nz(var.body_bytes_sent),
    nz(var.request_time),
    nz(var.upstream_response_time),
    clean(var.http_referer),
    clean(var.http_user_agent),
  }, "\t") .. "\n"

  -- Defer the send: cosockets are disabled in log_by_lua*, but they are
  -- allowed in ngx.timer.at callbacks, which is the standard workaround.
  local ok, terr = ngx.timer.at(0, send_line, line)
  if not ok and terr ~= "too many pending timers" then
    -- Pending-timer exhaustion is expected under extreme load and should
    -- not spam the error log; anything else is unusual.
    ngx.log(ngx.WARN, "cfm log timer.at failed: ", terr)
  end
end

return _M

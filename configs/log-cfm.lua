-- /usr/local/openresty/nginx/lua/log-cfm.lua
--
-- CFM webdetector log ingestion via Unix socket.
--
-- Intended for use inside log_by_lua_block (runs after the response has been
-- sent to the client; cosockets are allowed).
--
-- Emits one TSV record per request to /run/cfm/ingest.sock, matching the
-- exact column order and delimiters produced by the cfm_tsv access_log
-- format (configs/openresty-cfm-tsv.conf). The receiver (CFM socket
-- listener) reuses the existing TSV parser, so the contract MUST stay in
-- sync with internal/webdetector/engine.go::parseTSV.
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
-- cosockets per worker, idle timeout 10s. First request per worker pays
-- the connect cost (≤50ms), subsequent ones reuse the pool.
--
-- Failure policy: if the socket is missing or the send fails (CFM not
-- running, socket being rotated, etc.) we ngx.log(WARN) once in a while
-- and drop the line silently. The request must NEVER be affected.

local _M = {}

local SOCK_PATH    = "/run/cfm/ingest.sock"
local CONNECT_MS   = 50
local SEND_MS      = 50
local KEEPALIVE_MS = 10000
local POOL_SIZE    = 100

-- Sanitize a field so it cannot break the TSV contract: strip \t, \r, \n.
-- Cheap, single-pass.
local function clean(s)
  if s == nil then return "" end
  if type(s) ~= "string" then s = tostring(s) end
  -- gsub returns (new, count); we only care about the new string.
  s = s:gsub("[\t\r\n]", " ")
  return s
end

local function nz(s)
  if s == nil or s == "" then return "-" end
  return s
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

  local sock = ngx.socket.tcp()
  sock:settimeouts(CONNECT_MS, SEND_MS, SEND_MS)

  local ok, err = sock:connect("unix:" .. SOCK_PATH)
  if not ok then
    -- Socket absent / CFM down / permissions. Drop silently; a WARN here
    -- would hit every request and drown the error log, so we skip.
    return
  end

  local _, serr = sock:send(line)
  if serr then
    ngx.log(ngx.WARN, "cfm log socket send failed: ", serr)
    sock:close()
    return
  end

  -- Pool the connection for reuse by the next request on this worker.
  local kok, kerr = sock:setkeepalive(KEEPALIVE_MS, POOL_SIZE)
  if not kok then
    -- Not fatal; pool may be full on a very hot worker.
    sock:close()
    if kerr and kerr ~= "closed" then
      ngx.log(ngx.WARN, "cfm log socket keepalive failed: ", kerr)
    end
  end
end

return _M

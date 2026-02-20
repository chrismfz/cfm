-- /opt/openresty/nginx/lua/sslcollector.lua
-- QUIC-safe SSL Collector (preload + refresh):
-- - Background timer fetches /dumpall over unix socket and stores PEM strings in shared_dict
-- - ssl_certificate_by_lua_block ONLY does dict lookup + PEM parse + set_cert (no I/O, no yield)

local ssl  = require "ngx.ssl"
local http = require "resty.http"
local json = require "cjson.safe"

local dict = ngx.shared.sslcache

-- Socket + token (token fallback for now; you can remove fallback once env is always set)
local SOCK  = os.getenv("OPENRESTY_SOCK")  or "/var/run/sslcollector.sock"
local TOKEN = os.getenv("OPENRESTY_TOKEN") or "supersecret"

-- Tunables
local POLL_SECS = tonumber(os.getenv("SSL_POLL_SECS") or "20")    -- how often to poll /stats
local DUMP_TTL  = tonumber(os.getenv("SSL_DUMP_TTL")  or "3600")  -- TTL for cached entries
local LOCK_TTL  = tonumber(os.getenv("SSL_LOCK_TTL")  or "30")    -- dumpall lock ttl
local HTTP_TIMEOUT_MS = tonumber(os.getenv("SSL_HTTP_TIMEOUT_MS") or "5000")

local M = {}

local function normalize_name(s)
  if not s then return "" end
  s = tostring(s)
  s = s:lower()
  s = s:gsub("^%s+", ""):gsub("%s+$", "")  -- trim
  s = s:gsub("%.$", "")                   -- strip trailing dot
  return s
end

local function auth_headers()
  local h = { ["Host"] = "localhost" }
  if TOKEN and TOKEN ~= "" then
    h["X-SSLCollector-Token"] = TOKEN
  end
  return h
end

local function sock_get(path)
  local httpc = http.new()
  httpc:set_timeout(HTTP_TIMEOUT_MS)

  local ok, err = httpc:connect("unix:" .. SOCK)
  if not ok then
    return nil, "connect: " .. (err or "?")
  end

  local res, rerr = httpc:request({
    method  = "GET",
    path    = path,
    headers = auth_headers(),
  })

  if not res then
    httpc:close()
    return nil, "request: " .. (rerr or "?")
  end

  local body = res:read_body()
  httpc:close()

  return { status = res.status, body = body }
end

-- Store PEM strings (shared_dict-safe)
local function store_pair(prefix, name, cert_pem, key_pem, ttl)
  if not name or name == "" then
    return false, "empty name"
  end
  if not cert_pem or cert_pem == "" then
    return false, "empty cert_pem"
  end
  if not key_pem or key_pem == "" then
    return false, "empty key_pem"
  end

  local kc = prefix .. "pemcert:" .. name
  local kk = prefix .. "pemkey:"  .. name

  local okc, errc = dict:set(kc, cert_pem, ttl)
  if not okc then
    return false, "dict:set cert failed: " .. (errc or "?")
  end

  local okk, errk = dict:set(kk, key_pem, ttl)
  if not okk then
    return false, "dict:set key failed: " .. (errk or "?")
  end

  return true
end

local function do_dumpall()
  local lock_key = "lock:dumpall"
  if not dict:add(lock_key, true, LOCK_TTL) then
    return
  end

  local r, err = sock_get("/dumpall")
  if not r then
    ngx.log(ngx.ERR, "[sslcollector] dumpall failed: ", err)
    dict:delete(lock_key)
    return
  end
  if r.status ~= 200 then
    ngx.log(ngx.ERR, "[sslcollector] dumpall http ", r.status)
    dict:delete(lock_key)
    return
  end

  local data = json.decode(r.body)
  if not data then
    ngx.log(ngx.ERR, "[sslcollector] dumpall bad json")
    dict:delete(lock_key)
    return
  end

  local ver = data.version or data.Version or ""
  if ver ~= "" then
    dict:set("meta:version", ver, 86400)
  end
  if data.generated_at then
    dict:set("meta:generated_at", tostring(data.generated_at), 86400)
  end

  local okN, failN = 0, 0

  local exact = data.exact or data.Exact or {}
  for _, it in ipairs(exact) do
    local host = normalize_name(it.host or it.Host)
    local cert_pem = it.cert_pem or it.cert or it.CertPEM
    local key_pem  = it.key_pem  or it.key  or it.KeyPEM

    if host ~= "" and cert_pem and key_pem then
      local ok, e = store_pair("e:", host, cert_pem, key_pem, DUMP_TTL)
      if ok then okN = okN + 1 else failN = failN + 1; ngx.log(ngx.WARN, "[sslcollector] store exact fail host=", host, " err=", e) end
    else
      failN = failN + 1
    end
  end

  local wild = data.wild or data.Wild or {}
  for _, it in ipairs(wild) do
    local suf = normalize_name(it.suffix or it.Suffix) -- represents "*.suffix"
    local cert_pem = it.cert_pem or it.cert or it.CertPEM
    local key_pem  = it.key_pem  or it.key  or it.KeyPEM

    if suf ~= "" and cert_pem and key_pem then
      local ok, e = store_pair("w:", suf, cert_pem, key_pem, DUMP_TTL)
      if ok then okN = okN + 1 else failN = failN + 1; ngx.log(ngx.WARN, "[sslcollector] store wild fail suffix=", suf, " err=", e) end
    else
      failN = failN + 1
    end
  end

  dict:set("meta:ready", "1", 86400)
  ngx.log(ngx.NOTICE, "[sslcollector] dumpall loaded ok=", okN, " fail=", failN, " ver=", (ver ~= "" and ver or "-"))

  dict:delete(lock_key)
end

local function poll_stats(premature)
  if premature then return end

  local r = sock_get("/stats")
  if r and r.status == 200 then
    local st = json.decode(r.body)
    if st then
      local newv = st.Version or st.version or ""
      if newv ~= "" then
        local cur = dict:get("meta:version") or ""
        if newv ~= cur then
          ngx.log(ngx.NOTICE, "[sslcollector] version change ", cur, " -> ", newv, " (refresh)")
          do_dumpall()
          dict:set("meta:version", newv, 86400)
        end
      end
    end
  end

  local ok, e = ngx.timer.at(POLL_SECS, poll_stats)
  if not ok then
    ngx.log(ngx.ERR, "[sslcollector] poll timer error: ", e)
  end
end

function M.start_background()
  local ok, e = ngx.timer.at(0, function(premature)
    if premature then return end
    do_dumpall()
    -- slight delay avoids immediate "version change from empty" double-run
    ngx.timer.at(1, poll_stats)
  end)
  if not ok then
    ngx.log(ngx.ERR, "[sslcollector] start_background timer error: ", e)
  end
end

-- QUIC-safe: no socket calls here.
function M.set_cert()
  local sni = ssl.server_name()
  if not sni or sni == "" then
    return
  end
  sni = normalize_name(sni)

  -- Exact PEM
  local cert_pem = dict:get("e:pemcert:" .. sni)
  local key_pem  = dict:get("e:pemkey:"  .. sni)

  -- Wildcard suffix PEM (longest suffix match)
  if not cert_pem or not key_pem then
    local tmp = sni
    while true do
      local dot = string.find(tmp, "%.")
      if not dot then break end
      tmp = string.sub(tmp, dot + 1)
      cert_pem = dict:get("w:pemcert:" .. tmp)
      key_pem  = dict:get("w:pemkey:"  .. tmp)
      if cert_pem and key_pem then
        break
      end
    end
  end

  if not cert_pem or not key_pem then
    return -- keep fallback cert
  end

  local cert_der, cerr = ssl.parse_pem_cert(cert_pem)
  if not cert_der then
    ngx.log(ngx.ERR, "[sslcollector] parse cert failed sni=", sni, " err=", cerr or "?")
    return
  end

  local key_der, kerr = ssl.parse_pem_priv_key(key_pem)
  if not key_der then
    ngx.log(ngx.ERR, "[sslcollector] parse key failed sni=", sni, " err=", kerr or "?")
    return
  end

  ssl.clear_certs()

  local ok1, err1 = ssl.set_cert(cert_der)
  if not ok1 then
    ngx.log(ngx.ERR, "[sslcollector] ssl.set_cert failed sni=", sni, " err=", err1 or "?")
    return
  end

  local ok2, err2 = ssl.set_priv_key(key_der)
  if not ok2 then
    ngx.log(ngx.ERR, "[sslcollector] ssl.set_priv_key failed sni=", sni, " err=", err2 or "?")
    return
  end
end

return M

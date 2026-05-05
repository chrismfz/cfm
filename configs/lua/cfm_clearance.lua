local _M = {}

local bit = require "bit"
local ok, cjson = pcall(require, "cjson.safe")
if not ok then
  cjson = require "cjson"
end

-- ngx is provided by OpenResty at runtime.
local ngx = ngx

local function lower(s) return string.lower(s or "") end

local function normalize_host(h)
  h = lower(h or "")
  h = h:gsub("^%s+", ""):gsub("%s+$", "")
  h = h:gsub(":%d+$", "")
  h = h:gsub("%.+$", "")
  return h
end

local function b64url_decode(seg)
  if not seg or seg == "" then return nil end
  seg = seg:gsub("-", "+"):gsub("_", "/")
  local m = #seg % 4
  if m == 2 then seg = seg .. "==" elseif m == 3 then seg = seg .. "=" elseif m == 1 then return nil end
  return ngx.decode_base64(seg)
end

local function hex_from_bin(s)
  return (s:gsub('.', function(c) return string.format('%02x', string.byte(c)) end))
end

local function hmac_sha256_hex(secret, payload)
  local key = tostring(secret or "")
  local msg = tostring(payload or "")

  if ngx and type(ngx.hmac_sha256) == "function" then
    local ok, bin = pcall(ngx.hmac_sha256, key, msg)
    if ok and type(bin) == "string" then
      return hex_from_bin(bin), nil
    end
  end

  local ok_hmac, hmac_mod = pcall(require, "resty.openssl.hmac")
  if ok_hmac and hmac_mod then
    local ctx, new_err = hmac_mod.new(key, "sha256")
    if not ctx then return nil, "crypto_unavailable" end
    local ok_update = pcall(ctx.update, ctx, msg)
    if not ok_update then return nil, "crypto_unavailable" end
    local ok_final, bin = pcall(ctx.final, ctx)
    if ok_final and type(bin) == "string" then
      return hex_from_bin(bin), nil
    end
  end

  return nil, "crypto_unavailable"
end

local function ct_eq_hex(a, b)
  if not a or not b or #a ~= #b then return false end
  local acc = 0
  for i = 1, #a do acc = bit.bor(acc, bit.bxor(string.byte(a, i), string.byte(b, i))) end
  return acc == 0
end

function _M.validate(token, ip, host, scope, secret)
  if not token or token == "" then return false, "missing" end
  local raw = b64url_decode(token)
  if not raw then return false, "bad_sig" end
  local obj = cjson.decode(raw)
  if obj == nil or type(obj) ~= "table" then return false, "bad_sig" end
  if tostring(obj.v or "") ~= "1" then return false, "bad_sig" end
  local exp = tonumber(obj.exp or 0) or 0
  if exp <= 0 or exp <= ngx.time() then return false, "expired" end
  if tostring(obj.ip or "") ~= tostring(ip or "") then return false, "ip_mismatch" end
  if normalize_host(obj.host) ~= normalize_host(host) then return false, "host_mismatch" end
  if tostring(obj.scope or "") ~= tostring(scope or "") then return false, "scope_mismatch" end
  if tostring(obj.nonce or "") == "" then return false, "bad_sig" end
  local mac = tostring(obj.hmac or "")
  if not mac:match("^[0-9a-fA-F]+$") then return false, "bad_sig" end
  local payload = table.concat({ tostring(obj.v), tostring(exp), tostring(obj.ip), normalize_host(obj.host), tostring(obj.scope), tostring(obj.nonce) }, "|")
  local want, hmac_err = hmac_sha256_hex(secret, payload)
  if not want then return false, hmac_err or "validator_error" end
  if not ct_eq_hex(lower(mac), lower(want)) then return false, "bad_sig" end
  return true, "ok"
end

function _M.normalize_host(host)
  return normalize_host(host)
end

local function normalize_forwarded_port(port)
  local p = tostring(port or ""):match("%d+")
  if not p or p == "" then return nil end
  return p
end

function _M.panel_scope(panel_port, forwarded_port, panel_origin, server_port)
  local port = normalize_forwarded_port(panel_port)
  if not port then
    port = normalize_forwarded_port(forwarded_port)
  end
  if not port then
    port = normalize_forwarded_port(tostring(panel_origin or ""):match(":(%d+)"))
  end
  if not port then
    port = normalize_forwarded_port(server_port)
  end
  if not port then port = "unknown" end
  return "panel:" .. port
end

function _M.derive_scope(mode, forwarded_port, panel_origin, server_port)
  if tostring(mode or "web") == "web" then return "web" end
  return _M.panel_scope(nil, forwarded_port, panel_origin, server_port)
end

function _M.normalize_forwarded_port(port)
  return normalize_forwarded_port(port)
end

return _M

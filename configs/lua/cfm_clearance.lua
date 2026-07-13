local _M = {}

local bit = require "bit"
local ok, cjson = pcall(require, "cjson.safe")
if not ok then
  cjson = require "cjson"
end

-- ngx is provided by OpenResty at runtime.
local ngx = ngx

local function lower(s) return string.lower(s or "") end

-- normalize_host mirrors the Go normalizeClearanceHost() (challenge_server.go)
-- so a clearance minted server-side and validated in Lua bind to the same host.
-- The old `:%d+$` port strip corrupted IPv6-literal Hosts — it deleted the last
-- hextet of an UNBRACKETED literal (2001:db8::1 -> "2001:db8:") and never
-- unwrapped brackets, so distinct IPv6 hosts collapsed to one value and a
-- clearance for one was accepted on an adjacent one (audit F40). Match Go: strip
-- a trailing port ONLY for a bracketed literal or a single-colon host:port; an
-- unbracketed literal (>=2 colons) is left intact.
local function normalize_host(h)
  h = lower(h or "")
  h = h:gsub("^%s+", ""):gsub("%s+$", "")   -- TrimSpace
  h = h:gsub("%.$", "")                       -- TrimSuffix(".")  [Go step 2]
  if h:sub(1, 1) == "[" then
    -- Bracketed IPv6 literal ([ipv6] or [ipv6]:port): unwrap to the ipv6,
    -- dropping the brackets AND any :port.
    local rb = h:find("]", 1, true)
    if rb then h = h:sub(2, rb - 1) end
  else
    -- No brackets. Count colons: exactly one is a host:port → strip the port
    -- (mirrors net.SplitHostPort's single-colon case); zero is portless; two or
    -- more is an unbracketed IPv6 literal, left INTACT.
    local _, ncolon = h:gsub(":", "")
    if ncolon == 1 then h = h:match("^([^:]*)") end
  end
  h = h:gsub("%.$", "")                       -- TrimSuffix(".")  [Go step 6]
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

-- Lazy-cached HMAC backend resolution. Tried in order:
--   1) ngx.hmac_sha256        (lua-resty-core, OpenResty 1.21+ default)
--   2) resty.openssl.hmac     (lua-resty-openssl, optional package)
--   3) resty.sha256 + manual  (lua-resty-string, ALWAYS bundled with OpenResty)
-- Falling back to (3) is critical for environments where (1) and (2) are
-- absent — without it, every clearance cookie verifies as
-- "crypto_unavailable" and the panel goes into an endless challenge loop.
local hmac_backend          -- "ngx" | "openssl" | "sha256" | false
local hmac_backend_sha256   -- cached resty.sha256 module (when backend == "sha256")

local function resolve_hmac_backend()
  if hmac_backend ~= nil then return hmac_backend end
  if ngx and type(ngx.hmac_sha256) == "function" then
    hmac_backend = "ngx"
    return hmac_backend
  end
  do
    local ok, mod = pcall(require, "resty.openssl.hmac")
    if ok and mod then
      hmac_backend = "openssl"
      return hmac_backend
    end
  end
  do
    local ok, mod = pcall(require, "resty.sha256")
    if ok and mod then
      hmac_backend = "sha256"
      hmac_backend_sha256 = mod
      return hmac_backend
    end
  end
  hmac_backend = false
  if ngx and type(ngx.log) == "function" then
    ngx.log(ngx.WARN,
      "[cfm_clearance] no HMAC-SHA256 backend available: ",
      "tried ngx.hmac_sha256 (lua-resty-core), resty.openssl.hmac (lua-resty-openssl), ",
      "and resty.sha256 (lua-resty-string) — clearance cookies will all fail validation")
  end
  return hmac_backend
end

local function hmac_sha256_via_resty_sha256(key, msg)
  local sha = hmac_backend_sha256
  if not sha then return nil, "crypto_unavailable" end
  local block_size = 64  -- SHA-256 block size in bytes

  -- Shorten an over-long key by hashing it.
  if #key > block_size then
    local h = sha:new()
    if not h then return nil, "crypto_unavailable" end
    h:update(key)
    local short = h:final()
    if not short then return nil, "crypto_unavailable" end
    key = short
  end
  if #key < block_size then
    key = key .. string.rep("\0", block_size - #key)
  end

  -- Inner / outer pads
  local ipad = {}
  local opad = {}
  for i = 1, block_size do
    local b = string.byte(key, i)
    ipad[i] = string.char(bit.bxor(b, 0x36))
    opad[i] = string.char(bit.bxor(b, 0x5c))
  end
  local ipad_s = table.concat(ipad)
  local opad_s = table.concat(opad)

  local h = sha:new()
  if not h then return nil, "crypto_unavailable" end
  h:update(ipad_s)
  h:update(msg)
  local inner = h:final()
  if not inner then return nil, "crypto_unavailable" end

  h = sha:new()
  if not h then return nil, "crypto_unavailable" end
  h:update(opad_s)
  h:update(inner)
  local final = h:final()
  if not final then return nil, "crypto_unavailable" end
  return final, nil
end

local function hmac_sha256_hex(secret, payload)
  local key = tostring(secret or "")
  local msg = tostring(payload or "")

  local backend = resolve_hmac_backend()
  if backend == "ngx" then
    local ok, bin = pcall(ngx.hmac_sha256, key, msg)
    if ok and type(bin) == "string" then
      return hex_from_bin(bin), nil
    end
    -- ngx.hmac_sha256 is a function but failed at runtime: fall through
    -- to the next backend rather than wedging.
  end

  if backend == "openssl" or backend == "ngx" then
    local ok_hmac, hmac_mod = pcall(require, "resty.openssl.hmac")
    if ok_hmac and hmac_mod then
      local ctx = hmac_mod.new(key, "sha256")
      if ctx then
        local ok_update = pcall(ctx.update, ctx, msg)
        if ok_update then
          local ok_final, bin = pcall(ctx.final, ctx)
          if ok_final and type(bin) == "string" then
            return hex_from_bin(bin), nil
          end
        end
      end
    end
  end

  -- Always reachable in stock OpenResty (lua-resty-string ships resty.sha256).
  if backend == "sha256" or hmac_backend_sha256 == nil then
    if hmac_backend_sha256 == nil then
      local ok, mod = pcall(require, "resty.sha256")
      if ok and mod then hmac_backend_sha256 = mod end
    end
    if hmac_backend_sha256 then
      local bin, err = hmac_sha256_via_resty_sha256(key, msg)
      if bin then return hex_from_bin(bin), nil end
      return nil, err or "crypto_unavailable"
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
  -- Fail CLOSED on a nil/empty secret, mirroring _M.mint's `missing_secret`
  -- guard. Without this, hmac_sha256_hex coerces a nil secret to key="" and
  -- computes a real HMAC with an EMPTY key — which is publicly computable, so an
  -- attacker could forge a valid clearance. That state became reachable at
  -- runtime with audit F47 (a missing bridge token no longer 500s; it fails open,
  -- and the token is also the clearance HMAC secret, so validate now runs with
  -- secret=nil during the token-missing window). A forged clearance would
  -- short-circuit forced-challenge gates and downgrade challenge-tier WAF verdicts
  -- (block-tier still blocks). No legitimate caller passes an empty secret.
  if not secret or secret == "" then return false, "missing_secret" end
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

-- mint() builds a fresh cfm_clearance token bound to (ip, host, scope)
-- with exp = now + ttl_sec. Layout (payload + JSON keys + base64url-of-JSON)
-- mirrors issueClearanceToken() in internal/webdetector/challenge_server.go
-- so tokens minted here validate identically on the Go side.
--
-- Returns (token_string, nil) on success, (nil, err) otherwise.
local function b64url_encode(s)
  -- ngx.encode_base64 returns standard base64; convert to RawURLEncoding
  -- (no padding, '+'→'-', '/'→'_') to match Go's base64.RawURLEncoding.
  local b = ngx.encode_base64(s)
  if not b then return nil end
  b = b:gsub("=+$", ""):gsub("%+", "-"):gsub("/", "_")
  return b
end

local _nonce_counter = 0

local function random_nonce()
  -- Try resty.random first (cryptographically random when available).
  local ok_rnd, rnd = pcall(require, "resty.random")
  if ok_rnd and rnd and type(rnd.bytes) == "function" then
    local b = rnd.bytes(16, true) or rnd.bytes(16)
    if b and #b > 0 then
      local enc = b64url_encode(b)
      if enc and enc ~= "" then return enc end
    end
  end
  -- Fallback: time + worker pid + monotonic counter, hashed through whichever
  -- HMAC backend is available so the result is opaque even if inputs are
  -- guessable. Validator only requires nonce != "" and binds it via HMAC, so a
  -- non-cryptographic nonce is still safe against forgery — the secret is.
  _nonce_counter = _nonce_counter + 1
  local seed = tostring(ngx.now()) .. "|" .. tostring(ngx.worker.pid())
            .. "|" .. tostring(_nonce_counter) .. "|" .. tostring(math.random())
  local hex = hmac_sha256_hex(seed, seed) -- routes via ngx/openssl/resty.sha256
  if hex and hex ~= "" then return hex end
  -- Last-resort: hex of the seed itself (still non-empty, validator passes).
  return (seed:gsub('.', function(c) return string.format('%02x', string.byte(c)) end))
end

function _M.mint(ip, host, scope, secret, ttl_sec)
  if not secret or secret == "" then return nil, "missing_secret" end
  ttl_sec = tonumber(ttl_sec or 0) or 0
  if ttl_sec <= 0 then return nil, "bad_ttl" end
  local exp = ngx.time() + ttl_sec
  local nhost = normalize_host(host)
  local nonce = random_nonce()
  local payload = table.concat({ "1", tostring(exp), tostring(ip or ""), nhost, tostring(scope or ""), nonce }, "|")
  local mac, err = hmac_sha256_hex(secret, payload)
  if not mac then return nil, err or "hmac_failed" end
  local obj = {
    v     = "1",
    exp   = exp,
    ip    = tostring(ip or ""),
    host  = nhost,
    scope = tostring(scope or ""),
    nonce = nonce,
    hmac  = mac,
  }
  local json = cjson.encode(obj)
  if not json then return nil, "encode_failed" end
  local tok = b64url_encode(json)
  if not tok or tok == "" then return nil, "b64_failed" end
  return tok, nil
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

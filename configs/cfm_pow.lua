-- cfm_pow.lua
-- PoW challenge page + verify endpoint for OpenResty in-path mode.
--
-- Ported from challenge_server.go. Crypto must match exactly:
--
--   issueToken:  HMAC-SHA256(secret, ip \0 ua \0 cookie)  → base64url-nopad
--   powBind:     ua .. "|" .. cookie
--   powToken:    58 bytes = ts(8 big-endian int64) + diff(2 big-endian uint16)
--                         + nonce(16 random) + mac(32 HMAC-SHA256)
--                mac covers: ts(8) + diff(2) + nonce(16) + bind
--   solution:    integer string i where SHA-256(nonce \0 bind \0 i) has diff leading zero bits
--
--   solved_cookie: "cfm_ok" = base64url(HMAC-SHA256(secret, "ok\0" + ip + "\0" + ts_expire_unix))
--                            + "." + ts_expire_unix
--                  TTL: 60 minutes
--
-- Env vars:
--   CFM_CHALLENGE_SECRET  (must match Go side)
--   CFM_NGINX_TOKEN       (bridge token)

local _M = {}

local hmac    = require "resty.hmac"
local sha256  = require "resty.sha256"
local str     = require "resty.string"
local rnd     = require "resty.random"

-- ── Helpers ───────────────────────────────────────────────────────────────────

local SECRET = os.getenv("CFM_CHALLENGE_SECRET") or "cfm-default-secret-change-me"

-- base64url encode (no padding), compatible with Go's base64.RawURLEncoding
local b64url_enc
do
    local mime = require "mime"
    b64url_enc = function(s)
        local b = mime.b64(s)
        -- standard → url-safe, strip padding
        b = b:gsub("+", "-"):gsub("/", "_"):gsub("=", "")
        return b
    end
end

local b64url_dec
do
    local mime = require "mime"
    b64url_dec = function(s)
        -- url-safe → standard, add padding
        s = s:gsub("-", "+"):gsub("_", "/")
        local pad = (4 - #s % 4) % 4
        s = s .. string.rep("=", pad)
        return mime.unb64(s)
    end
end

local function hmac_sha256(key, data)
    local h = hmac:new(key, hmac.ALGOS.SHA256)
    if not h then return nil end
    h:update(data)
    return h:final()
end

local function sha256_digest(data)
    local h = sha256:new()
    if not h then return nil end
    h:update(data)
    return h:final()
end

-- big-endian int64 → 8 bytes
local function pack_int64_be(n)
    local b = {}
    for i = 8, 1, -1 do
        b[i] = string.char(n % 256)
        n = math.floor(n / 256)
    end
    return table.concat(b)
end

-- big-endian uint16 → 2 bytes
local function pack_uint16_be(n)
    return string.char(math.floor(n / 256) % 256, n % 256)
end

-- 8 bytes big-endian → int (for ts decode)
local function unpack_int64_be(s)
    local n = 0
    for i = 1, 8 do
        n = n * 256 + s:byte(i)
    end
    return n
end

local function unpack_uint16_be(s)
    return s:byte(1) * 256 + s:byte(2)
end

-- count leading zero bits in a byte string
local function leading_zero_bits(s)
    local bits = 0
    for i = 1, #s do
        local b = s:byte(i)
        if b == 0 then
            bits = bits + 8
        else
            -- count leading zeros in this byte
            local mask = 0x80
            while mask > 0 do
                if b & mask == 0 then
                    bits = bits + 1
                    mask = mask >> 1
                else
                    return bits
                end
            end
            return bits
        end
    end
    return bits
end

-- ── PoW config (must match Go defaultPowConfig()) ─────────────────────────────

local POW_DIFFICULTY  = 14        -- leading zero bits required
local POW_TTL_SECS    = 300       -- token valid for 5 minutes
local POW_ENABLED     = true
local SOLVED_TTL_SECS = 3600      -- solved cookie valid for 60 minutes

-- ── Token (HMAC-SHA256 over ip + ua + cookie) ─────────────────────────────────

local function issue_token(ip, ua, cookie)
    -- Go: mac.Write(ip), Write(\0), Write(ua), Write(\0), Write(cookie)
    local data = ip .. "\0" .. ua .. "\0" .. cookie
    local mac = hmac_sha256(SECRET, data)
    if not mac then return nil end
    return b64url_enc(mac)
end

local function verify_token(tok, ip, ua, cookie)
    local want = issue_token(ip, ua, cookie)
    if not want or not tok then return false end
    -- constant-time compare
    if #tok ~= #want then return false end
    local diff = 0
    for i = 1, #tok do
        diff = diff | (tok:byte(i) ~ want:byte(i))
    end
    return diff == 0
end

-- ── PoW token issue ───────────────────────────────────────────────────────────

local function issue_pow_token(now_unix, difficulty, nonce16, bind)
    -- layout: ts(8) + diff(2) + nonce(16) + mac(32) = 58 bytes
    local ts_bytes   = pack_int64_be(now_unix)
    local diff_bytes = pack_uint16_be(difficulty)
    -- mac covers: ts + diff + nonce + bind
    local mac_input = ts_bytes .. diff_bytes .. nonce16 .. bind
    local mac = hmac_sha256(SECRET, "pow:" .. mac_input)
    if not mac then return nil end
    local raw = ts_bytes .. diff_bytes .. nonce16 .. mac
    if #raw ~= 58 then return nil end
    return b64url_enc(raw)
end

-- ── PoW token verify ──────────────────────────────────────────────────────────

-- Returns diff, nonce16 or nil, err
local function verify_pow_token(pow_tok, bind, now_unix)
    local raw = b64url_dec(pow_tok)
    if not raw or #raw ~= 58 then
        return nil, "bad length"
    end

    local ts_bytes   = raw:sub(1, 8)
    local diff_bytes = raw:sub(9, 10)
    local nonce16    = raw:sub(11, 26)
    local mac_got    = raw:sub(27, 58)

    -- check TTL
    local ts = unpack_int64_be(ts_bytes)
    if math.abs(now_unix - ts) > POW_TTL_SECS then
        return nil, "expired"
    end

    local diff = unpack_uint16_be(diff_bytes)

    -- verify mac
    local mac_input = ts_bytes .. diff_bytes .. nonce16 .. bind
    local mac_want = hmac_sha256(SECRET, "pow:" .. mac_input)
    if not mac_want then return nil, "hmac failed" end

    -- constant-time compare
    if #mac_got ~= #mac_want then return nil, "mac mismatch" end
    local d = 0
    for i = 1, #mac_got do
        d = d | (mac_got:byte(i) ~ mac_want:byte(i))
    end
    if d ~= 0 then return nil, "mac mismatch" end

    return diff, nonce16
end

-- ── PoW solution verify ───────────────────────────────────────────────────────

-- verify_pow_solution checks that SHA-256(nonce \0 bind \0 sol) has diff leading zero bits
-- Must match JS solvePow() and Go verifyPowSolution()
local function verify_pow_solution(nonce16, bind, sol, diff)
    if not sol or sol == "" then return false end
    -- prefix = nonce16 \0 bind \0
    local msg = nonce16 .. "\0" .. bind .. "\0" .. sol
    local digest = sha256_digest(msg)
    if not digest then return false end
    return leading_zero_bits(digest) >= diff
end

-- ── Solved cookie ─────────────────────────────────────────────────────────────

-- Format: base64url(HMAC-SHA256(secret, "ok\0" + ip + "\0" + expire_ts)) + "." + expire_ts
-- The expire_ts is unix seconds as a decimal string.

local function issue_solved_cookie(ip)
    local expire = ngx.time() + SOLVED_TTL_SECS
    local data = "ok\0" .. ip .. "\0" .. tostring(expire)
    local mac = hmac_sha256(SECRET, data)
    if not mac then return nil end
    return b64url_enc(mac) .. "." .. tostring(expire)
end

local function verify_solved_cookie(val, ip)
    if not val or val == "" then return false end
    local mac_b64, expire_str = val:match("^([^.]+)%.(%d+)$")
    if not mac_b64 or not expire_str then return false end
    local expire = tonumber(expire_str)
    if not expire or ngx.time() > expire then return false end
    -- recompute
    local data = "ok\0" .. ip .. "\0" .. expire_str
    local mac_want = hmac_sha256(SECRET, data)
    if not mac_want then return false end
    local mac_got = b64url_dec(mac_b64)
    if not mac_got or #mac_got ~= #mac_want then return false end
    local d = 0
    for i = 1, #mac_got do
        d = d | (mac_got:byte(i) ~ mac_want:byte(i))
    end
    return d == 0
end

-- ── Challenge HTML (matches challengeHTML() in challenge_server.go) ───────────

local CHALLENGE_HTML = [[<!doctype html>
<html>
<head>
  <meta charset="utf-8" />
  <meta name="viewport" content="width=device-width, initial-scale=1" />
  <title>Just a moment...</title>
  <style>
    body{font-family:system-ui,-apple-system,Segoe UI,Roboto,Ubuntu,Cantarell,Noto Sans,sans-serif;background:#0b1020;color:#e8eefc;display:flex;min-height:100vh;align-items:center;justify-content:center}
    .card{width:min(520px,92vw);background:rgba(255,255,255,.06);border:1px solid rgba(255,255,255,.12);border-radius:16px;padding:22px;box-shadow:0 20px 60px rgba(0,0,0,.35)}
    .h{font-size:20px;font-weight:650;margin:0 0 10px}
    .p{opacity:.9;line-height:1.45;margin:0 0 14px}
    .muted{opacity:.7;font-size:13px}
    .spinner{width:34px;height:34px;border-radius:999px;border:3px solid rgba(255,255,255,.18);border-top-color:#fff;animation:spin 1s linear infinite;margin:14px 0}
    @keyframes spin{to{transform:rotate(360deg)}}
    code{background:rgba(255,255,255,.08);padding:.15rem .35rem;border-radius:8px}
  </style>
</head>
<body>
  <div class="card">
    <div class="h">Checking your browser...</div>
    <div class="p">We're verifying your request before accessing <code>%s</code>.</div>
    <div class="spinner"></div>
    <div class="muted">This should take less than a second. If you're stuck, enable JavaScript &amp; cookies.</div>
  </div>
<script>
(function(){
  var token = "%s";
  var powTok = "%s";
  var next = "%s";
  var difficulty = %d;

  function getCookie(name){
    var parts=("; "+document.cookie).split("; "+name+"=");
    if(parts.length===2)return decodeURIComponent(parts.pop().split(";").shift());
    return "";
  }

  function b64urlToBytes(s){
    s=(s||"").replace(/-/g,"+").replace(/_/g,"/");
    while(s.length%4)s+="=";
    var bin=atob(s),out=new Uint8Array(bin.length);
    for(var i=0;i<bin.length;i++)out[i]=bin.charCodeAt(i);
    return out;
  }

  function hasLeadingZeroBits(bytes,bits){
    if(bits<=0)return true;
    var full=Math.floor(bits/8),rem=bits%8;
    for(var i=0;i<full;i++)if(bytes[i]!==0)return false;
    if(rem===0)return true;
    return(bytes[full]&(0xFF<<(8-rem)))===0;
  }

  async function sha256(u8){
    return new Uint8Array(await crypto.subtle.digest("SHA-256",u8));
  }

  async function solvePow(){
    var raw=b64urlToBytes(powTok);
    if(raw.length!==58)throw new Error("bad pow token");
    var nonce=raw.slice(10,26);
    var ua=(navigator.userAgent||"").trim();
    var c=getCookie("cfm_chal");
    var bindStr=ua+"|"+c;
    var enc=new TextEncoder();
    var bindBytes=enc.encode(bindStr);
    var prefix=new Uint8Array(nonce.length+1+bindBytes.length+1);
    prefix.set(nonce,0);
    prefix[nonce.length]=0;
    prefix.set(bindBytes,nonce.length+1);
    prefix[prefix.length-1]=0;
    var i=0;
    while(true){
      var solStr=String(i++);
      var solBytes=enc.encode(solStr);
      var msg=new Uint8Array(prefix.length+solBytes.length);
      msg.set(prefix,0);
      msg.set(solBytes,prefix.length);
      var dig=await sha256(msg);
      if(hasLeadingZeroBits(dig,difficulty))return solStr;
      if((i%2000)===0)await new Promise(function(r){setTimeout(r,0);});
    }
  }

  (async function(){
    try{
      var sol=await solvePow();
      fetch("/cfm_verify?next="+encodeURIComponent(next),{
        method:"POST",
        headers:{
          "X-CFM-Token":token,
          "X-CFM-Pow":powTok,
          "X-CFM-Sol":sol
        },
        credentials:"include"
      }).then(function(res){
        if(res.redirected){window.location=res.url;return;}
        if(res.ok){window.location=next||"/";}
        else{setTimeout(function(){location.reload();},1200);}
      }).catch(function(){setTimeout(function(){location.reload();},1200);});
    }catch(e){setTimeout(function(){location.reload();},1200);}
  })();
})();
</script>
</body>
</html>]]

-- html_escape for injecting values into HTML
local function he(s)
    if not s then return "" end
    s = tostring(s)
    s = s:gsub("&", "&amp;")
    s = s:gsub("<", "&lt;")
    s = s:gsub(">", "&gt;")
    s = s:gsub('"', "&quot;")
    s = s:gsub("'", "&#39;")
    return s
end

-- ── get_cookie helper ─────────────────────────────────────────────────────────

local function get_cookie(name)
    local cookie_str = ngx.var.http_cookie or ""
    -- simple pattern; works for standard cookie formats
    local val = cookie_str:match(name .. "=([^;]+)")
    if val then
        return ngx.unescape_uri(val:match("^%s*(.-)%s*$"))
    end
    return nil
end

-- ── serve_challenge: render the PoW page ─────────────────────────────────────

function _M.serve_challenge(ip, ua, host, next_url)
    if not next_url or next_url == "" then next_url = "/" end
    if next_url:sub(1, 1) ~= "/" then next_url = "/" end
    if #next_url > 2048 then next_url = "/" end

    -- Get or set cfm_chal cookie
    local cookie_val = get_cookie("cfm_chal")
    if not cookie_val or cookie_val == "" then
        -- Generate random cookie value (32 random bytes → base64url)
        local rb = rnd.bytes(32, true)
        if not rb then rb = tostring(ngx.time()) .. tostring(math.random(1e9)) end
        cookie_val = b64url_enc(rb)
        -- Set cookie (HttpOnly=false so JS can read it)
        local secure = (ngx.var.https == "on") and "; Secure" or ""
        ngx.header["Set-Cookie"] = "cfm_chal=" .. cookie_val
            .. "; Path=/; Max-Age=300; SameSite=Lax" .. secure
    end

    -- Issue HMAC token (ip + ua + cookie)
    local tok = issue_token(ip, ua, cookie_val)
    if not tok then
        ngx.status = 500
        ngx.say("token error")
        return ngx.exit(500)
    end

    -- Issue PoW token
    local nonce = rnd.bytes(16, true)
    if not nonce then
        ngx.status = 500
        ngx.say("rng error")
        return ngx.exit(500)
    end
    local bind = ua .. "|" .. cookie_val
    local pow_tok = issue_pow_token(ngx.time(), POW_DIFFICULTY, nonce, bind)
    if not pow_tok then
        ngx.status = 500
        ngx.say("pow error")
        return ngx.exit(500)
    end

    ngx.status = 200
    ngx.header["Content-Type"] = "text/html; charset=utf-8"
    ngx.header["Cache-Control"] = "no-store"
    ngx.print(string.format(CHALLENGE_HTML,
        he(host),
        he(tok),
        he(pow_tok),
        he(next_url),
        POW_DIFFICULTY
    ))
    return ngx.exit(200)
end

-- ── handle_verify: POST /cfm_verify ──────────────────────────────────────────
-- Called by the JS fetch() after PoW is solved.
-- On success: sets cfm_ok cookie, invalidates cache, redirects to next.

function _M.handle_verify(ip, ua)
    if ngx.req.get_method() ~= "POST" then
        ngx.status = 405
        ngx.say("method not allowed")
        return ngx.exit(405)
    end

    -- Drain body (we don't use it)
    ngx.req.read_body()

    local next_url = ngx.var.arg_next or "/"
    if next_url == "" then next_url = "/" end
    if next_url:sub(1, 1) ~= "/" then next_url = "/" end
    if #next_url > 2048 then next_url = "/" end

    -- Read cookie
    local cookie_val = get_cookie("cfm_chal")
    if not cookie_val or cookie_val == "" then
        ngx.status = 403
        ngx.say("missing cookie")
        return ngx.exit(403)
    end

    -- Read headers sent by JS
    local tok     = ngx.req.get_headers()["X-CFM-Token"] or ""
    local pow_tok = ngx.req.get_headers()["X-CFM-Pow"]   or ""
    local sol     = ngx.req.get_headers()["X-CFM-Sol"]   or ""

    tok     = tok:match("^%s*(.-)%s*$")
    pow_tok = pow_tok:match("^%s*(.-)%s*$")
    sol     = sol:match("^%s*(.-)%s*$")

    if tok == "" then
        ngx.status = 403; ngx.say("missing token"); return ngx.exit(403)
    end
    if pow_tok == "" or sol == "" then
        ngx.status = 403; ngx.say("missing pow"); return ngx.exit(403)
    end

    -- Verify HMAC token
    if not verify_token(tok, ip, ua, cookie_val) then
        ngx.status = 403; ngx.say("bad token"); return ngx.exit(403)
    end

    -- Verify PoW token (signature + TTL)
    local bind = ua .. "|" .. cookie_val
    local diff, nonce16, perr = verify_pow_token(pow_tok, bind, ngx.time())
    if not diff then
        ngx.log(ngx.WARN, "[cfm] pow token invalid: ", perr)
        ngx.status = 403; ngx.say("bad pow"); return ngx.exit(403)
    end

    -- Verify PoW solution
    if not verify_pow_solution(nonce16, bind, sol, diff) then
        ngx.status = 403; ngx.say("bad solution"); return ngx.exit(403)
    end

    -- PoW solved. Issue the "solved" cookie.
    local solved_val = issue_solved_cookie(ip)
    if not solved_val then
        ngx.status = 500; ngx.say("cookie error"); return ngx.exit(500)
    end

    local secure = (ngx.var.https == "on") and "; Secure" or ""
    ngx.header["Set-Cookie"] = "cfm_ok=" .. solved_val
        .. "; Path=/; Max-Age=" .. SOLVED_TTL_SECS .. "; SameSite=Lax" .. secure

    -- Invalidate the cached "challenge" decision so Lua re-queries on next request
    local decisions = require "cfm_decisions"
    decisions.invalidate(ip, ngx.var.host)

    -- Tell cfm bridge to clear this IP (best-effort, fire-and-forget)
    -- We do this via a background notify rather than blocking the response
    local sock = ngx.socket.tcp()
    sock:settimeout(100)
    if sock:connect("unix:" .. (os.getenv("CFM_NGINX_SOCK") or "/var/run/cfm/cfm_nginx.sock")) then
        local BRIDGE_TOKEN = os.getenv("CFM_NGINX_TOKEN") or "cfm"
        local body = '{"ip":"' .. ip .. '"}'
        local req = "POST /nginx/ip/clear HTTP/1.0\r\n"
            .. "Host: cfm\r\n"
            .. "X-CFM-Token: " .. BRIDGE_TOKEN .. "\r\n"
            .. "Content-Type: application/json\r\n"
            .. "Content-Length: " .. #body .. "\r\n"
            .. "Connection: close\r\n"
            .. "\r\n"
            .. body
        sock:send(req)
        sock:close()
    end

    ngx.log(ngx.INFO, "[cfm] pow solved ip=", ip, " next=", next_url)

    ngx.header["Cache-Control"] = "no-store"
    ngx.redirect(next_url, 303)
end

-- ── Public: check solved cookie ───────────────────────────────────────────────

function _M.is_solved(ip)
    local val = get_cookie("cfm_ok")
    if not val then return false end
    return verify_solved_cookie(val, ip)
end

return _M

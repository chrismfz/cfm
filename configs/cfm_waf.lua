-- /usr/local/openresty/nginx/lua/cfm_waf.lua
local _M = {}

-- Base config (safe defaults)
local CFG = {
  enabled = true,

  rule_xss      = true,
  rule_sqli     = true,

  -- New block rules (high-confidence, near-zero FP)
  rule_traversal       = false,
  rule_rce             = true,
  rule_exploit_methods = true,

  -- Dry-run / audit rules (LOGONLY)
  -- Useful to measure FP rate before enabling challenge/block.
  rule_logonly_cmd_params = true,
  rule_logonly_serialize  = true,

  -- OWASP-ish additions (safe defaults for shared hosting)
  --
  -- A07: Authentication Failures (burst brute on login endpoints)
  -- We do NOT block here: we challenge on bursts to avoid hurting legit users.
  rule_auth_burst_challenge = true,
  auth_window_sec           = 20,  -- sliding window length
  auth_burst_threshold      = 8,   -- hits per window to trigger
  auth_ttl_sec              = 600, -- challenge TTL when triggered

  -- A05: Injection (payload markers) - LOGONLY first (FP-prone)
  -- This looks for shell separators / backticks / $() etc in query args.
  rule_logonly_cmd_payload  = true,

  -- A10: Exceptional conditions / debug toggles - LOGONLY
  -- e.g. XDEBUG_SESSION_START, debug=1, stacktrace=1, etc.
  rule_logonly_debug_toggles = true,




  default_ttl_sec   = 600,   -- 10m challenge TTL
  block_ttl_sec     = 3600,  -- 1h block TTL for high-confidence rules
  push_cooldown_sec = 60,
  max_scan_len      = 2048
}

do
  local ok, usercfg = pcall(require, "cfm_waf_config")
  if ok and type(usercfg) == "table" then
    for k, v in pairs(usercfg) do CFG[k] = v end
  end
end

function _M.enabled()
  return CFG.enabled == true
end

-- ── Helpers ──────────────────────────────────────────────────────────────────

local function has(s, pat)
  if not s or s == "" then return false end
  return (string.find(s, pat, 1, true) ~= nil)
end

local function lower(s)
  if not s then return "" end
  return string.lower(s)
end

local function cap(s, n)
  if not s then return "" end
  if #s <= n then return s end
  return string.sub(s, 1, n)
end

-- Helpers: begins-with and contains-any (plain find)
local function begins(s, prefix)
  if not s or not prefix then return false end
  return string.sub(s, 1, #prefix) == prefix
end

-- ── CHALLENGE detectors (existing, lower confidence) ─────────────────────────

local function detect_xss(uri, args)
  local s = lower(cap((uri or "") .. "?" .. (args or ""), CFG.max_scan_len))
  if has(s, "<script") or has(s, "%3cscript") then return true end
  if has(s, "javascript:")                     then return true end
  if has(s, "onerror=")  or has(s, "onload=") then return true end
  return false
end

local function detect_sqli(uri, args)
  local s = lower(cap((uri or "") .. "?" .. (args or ""), CFG.max_scan_len))
  if has(s, "union select")    or has(s, "union%20select")            then return true end
  if has(s, "information_schema")                                      then return true end
  if has(s, " or 1=1")         or has(s, " or%201=1")                 then return true end
  if has(s, "' or '1'='1")    or has(s, "%27%20or%20%271%27%3d%271") then return true end
  return false
end



-- ── AUTH burst challenge (A07) ───────────────────────────────────────────────
--
-- Goal: catch credential-stuffing / brute bursts against known login endpoints.
-- We CHALLENGE (not block) only when hits exceed threshold in a short window.
--
-- Uses ngx.shared.cfm_decisions keys:
--   "auth|ts|<ip>|<tag>"  → window start timestamp
--   "auth|cnt|<ip>|<tag>" → count in window
--
-- Returns subrule tag string (e.g. "AUTH_WP_LOGIN") or nil.
local function auth_endpoint_tag(uri, method)
  uri = lower(uri or "")
  method = lower(method or "get")

  -- WP / Woo
  if has(uri, "/wp-login.php") then
    -- brute is usually POST, but scanners also GET it; count both.
    return "AUTH_WP_LOGIN"
  end
  if has(uri, "/xmlrpc.php") then
    return "AUTH_WP_XMLRPC"
  end

  -- Joomla
  if has(uri, "/administrator/index.php") then
    return "AUTH_JOOMLA_ADMIN"
  end

  -- Drupal
  if has(uri, "/user/login") then
    return "AUTH_DRUPAL_LOGIN"
  end

  -- Magento
  if has(uri, "/admin") and (has(uri, "login") or has(uri, "auth")) then
    return "AUTH_MAGENTO_ADMIN"
  end

  -- OpenCart (common)
  if has(uri, "/admin/") and (has(uri, "index.php") or has(uri, "login")) then
    return "AUTH_OPENCART_ADMIN"
  end

  -- Generic patterns (keep conservative)
  if has(uri, "/admin/login") then return "AUTH_ADMIN_LOGIN" end
  if has(uri, "/login") and method == "post" then return "AUTH_LOGIN_POST" end

  return nil
end

local function detect_auth_burst(ip, uri, method, shdict)
  if not shdict or not ip or ip == "" then return nil end

  local tag = auth_endpoint_tag(uri, method)
  if not tag then return nil end

  local now = ngx.now()
  local win = tonumber(CFG.auth_window_sec or 20) or 20
  local thr = tonumber(CFG.auth_burst_threshold or 8) or 8

  local kts  = "auth|ts|"  .. ip .. "|" .. tag
  local kcnt = "auth|cnt|" .. ip .. "|" .. tag

  local ts  = shdict:get(kts)
  local cnt = shdict:get(kcnt) or 0

  if not ts or (now - ts) >= win then
    shdict:set(kts,  now, win + 1)
    shdict:set(kcnt, 1,   win + 1)
    return nil
  end

  cnt = cnt + 1
  shdict:set(kcnt, cnt, win + 1)

  if cnt >= thr then
    return tag
  end
  return nil
end


-- ── BLOCK detectors (extremely high confidence, near-zero FP) ────────────────

local function detect_traversal(uri, args)
  local s = lower(cap((uri or "") .. "?" .. (args or ""), CFG.max_scan_len))

  -- Null byte injection (always malicious)
  if has(s, "%00")        then return true end

  return false
end

local function detect_rce(uri, args)
  local s = lower(cap((uri or "") .. "?" .. (args or ""), CFG.max_scan_len))

  -- Log4Shell (still heavily probed)
  if has(s, "${jndi:")    then return true end
  if has(s, "${j{n{d{i") then return true end  -- obfuscated variant
  if has(s, "$%7bjndi")  then return true end  -- URL-encoded {

  -- Shell injection markers in query string
  if has(s, ";wget ")     then return true end
  if has(s, ";curl ")     then return true end
  if has(s, "|bash")      then return true end
  if has(s, "|sh ")       then return true end
  if has(s, "`wget")      then return true end
  if has(s, "`curl")      then return true end

  -- Base64 payload delivery combined with exec keywords
  if has(s, "base64,") and (has(s, "eval") or has(s, "exec") or has(s, "system")) then
    return true
  end

  return false
end

-- Returns "block", "challenge", or nil.
local function detect_exploit_method(method)
  method = lower(method or "")
  -- Cross-Site Tracing + proxy abuse → always block
  if method == "trace"    then return "block"     end
  if method == "track"    then return "block"     end
  if method == "connect"  then return "block"     end
  -- WebDAV probing → challenge (WebDAV may be legitimately enabled)
  if method == "propfind" then return "challenge" end
  if method == "search"   then return "challenge" end
  return nil
end

-- ── LOGONLY detectors (audit mode) ───────────────────────────────────────────
-- Return a subrule tag string (e.g. "PAY_SEMI") or nil.

-- A05 (Injection): suspicious shell-ish payload markers in query args.
-- NOTE: FP can happen with legit content/search queries; keep LOGONLY first.
local function detect_cmd_payload(args)
  local a = lower(cap(args or "", CFG.max_scan_len))
  if a == "" then return nil end

  -- FP guard: skip data:*;base64 blobs
  if has(a, "data:") and has(a, ";base64,") then
    return nil
  end

  -- FP guard: long base64-ish segment
  do
    local p = string.find(a, "base64,", 1, true)
    if p then
      local rest = string.sub(a, p + 7)
      if #rest >= 256 then
        return nil
      end
    end
  end

  -- FP guard: large single parameter values (JWTs, signatures, blobs)
  do
    for val in string.gmatch(a, "=([^&]+)") do
      if #val >= 512 then
        return nil
      end
    end
  end

  -- FP guard: common ecommerce filter syntax
  -- Example:
  -- filters=price[19_23]|megethos[688-109]|product_cat[511-89]
  do
    if begins(a, "filters=") then
      local v = string.sub(a, 9)
      if v ~= "" and
         string.match(v, "^[a-z0-9_%-%[%]%|]+$") and
         not has(v, "||") and
         not has(v, "%7c%7c") and
         not has(v, "`") and
         not has(v, "%60") and
         not has(v, ";wget") and
         not has(v, ";curl") and
         not has(v, ";bash") and
         not has(v, ";sh ") and
         not has(v, "$(") and
         not has(v, "%24%28") then
        return nil
      end
    end
  end

  -- FP guard: duplicate query separator like &&page=2 or &&p=2
  if string.match(a, "[%?&][^=]+=[^&]*&&[a-z0-9_%-]+=") then
    return nil
  end

  -- FP guard: app/widget values using || as delimiter
  -- Example:
  -- main_opt_id=main-content-style33||widget_1
  if string.match(a, "[%?&][a-z0-9_%-]+=([a-z0-9_%-]+%|%|[a-z0-9_%-]+)") then
    return nil
  end
  if string.match(a, "[%?&][a-z0-9_%-]+=([a-z0-9_%-]+||[a-z0-9_%-]+)") then
    return nil
  end

  -- FP guard: known Jetpack xmlrpc token pattern
  if has(a, "/xmlrpc.php?for=jetpack&token=") then
    return nil
  end

  local function has_semi_cmd(s)
    if has(s, ";wget") or has(s, ";curl") or has(s, ";bash") or has(s, ";sh ") then return true end
    if has(s, "%3bwget") or has(s, "%3bcurl") or has(s, "%3bbash") or has(s, "%3bsh%20") then return true end
    if has(s, "%3bwget") or has(s, "%3bcurl") or has(s, "%3bbash") or has(s, "%3bsh+") then return true end
    if has(s, "%3Bwget") or has(s, "%3Bcurl") or has(s, "%3Bbash") or has(s, "%3Bsh%20") then return true end
    if has(s, "%3Bwget") or has(s, "%3Bcurl") or has(s, "%3Bbash") or has(s, "%3Bsh+") then return true end
    return false
  end

  if has_semi_cmd(a) then
    return "PAY_SEMI_CMD"
  end

  -- Single pipe only in shell-ish context
  if has(a, "|wget") or has(a, "%7cwget") then return "PAY_PIPE_WGET" end
  if has(a, "|curl") or has(a, "%7ccurl") then return "PAY_PIPE_CURL" end
  if has(a, "|bash") or has(a, "%7cbash") then return "PAY_PIPE_BASH" end
  if has(a, "|sh ") or has(a, "%7csh%20") or has(a, "%7csh+") then return "PAY_PIPE_SH" end

  -- Backticks are still high-confidence enough
  if has(a, "%60") or has(a, "`") then
    return "PAY_BACKTICK"
  end

  return nil
end





-- A10 (Exceptional conditions): debug toggles / stacktrace probes.
-- Keep LOGONLY: some dev/staging sites legitimately use these.
local function detect_debug_toggles(args)
  local a = lower(cap(args or "", CFG.max_scan_len))
  if a == "" then return nil end

  -- PHP/Xdebug probes
  if has(a, "xdebug_session_start=") then return "DBG_XDEBUG" end
  if has(a, "xdebug=") then return "DBG_XDEBUG_KEY" end

  -- Generic debug toggles
  if has(a, "debug=true") or has(a, "debug=1") then return "DBG_DEBUG" end
  if has(a, "trace=1") or has(a, "trace=true") then return "DBG_TRACE" end
  if has(a, "stacktrace=1") or has(a, "stacktrace=true") then return "DBG_STACKTRACE" end

  return nil
end




-- ── LOGONLY detectors (audit mode) ───────────────────────────────────────────
-- Return a subrule tag string (e.g. "CMD_EXEC") or nil.

-- Detect suspicious "command/eval" parameter keys (low FP if key-only).
-- Note: nginx $args does NOT include the leading '?', so we match:
--   "key=" at start OR "&key=" later.
local function detect_cmd_param_key(args)
  local a = lower(cap(args or "", CFG.max_scan_len))
  if a == "" then return nil end

  local function key(k)
    -- key at the very beginning: "k="
    if string.sub(a, 1, #k + 1) == (k .. "=") then return true end
    -- key later in the query string: "&k="
    if has(a, "&" .. k .. "=") then return true end
    return false
  end

  -- (Recommend: remove cmd, keep high-signal only)
  if key("exec")       then return "CMD_EXEC" end
  if key("system")     then return "CMD_SYSTEM" end
  if key("passthru")   then return "CMD_PASSTHRU" end
  if key("shell_exec") then return "CMD_SHELL_EXEC" end
  if key("eval")       then return "CMD_EVAL" end
  if key("assert")     then return "CMD_ASSERT" end

  return nil
end


-- Detect PHP serialized object markers (keep strict → lower FP).
-- Looks for: O:<n>:"Class" or URL-encoded equivalent.
local function detect_php_serialize(args)
  local a = lower(cap(args or "", CFG.max_scan_len))
  if a == "" then return nil end

  -- plain: o:8:"classname"
  if has(a, "o:") and has(a, ":\"") then return "SER_O_PLAIN" end
  if has(a, "c:") and has(a, ":\"") then return "SER_C_PLAIN" end

  -- url-encoded: o%3a8%3a%22classname%22
  if has(a, "o%3a") and has(a, "%22") then return "SER_O_URL" end
  if has(a, "c%3a") and has(a, "%22") then return "SER_C_URL" end

  return nil
end

-- ── Public API ───────────────────────────────────────────────────────────────
--
-- Returns: hit(bool), reason(string), ttl_sec(int), action(string)
--   action = "block"     → 403, do not proxy
--   action = "challenge" → route to challenge server
--   action = "logonly"   → log/push to bridge but DO NOT challenge/block
--
-- Rule priority (descending):
--   traversal > rce > exploit_method >  xss > sqli >  > logonly
--
function _M.check(ctx)
  if not CFG.enabled then
    return false, nil, nil, nil
  end

  ctx = ctx or {}
  local uri    = ctx.uri    or ""
  local args   = ctx.args   or ""
  local method = ctx.method or "GET"
  local ip     = ctx.ip     or ""
  local shdict = ctx.shdict

  -- 1) Path traversal / null byte / double-encoded → BLOCK
  if CFG.rule_traversal and detect_traversal(uri, args) then
    return true, "WAF_TRAVERSAL", CFG.block_ttl_sec, "block"
  end

  -- 2) RCE / log4shell / shell injection → BLOCK
  if CFG.rule_rce and detect_rce(uri, args) then
    return true, "WAF_RCE", CFG.block_ttl_sec, "block"
  end

  -- 3) Exploit HTTP methods → BLOCK or CHALLENGE by method
  if CFG.rule_exploit_methods then
    local maction = detect_exploit_method(method)
    if maction == "block" then
      return true, "WAF_EXPLOIT_METHOD", CFG.block_ttl_sec, "block"
    elseif maction == "challenge" then
      return true, "WAF_EXPLOIT_METHOD", CFG.default_ttl_sec, "challenge"
    end
  end


  -- 5) XSS → CHALLENGE
  if CFG.rule_xss and detect_xss(uri, args) then
    return true, "WAF_XSS", CFG.default_ttl_sec, "challenge"
  end

  -- 6) SQLi → CHALLENGE
  if CFG.rule_sqli and detect_sqli(uri, args) then
    return true, "WAF_SQLI", CFG.default_ttl_sec, "challenge"
  end


  -- 7.5) Auth burst challenge (A07): brute bursts on login endpoints
  if CFG.rule_auth_burst_challenge then
    local peer = ctx.peer or ""

    -- Failsafe: if the "client ip" equals the proxy peer ip, real_ip probably
    -- isn't applied and we'd count per Cloudflare POP. Skip to avoid POP-wide challenge.
    if peer ~= "" and ip ~= "" and ip == peer then
      -- skip
    else
      local tag = detect_auth_burst(ip, uri, method, shdict)
      if tag then
        return true, "WAF_AUTH_BURST:" .. tag, (CFG.auth_ttl_sec or CFG.default_ttl_sec), "challenge"
      end
    end
  end



  -- 8) LOGONLY: cmd/eval parameter keys (audit)
  if CFG.rule_logonly_cmd_params then
    local tag = detect_cmd_param_key(args)
    if tag then
      return true, "WAF_LOGONLY_CMD_PARAM:" .. tag, CFG.default_ttl_sec, "logonly"
    end
  end

  -- 8.5) LOGONLY: command payload markers (A05) - audit only
  if CFG.rule_logonly_cmd_payload then
    local tag = detect_cmd_payload(args)
    if tag then
      return true, "WAF_LOGONLY_CMD_PAYLOAD:" .. tag, CFG.default_ttl_sec, "logonly"
    end
  end

  -- 8.6) LOGONLY: debug toggles / stacktrace probes (A10) - audit only
  if CFG.rule_logonly_debug_toggles then
    local tag = detect_debug_toggles(args)
    if tag then
      return true, "WAF_LOGONLY_DEBUG_TOGGLE:" .. tag, CFG.default_ttl_sec, "logonly"
    end
  end



  -- 9) LOGONLY: PHP serialize markers (audit)
  if CFG.rule_logonly_serialize then
    local tag = detect_php_serialize(args)
    if tag then
      return true, "WAF_LOGONLY_SERIALIZE:" .. tag, CFG.default_ttl_sec, "logonly"
    end
  end

  return false, nil, nil, nil
end

-- Anti-spam: returns true if we should push to /nginx/ip now.
-- reason is included in the key so block/challenge/logonly don't share cooldown.
function _M.should_push(shdict, ip, reason)
  if not shdict or not ip or ip == "" then return true end
  local k  = "wafpush|" .. (reason or "WAF") .. "|" .. ip
  local ok = shdict:add(k, 1, CFG.push_cooldown_sec)
  return ok == true
end

return _M

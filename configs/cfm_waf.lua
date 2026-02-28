-- /usr/local/openresty/nginx/lua/cfm_waf.lua
local _M = {}

-- Base config (safe defaults)
local CFG = {
  enabled = true,

  rule_xss      = true,
  rule_sqli     = true,
  rule_wp_brute = false,

  -- New block rules (high-confidence, near-zero FP)
  rule_traversal       = true,
  rule_rce             = true,
  rule_exploit_methods = true,

  -- Dry-run / audit rules (LOGONLY)
  -- Useful to measure FP rate before enabling challenge/block.
  rule_logonly_cmd_params = true,
  rule_logonly_serialize  = true,

  -- Cookie-less high-RPS challenge (needs shdict + cookie in ctx)
  rule_cookieless          = true,
  cookieless_rps_threshold = 30,  -- req/s per IP without Cookie
  cookieless_window_sec    = 10,  -- sliding window

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

local function detect_wp_brute(uri, method)
  if method ~= "POST" then return false end
  return has(uri or "", "/wp-login.php")
end

-- ── BLOCK detectors (extremely high confidence, near-zero FP) ────────────────

local function detect_traversal(uri, args)
  local s = lower(cap((uri or "") .. "?" .. (args or ""), CFG.max_scan_len))

  -- Classic traversal sequences
  if has(s, "../")        then return true end
  if has(s, "..\\")       then return true end

  -- URL-encoded traversal (various partial encodings)
  if has(s, "%2e%2e%2f")  then return true end  -- ../
  if has(s, "%2e%2e/")    then return true end  -- ../ (partial)
  if has(s, "..%2f")      then return true end  -- ../ (partial)
  if has(s, "%2e%2e%5c")  then return true end  -- ..\
  if has(s, "%2e%2e\\")   then return true end  -- ..\ (partial)
  if has(s, "..%5c")      then return true end  -- ..\ (partial)

  -- Double-encoded traversal (WAF bypass)
  if has(s, "%252e%252e") then return true end  -- → %2e%2e → ..
  if has(s, "%252f")      then return true end  -- → %2f   → /  (in traversal context)

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

-- ── Cookie-less high-RPS challenge (shared dict counting) ────────────────────
--
-- Real browsers always present cookies after the first response. High-RPS
-- requests that never carry a Cookie header are a strong bot signal.
-- Uses ngx.shared.cfm_decisions with keys:
--   "waf_ck|ts|<ip>"  → window start timestamp
--   "waf_ck|cnt|<ip>" → request count in window
--
local function detect_cookieless_rps(ip, cookie, shdict)
  if not shdict or not ip or ip == "" then return false end
  if cookie and cookie ~= "" then return false end  -- has cookie → skip

  local now       = ngx.now()
  local win       = CFG.cookieless_window_sec
  local threshold = CFG.cookieless_rps_threshold * win  -- abs count in window

  local kts  = "waf_ck|ts|"  .. ip
  local kcnt = "waf_ck|cnt|" .. ip

  local ts  = shdict:get(kts)
  local cnt = shdict:get(kcnt) or 0

  if not ts or (now - ts) >= win then
    shdict:set(kts,  now, win + 1)
    shdict:set(kcnt, 1,   win + 1)
    return false  -- first hit of a new window, never trigger immediately
  end

  cnt = cnt + 1
  shdict:set(kcnt, cnt, win + 1)
  return cnt >= threshold
end

-- ── LOGONLY detectors (audit mode) ───────────────────────────────────────────
-- Return a subrule tag string (e.g. "CMD_EXEC") or nil.

-- Detect suspicious "command/eval" parameter keys (low FP if key-only).
-- Examples: ?cmd=, &exec=, &system=, &eval=
local function detect_cmd_param_key(args)
  local a = lower(cap(args or "", CFG.max_scan_len))
  if a == "" then return nil end

  -- key-only matches: look for "?key=" or "&key="
  if has(a, "?cmd=") or has(a, "&cmd=") then return "CMD_CMD" end
  if has(a, "?exec=") or has(a, "&exec=") then return "CMD_EXEC" end
  if has(a, "?system=") or has(a, "&system=") then return "CMD_SYSTEM" end
  if has(a, "?passthru=") or has(a, "&passthru=") then return "CMD_PASSTHRU" end
  if has(a, "?shell_exec=") or has(a, "&shell_exec=") then return "CMD_SHELL_EXEC" end
  if has(a, "?eval=") or has(a, "&eval=") then return "CMD_EVAL" end
  if has(a, "?assert=") or has(a, "&assert=") then return "CMD_ASSERT" end

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
--   traversal > rce > exploit_method > wp_brute > xss > sqli > cookieless > logonly
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
  local cookie = ctx.cookie or ""
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

  -- 4) WP brute force → CHALLENGE
  if CFG.rule_wp_brute and detect_wp_brute(uri, method) then
    return true, "WAF_WP_BRUTE", CFG.default_ttl_sec, "challenge"
  end

  -- 5) XSS → CHALLENGE
  if CFG.rule_xss and detect_xss(uri, args) then
    return true, "WAF_XSS", CFG.default_ttl_sec, "challenge"
  end

  -- 6) SQLi → CHALLENGE
  if CFG.rule_sqli and detect_sqli(uri, args) then
    return true, "WAF_SQLI", CFG.default_ttl_sec, "challenge"
  end

  -- 7) Cookie-less high RPS → CHALLENGE
  if CFG.rule_cookieless and detect_cookieless_rps(ip, cookie, shdict) then
    return true, "WAF_COOKIELESS_RPS", CFG.default_ttl_sec, "challenge"
  end

  -- 8) LOGONLY: cmd/eval parameter keys (audit)
  if CFG.rule_logonly_cmd_params then
    local tag = detect_cmd_param_key(args)
    if tag then
      return true, "WAF_LOGONLY_CMD_PARAM:" .. tag, CFG.default_ttl_sec, "logonly"
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

-- /usr/local/openresty/nginx/lua/cfm_waf.lua
--
-- CFM inline WAF
--
-- Design goals:
--   1) Cheap request-side checks first
--   2) Unified rule modes: disabled | logonly | challenge | block
--   3) Easy to tune/promote rules without renaming config keys
--   4) Keep expensive body inspection narrow and conservative
--
-- Public API:
--   _M.enabled() -> bool
--   _M.check(ctx) -> hit(bool), reason(string), ttl_sec(int), action(string)
--   _M.should_push(shdict, ip, reason) -> bool
--
-- ctx fields expected from caller:
--   uri, args, method, host, ip, peer, cf_ip, cookie, shdict, headers, body

local _M = {}

-- ─────────────────────────────────────────────────────────────────────────────
-- CONFIG
-- ─────────────────────────────────────────────────────────────────────────────
local CFG = {
  enabled = true,

  -- Rule modes:
  --   "disabled"  -> detector skipped
  --   "logonly"   -> log/push only, never challenge/block inline
  --   "challenge" -> send to challenge server
  --   "block"     -> return 403 immediately

  -- Core request-side protections
  rule_traversal       = "disabled",   -- ../, null bytes, basic traversal markers
  rule_rce             = "block",      -- strong RCE / shell / jndi markers
  rule_exploit_methods = "challenge",  -- TRACE/TRACK/CONNECT etc
  rule_xss             = "challenge",  -- cheap reflected-XSS style patterns
  rule_sqli            = "challenge",  -- cheap SQLi signatures

  -- Safer rollout / audit-first rules
  rule_php_wrappers    = "logonly",    -- php:// phar:// data:// zip:// expect:// glob://
  rule_ip_host         = "logonly",    -- Host header is bare IPv4/IPv6 literal
  rule_ctrl_chars      = "logonly",    -- suspicious ASCII control chars in args/body
  rule_b64_injection   = "logonly",    -- POST-body base64 decode heuristic scanner

  -- Auth / brute / XML-RPC
  rule_auth_burst         = "challenge", -- generic login endpoint burst
  rule_auth_wp_checks     = "challenge", -- HEAD wp-login, no UA+Referer POST wp-login
  rule_xmlrpc_multicall   = "challenge", -- system.multicall in XML-RPC body
  rule_xmlrpc_pingback    = "challenge", -- pingback.ping in XML-RPC body
  rule_xmlrpc_post_burst  = "challenge", -- generic repeated POST /xmlrpc.php

  -- Audit-only payload rules
  rule_cmd_params       = "logonly",   -- suspicious parameter keys like exec= system=
  rule_cmd_payload      = "logonly",   -- payload-y separators/tokens in args
  rule_debug_toggles    = "logonly",   -- xdebug, trace, debug, stacktrace
  rule_serialize        = "logonly",   -- PHP serialized object markers

  -- Generic auth burst tuning
  auth_window_sec       = 20,
  auth_burst_threshold  = 8,
  auth_ttl_sec          = 600,

  -- WP login helper tuning
  auth_wp_login_head_ttl_sec    = 600,
  auth_wp_login_noua_ttl_sec    = 600,

  -- XML-RPC direct body signatures
  auth_xmlrpc_multicall_ttl_sec = 1800,
  auth_xmlrpc_pingback_ttl_sec  = 1800,

  -- Generic XML-RPC POST burst tuning
  xmlrpc_post_window_sec        = 60,
  xmlrpc_post_threshold         = 6,
  xmlrpc_post_ttl_sec           = 1800,

  -- Generic defaults
  default_ttl_sec   = 600,
  block_ttl_sec     = 3600,
  push_cooldown_sec = 60,
  max_scan_len      = 2048,
}

-- Optional user overrides from cfm_waf_config.lua
do
  local ok, usercfg = pcall(require, "cfm_waf_config")
  if ok and type(usercfg) == "table" then
    for k, v in pairs(usercfg) do
      CFG[k] = v
    end
  end
end

-- ─────────────────────────────────────────────────────────────────────────────
-- MODE HELPERS
-- ─────────────────────────────────────────────────────────────────────────────

-- Validate / normalize a rule mode.
-- Also supports legacy booleans:
--   true  -> default_mode
--   false -> disabled
local function rule_mode(v, default_mode)
  if v == "disabled" or v == "logonly" or v == "challenge" or v == "block" then
    return v
  end
  if v == true then
    return default_mode or "challenge"
  end
  return "disabled"
end

-- Return ttl and action for a rule mode.
-- logonly/challenge/block use ttl; disabled is handled earlier.
local function mode_ttl_action(mode, ttl)
  return ttl, mode
end

function _M.enabled()
  return CFG.enabled == true
end

-- ─────────────────────────────────────────────────────────────────────────────
-- GENERIC STRING HELPERS
-- ─────────────────────────────────────────────────────────────────────────────

-- Plain substring search; avoids regex cost for simple tokens.
local function has(s, pat)
  if not s or s == "" then return false end
  return string.find(s, pat, 1, true) ~= nil
end

-- Lowercase safely.
local function lower(s)
  if not s then return "" end
  return string.lower(s)
end

-- Cap large strings to keep scanning cheap.
local function cap(s, n)
  if not s then return "" end
  if #s <= n then return s end
  return string.sub(s, 1, n)
end

-- Prefix test.
local function begins(s, prefix)
  if not s or not prefix then return false end
  return string.sub(s, 1, #prefix) == prefix
end

-- Single URL decode pass.
-- Used by normalize() to collapse encoded payloads.
local function url_decode_once(s)
  return (s:gsub("%%(%x%x)", function(h)
    return string.char(tonumber(h, 16))
  end))
end

-- Normalize input before matching:
--   1) cap length earlier in callers
--   2) decode %xx twice
--   3) lowercase
--
-- Two decode passes help close basic double-encoding bypasses.
local function normalize(s)
  if not s or s == "" then return "" end
  s = url_decode_once(s)
  s = url_decode_once(s)
  return string.lower(s)
end

-- Normalize URI+args together for detectors that scan the request line area.
local function scan_str(uri, args)
  return normalize(cap((uri or "") .. "?" .. (args or ""), CFG.max_scan_len))
end

-- ─────────────────────────────────────────────────────────────────────────────
-- HOST HELPERS
-- ─────────────────────────────────────────────────────────────────────────────

-- Strip optional port from Host while preserving IPv6 correctly.
-- Supports:
--   example.com
--   example.com:443
--   1.2.3.4
--   1.2.3.4:443
--   [2001:db8::1]
--   [2001:db8::1]:443
--   bare 2001:db8::1
local function strip_host_port(host)
  if not host or host == "" then return "" end
  host = host:gsub("^%s+", ""):gsub("%s+$", "")

  -- Bracketed IPv6 with optional port
  local b = host:match("^%[([^%]]+)%](?::%d+)?$")
  if b then return b end

  -- Hostname/IPv4 with :port
  if host:match("^[^:]+:%d+$") then
    return host:match("^([^:]+):%d+$") or host
  end

  -- Bare hostname or bare IPv6
  return host
end

-- Strict-ish IPv4 literal check.
local function is_ipv4_literal(h)
  local a, b, c, d = h:match("^(%d+)%.(%d+)%.(%d+)%.(%d+)$")
  if not a then return false end
  a, b, c, d = tonumber(a), tonumber(b), tonumber(c), tonumber(d)
  if not a or not b or not c or not d then return false end
  return a <= 255 and b <= 255 and c <= 255 and d <= 255
end

-- Simple IPv6 literal check.
-- Good enough for "bare IP in Host" detection.
local function is_ipv6_literal(h)
  if not h or h == "" then return false end
  if not h:find(":", 1, true) then return false end
  if h:match("^[0-9a-fA-F:]+$") then return true end
  return false
end

-- ─────────────────────────────────────────────────────────────────────────────
-- BLOCK-CLASS DETECTORS
-- ─────────────────────────────────────────────────────────────────────────────

-- Detect obvious traversal / null-byte usage.
-- Kept conservative because traversal can be noisy if over-broad.
local function detect_traversal(uri, args)
  local s = scan_str(uri, args)

  if has(s, "%00") or has(s, "\x00") then return true end
  if has(s, "../") or has(s, "..\\") then return true end

  return false
end

-- Detect strong RCE-like indicators.
-- These are meant to stay high-confidence.
local function detect_rce(uri, args)
  local s = scan_str(uri, args)

  -- Log4Shell / JNDI style probes
  if has(s, "${jndi:")   then return true end
  if has(s, "${j{n{d{i") then return true end
  if has(s, "$%7bjndi")  then return true end

  -- Obvious shell-ish separators / payloads
  if has(s, ";wget ") then return true end
  if has(s, ";curl ") then return true end
  if has(s, "|bash")  then return true end
  if has(s, "|sh ")   then return true end
  if has(s, "`wget")  then return true end
  if has(s, "`curl")  then return true end

  -- Encoded payload-delivery + exec-ish markers
  if has(s, "base64,") and (has(s, "eval") or has(s, "exec") or has(s, "system")) then
    return true
  end

  return false
end

-- Detect dangerous / unusual HTTP methods.
-- Some are block-worthy; others are challenge-worthy.
local function detect_exploit_method(method)
  method = lower(method or "")

  if method == "trace"   then return "block" end
  if method == "track"   then return "block" end
  if method == "connect" then return "block" end

  if method == "propfind" then return "challenge" end
  if method == "search"   then return "challenge" end

  return nil
end

-- ─────────────────────────────────────────────────────────────────────────────
-- LOGONLY-CLASS SAFER ROLLOUT DETECTORS
-- ─────────────────────────────────────────────────────────────────────────────

-- Detect dangerous PHP stream wrappers in args/body.
-- Safer to start as logonly because body scanning can surprise.
local function detect_php_wrappers(args, body)
  local s = normalize(cap((args or "") .. "&" .. (body or ""), CFG.max_scan_len))
  if s == "" then return nil end

  if has(s, "php://")    then return "WRAP_PHP" end
  if has(s, "phar://")   then return "WRAP_PHAR" end
  if has(s, "data://")   then return "WRAP_DATA" end
  if has(s, "zip://")    then return "WRAP_ZIP" end
  if has(s, "expect://") then return "WRAP_EXPECT" end
  if has(s, "glob://")   then return "WRAP_GLOB" end

  return nil
end

-- Detect bare IP literals in Host header.
-- Often suspicious for direct-IP probing, host-header abuse, or bypass attempts.
local function detect_ip_host(host)
  local h = strip_host_port(host)
  if h == "" then return false end
  if is_ipv4_literal(h) then return true end
  if is_ipv6_literal(h) then return true end
  return false
end

-- Detect suspicious ASCII control characters.
-- Excludes TAB/LF/CR by only matching:
--   0x01-0x08, 0x0B, 0x0C, 0x0E-0x1F
local function detect_ctrl_chars(args, body)
  local s = (args or "") .. (body or "")
  if s:find("[\x01-\x08\x0b\x0c\x0e-\x1f]") then
    return true
  end
  return false
end

-- Base64 body heuristic scanner.
-- Intentionally conservative and logonly-first.
-- Looks for large-ish base64 values, decodes them, then scans decoded text
-- for webshell/XSS/SQLi-ish indicators.
local function detect_b64_injection(body)
  if not body or body == "" then return nil end

  for candidate in body:gmatch("=([A-Za-z0-9+/]+=*)") do
    if #candidate >= 24 then
      local decoded = ngx.decode_base64(candidate)
      if decoded and #decoded >= 12 then
        local d = string.lower(decoded)

        -- PHP / upload / shell-ish indicators
        if has(d, "$_get") or has(d, "$_post") or has(d, "$_cookie")
          or has(d, "$_server") or has(d, "$_session")
          or has(d, "$globals") or has(d, "http_raw_post_data") then
          return "B64_SUPERGLOBAL"
        end

        if has(d, "eval(")               then return "B64_EVAL" end
        if has(d, "assert(")             then return "B64_ASSERT" end
        if has(d, "exec(")               then return "B64_EXEC" end
        if has(d, "system(")             then return "B64_SYSTEM" end
        if has(d, "passthru(")           then return "B64_PASSTHRU" end
        if has(d, "shell_exec(")         then return "B64_SHELL_EXEC" end
        if has(d, "base64_decode(")      then return "B64_B64_DECODE" end
        if has(d, "gzinflate(")          then return "B64_GZINFLATE" end
        if has(d, "move_uploaded_file(") then return "B64_MOVEUPLOAD" end
        if has(d, "fsockopen(")          then return "B64_FSOCKOPEN" end
        if has(d, "curl_exec(")          then return "B64_CURL_EXEC" end
        if has(d, "file_get_contents(")  then return "B64_FILEGET" end

        -- PHP / HTML markers
        if has(d, "<?php") or has(d, "<?=") then return "B64_PHP_TAG" end
        if has(d, "<script") then return "B64_XSS_SCRIPT" end
        if has(d, "<iframe") then return "B64_XSS_IFRAME" end
        if has(d, "<object") then return "B64_XSS_OBJECT" end

        -- Serialized object-ish markers
        if d:match('%bo%:%d+%:"') or d:match('%bc%:%d+%:"') then
          return "B64_OBJ_INJECT"
        end

        -- SQL-ish markers
        if has(d, "union select")       then return "B64_SQLI_UNION" end
        if has(d, "insert into")        then return "B64_SQLI_INSERT" end
        if has(d, "information_schema") then return "B64_SQLI_SCHEMA" end
      end
    end
  end

  return nil
end

-- ─────────────────────────────────────────────────────────────────────────────
-- CHALLENGE-CLASS DETECTORS
-- ─────────────────────────────────────────────────────────────────────────────

-- Cheap reflected-XSS style detector.
local function detect_xss(uri, args)
  local s = scan_str(uri, args)

  if has(s, "<script")      or has(s, "%3cscript") then return true end
  if has(s, "javascript:")                         then return true end
  if has(s, "onerror=")     or has(s, "onload=")  then return true end
  if has(s, "onmouseover=") or has(s, "onfocus=") then return true end

  return false
end

-- Cheap SQLi detector.
local function detect_sqli(uri, args)
  local s = scan_str(uri, args)

  if has(s, "union select") or has(s, "union%20select") then return true end
  if has(s, "information_schema") then return true end
  if has(s, " or 1=1") or has(s, " or%201=1") then return true end
  if has(s, "' or '1'='1") or has(s, "%27%20or%20%271%27%3d%271") then return true end

  return false
end

-- ─────────────────────────────────────────────────────────────────────────────
-- AUTH / BRUTE / XML-RPC HELPERS
-- ─────────────────────────────────────────────────────────────────────────────

-- Classify a request into a known auth endpoint family.
local function auth_endpoint_tag(uri, method)
  uri = lower(uri or "")
  method = lower(method or "get")

  if has(uri, "/wp-login.php") then return "AUTH_WP_LOGIN" end
  if has(uri, "/xmlrpc.php")   then return "AUTH_WP_XMLRPC" end
  if has(uri, "/administrator/index.php") then return "AUTH_JOOMLA_ADMIN" end
  if has(uri, "/user/login") then return "AUTH_DRUPAL_LOGIN" end

  if has(uri, "/admin") and (has(uri, "login") or has(uri, "auth")) then
    return "AUTH_MAGENTO_ADMIN"
  end
  if has(uri, "/admin/") and (has(uri, "index.php") or has(uri, "login")) then
    return "AUTH_OPENCART_ADMIN"
  end

  if has(uri, "/admin/login") then return "AUTH_ADMIN_LOGIN" end
  if has(uri, "/login") and method == "post" then return "AUTH_LOGIN_POST" end

  return nil
end

-- Generic auth burst counter by IP + auth endpoint family.
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
    shdict:set(kts, now, win + 1)
    shdict:set(kcnt, 1, win + 1)
    return nil
  end

  cnt = cnt + 1
  shdict:set(kcnt, cnt, win + 1)

  if cnt >= thr then
    return tag
  end
  return nil
end

-- Detect especially suspicious wp-login probes.
local function detect_wp_login_probe(uri, method, headers)
  uri = lower(uri or "")
  method = lower(method or "get")
  headers = headers or {}

  if not has(uri, "/wp-login.php") then return nil end

  local ua  = lower(headers["user-agent"] or headers["User-Agent"] or "")
  local ref = lower(headers["referer"]   or headers["Referer"]   or "")

  if method == "head" then
    return "AUTH_WP_LOGIN_HEAD"
  end

  if method == "post" and ua == "" and ref == "" then
    return "AUTH_WP_LOGIN_NO_UA_REF"
  end

  return nil
end

-- Detect strong XML-RPC body signatures.
local function detect_xmlrpc_probe(uri, method, body)
  uri = lower(uri or "")
  method = lower(method or "get")
  body = normalize(cap(body or "", CFG.max_scan_len))

  if not has(uri, "/xmlrpc.php") then return nil end
  if method ~= "post" then return nil end

  if has(body, "system.multicall") then
    return "AUTH_WP_XMLRPC_MULTICALL"
  end

  if has(body, "pingback.ping") then
    return "AUTH_WP_XMLRPC_PINGBACK"
  end

  return nil
end

-- Detect generic repeated POST /xmlrpc.php bursts.
-- Useful even when body does not contain strong known methods.
local function detect_xmlrpc_post_burst(ip, uri, method, shdict)
  if not shdict or not ip or ip == "" then return nil end

  uri = lower(uri or "")
  method = lower(method or "get")

  if method ~= "post" then return nil end
  if not has(uri, "/xmlrpc.php") then return nil end

  local now = ngx.now()
  local win = tonumber(CFG.xmlrpc_post_window_sec or 60) or 60
  local thr = tonumber(CFG.xmlrpc_post_threshold or 6) or 6

  local kts  = "xmlrpc|ts|"  .. ip
  local kcnt = "xmlrpc|cnt|" .. ip

  local ts  = shdict:get(kts)
  local cnt = shdict:get(kcnt) or 0

  if not ts or (now - ts) >= win then
    shdict:set(kts, now, win + 1)
    shdict:set(kcnt, 1, win + 1)
    return nil
  end

  cnt = cnt + 1
  shdict:set(kcnt, cnt, win + 1)

  if cnt >= thr then
    return "AUTH_WP_XMLRPC_POST_BURST"
  end

  return nil
end

-- ─────────────────────────────────────────────────────────────────────────────
-- AUDIT-CLASS DETECTORS
-- ─────────────────────────────────────────────────────────────────────────────

-- Detect suspicious parameter keys.
-- Key-only matching keeps FP lower than scanning arbitrary values.
local function detect_cmd_param_key(args)
  local a = normalize(cap(args or "", CFG.max_scan_len))
  if a == "" then return nil end

  local function key(k)
    if string.sub(a, 1, #k + 1) == (k .. "=") then return true end
    if has(a, "&" .. k .. "=") then return true end
    return false
  end

  if key("exec")       then return "CMD_EXEC" end
  if key("system")     then return "CMD_SYSTEM" end
  if key("passthru")   then return "CMD_PASSTHRU" end
  if key("shell_exec") then return "CMD_SHELL_EXEC" end
  if key("eval")       then return "CMD_EVAL" end
  if key("assert")     then return "CMD_ASSERT" end

  return nil
end

-- Detect shell-ish payload markers in args.
-- Heavily guarded because this area is FP-prone.
local function detect_cmd_payload(args)
  local a = normalize(cap(args or "", CFG.max_scan_len))
  if a == "" then return nil end

  -- Skip obvious data:base64 blobs
  if has(a, "data:") and has(a, ";base64,") then
    return nil
  end

  -- Skip long base64-ish segments
  do
    local p = string.find(a, "base64,", 1, true)
    if p then
      local rest = string.sub(a, p + 7)
      if #rest >= 256 then return nil end
    end
  end

  -- Skip huge values (JWT/signature/blob style)
  do
    for val in string.gmatch(a, "=([^&]+)") do
      if #val >= 512 then return nil end
    end
  end

  -- Skip common ecommerce filters syntax
  do
    if begins(a, "filters=") then
      local v = string.sub(a, 9)
      if v ~= "" and string.match(v, "^[a-z0-9_%-%[%]%|]+$")
         and not has(v, "||") and not has(v, "%7c%7c")
         and not has(v, "`")  and not has(v, "%60")
         and not has(v, ";wget") and not has(v, ";curl")
         and not has(v, ";bash") and not has(v, ";sh ") then
        return nil
      end
    end
  end

  -- Skip duplicate query separators like &&page=2
  if string.match(a, "[%?&][^=]+=[^&]*&&[a-z0-9_%-]+=") then
    return nil
  end

  -- Skip app/widget || delimiters
  if string.match(a, "[%?&][a-z0-9_%-]+=([a-z0-9_%-]+%|%|[a-z0-9_%-]+)") then
    return nil
  end

  -- Skip known Jetpack pattern
  if has(a, "/xmlrpc.php?for=jetpack&token=") then
    return nil
  end

  -- Skip known tracking params / opaque marketing blobs
  if has(a, "fbclid=") or has(a, "ttclid=") or has(a, "gclid=")
     or has(a, "msclkid=") or has(a, "__bpgid=") then
    return nil
  end

  local function has_semi_cmd(s)
    if has(s, ";wget") or has(s, ";curl") or has(s, ";bash") or has(s, ";sh ") then return true end
    if has(s, "%3bwget") or has(s, "%3bcurl") or has(s, "%3bbash") or has(s, "%3bsh%20") then return true end
    if has(s, "%3Bwget") or has(s, "%3Bcurl") or has(s, "%3Bbash") or has(s, "%3Bsh%20") then return true end
    return false
  end

  if has_semi_cmd(a) then return "PAY_SEMI_CMD" end

  if has(a, "|wget") or has(a, "%7cwget") then return "PAY_PIPE_WGET" end
  if has(a, "|curl") or has(a, "%7ccurl") then return "PAY_PIPE_CURL" end
  if has(a, "|bash") or has(a, "%7cbash") then return "PAY_PIPE_BASH" end
  if has(a, "|sh ")  or has(a, "%7csh%20") or has(a, "%7csh+") then return "PAY_PIPE_SH" end

  if has(a, "%60") or has(a, "`") then return "PAY_BACKTICK" end

  return nil
end

-- Detect developer/debug toggles in args.
local function detect_debug_toggles(args)
  local a = normalize(cap(args or "", CFG.max_scan_len))
  if a == "" then return nil end

  if has(a, "xdebug_session_start=") then return "DBG_XDEBUG" end
  if has(a, "xdebug=") then return "DBG_XDEBUG_KEY" end
  if has(a, "debug=true") or has(a, "debug=1") then return "DBG_DEBUG" end
  if has(a, "trace=1") or has(a, "trace=true") then return "DBG_TRACE" end
  if has(a, "stacktrace=1") or has(a, "stacktrace=true") then return "DBG_STACKTRACE" end

  return nil
end

-- Detect PHP serialized object markers.
local function detect_php_serialize(args)
  local a = normalize(cap(args or "", CFG.max_scan_len))
  if a == "" then return nil end

  if has(a, "o:") and has(a, ":\"") then return "SER_O_PLAIN" end
  if has(a, "c:") and has(a, ":\"") then return "SER_C_PLAIN" end
  if has(a, "o%3a") and has(a, "%22") then return "SER_O_URL" end
  if has(a, "c%3a") and has(a, "%22") then return "SER_C_URL" end

  return nil
end

-- ─────────────────────────────────────────────────────────────────────────────
-- MAIN CHECK
-- ─────────────────────────────────────────────────────────────────────────────

function _M.check(ctx)
  if not CFG.enabled then
    return false, nil, nil, nil
  end

  ctx = ctx or {}
  local uri     = ctx.uri     or ""
  local args    = ctx.args    or ""
  local method  = ctx.method  or "GET"
  local ip      = ctx.ip      or ""
  local shdict  = ctx.shdict
  local headers = ctx.headers or {}
  local body    = ctx.body    or ""

  -- 1) Traversal
  do
    local mode = rule_mode(CFG.rule_traversal, "block")
    if mode ~= "disabled" and detect_traversal(uri, args) then
      local ttl = (mode == "block") and CFG.block_ttl_sec or CFG.default_ttl_sec
      ttl, mode = mode_ttl_action(mode, ttl)
      return true, "WAF_TRAVERSAL", ttl, mode
    end
  end

  -- 2) RCE
  do
    local mode = rule_mode(CFG.rule_rce, "block")
    if mode ~= "disabled" and detect_rce(uri, args) then
      local ttl = (mode == "block") and CFG.block_ttl_sec or CFG.default_ttl_sec
      ttl, mode = mode_ttl_action(mode, ttl)
      return true, "WAF_RCE", ttl, mode
    end
  end

  -- 3) Exploit methods
  do
    local mode = rule_mode(CFG.rule_exploit_methods, "challenge")
    if mode ~= "disabled" then
      local maction = detect_exploit_method(method)
      if maction == "block" then
        local final = (mode == "logonly") and "logonly" or "block"
        local ttl = (final == "block") and CFG.block_ttl_sec or CFG.default_ttl_sec
        return true, "WAF_EXPLOIT_METHOD", ttl, final
      elseif maction == "challenge" then
        local final = (mode == "block") and "block" or mode
        local ttl = (final == "block") and CFG.block_ttl_sec or CFG.default_ttl_sec
        return true, "WAF_EXPLOIT_METHOD", ttl, final
      end
    end
  end

  -- 4) PHP wrappers
  do
    local mode = rule_mode(CFG.rule_php_wrappers, "logonly")
    if mode ~= "disabled" then
      local tag = detect_php_wrappers(args, body)
      if tag then
        local ttl = (mode == "block") and CFG.block_ttl_sec or CFG.default_ttl_sec
        return true, "WAF_PHP_WRAPPER:" .. tag, ttl, mode
      end
    end
  end

  -- 5) Bare IP Host
  do
    local mode = rule_mode(CFG.rule_ip_host, "logonly")
    if mode ~= "disabled" and detect_ip_host(headers["Host"] or headers["host"] or "") then
      local ttl = (mode == "block") and CFG.block_ttl_sec or CFG.default_ttl_sec
      return true, "WAF_IP_HOST", ttl, mode
    end
  end

  -- 6) Control chars
  do
    local mode = rule_mode(CFG.rule_ctrl_chars, "logonly")
    if mode ~= "disabled" and detect_ctrl_chars(args, body) then
      local ttl = (mode == "block") and CFG.block_ttl_sec or CFG.default_ttl_sec
      return true, "WAF_CTRL_CHARS", ttl, mode
    end
  end

  -- 7) XSS
  do
    local mode = rule_mode(CFG.rule_xss, "challenge")
    if mode ~= "disabled" and detect_xss(uri, args) then
      local ttl = (mode == "block") and CFG.block_ttl_sec or CFG.default_ttl_sec
      return true, "WAF_XSS", ttl, mode
    end
  end

  -- 8) SQLi
  do
    local mode = rule_mode(CFG.rule_sqli, "challenge")
    if mode ~= "disabled" and detect_sqli(uri, args) then
      local ttl = (mode == "block") and CFG.block_ttl_sec or CFG.default_ttl_sec
      return true, "WAF_SQLI", ttl, mode
    end
  end

  -- 9) WP-specific auth checks
  do
    local mode = rule_mode(CFG.rule_auth_wp_checks, "challenge")
    if mode ~= "disabled" then
      local tag = detect_wp_login_probe(uri, method, headers)
      if tag == "AUTH_WP_LOGIN_HEAD" then
        local ttl = CFG.auth_wp_login_head_ttl_sec or CFG.auth_ttl_sec or CFG.default_ttl_sec
        return true, "WAF_AUTH_BURST:" .. tag, ttl, mode
      elseif tag == "AUTH_WP_LOGIN_NO_UA_REF" then
        local ttl = CFG.auth_wp_login_noua_ttl_sec or CFG.auth_ttl_sec or CFG.default_ttl_sec
        return true, "WAF_AUTH_BURST:" .. tag, ttl, mode
      end
    end
  end

  -- 10) XML-RPC strong body signatures
  do
    local xtag = detect_xmlrpc_probe(uri, method, body)
    if xtag == "AUTH_WP_XMLRPC_MULTICALL" then
      local mode = rule_mode(CFG.rule_xmlrpc_multicall, "challenge")
      if mode ~= "disabled" then
        local ttl = CFG.auth_xmlrpc_multicall_ttl_sec or CFG.auth_ttl_sec or CFG.default_ttl_sec
        return true, "WAF_AUTH_BURST:" .. xtag, ttl, mode
      end
    elseif xtag == "AUTH_WP_XMLRPC_PINGBACK" then
      local mode = rule_mode(CFG.rule_xmlrpc_pingback, "challenge")
      if mode ~= "disabled" then
        local ttl = CFG.auth_xmlrpc_pingback_ttl_sec or CFG.auth_ttl_sec or CFG.default_ttl_sec
        return true, "WAF_AUTH_BURST:" .. xtag, ttl, mode
      end
    end
  end

  -- 11) Generic XML-RPC POST burst
  do
    local mode = rule_mode(CFG.rule_xmlrpc_post_burst, "challenge")
    if mode ~= "disabled" then
      local tag = detect_xmlrpc_post_burst(ip, uri, method, shdict)
      if tag then
        local ttl = CFG.xmlrpc_post_ttl_sec or CFG.auth_ttl_sec or CFG.default_ttl_sec
        return true, "WAF_AUTH_BURST:" .. tag, ttl, mode
      end
    end
  end

  -- 12) Generic auth endpoint burst
  do
    local mode = rule_mode(CFG.rule_auth_burst, "challenge")
    if mode ~= "disabled" then
      local peer = ctx.peer or ""

      -- Fail-safe: do not count bursts if real client IP appears to still be proxy peer
      if not (peer ~= "" and ip ~= "" and ip == peer) then
        local tag = detect_auth_burst(ip, uri, method, shdict)
        if tag then
          local ttl = CFG.auth_ttl_sec or CFG.default_ttl_sec
          return true, "WAF_AUTH_BURST:" .. tag, ttl, mode
        end
      end
    end
  end

  -- 13) Suspicious command parameter keys
  do
    local mode = rule_mode(CFG.rule_cmd_params, "logonly")
    if mode ~= "disabled" then
      local tag = detect_cmd_param_key(args)
      if tag then
        return true, "WAF_CMD_PARAM:" .. tag, CFG.default_ttl_sec, mode
      end
    end
  end

  -- 14) Suspicious payload markers
  do
    local mode = rule_mode(CFG.rule_cmd_payload, "logonly")
    if mode ~= "disabled" then
      local tag = detect_cmd_payload(args)
      if tag then
        return true, "WAF_CMD_PAYLOAD:" .. tag, CFG.default_ttl_sec, mode
      end
    end
  end

  -- 15) Debug toggles
  do
    local mode = rule_mode(CFG.rule_debug_toggles, "logonly")
    if mode ~= "disabled" then
      local tag = detect_debug_toggles(args)
      if tag then
        return true, "WAF_DEBUG_TOGGLE:" .. tag, CFG.default_ttl_sec, mode
      end
    end
  end

  -- 16) PHP serialize markers
  do
    local mode = rule_mode(CFG.rule_serialize, "logonly")
    if mode ~= "disabled" then
      local tag = detect_php_serialize(args)
      if tag then
        return true, "WAF_SERIALIZE:" .. tag, CFG.default_ttl_sec, mode
      end
    end
  end

  -- 17) Base64 POST body scanner
  do
    local mode = rule_mode(CFG.rule_b64_injection, "logonly")
    if mode ~= "disabled" and lower(method) == "post" and body ~= "" then
      local tag = detect_b64_injection(body)
      if tag then
        local ttl = (mode == "block") and CFG.block_ttl_sec or CFG.default_ttl_sec
        return true, "WAF_B64_INJECT:" .. tag, ttl, mode
      end
    end
  end

  return false, nil, nil, nil
end

-- Decide whether we should push this WAF event to /nginx/ip now.
-- Uses a small per-IP+reason cooldown to avoid bridge spam.
function _M.should_push(shdict, ip, reason)
  if not shdict or not ip or ip == "" then return true end
  local k  = "wafpush|" .. (reason or "WAF") .. "|" .. ip
  local ok = shdict:add(k, 1, CFG.push_cooldown_sec)
  return ok == true
end

return _M

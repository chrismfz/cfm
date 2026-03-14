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

  -- ── Core request-side protections ─────────────────────────────────────────
  rule_traversal       = "disabled",   -- ../, null bytes, basic traversal markers
  rule_rce             = "block",      -- strong RCE / shell / jndi markers
  rule_exploit_methods = "challenge",  -- TRACE/TRACK/CONNECT etc
  rule_xss             = "challenge",  -- cheap reflected-XSS style patterns
  rule_sqli            = "challenge",  -- cheap SQLi signatures (+ SQL comment bypass)

  -- ── Safer rollout / audit-first rules ─────────────────────────────────────
  rule_php_wrappers      = "logonly",  -- php:// phar:// data:// zip:// expect:// glob://
  rule_ip_host           = "logonly",  -- Host header is bare IPv4/IPv6 literal
  rule_ctrl_chars        = "logonly",  -- suspicious ASCII control chars in args/body
  rule_php_webshell_body = "logonly",  -- raw POST-body PHP webshell scorer (<?php + exec/superglobals)
  rule_b64_injection     = "logonly",  -- POST-body base64 decode heuristic scanner

  -- ── Auth / brute / XML-RPC ────────────────────────────────────────────────
  rule_auth_burst         = "challenge", -- generic login endpoint burst
  rule_auth_wp_checks     = "challenge", -- HEAD wp-login, no UA+Referer POST wp-login
  rule_xmlrpc_multicall   = "challenge", -- system.multicall in XML-RPC body
  rule_xmlrpc_pingback    = "challenge", -- pingback.ping in XML-RPC body
  rule_xmlrpc_post_burst  = "challenge", -- generic repeated POST /xmlrpc.php

  -- ── Audit / payload rules ─────────────────────────────────────────────────
  rule_cmd_params       = "logonly",   -- suspicious parameter keys like exec= system=
  rule_cmd_payload      = "logonly",   -- fallback/default mode for payload-y separators/tokens in args
  rule_debug_toggles    = "logonly",   -- xdebug, trace, debug, stacktrace
  rule_serialize        = "logonly",   -- PHP serialized object markers

  -- Per-tag override modes for cmd payloads.
  -- Empty/nil means: fall back to rule_cmd_payload.
  rule_cmd_payload_semi_cmd  = nil,         -- PAY_SEMI_CMD
  rule_cmd_payload_pipe_wget = nil,         -- PAY_PIPE_WGET
  rule_cmd_payload_pipe_curl = nil,         -- PAY_PIPE_CURL
  rule_cmd_payload_pipe_bash = nil,         -- PAY_PIPE_BASH
  rule_cmd_payload_pipe_sh   = nil,         -- PAY_PIPE_SH
  rule_cmd_payload_backtick  = "logonly",   -- PAY_BACKTICK

  -- ── Research additions – all logonly for initial FP observation ────────────
  -- Sources: uusec-waf (BSD), ZhongKui (Apache2), anti_ddos_challenge (MIT),
  --          nginx_waf (MIT).  Promote individually after watching logs.

  -- [top-6]  Header vulnerability bundle
  rule_bad_ua           = "logonly",  -- empty UA; known scanner/bot UAs (sqlmap, nikto, …)
  rule_shellshock       = "logonly",  -- Shellshock CVE-2014-6271 () { pattern in headers/URI
  rule_header_vulns     = "logonly",  -- httpoxy (Proxy:), CVE-2017-7269 (Lock-Token:/If:),
                                      -- CVE-2025-24813 (Tomcat PUT /session + Content-Range)

  -- [top-7]  Content-Type validation
  rule_content_type_anomaly = "logonly",  -- non-standard charset bypass; malformed multipart boundary

  -- [top-8]  Proxy header integrity
  rule_proxy_header_sqli = "logonly",  -- single-quote / non-string in XFF, X-Real-IP, Client-IP

  -- [top-9]  SSRF + JS prototype pollution
  rule_ssrf             = "logonly",  -- SSRF protocol schemes (file://, gopher://, …) + IP obfuscation
  rule_js_proto         = "logonly",  -- JS __proto__ / constructor.prototype pollution

  -- [top-10] XXE + CRLF + HTTP request smuggling
  rule_xxe              = "logonly",  -- XXE DOCTYPE/ENTITY SYSTEM in request body
  rule_crlf_injection   = "logonly",  -- CRLF / HTTP response-splitting in args or body
  rule_http_smuggling   = "logonly",  -- HTTP verb embedded in body / querystring (smuggling)

  -- [top-4]  Upload controls
  rule_upload_filename  = "logonly",  -- webshell extension in multipart filename (.php, .jsp, user.ini …)
  rule_upload_content   = "logonly",  -- webshell bytes / PHP tags inside uploaded file content

  -- [top-5]  PHP double-extension URI
  rule_php_double_ext   = "logonly",  -- .php. double-extension in URI (shell.php.jpg)

  -- ── Tuning ────────────────────────────────────────────────────────────────

  -- Generic auth burst tuning
  auth_window_sec      = 20,
  auth_burst_threshold = 8,
  auth_ttl_sec         = 600,

  -- WP login helper tuning
  auth_wp_login_head_ttl_sec = 600,
  auth_wp_login_noua_ttl_sec = 600,

  -- XML-RPC direct body signatures
  auth_xmlrpc_multicall_ttl_sec = 1800,
  auth_xmlrpc_pingback_ttl_sec  = 1800,

  -- Generic XML-RPC POST burst tuning
  xmlrpc_post_window_sec = 60,
  xmlrpc_post_threshold  = 6,
  xmlrpc_post_ttl_sec    = 1800,

  -- Generic defaults
  default_ttl_sec   = 600,
  block_ttl_sec     = 3600,
  push_cooldown_sec = 60,
  max_scan_len      = 2048,

  -- Raw PHP webshell body scanner tuning
  php_webshell_max_scan_len = 2048,
  php_webshell_min_score    = 5,

  -- Bad UA scorer tuning
  -- Signals and their point values (all accumulate):
  --   +2  empty / whitespace-only UA
  --   +2  generic HTTP library UA (python-requests, libwww-perl, winhttp, httrack)
  --   +1  HEAD method (scanners probe existence before fetching)
  --   +1  no Accept header (real browsers always send one)
  --   +1  no Referer on a non-root, non-asset URI
  --   +4  URI targets a sensitive file  (.env, .git/, wp-config.php, ...)
  --   +3  URI targets a credential / backup artifact (passwords.txt, *.sql, ...)
  --   instant  known scanner tool UA (sqlmap, nikto, masscan, ...) bypasses scoring
  --
  -- Threshold examples at default of 4:
  --   empty UA hitting a normal page        = 2  -> pass  (legit bots / your C++ agents)
  --   empty UA + HEAD + no Accept           = 4  -> trigger
  --   empty UA + .git/HEAD URI              = 6  -> trigger
  --   python-requests on any article page   = 2  -> pass  (scrapers, uptime monitors)
  --   python-requests + HEAD + no Accept    = 4  -> trigger
  --   any UA  + /backup/db.sql              = 3  -> pass  (score alone insufficient)
  --   empty UA + /backup/db.sql             = 5  -> trigger
  bad_ua_min_score = 4,
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

local function mode_ttl_action(mode, ttl)
  return ttl, mode
end

local function cmd_payload_mode(tag)
  local override = nil

  if tag == "PAY_SEMI_CMD" then
    override = CFG.rule_cmd_payload_semi_cmd
  elseif tag == "PAY_PIPE_WGET" then
    override = CFG.rule_cmd_payload_pipe_wget
  elseif tag == "PAY_PIPE_CURL" then
    override = CFG.rule_cmd_payload_pipe_curl
  elseif tag == "PAY_PIPE_BASH" then
    override = CFG.rule_cmd_payload_pipe_bash
  elseif tag == "PAY_PIPE_SH" then
    override = CFG.rule_cmd_payload_pipe_sh
  elseif tag == "PAY_BACKTICK" then
    override = CFG.rule_cmd_payload_backtick
  end

  if override == nil then
    return rule_mode(CFG.rule_cmd_payload, "logonly")
  end
  return rule_mode(override, rule_mode(CFG.rule_cmd_payload, "logonly"))
end

function _M.enabled()
  return CFG.enabled == true
end

-- ─────────────────────────────────────────────────────────────────────────────
-- GENERIC STRING HELPERS
-- ─────────────────────────────────────────────────────────────────────────────

local function has(s, pat)
  if not s or s == "" then return false end
  return string.find(s, pat, 1, true) ~= nil
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

local function begins(s, prefix)
  if not s or not prefix then return false end
  return string.sub(s, 1, #prefix) == prefix
end

local function url_decode_once(s)
  return (s:gsub("%%(%x%x)", function(h)
    return string.char(tonumber(h, 16))
  end))
end

local function normalize(s)
  if not s or s == "" then return "" end
  s = url_decode_once(s)
  s = url_decode_once(s)
  return string.lower(s)
end

-- Strip SQL inline comments before SQLi scanning.
-- Catches keyword-splitting bypasses like UN/**/ION SE/**/LECT.
-- Applied only in the SQLi path; not in normalize() to avoid
-- altering the scan surface for other checks.
local function strip_sql_comments(s)
  return (s:gsub("/%*.-%*/", ""):gsub("%-%-[^\n]*", ""))
end

local function scan_str(uri, args)
  return normalize(cap((uri or "") .. "?" .. (args or ""), CFG.max_scan_len))
end

-- ─────────────────────────────────────────────────────────────────────────────
-- HOST HELPERS
-- ─────────────────────────────────────────────────────────────────────────────

local function strip_host_port(host)
  if not host or host == "" then return "" end
  host = host:gsub("^%s+", ""):gsub("%s+$", "")

  -- Bracketed IPv6 with or without port
  local b = host:match("^%[([^%]]+)%]:%d+$") or host:match("^%[([^%]]+)%]$")
  if b then return b end

  -- Hostname / IPv4 with :port
  if host:match("^[^:]+:%d+$") then
    return host:match("^([^:]+):%d+$") or host
  end

  -- Bare hostname or bare IPv6
  return host
end

local function is_ipv4_literal(h)
  local a, b, c, d = h:match("^(%d+)%.(%d+)%.(%d+)%.(%d+)$")
  if not a then return false end
  a, b, c, d = tonumber(a), tonumber(b), tonumber(c), tonumber(d)
  if not a or not b or not c or not d then return false end
  return a <= 255 and b <= 255 and c <= 255 and d <= 255
end

local function is_ipv6_literal(h)
  if not h or h == "" then return false end
  if not h:find(":", 1, true) then return false end
  if h:match("^[0-9a-fA-F:]+$") then return true end
  return false
end

-- ─────────────────────────────────────────────────────────────────────────────
-- BLOCK-CLASS DETECTORS
-- ─────────────────────────────────────────────────────────────────────────────

local function detect_traversal(uri, args)
  local s = scan_str(uri, args)

  if has(s, "%00") or has(s, "\x00") then return true end
  if has(s, "../") or has(s, "..\\") then return true end

  return false
end

local function detect_rce(uri, args)
  local s = scan_str(uri, args)

  if has(s, "${jndi:")   then return true end
  if has(s, "${j{n{d{i") then return true end
  if has(s, "$%7bjndi")  then return true end

  if has(s, ";wget ") then return true end
  if has(s, ";curl ") then return true end
  if has(s, "|bash")  then return true end
  if has(s, "|sh ")   then return true end
  if has(s, "`wget")  then return true end
  if has(s, "`curl")  then return true end

  if has(s, "base64,") and (has(s, "eval") or has(s, "exec") or has(s, "system")) then
    return true
  end

  return false
end

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
-- LOGONLY-CLASS SAFER ROLLOUT DETECTORS (existing)
-- ─────────────────────────────────────────────────────────────────────────────

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
--
-- Safer rollout:
--   * always inspect args
--   * inspect body only for textual payloads
--   * skip multipart/form-data bodies (binary uploads are noisy by design)
local function is_known_binaryish_telemetry_uri(uri)
  local u = lower(uri or "")
  if u == "" then return false end

  -- WordPress Optimization Detective web-vitals endpoint.
  -- This endpoint can legitimately carry compressed/packed metric payloads.
  if u:match("^/wp%-json/optimization%-detective/")
     and has(u, "/url-metrics:store") then
    return true
  end

  return false
end

local function detect_ctrl_chars(args, body, headers, uri)
  if is_known_binaryish_telemetry_uri(uri) then
    return false
  end

  local a = args or ""
  if a ~= "" and a:find("[\x01-\x08\x0b\x0c\x0e-\x1f]") then
    return true
  end

  if not body or body == "" then
    return false
  end

  headers = headers or {}
  local ct = lower(headers["content-type"] or headers["Content-Type"] or "")

  if has(ct, "multipart/form-data") then
    return false
  end

  if ct ~= ""
     and not has(ct, "application/x-www-form-urlencoded")
     and not has(ct, "application/json")
     and not has(ct, "application/xml")
     and not has(ct, "text/") then
    return false
  end

  if body:find("[\x01-\x08\x0b\x0c\x0e-\x1f]") then
    return true
  end

  return false
end

local function is_textual_body_content_type(content_type)
  local ct = lower(content_type or "")
  if ct == "" then return true end

  if has(ct, "multipart/form-data")              then return false end
  if has(ct, "application/x-www-form-urlencoded") then return true end
  if has(ct, "application/json")                  then return true end
  if has(ct, "application/xml")                   then return true end
  if has(ct, "text/")                             then return true end

  return false
end

local function detect_php_webshell_body(body, headers)
  if not body or body == "" then return nil end

  headers = headers or {}
  local ct = headers["content-type"] or headers["Content-Type"] or ""
  if not is_textual_body_content_type(ct) then
    return nil
  end

  local s = normalize(cap(body, tonumber(CFG.php_webshell_max_scan_len) or CFG.max_scan_len))
  if s == "" then return nil end

  if has(ct, "application/x-www-form-urlencoded") then
    s = s:gsub("%+", " ")
  end

  if not (has(s, "<?") or has(s, "$_") or has(s, "eval") or has(s, "system")
          or has(s, "passthru") or has(s, "shell_exec") or has(s, "exec")) then
    return nil
  end

  local score = 0

  if has(s, "<?php") or has(s, "<?=") then
    score = score + 2
  end

  if has(s, "$_get") or has(s, "$_post") or has(s, "$_request")
     or has(s, "$_cookie") or has(s, "$_server") then
    score = score + 2
  end

  local function has_php_callable(name)
    if s:find("%f[%a_]" .. name .. "%s*%(") then return true end
    if s:find("@%s*" .. name .. "%s*%(") then return true end
    return false
  end

  if has_php_callable("eval") then score = score + 3 end
  if has_php_callable("assert") then score = score + 3 end
  if has_php_callable("system") then score = score + 3 end
  if has_php_callable("exec") then score = score + 3 end
  if has_php_callable("passthru") then score = score + 3 end
  if has_php_callable("shell_exec") then score = score + 3 end
  if has_php_callable("popen") then score = score + 3 end
  if has_php_callable("proc_open") then score = score + 3 end

  if has(s, ";") and (has(s, "?>") or has(s, "<?php") or has(s, "<?=")) then
    score = score + 1
  end

  local min_score = tonumber(CFG.php_webshell_min_score) or 5
  if score < min_score then
    return nil
  end

  if s:find("<?php.-@?eval%s*%(") and s:find("%$_post") then return "RAW_EVAL_POST" end
  if s:find("<?php.-@?system%s*%(") and s:find("%$_get") then return "RAW_SYSTEM_GET" end
  if s:find("<?php.-@?passthru%s*%(") and s:find("%$_request") then return "RAW_PASSTHRU_REQUEST" end

  if has_php_callable("eval")       then return "RAW_EVAL" end
  if has_php_callable("assert")     then return "RAW_ASSERT" end
  if has_php_callable("system")     then return "RAW_SYSTEM" end
  if has_php_callable("exec")       then return "RAW_EXEC" end
  if has_php_callable("passthru")   then return "RAW_PASSTHRU" end
  if has_php_callable("shell_exec") then return "RAW_SHELL_EXEC" end
  if has_php_callable("popen")      then return "RAW_POPEN" end
  if has_php_callable("proc_open")  then return "RAW_PROC_OPEN" end

  if has(s, "$_get") or has(s, "$_post") or has(s, "$_request") then
    return "RAW_SUPERGLOBAL"
  end

  return "RAW_SCORING_HIT"
end

local function detect_b64_injection(body)
  if not body or body == "" then return nil end

  for candidate in body:gmatch("=([A-Za-z0-9+/]+=*)") do
    if #candidate >= 24 then
      local decoded = ngx.decode_base64(candidate)
      if decoded and #decoded >= 12 then
        local d = string.lower(decoded)

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

        if has(d, "<?php") or has(d, "<?=") then return "B64_PHP_TAG" end
        if has(d, "<script") then return "B64_XSS_SCRIPT" end
        if has(d, "<iframe") then return "B64_XSS_IFRAME" end
        if has(d, "<object") then return "B64_XSS_OBJECT" end

        if d:match('%bo%:%d+%:"') or d:match('%bc%:%d+%:"') then
          return "B64_OBJ_INJECT"
        end

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

local function detect_xss(uri, args)
  local s = scan_str(uri, args)

  if has(s, "<script")      or has(s, "%3cscript") then return true end
  if has(s, "javascript:")                         then return true end
  if has(s, "onerror=")     or has(s, "onload=")  then return true end
  if has(s, "onmouseover=") or has(s, "onfocus=") then return true end

  return false
end

local function detect_sqli(uri, args)
  -- Use comment-stripped version to catch UN/**/ION SE/**/LECT bypass patterns.
  -- Double URL-decode is already applied by normalize() / scan_str().
  local s  = scan_str(uri, args)
  local sc = strip_sql_comments(s)

  if has(sc, "union select")        then return true end
  if has(sc, "union%20select")      then return true end
  if has(sc, "information_schema")  then return true end
  if has(sc, " or 1=1")             then return true end
  if has(sc, " or%201=1")           then return true end
  if has(sc, "' or '1'='1")        then return true end
  if has(sc, "%27%20or%20%271%27%3d%271") then return true end

  return false
end

-- ─────────────────────────────────────────────────────────────────────────────
-- AUTH / BRUTE / XML-RPC HELPERS
-- ─────────────────────────────────────────────────────────────────────────────

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

local function detect_cmd_payload(args)
  local a = normalize(cap(args or "", CFG.max_scan_len))
  if a == "" then return nil end

  local ignore_backtick_only = false

  if has(a, "data:") and has(a, ";base64,") then
    return nil
  end

  do
    local p = string.find(a, "base64,", 1, true)
    if p then
      local rest = string.sub(a, p + 7)
      if #rest >= 256 then return nil end
    end
  end

  do
    for val in string.gmatch(a, "=([^&]+)") do
      if #val >= 512 then return nil end
    end
  end

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

  if string.match(a, "[%?&][^=]+=[^&]*&&[a-z0-9_%-]+=") then
    return nil
  end

  if string.match(a, "[%?&][a-z0-9_%-]+=([a-z0-9_%-]+%|%|[a-z0-9_%-]+)") then
    return nil
  end

  if has(a, "/xmlrpc.php?for=jetpack&token=") then
    return nil
  end

  if has(a, "fbclid=") or has(a, "ttclid=") or has(a, "gclid=")
     or has(a, "msclkid=") or has(a, "__bpgid=") then
    return nil
  end

  -- Search/autocomplete suppression:
  -- do not return nil for the whole request, only suppress final PAY_BACKTICK
  -- if the suspicious bit is limited to a search-like free-text field.
  do
    for key, val in a:gmatch("([a-z0-9_%-]+)=([^&]+)") do
      if key == "q" or key == "s" or key == "term" or key == "search" or key == "query" then
        local cleaned = val:gsub("%%60", ""):gsub("`", "")
        if cleaned ~= val then
          if not has(cleaned, ";wget")
             and not has(cleaned, ";curl")
             and not has(cleaned, ";bash")
             and not has(cleaned, ";sh ")
             and not has(cleaned, "%3bwget")
             and not has(cleaned, "%3bcurl")
             and not has(cleaned, "%3bbash")
             and not has(cleaned, "%3bsh%20")
             and not has(cleaned, "|wget")
             and not has(cleaned, "|curl")
             and not has(cleaned, "|bash")
             and not has(cleaned, "|sh ")
             and not has(cleaned, "%7cwget")
             and not has(cleaned, "%7ccurl")
             and not has(cleaned, "%7cbash")
             and not has(cleaned, "%7csh%20")
             and not has(cleaned, "%7csh+") then
            ignore_backtick_only = true
          end
        end
      end
    end
  end

  local function has_semi_cmd(s)
    if has(s, ";wget") or has(s, ";curl") or has(s, ";bash") or has(s, ";sh ") then return true end
    if has(s, "%3bwget") or has(s, "%3bcurl") or has(s, "%3bbash") or has(s, "%3bsh%20") then return true end
    return false
  end

  if has_semi_cmd(a) then return "PAY_SEMI_CMD" end

  if has(a, "|wget") or has(a, "%7cwget") then return "PAY_PIPE_WGET" end
  if has(a, "|curl") or has(a, "%7ccurl") then return "PAY_PIPE_CURL" end
  if has(a, "|bash") or has(a, "%7cbash") then return "PAY_PIPE_BASH" end
  if has(a, "|sh ")  or has(a, "%7csh%20") or has(a, "%7csh+") then return "PAY_PIPE_SH" end

  local function has_backtick_cmd(s)
    -- Require an actual backtick command-substitution shape to avoid
    -- flagging accidental trailing backticks in business app query params.
    local inner = s:match("`([^`]+)`")
    if not inner then return false end

    if inner:match("^%s*(wget|curl|bash|sh|nc|ncat|perl|python|php|ruby|lua|id|uname|whoami|cat|ls|ping)%f[^%a]") then
      return true
    end

    if inner:find(";", 1, true) or inner:find("|", 1, true) or inner:find("&&", 1, true) then
      return true
    end

    return false
  end

  if not ignore_backtick_only and has_backtick_cmd(a) then
    return "PAY_BACKTICK"
  end

  return nil
end

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
-- RESEARCH ADDITIONS – HEADER / PROTOCOL CHECKS
-- ─────────────────────────────────────────────────────────────────────────────

-- [top-6a] Bad UA scorer.
-- Sources: uusec scanner-detection (plugin), anti_ddos_challenge.lua UA list.
--
-- Returns: score (int), composite_tag (string) or 0, nil if nothing fires.
--
-- Two tiers:
--   INSTANT  - known scanner tool UAs fire regardless of score.
--              These have zero legitimate use on shared hosting.
--   SCORED   - weak signals that are innocent alone but suspicious in combination.
--              Each signal adds points; caller checks against CFG.bad_ua_min_score.
--
-- Scored signals and weights:
--   UA presence:  empty/whitespace=+2, generic HTTP lib=+2
--   Method:       HEAD=+1   (scanners probe existence cheaply)
--   Headers:      no Accept=+1, no Referer on non-root URI=+1
--   URI target:   sensitive file (.env/.git/wp-config)=+4,
--                 credential/backup artifact (*.sql, passwords.txt)=+3
local function detect_bad_ua_scored(headers, uri, method)
  headers = headers or {}
  local ua  = headers["user-agent"] or headers["User-Agent"] or ""
  local ual = lower(ua)

  -- INSTANT: named scanner / exploit tools - bypass scoring
  -- Slowloris self-identifies via Referer
  local ref = lower(headers["referer"] or headers["Referer"] or "")
  if has(ref, "code.google.com/p/slowhttptest") then return 99, "REF_SLOWLORIS" end

  if has(ual, "sqlmap")    then return 99, "UA_SQLMAP" end
  if has(ual, "nikto")     then return 99, "UA_NIKTO" end
  if has(ual, "nessus")    then return 99, "UA_NESSUS" end
  if has(ual, "masscan")   then return 99, "UA_MASSCAN" end
  if has(ual, "zgrab")     then return 99, "UA_ZGRAB" end
  if has(ual, "nuclei")    then return 99, "UA_NUCLEI" end
  if has(ual, "dirbuster") then return 99, "UA_DIRBUSTER" end
  if has(ual, "gobuster")  then return 99, "UA_GOBUSTER" end
  if has(ual, "wfuzz")     then return 99, "UA_WFUZZ" end
  if has(ual, "awvs")      then return 99, "UA_AWVS" end
  if has(ual, "appscan")   then return 99, "UA_APPSCAN" end

  -- SCORED: accumulate weak signals
  local score = 0
  local tags  = {}
  local ul = lower(uri or "")
  local m = lower(method or "")

  -- Signal 1: UA quality (+2 for empty or known generic lib)
  if ua == "" or ual:match("^%s*$") then
    score = score + 2; tags[#tags+1] = "UA_EMPTY"
  elseif has(ual, "python-requests") then
    score = score + 2; tags[#tags+1] = "UA_PY_REQUESTS"
  elseif has(ual, "libwww-perl") then
    score = score + 2; tags[#tags+1] = "UA_LIBWWW"
  elseif has(ual, "winhttp") then
    score = score + 2; tags[#tags+1] = "UA_WINHTTP"
  elseif has(ual, "httrack") then
    score = score + 2; tags[#tags+1] = "UA_HTTRACK"
  end

  -- If UA is perfectly fine, no further scoring needed
  if score == 0 then return 0, nil end

  -- Signal 2: HEAD method (+1) - cheap existence probe used by scanners
  if m == "head" then
    score = score + 1; tags[#tags+1] = "HEAD"
  end

  -- Pre-compute URI risk class used by header-quality scoring.
  local uri_sensitive = false
  local uri_backup = false

  if has(ul, "/.git/")             then uri_sensitive = true end
  if has(ul, "/.env")              then uri_sensitive = true end
  if has(ul, "/wp-config.php")     then uri_sensitive = true end
  if has(ul, "/.htaccess")         then uri_sensitive = true end
  if has(ul, "/.htpasswd")         then uri_sensitive = true end
  if has(ul, "/config.php")        then uri_sensitive = true end
  if has(ul, "/configuration.php") then uri_sensitive = true end
  if has(ul, "/settings.php")      then uri_sensitive = true end

  if ul:match("%.sql$") or ul:match("%.sql%.gz$") or ul:match("%.sql%.zip$") then
    uri_backup = true
  end
  if ul:match("password") or ul:match("credential") or ul:match("passwd") then
    uri_backup = true
  end
  local in_backup_path = has(ul, "/backup") or has(ul, "/bak/") or has(ul, "/old/")
                      or has(ul, "/restore") or has(ul, "/archive")
  if in_backup_path and (ul:match("%.zip$") or ul:match("%.tar$") or ul:match("%.gz$")
                      or ul:match("%.rar$") or ul:match("%.tgz$")) then
    uri_backup = true
  end

  local strict_header_scoring = (m ~= "get" and m ~= "head") or uri_sensitive or uri_backup

  -- Signal 3: no Accept header (+1)
  -- Applied only on higher-risk request context to avoid FP on benign crawlers.
  local accept = headers["accept"] or headers["Accept"] or ""
  if accept == "" and strict_header_scoring then
    score = score + 1; tags[#tags+1] = "NO_ACCEPT"
  end

  -- Signal 4: no Referer on a non-trivial URI (+1)
  -- Skip scoring on root, common entry points, and static assets
  local is_entry = (ul == "/" or ul == ""
    or ul:match("%.css$") or ul:match("%.js$")  or ul:match("%.ico$")
    or ul:match("%.png$") or ul:match("%.jpg$") or ul:match("%.gif$")
    or ul:match("%.svg$") or ul:match("%.woff"))
  if strict_header_scoring and not is_entry and ref == "" then
    score = score + 1; tags[#tags+1] = "NO_REFERER"
  end

  -- Signal 5: URI targets a high-value sensitive file (+4)
  if uri_sensitive then
    if has(ul, "/.git/")             then tags[#tags+1] = "URI_GIT" end
    if has(ul, "/.env")              then tags[#tags+1] = "URI_ENV" end
    if has(ul, "/wp-config.php")     then tags[#tags+1] = "URI_WPCONFIG" end
    if has(ul, "/.htaccess")         then tags[#tags+1] = "URI_HTACCESS" end
    if has(ul, "/.htpasswd")         then tags[#tags+1] = "URI_HTPASSWD" end
    if has(ul, "/config.php")        then tags[#tags+1] = "URI_CONFIG_PHP" end
    if has(ul, "/configuration.php") then tags[#tags+1] = "URI_JOOMLA_CFG" end
    if has(ul, "/settings.php")      then tags[#tags+1] = "URI_SETTINGS_PHP" end
    score = score + 4
  end

  -- Signal 6: URI targets a credential / backup artifact (+3)
  -- Archives only scored when inside a backup-like path to avoid
  -- flagging legitimate CDN or media ZIP downloads.
  if uri_backup then
    if ul:match("%.sql$") or ul:match("%.sql%.gz$") or ul:match("%.sql%.zip$") then
      tags[#tags+1] = "URI_SQL_DUMP"
    end
    if ul:match("password") or ul:match("credential") or ul:match("passwd") then
      tags[#tags+1] = "URI_CRED_FILE"
    end
    if in_backup_path and (ul:match("%.zip$") or ul:match("%.tar$") or ul:match("%.gz$")
                        or ul:match("%.rar$") or ul:match("%.tgz$")) then
      tags[#tags+1] = "URI_BACKUP_ARCHIVE"
    end
    score = score + 3
  end

  return score, table.concat(tags, "+")
end

-- [top-6b] Shellshock CVE-2014-6271 / CVE-2014-7169.
-- Source: uusec shellshock-vulnerability.lua.
-- Pattern: () { in any header value or URI.
-- Checks URL-decoded copy of each header to catch %28%29+%7b variants.
local function detect_shellshock(headers, uri)
  local pat = "%(%)%s*{"

  headers = headers or {}
  for hname, hval in pairs(headers) do
    if type(hval) == "string" then
      local decoded = url_decode_once(hval)
      if decoded:find(pat) then
        return "SHELLSHOCK_HDR:" .. tostring(hname):sub(1, 32)
      end
    end
  end

  local u = url_decode_once(uri or "")
  if u:find(pat) then return "SHELLSHOCK_URI" end

  return nil
end

-- [top-6c] Header presence vulnerability checks.
-- Sources: uusec header-vulnerability.lua + cve-2025-24813.lua.
--   * Proxy:     – httpoxy: CGI/FastCGI sees HTTP_PROXY env var, can redirect outbound traffic.
--   * Lock-Token: / If: – CVE-2017-7269: IIS 6.0 WebDAV ScStoragePathFromUrl overflow.
--   * PUT /…/session + Content-Range – CVE-2025-24813: Tomcat partial PUT RCE (March 2025).
-- All are pure header presence checks – zero FP on normal browser traffic.
local function detect_header_vulns(headers, uri, method)
  headers = headers or {}

  if headers["proxy"] or headers["Proxy"] then
    return "HEADER_HTTPOXY"
  end

  if headers["lock-token"] or headers["Lock-Token"] then
    return "HEADER_LOCK_TOKEN"
  end

  if headers["if"] or headers["If"] then
    return "HEADER_IF_WEBDAV"
  end

  -- CVE-2025-24813: PUT request to a path ending in /session with Content-Range
  if lower(method or "") == "put" then
    local u = lower(uri or "")
    if u:match("/session$")
       and (headers["content-range"] or headers["Content-Range"]) then
      return "CVE_2025_24813"
    end
  end

  return nil
end

-- ─────────────────────────────────────────────────────────────────────────────
-- RESEARCH ADDITIONS – CONTENT-TYPE / PROTOCOL ANOMALY CHECKS
-- ─────────────────────────────────────────────────────────────────────────────

-- [top-7] Content-Type header anomaly detection.
-- Sources: uusec abnormal-character-encoding-requests.lua +
--          uusec boundary-exception-interception.lua.
--
-- Charset bypass: attackers set Content-Type: application/x-www-form-urlencoded;
--   charset=IBM037 (or IBM500, cp875 etc.) so the WAF can't decode the payload
--   while the backend still processes it using its own charset logic.
--   Only allow the small set of charsets that nginx/PHP legitimately uses.
--
-- Boundary bypass: PHP's non-RFC-compliant multipart boundary parsing can be
--   exploited by sending a malformed boundary= value to confuse content scanners.
local function detect_content_type_anomaly(headers)
  headers = headers or {}
  local ct = headers["content-type"] or headers["Content-Type"] or ""
  if ct == "" then return nil end

  -- Non-string Content-Type indicates header injection
  if type(ct) ~= "string" then return "CT_NON_STRING" end

  local ctl = lower(ct)

  if has(ctl, "charset") then
    local charset_val = ctl:match("charset%s*=%s*([%w%-]+)")
    if charset_val then
      local safe_charsets = {
        ["utf-8"]=true, ["utf8"]=true,
        ["gbk"]=true, ["gb2312"]=true, ["gb18030"]=true,
        ["iso-8859-1"]=true, ["iso-8859-15"]=true,
        ["windows-1252"]=true, ["latin1"]=true,
        ["us-ascii"]=true, ["ascii"]=true,
      }
      if not safe_charsets[charset_val] then
        return "CT_CHARSET_BYPASS:" .. charset_val:sub(1, 32)
      end
    end
    -- Multiple charset= declarations in one Content-Type
    local _, n = ctl:gsub("charset", "charset")
    if n > 1 then return "CT_MULTI_CHARSET" end
  end

  if has(ctl, "boundary") then
    -- Count boundary= *declarations*, not bare substring occurrences.
    -- Browser-generated boundary strings (e.g. ----WebKitFormBoundaryXxx,
    -- ---------------------------1234567890) contain the word "boundary"
    -- inside the value itself, so counting the raw word gives n=2 on every
    -- normal file upload.  Counting "boundary=" is safe and correct.
    local _, n = ctl:gsub("boundary%s*=", "boundary=")
    if n > 1 then return "CT_MULTI_BOUNDARY" end
    -- Boundary value: allow leading dashes (RFC 2046 permits up to 70 chars
    -- of printable ASCII; browsers use long dash prefixes by convention).
    local bval = ctl:match("boundary%s*=%s*([^%s;,]+)")
    if bval and not bval:match("^%-*[0-9A-Za-z%-%_%.]+$") then
      return "CT_BAD_BOUNDARY"
    end
  end

  return nil
end

-- [top-8] Single-quote SQLi / non-string values in proxy IP headers.
-- Source: uusec proxy-header-sql-injection.lua.
-- Why: some apps log or query-build using XFF/X-Real-IP without sanitization.
-- A non-string (table) value = multiple headers sent = header injection attempt.
local function detect_proxy_header_sqli(headers)
  headers = headers or {}
  local suspects = {
    ["x-forwarded-for"] = headers["x-forwarded-for"] or headers["X-Forwarded-For"],
    ["x-real-ip"]       = headers["x-real-ip"]       or headers["X-Real-IP"],
    ["client-ip"]       = headers["client-ip"]        or headers["Client-IP"],
    ["x-client-ip"]     = headers["x-client-ip"]      or headers["X-Client-IP"],
  }
  for hname, hval in pairs(suspects) do
    if hval ~= nil then
      if type(hval) ~= "string" then
        return "PROXY_HDR_INJECT:" .. hname
      end
      if has(hval, "'") then
        return "PROXY_HDR_SQLI:" .. hname
      end
    end
  end
  return nil
end

-- ─────────────────────────────────────────────────────────────────────────────
-- RESEARCH ADDITIONS – URI CHECKS
-- ─────────────────────────────────────────────────────────────────────────────

-- [top-5 / php-security] PHP double-extension URI.
-- Source: uusec php-security-rule-set.lua.
-- Pattern: .php. or .phtml. in URI catches shell.php.jpg type uploads that
-- execute as PHP on misconfigured servers (AddHandler / FilesMatch directives).
local function detect_php_double_ext(uri)
  local u = lower(uri or "")
  if u:match("%.php%d?%.") then return "PHP_DOUBLE_EXT" end
  if u:match("%.phtml%.")  then return "PHTML_DOUBLE_EXT" end
  return nil
end

-- ─────────────────────────────────────────────────────────────────────────────
-- RESEARCH ADDITIONS – ARGS / BODY INJECTION CHECKS
-- ─────────────────────────────────────────────────────────────────────────────

-- [top-9a] SSRF via dangerous protocol schemes and IP obfuscation.
-- Source: uusec universal-attack.lua (protocol list + IP obfuscation patterns).
-- Notes:
--   * Only flag schemes that are never legitimate in form parameter values.
--     http:// and https:// are intentionally excluded (redirect/callback params).
--   * IP obfuscation checks are narrow to avoid FP: octal, hex, and decimal
--     longform IPs inside :// scheme context only.
local function detect_ssrf_proto(args, body)
  local s = normalize(cap((args or "") .. "&" .. (body or ""), CFG.max_scan_len))
  if s == "" then return nil end

  if has(s, "file://")   then return "SSRF_FILE" end
  if has(s, "gopher://") then return "SSRF_GOPHER" end
  if has(s, "dict://")   then return "SSRF_DICT" end
  if has(s, "ldap://")   then return "SSRF_LDAP" end
  if has(s, "ldaps://")  then return "SSRF_LDAPS" end
  if has(s, "tftp://")   then return "SSRF_TFTP" end
  -- sftp:// and ftp:// in param values are suspicious but occur in some
  -- legitimate file-picker integrations; tag them differently for easier triage
  if has(s, "sftp://")   then return "SSRF_SFTP" end
  if has(s, "ftp://")    then return "SSRF_FTP" end

  -- Octal IPv4 notation: 0177.0.0.1 = 127.0.0.1
  -- Restrict to URL-host context (://) to avoid ad/tracking token false positives.
  if s:match("://0[0-7]+%.0[0-7]+%.0[0-7]+%.0[0-7]+") then
    return "SSRF_OCTAL_IP"
  end
  -- Hex IPv4: 0x7f000001
  if s:match("://0x[0-9a-f][0-9a-f][0-9a-f][0-9a-f][0-9a-f][0-9a-f][0-9a-f][0-9a-f]%f[^0-9a-f]") then
    return "SSRF_HEX_IP"
  end
  -- Decimal longform IP inside a URL: ://2130706433 (= 127.0.0.1)
  if s:match("://[0-9][0-9][0-9][0-9][0-9][0-9][0-9][0-9][0-9][0-9]%f[^0-9]") then
    return "SSRF_DWORD_IP"
  end

  return nil
end

-- [top-9b] JavaScript prototype pollution.
-- Source: uusec universal-attack.lua.
-- __proto__ and constructor.prototype in JSON bodies or args are the two
-- canonical pollution vectors in Node.js/JS backend frameworks.
local function detect_js_proto(args, body)
  local s = normalize(cap((args or "") .. "&" .. (body or ""), CFG.max_scan_len))
  if s == "" then return nil end

  if has(s, "__proto__") then return "JS_PROTO_PROTO" end
  if has(s, "constructor") and (has(s, ".prototype") or has(s, "[prototype")) then
    return "JS_PROTO_CONSTRUCTOR"
  end

  return nil
end

-- ─────────────────────────────────────────────────────────────────────────────
-- RESEARCH ADDITIONS – BODY CHECKS
-- ─────────────────────────────────────────────────────────────────────────────

-- [top-10a] XXE – XML External Entity injection.
-- Source: uusec xxe-attack.lua.
-- Only scans XML / form-encoded / text bodies.  Checks for SYSTEM or PUBLIC
-- entity declarations which are the canonical XXE primitives.
local function detect_xxe(body, headers)
  if not body or body == "" then return nil end

  headers = headers or {}
  local ct = lower(headers["content-type"] or headers["Content-Type"] or "")

  -- Skip clearly non-XML binary / JSON bodies to limit false positives
  if ct ~= ""
     and not has(ct, "xml")
     and not has(ct, "text/")
     and not has(ct, "application/x-www-form-urlencoded") then
    return nil
  end

  local bl = lower(cap(body, CFG.max_scan_len))

  if (has(bl, "<!doctype") or has(bl, "<!entity")) and has(bl, "system") then
    return "XXE_SYSTEM"
  end
  if has(bl, "<!entity") and has(bl, "public") then
    return "XXE_PUBLIC"
  end

  return nil
end

-- [top-10b] CRLF / HTTP response-splitting injection.
-- Source: uusec http-response-splitting.lua.
-- Checks for CR or LF followed by a header name in args and body.
-- Also checks for URL-encoded %0d%0a sequences.
local function detect_crlf_injection(args, body)
  local s = cap((args or "") .. "&" .. (body or ""), CFG.max_scan_len)
  if s == "" then return nil end

  -- Raw CR/LF followed by a header keyword
  if s:find("[\r\n]%W*content%-type%s*:",   1) then return "CRLF_CONTENT_TYPE" end
  if s:find("[\r\n]%W*content%-length%s*:", 1) then return "CRLF_CONTENT_LENGTH" end
  if s:find("[\r\n]%W*set%-cookie%s*:",     1) then return "CRLF_SET_COOKIE" end
  if s:find("[\r\n]%W*location%s*:",        1) then return "CRLF_LOCATION" end

  -- URL-encoded CRLF sequences
  local sl = lower(s)
  if has(sl, "%0d%0a") or has(sl, "%0a") then
    local decoded = sl
      :gsub("%%0d%%0a", "\r\n")
      :gsub("%%0d",     "\r")
      :gsub("%%0a",     "\n")
    if decoded:find("[\r\n]%W*content%-type%s*:")   or
       decoded:find("[\r\n]%W*set%-cookie%s*:")     or
       decoded:find("[\r\n]%W*location%s*:")        then
      return "CRLF_URL_ENCODED"
    end
  end

  return nil
end

-- [top-10c] HTTP request smuggling – verb embedded in args / body.
-- Source: uusec http-request-smuggling.lua.
-- Attackers embed a second HTTP request line inside a parameter value to inject
-- a request past a frontend proxy.  Matches: VERB<space>PATH<space>HTTP/N
local function detect_http_smuggling(args, body)
  local function smug_check(s)
    if not s or s == "" then return nil end
    -- Use plain string find for speed first, then confirm with pattern
    if not (has(s, " http/") or has(s, "%20http/") or has(s, "+http/")) then
      return nil
    end
    local sl = lower(s)
    local verb = sl:match(
      "(get|post|head|put|delete|options|patch|connect|trace|track|"
      .. "propfind|proppatch|mkcol|copy|move|lock|unlock)"
      .. "%s+[^%s]+%s+http/%d"
    )
    if verb then return "SMUG_" .. string.upper(verb) end
    return nil
  end

  local t = smug_check(args)
  if t then return t end
  t = smug_check(body)
  if t then return t end
  return nil
end

-- ─────────────────────────────────────────────────────────────────────────────
-- RESEARCH ADDITIONS – UPLOAD CHECKS (multipart body)
-- ─────────────────────────────────────────────────────────────────────────────

-- [top-4a] Webshell extension in multipart upload filename.
-- Source: uusec upload-file-name-filtering.lua (extended).
-- Key shared-hosting additions: user.ini (per-dir PHP config override),
-- php.ini, .htaccess, .env – all can reconfigure execution without needing
-- a direct .php upload.
-- Checks quoted, single-quoted, and unquoted Content-Disposition filenames.
local function detect_upload_filename(body, headers)
  if not body or body == "" then return nil end

  headers = headers or {}
  local ct = lower(headers["content-type"] or headers["Content-Type"] or "")
  if not has(ct, "multipart/form-data") then return nil end

  local function bad_fname(fname)
    fname = lower(fname or "")
    -- HTML entity decode (basic)
    fname = fname:gsub("&#(%d+);", function(n)
      local c = tonumber(n)
      if c and c < 128 then return string.char(c) end
      return ""
    end)

    -- Special full-name matches (shared hosting critical paths)
    if has(fname, "user.ini")   then return "user.ini" end
    if has(fname, "php.ini")    then return "php.ini" end
    if has(fname, ".htaccess")  then return ".htaccess" end
    if has(fname, ".htpasswd")  then return ".htpasswd" end
    if has(fname, ".env")       then return ".env" end
    if has(fname, "web.config") then return "web.config" end

    -- Extension checks: match anywhere in filename to catch double-extensions
    if fname:match("%.php[%d]?[^%w]") or fname:match("%.php[%d]?$") then return "php" end
    if fname:match("%.phtml")   then return "phtml" end
    if fname:match("%.phar")    then return "phar" end
    if fname:match("%.asp[x]?") then return "asp" end
    if fname:match("%.asa[x]?") then return "asa" end
    if fname:match("%.asmx")    then return "asmx" end
    if fname:match("%.ascx")    then return "ascx" end
    if fname:match("%.jsp[x]?") then return "jsp" end
    if fname:match("%.cer[^t]") or fname:match("%.cer$") then return "cer" end
    if fname:match("%.cdx")     then return "cdx" end
    if fname:match("%.war$")    then return "war" end
    if fname:match("%.class$")  then return "class" end
    if fname:match("%.exe$")    then return "exe" end
    if fname:match("%.sh$")     then return "sh" end
    if fname:match("%.cgi$")    then return "cgi" end
    if fname:match("%.pl$")     then return "pl" end

    return nil
  end

  -- Match double-quoted, single-quoted, and unquoted filename= values
  for fname in body:gmatch('[Ff]ilename%s*=%s*"([^"]+)"') do
    local hit = bad_fname(fname)
    if hit then return "UPLOAD_FNAME:" .. hit .. ":" .. fname:sub(1, 64) end
  end
  for fname in body:gmatch("[Ff]ilename%s*=%s*'([^']+)'") do
    local hit = bad_fname(fname)
    if hit then return "UPLOAD_FNAME:" .. hit .. ":" .. fname:sub(1, 64) end
  end
  for fname in body:gmatch("[Ff]ilename%s*=%s*([^%s;\"'][^%s;\"']*)") do
    local hit = bad_fname(fname)
    if hit then return "UPLOAD_FNAME:" .. hit .. ":" .. fname:sub(1, 64) end
  end

  return nil
end

-- [top-4b] Webshell / malicious content in uploaded file bytes.
-- Sources: uusec upload-file-content-filtering.lua + imagemagick-vulnerability.lua.
-- Scans the raw multipart body for PHP tags, JSP tags, and ImageMagick MVG
-- injection patterns.  Only fires on multipart/form-data.
-- Note: detect_php_webshell_body already covers direct PHP POSTs; this rule
-- adds coverage for files disguised with a different Content-Type / extension.
local function detect_upload_content(body, headers)
  if not body or body == "" then return nil end

  headers = headers or {}
  local ct = lower(headers["content-type"] or headers["Content-Type"] or "")
  if not has(ct, "multipart/form-data") then return nil end

  local b = lower(cap(body, CFG.max_scan_len))

  if has(b, "<?php") or has(b, "<?=") then return "UPLOAD_PHP_TAG" end
  if has(b, "<jsp:")                   then return "UPLOAD_JSP_TAG" end

  -- PHP superglobals inside file content = almost certainly a webshell
  if has(b, "$_get")    or has(b, "$_post")   or has(b, "$_request")
     or has(b, "$_files") or has(b, "$_server") or has(b, "$_cookie") then
    return "UPLOAD_PHP_SUPERGLOBAL"
  end

  -- ImageMagick MVG / SVG command injection (ImageTragick)
  if has(b, "push graphic-context") then return "UPLOAD_IMAGEMAGICK_MVG" end
  if b:find("<image%s") and has(b, "url%(") then return "UPLOAD_IMAGEMAGICK_URL" end

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

  -- ── 1) Bad User-Agent (scored) ──────────────────────────────────────────
  do
    local mode = rule_mode(CFG.rule_bad_ua, "logonly")
    if mode ~= "disabled" then
      local score, tag = detect_bad_ua_scored(headers, uri, method)
      local threshold = tonumber(CFG.bad_ua_min_score) or 4
      if score >= threshold then
        local ttl = (mode == "block") and CFG.block_ttl_sec or CFG.default_ttl_sec
        return true, "WAF_BAD_UA:" .. tag .. ":score=" .. score, ttl, mode
      end
    end
  end

  -- ── 2) Header vulnerabilities (httpoxy / CVE-2017-7269 / CVE-2025-24813) ─
  do
    local mode = rule_mode(CFG.rule_header_vulns, "logonly")
    if mode ~= "disabled" then
      local tag = detect_header_vulns(headers, uri, method)
      if tag then
        local ttl = (mode == "block") and CFG.block_ttl_sec or CFG.default_ttl_sec
        return true, "WAF_HEADER_VULN:" .. tag, ttl, mode
      end
    end
  end

  -- ── 3) Proxy header SQLi / injection ─────────────────────────────────────
  do
    local mode = rule_mode(CFG.rule_proxy_header_sqli, "logonly")
    if mode ~= "disabled" then
      local tag = detect_proxy_header_sqli(headers)
      if tag then
        local ttl = (mode == "block") and CFG.block_ttl_sec or CFG.default_ttl_sec
        return true, "WAF_PROXY_HDR:" .. tag, ttl, mode
      end
    end
  end

  -- ── 4) Content-Type anomaly (charset bypass / malformed boundary) ─────────
  do
    local mode = rule_mode(CFG.rule_content_type_anomaly, "logonly")
    if mode ~= "disabled" then
      local tag = detect_content_type_anomaly(headers)
      if tag then
        local ttl = (mode == "block") and CFG.block_ttl_sec or CFG.default_ttl_sec
        return true, "WAF_CT_ANOMALY:" .. tag, ttl, mode
      end
    end
  end

  -- ── 5) Traversal ──────────────────────────────────────────────────────────
  do
    local mode = rule_mode(CFG.rule_traversal, "block")
    if mode ~= "disabled" and detect_traversal(uri, args) then
      local ttl = (mode == "block") and CFG.block_ttl_sec or CFG.default_ttl_sec
      ttl, mode = mode_ttl_action(mode, ttl)
      return true, "WAF_TRAVERSAL", ttl, mode
    end
  end

  -- ── 6) RCE ────────────────────────────────────────────────────────────────
  do
    local mode = rule_mode(CFG.rule_rce, "block")
    if mode ~= "disabled" and detect_rce(uri, args) then
      local ttl = (mode == "block") and CFG.block_ttl_sec or CFG.default_ttl_sec
      ttl, mode = mode_ttl_action(mode, ttl)
      return true, "WAF_RCE", ttl, mode
    end
  end

  -- ── 7) Shellshock (CVE-2014-6271) ────────────────────────────────────────
  do
    local mode = rule_mode(CFG.rule_shellshock, "logonly")
    if mode ~= "disabled" then
      local tag = detect_shellshock(headers, uri)
      if tag then
        local ttl = (mode == "block") and CFG.block_ttl_sec or CFG.default_ttl_sec
        return true, "WAF_SHELLSHOCK:" .. tag, ttl, mode
      end
    end
  end

  -- ── 8) Exploit methods ────────────────────────────────────────────────────
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

  -- ── 9) PHP wrappers ───────────────────────────────────────────────────────
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

  -- ── 10) PHP double-extension in URI ──────────────────────────────────────
  do
    local mode = rule_mode(CFG.rule_php_double_ext, "logonly")
    if mode ~= "disabled" then
      local tag = detect_php_double_ext(uri)
      if tag then
        local ttl = (mode == "block") and CFG.block_ttl_sec or CFG.default_ttl_sec
        return true, "WAF_PHP_DOUBLE_EXT:" .. tag, ttl, mode
      end
    end
  end

  -- ── 11) Bare IP Host ──────────────────────────────────────────────────────
  do
    local mode = rule_mode(CFG.rule_ip_host, "logonly")
    if mode ~= "disabled" and detect_ip_host(headers["Host"] or headers["host"] or "") then
      local ttl = (mode == "block") and CFG.block_ttl_sec or CFG.default_ttl_sec
      return true, "WAF_IP_HOST", ttl, mode
    end
  end

  -- ── 12) Control chars ─────────────────────────────────────────────────────
  do
    local mode = rule_mode(CFG.rule_ctrl_chars, "logonly")
    if mode ~= "disabled" and detect_ctrl_chars(args, body, headers, uri) then
      local ttl = (mode == "block") and CFG.block_ttl_sec or CFG.default_ttl_sec
      return true, "WAF_CTRL_CHARS", ttl, mode
    end
  end

  -- ── 13) SSRF protocol schemes + IP obfuscation ───────────────────────────
  do
    local mode = rule_mode(CFG.rule_ssrf, "logonly")
    if mode ~= "disabled" then
      local tag = detect_ssrf_proto(args, body)
      if tag then
        local ttl = (mode == "block") and CFG.block_ttl_sec or CFG.default_ttl_sec
        return true, "WAF_SSRF:" .. tag, ttl, mode
      end
    end
  end

  -- ── 14) JS prototype pollution ────────────────────────────────────────────
  do
    local mode = rule_mode(CFG.rule_js_proto, "logonly")
    if mode ~= "disabled" then
      local tag = detect_js_proto(args, body)
      if tag then
        local ttl = (mode == "block") and CFG.block_ttl_sec or CFG.default_ttl_sec
        return true, "WAF_JS_PROTO:" .. tag, ttl, mode
      end
    end
  end

  -- ── 15) Raw PHP webshell body (scored) ───────────────────────────────────
  do
    local mode = rule_mode(CFG.rule_php_webshell_body, "logonly")
    if mode ~= "disabled" and lower(method) == "post" and body ~= "" then
      local tag = detect_php_webshell_body(body, headers)
      if tag then
        local ttl = (mode == "block") and CFG.block_ttl_sec or CFG.default_ttl_sec
        return true, "WAF_PHP_WEBSHELL_BODY:" .. tag, ttl, mode
      end
    end
  end

  -- ── 16) Upload filename extension blacklist ───────────────────────────────
  do
    local mode = rule_mode(CFG.rule_upload_filename, "logonly")
    if mode ~= "disabled" and lower(method) == "post" and body ~= "" then
      local tag = detect_upload_filename(body, headers)
      if tag then
        local ttl = (mode == "block") and CFG.block_ttl_sec or CFG.default_ttl_sec
        return true, "WAF_UPLOAD_FNAME:" .. tag, ttl, mode
      end
    end
  end

  -- ── 17) Upload content / webshell byte scan ───────────────────────────────
  do
    local mode = rule_mode(CFG.rule_upload_content, "logonly")
    if mode ~= "disabled" and lower(method) == "post" and body ~= "" then
      local tag = detect_upload_content(body, headers)
      if tag then
        local ttl = (mode == "block") and CFG.block_ttl_sec or CFG.default_ttl_sec
        return true, "WAF_UPLOAD_CONTENT:" .. tag, ttl, mode
      end
    end
  end

  -- ── 18) XSS ───────────────────────────────────────────────────────────────
  do
    local mode = rule_mode(CFG.rule_xss, "challenge")
    if mode ~= "disabled" and detect_xss(uri, args) then
      local ttl = (mode == "block") and CFG.block_ttl_sec or CFG.default_ttl_sec
      return true, "WAF_XSS", ttl, mode
    end
  end

  -- ── 19) SQLi (+ SQL comment bypass) ──────────────────────────────────────
  do
    local mode = rule_mode(CFG.rule_sqli, "challenge")
    if mode ~= "disabled" and detect_sqli(uri, args) then
      local ttl = (mode == "block") and CFG.block_ttl_sec or CFG.default_ttl_sec
      return true, "WAF_SQLI", ttl, mode
    end
  end

  -- ── 20) XXE ───────────────────────────────────────────────────────────────
  do
    local mode = rule_mode(CFG.rule_xxe, "logonly")
    if mode ~= "disabled" and lower(method) == "post" and body ~= "" then
      local tag = detect_xxe(body, headers)
      if tag then
        local ttl = (mode == "block") and CFG.block_ttl_sec or CFG.default_ttl_sec
        return true, "WAF_XXE:" .. tag, ttl, mode
      end
    end
  end

  -- ── 21) CRLF / HTTP response splitting ───────────────────────────────────
  do
    local mode = rule_mode(CFG.rule_crlf_injection, "logonly")
    if mode ~= "disabled" then
      local tag = detect_crlf_injection(args, body)
      if tag then
        local ttl = (mode == "block") and CFG.block_ttl_sec or CFG.default_ttl_sec
        return true, "WAF_CRLF:" .. tag, ttl, mode
      end
    end
  end

  -- ── 22) HTTP request smuggling ────────────────────────────────────────────
  do
    local mode = rule_mode(CFG.rule_http_smuggling, "logonly")
    if mode ~= "disabled" then
      local tag = detect_http_smuggling(args, body)
      if tag then
        local ttl = (mode == "block") and CFG.block_ttl_sec or CFG.default_ttl_sec
        return true, "WAF_HTTP_SMUGGLING:" .. tag, ttl, mode
      end
    end
  end

  -- ── 23) WP-specific auth checks ──────────────────────────────────────────
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

  -- ── 24) XML-RPC strong body signatures ───────────────────────────────────
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

  -- ── 25) Generic XML-RPC POST burst ───────────────────────────────────────
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

  -- ── 26) Generic auth endpoint burst ──────────────────────────────────────
  do
    local mode = rule_mode(CFG.rule_auth_burst, "challenge")
    if mode ~= "disabled" then
      local peer = ctx.peer or ""

      if not (peer ~= "" and ip ~= "" and ip == peer) then
        local tag = detect_auth_burst(ip, uri, method, shdict)
        if tag then
          local ttl = CFG.auth_ttl_sec or CFG.default_ttl_sec
          return true, "WAF_AUTH_BURST:" .. tag, ttl, mode
        end
      end
    end
  end

  -- ── 27) Suspicious command parameter keys ─────────────────────────────────
  do
    local mode = rule_mode(CFG.rule_cmd_params, "logonly")
    if mode ~= "disabled" then
      local tag = detect_cmd_param_key(args)
      if tag then
        return true, "WAF_CMD_PARAM:" .. tag, CFG.default_ttl_sec, mode
      end
    end
  end

  -- ── 28) Suspicious payload markers ───────────────────────────────────────
  do
    local tag = detect_cmd_payload(args)
    if tag then
      local mode = cmd_payload_mode(tag)
      if mode ~= "disabled" then
        local ttl = (mode == "block") and CFG.block_ttl_sec or CFG.default_ttl_sec
        return true, "WAF_CMD_PAYLOAD:" .. tag, ttl, mode
      end
    end
  end

  -- ── 29) Debug toggles ─────────────────────────────────────────────────────
  do
    local mode = rule_mode(CFG.rule_debug_toggles, "logonly")
    if mode ~= "disabled" then
      local tag = detect_debug_toggles(args)
      if tag then
        return true, "WAF_DEBUG_TOGGLE:" .. tag, CFG.default_ttl_sec, mode
      end
    end
  end

  -- ── 30) PHP serialize markers ─────────────────────────────────────────────
  do
    local mode = rule_mode(CFG.rule_serialize, "logonly")
    if mode ~= "disabled" then
      local tag = detect_php_serialize(args)
      if tag then
        return true, "WAF_SERIALIZE:" .. tag, CFG.default_ttl_sec, mode
      end
    end
  end

  -- ── 31) Base64 POST body scanner ──────────────────────────────────────────
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

function _M.should_push(shdict, ip, reason)
  if not shdict or not ip or ip == "" then return true end
  local k  = "wafpush|" .. (reason or "WAF") .. "|" .. ip
  local ok = shdict:add(k, 1, CFG.push_cooldown_sec)
  return ok == true
end

return _M

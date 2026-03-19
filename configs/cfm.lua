-- /usr/local/openresty/nginx/lua/cfm.lua
--
-- CFM OpenResty in-path enforcement
-- Optimized with Keepalive and Chunked Transfer Encoding support.
--
-- Fixes applied vs previous version:
--   [1] logonly WAF action now returns early — no longer falls through to bridge decision
--   [2] URI re-added to cache key (capped at 64 chars) — prevents allow-cache bypass on sensitive paths
--   [3] observe_waf reuses the keepalive pool via http_post_unix (no more rogue Connection: close)
--   [4] WAF caller now passes headers and a narrow request body (XML-RPC POST only)
--   [5] waf_should_read_body: added /wp-json/, /_ignition/, /cgi-bin/, timthumb.php,
--       upload+PHP URI combos, /wp-signup.php, /wp-activate.php; removed /export /restore /backup
--   [6] get_req_body_for_waf: ngx.ctx.waf_body caching — read_body() called at most once per request
--   [7] Step 0a: local-origin hard bypass — loopback/private TCP peer skips all challenge logic
--       (covers wp-cron, Joomla cron, any internal PHP HTTP call on shared hosting)
--   [8] POST resume: challenged POST bodies are stashed in shared dict and replayed after solve
--       (covers form submits, WP admin saves, JSON API calls — not multipart/file uploads)

local cjson = require "cjson.safe"


-- ─────────────────────────────────────────────────────────────────────────────
-- CONFIG
-- ─────────────────────────────────────────────────────────────────────────────
local CFG = {
  sock_path = "/var/run/cfm/cfm_nginx.sock",

  token        = "cfm",
  token_header = "X-CFM-Token",

  decision_timeout_ms   = 80,
  decision_cache_ttl_ms = 9000,
  waf_excl_cache_ttl_ms = tonumber(os.getenv("CFM_WAF_EXCL_CACHE_TTL_MS") or "5000"),
  waf_excl_meta_ttl_sec = tonumber(os.getenv("CFM_WAF_EXCL_META_TTL_SEC") or "15"),
  waf_excl_refresh_sec  = tonumber(os.getenv("CFM_WAF_EXCL_REFRESH_SEC") or "10"),

  block_code = 403,
  fail_open  = true,

  -- Debugging (set env vars in systemd/env if needed)
  debug         = (os.getenv("CFM_DEBUG") == "1"),
  debug_headers = (os.getenv("CFM_DEBUG_HEADERS") == "1"),
  log_allows    = (os.getenv("CFM_LOG_ALLOWS") == "1"),

  -- Sliding OK TTL (cookie + bridge okState)
  ok_ttl_sec         = tonumber(os.getenv("CFM_OK_TTL_SEC")         or "1800"),
  ok_touch_every_sec = tonumber(os.getenv("CFM_OK_TOUCH_EVERY_SEC") or "120"),

  -- Keepalive pool (per nginx worker)
  keepalive_idle_ms = tonumber(os.getenv("CFM_BRIDGE_KA_IDLE_MS") or "15000"),
  keepalive_pool    = tonumber(os.getenv("CFM_BRIDGE_KA_POOL")    or "128"),

  -- Narrow body read for inline WAF (only where needed)
  waf_body_max_len = tonumber(os.getenv("CFM_WAF_BODY_MAX_LEN") or "4096"),

  -- POST resume: stash challenged POST bodies so they can be replayed after solve.
  -- Enabled by default. Only covers allowlisted content types (form, JSON, text).
  -- Multipart / file uploads are intentionally excluded (size + complexity).
  -- Env overrides:
  --   CFM_POST_RESUME_ENABLE  = 0    disable entirely
  --   CFM_POST_RESUME_MAX_LEN = N    max body bytes to stash (default 64KB)
  --   CFM_POST_RESUME_TTL_SEC = N    seconds stash entry lives (default 90)
  post_resume_enable  = (os.getenv("CFM_POST_RESUME_ENABLE") or "1") == "1",
  post_resume_max_len = tonumber(os.getenv("CFM_POST_RESUME_MAX_LEN") or "65536"),
  post_resume_ttl_sec = tonumber(os.getenv("CFM_POST_RESUME_TTL_SEC") or "90"),
}


-- cfm_clamav is optional: if the file is missing cfm continues normally
local clamav_ok, clamav = pcall(require, "cfm_clamav")
if clamav_ok then clamav.init({ token = CFG.token, sock_path = CFG.sock_path  }) end


-- Shared dict used for both bridge decision cache (d|...) and POST resume stash (pr|...).
local SH = ngx.shared.cfm_decisions

-- ─────────────────────────────────────────────────────────────────────────────
-- UTILS
-- ─────────────────────────────────────────────────────────────────────────────

local function log_route(level, msg)
  ngx.log(level or ngx.WARN, "[cfm] ", msg)
end

-- URI-encode a value for use in query strings or redirect targets.
local function esc(s) return ngx.escape_uri(s or "") end

-- Append a key=value query arg to a URL, using ? or & as appropriate.
local function with_query_arg(u, k, v)
  u = tostring(u or "/")
  local sep = u:find("?", 1, true) and "&" or "?"
  return u .. sep .. tostring(k or "") .. "=" .. esc(v or "")
end

-- Safely append a Set-Cookie header without clobbering existing values.
-- nginx allows multiple Set-Cookie headers; this accumulates them correctly.
local function append_set_cookie(v)
  local h = ngx.header["Set-Cookie"]
  if not h then ngx.header["Set-Cookie"] = v; return end
  if type(h) == "table" then table.insert(h, v); ngx.header["Set-Cookie"] = h; return end
  ngx.header["Set-Cookie"] = { h, v }
end

-- Resolve the real visitor IP, preferring the already-set $remote_addr (which
-- the real_ip module has already resolved from CF-Connecting-IP), then falling
-- back to the CF header directly if $remote_addr is somehow empty.
local function real_ip()
  local rip = ngx.var.remote_addr
  if rip and rip ~= "" then return rip end
  local cf = ngx.var.http_cf_connecting_ip
  if cf and cf ~= "" then return cf end
  return "-"
end

local function lower(s)
  if not s then return "" end
  return string.lower(s)
end

-- Plain substring search (no pattern magic). Used throughout for path matching.
local function has(s, pat)
  if not s or s == "" then return false end
  return string.find(s, pat, 1, true) ~= nil
end

-- ─────────────────────────────────────────────────────────────────────────────
-- WAF BODY INSPECTION
-- ─────────────────────────────────────────────────────────────────────────────

-- Decide whether a POST destination is risky enough to justify reading the body
-- for inline WAF inspection. Goals:
--   1) cover common CMS/admin/plugin/theme exploit paths
--   2) stay generic across apps
--   3) avoid needing endless one-off endpoint additions
-- Only POST is ever inspected; GET/HEAD bodies are ignored.
local function waf_should_read_body(uri, method)
  uri    = lower(uri    or "")
  method = lower(method or "")

  if method ~= "post" then return false end

  -- Root-level high-risk filenames / endpoints
  if has(uri, "/xmlrpc.php")      then return true end
  if has(uri, "/wp-login.php")    then return true end
  if has(uri, "/wp-signup.php")   then return true end
  if has(uri, "/wp-activate.php") then return true end
  if has(uri, "/admin-ajax.php")  then return true end
  if has(uri, "/ajax")            then return true end
  if has(uri, "/api/")            then return true end
  if has(uri, "/graphql")         then return true end
  if has(uri, "/rest/")           then return true end

  -- WordPress REST API (primary REST attack surface)
  if has(uri, "/wp-json/") then return true end

  -- WordPress / WooCommerce
  if has(uri, "/wp-admin/")             then return true end
  if has(uri, "/wp-content/plugins/")   then return true end
  if has(uri, "/wp-content/themes/")    then return true end
  if has(uri, "/wp-content/uploads/")   then return true end
  if has(uri, "/wp-includes/")          then return true end
  if has(uri, "/wc-api/")               then return true end
  if has(uri, "/wc-ajax=")              then return true end
  if has(uri, "wc-ajax=")               then return true end

  -- Joomla
  if has(uri, "/administrator/") then return true end
  if has(uri, "/components/")    then return true end
  if has(uri, "/modules/")       then return true end
  if has(uri, "/plugins/")       then return true end
  if has(uri, "/templates/")     then return true end
  if has(uri, "/media/")         then return true end

  -- Drupal
  if has(uri, "/user/login")     then return true end
  if has(uri, "/admin/")         then return true end
  if has(uri, "/sites/default/") then return true end
  if has(uri, "/modules/")       then return true end
  if has(uri, "/themes/")        then return true end

  -- PrestaShop
  if has(uri, "/admin")          then return true end
  if has(uri, "/modules/")       then return true end
  if has(uri, "/themes/")        then return true end
  if has(uri, "/upload/")        then return true end
  if has(uri, "/filemanager/")   then return true end
  if has(uri, "/ajax-tab.php")   then return true end
  if has(uri, "/webservice/")    then return true end

  -- OpenCart
  if has(uri, "/admin/")           then return true end
  if has(uri, "/catalog/")         then return true end
  if has(uri, "/system/")          then return true end
  if has(uri, "/extension/")       then return true end
  if has(uri, "/index.php?route=") then return true end

  -- CS-Cart
  if has(uri, "/admin.php")               then return true end
  if has(uri, "/backend/")                then return true end
  if has(uri, "/api/")                    then return true end
  if has(uri, "/addons/")                 then return true end
  if has(uri, "/var/themes_repository/")  then return true end

  -- Generic admin / installer / uploader / importer / tool paths
  if has(uri, "/admin")        then return true end
  if has(uri, "/administrator") then return true end
  if has(uri, "/login")        then return true end
  if has(uri, "/auth")         then return true end
  if has(uri, "/upload")       then return true end
  if has(uri, "/uploads")      then return true end
  if has(uri, "/import")       then return true end
  if has(uri, "/install")      then return true end
  if has(uri, "/installer")    then return true end
  if has(uri, "/setup")        then return true end
  if has(uri, "/update")       then return true end
  if has(uri, "/upgrade")      then return true end
  if has(uri, "/filemanager")  then return true end
  if has(uri, "/connector")    then return true end
  if has(uri, "/shell")        then return true end
  if has(uri, "/cmd")          then return true end

  -- CGI / legacy script paths
  if has(uri, "/cgi-bin/") then return true end

  -- Laravel debug endpoint (CVE-2021-3129 and related Ignition RCE)
  if has(uri, "/_ignition/") then return true end

  -- Classic WordPress TimThumb RCE target
  if has(uri, "timthumb.php") then return true end

  -- PHP/script files uploaded to media directories (shell-in-image vector)
  if uri:match("/upload[s]?/.*%.php") then return true end
  if uri:match("/files/.*%.php")      then return true end

  -- Any PHP/PHTML file POST (broad but necessary for upload detection)
  if uri:match("%.php[%?/].*")   then return true end
  if uri:match("%.phtml[%?/].*") then return true end
  if uri:match("%.php$")         then return true end
  if uri:match("%.phtml$")       then return true end

  return false
end

-- Read the request body for WAF inspection, but only for destinations that
-- justify the cost (see waf_should_read_body above).
-- Result is cached in ngx.ctx.waf_body so read_body() is called at most once
-- per request even if this function is invoked multiple times.
local function get_req_body_for_waf(uri, method, max_len)
  if not waf_should_read_body(uri, method) then return "" end

  -- Return cached result if already read this request.
  if ngx.ctx.waf_body ~= nil then return ngx.ctx.waf_body end

  ngx.req.read_body()

  local data = ngx.req.get_body_data()
  if data and data ~= "" then
    local result = (#data > max_len) and string.sub(data, 1, max_len) or data
    ngx.ctx.waf_body = result
    return result
  end

  -- Body was spooled to disk (large request); read the first max_len bytes.
  local body_file = ngx.req.get_body_file()
  if body_file and body_file ~= "" then
    local f = io.open(body_file, "rb")
    if f then
      local chunk = f:read(max_len) or ""
      f:close()
      ngx.ctx.waf_body = chunk
      return chunk
    end
  end

  ngx.ctx.waf_body = ""
  return ""
end

-- ─────────────────────────────────────────────────────────────────────────────
-- POST RESUME  (stash + replay for challenged POSTs)
-- ─────────────────────────────────────────────────────────────────────────────
-- Problem: when a visitor is challenged mid-POST (e.g. saving a WP post,
-- submitting a forum reply, calling a JSON API), the browser is redirected to
-- the challenge page. After solving, it is redirected back as a GET — the
-- original POST body is gone and the action is silently lost.
--
-- Solution (Lua-side, no Go changes needed):
--   store_post_resume  — called when we are about to challenge a POST:
--     1. Reads and validates the body (size + content-type allowlist).
--     2. Encodes it as base64 and stores it in the shared dict under a random
--        token key "pr|<token>" with a short TTL (default 90s).
--     3. Appends ?cfm_rt=<token> to the ?next= redirect target so the token
--        survives the challenge round-trip in the URL.
--     Returns: token string on success, nil + reason string on skip.
--
--   try_apply_post_resume  — called at the top of every request, before any
--     challenge or cookie check:
--     1. Only acts on GET requests carrying ?cfm_rt=<token>.
--     2. Looks up and immediately deletes the stash entry (single-use).
--     3. Validates that ip + host still match (prevents token theft/replay).
--     4. Reconstructs the original POST in-place via ngx.req.set_method,
--        set_header, set_body_data, and set_uri — the upstream sees a normal
--        POST as if the challenge never happened.
--     5. Sets ngx.ctx.cfm_resumed_post = true so the rest of the pipeline
--        knows this is a replay and can re-run WAF/bridge checks rather than
--        fast-pathing through the solved-cookie shortcut.
--     Returns: true if replay was applied, false otherwise (no-op).
--
-- Limitations:
--   - multipart/form-data (file uploads) are NOT stashed — too large and
--     complex to reconstruct safely. Those users will lose their upload and
--     need to retry after solve.
--   - Bodies larger than post_resume_max_len (default 64KB) are skipped;
--     the request falls through to the normal challenge redirect.
--   - A re-challenged replay (WAF or bridge still fires on the replayed POST)
--     results in a 403 block rather than an infinite loop.

-- Returns true if the Content-Type is safe to stash and replay.
-- Allowlist: form-encoded, JSON, plain text.
-- Excludes multipart (file uploads) and any binary/unknown types.
local function ct_allows_resume(ct)
  ct = lower(ct or "")
  if ct == "" then return false end
  if has(ct, "application/x-www-form-urlencoded") then return true end
  if has(ct, "application/json")                  then return true end
  if has(ct, "text/plain")                         then return true end
  return false
end

-- Build a per-request opaque token for the stash key.
-- Combines nginx request_id (set by nginx), worker PID, and fractional
-- timestamp so collisions across workers and rapid requests are negligible.
-- MD5 output is 32 hex chars — compact enough for a URL query arg.
local function build_resume_token()
  local raw = table.concat({
    ngx.var.request_id or "",
    tostring(ngx.worker.pid()),
    tostring(ngx.now()),
  }, "|")
  return ngx.md5(raw)
end

-- Stash the current POST body in the shared dict for replay after solve.
-- Returns: token (string) on success, nil + reason (string) on skip.
local function store_post_resume(ip, host, uri, method)
  if not CFG.post_resume_enable or not SH then return nil, "disabled" end
  if lower(method or "") ~= "post"         then return nil, "not_post" end

  local ctype = ngx.var.content_type or ""
  if not ct_allows_resume(ctype) then return nil, "ctype_not_allowed" end

  -- Reject empty bodies and bodies over the configured size limit.
  local clen = tonumber(ngx.var.content_length or "0") or 0
  if clen <= 0 or clen > CFG.post_resume_max_len then return nil, "size_limit" end

  ngx.req.read_body()
  local body = ngx.req.get_body_data()
  if not body                              then return nil, "no_body_data" end
  if #body == 0 or #body > CFG.post_resume_max_len then return nil, "body_size" end

  local token = build_resume_token()
  local payload = cjson.encode({
    ip       = ip,
    host     = host,
    uri      = uri,
    method   = "POST",
    ctype    = ctype,
    body_b64 = ngx.encode_base64(body),
    ts       = ngx.time(),
  })
  SH:set("pr|" .. token, payload, CFG.post_resume_ttl_sec)
  return token, nil
end

-- Attempt to replay a previously stashed POST for the current GET request.
-- Called once per request before any challenge/cookie checks.
-- Returns true if a stash entry was found and applied (request is now a POST);
-- returns false for all other cases (normal request flow continues unchanged).
local function try_apply_post_resume(ip, host)
  if not CFG.post_resume_enable or not SH then return false end
  -- Only GET requests carry the ?cfm_rt= token (the browser redirect is a GET).
  if lower(ngx.req.get_method() or "") ~= "get" then return false end

  local args = ngx.req.get_uri_args()
  local tok = args and args["cfm_rt"]
  if type(tok) == "table" then tok = tok[1] end
  tok = tostring(tok or "")
  if tok == "" then return false end

  -- Load and immediately delete (single-use: prevents double-replay).
  local raw = SH:get("pr|" .. tok)
  SH:delete("pr|" .. tok)
  if not raw then return false end

  local obj = cjson.decode(raw)
  if not obj then return false end

  -- Bind check: IP and host must match the original request.
  -- Prevents a different visitor from stealing the token out of a shared URL.
  if tostring(obj.ip   or "") ~= tostring(ip   or "") then return false end
  if tostring(obj.host or "") ~= tostring(host or "") then return false end

  local body = ngx.decode_base64(obj.body_b64 or "")
  if not body or #body == 0 or #body > CFG.post_resume_max_len then return false end

  -- Reconstruct the original POST in-place.
  ngx.req.set_method(ngx.HTTP_POST)
  ngx.req.set_header("Content-Type", obj.ctype or "application/x-www-form-urlencoded")
  ngx.req.set_body_data(body)

  -- Restore original URI (strip cfm_rt from the path nginx sees).
  local target_uri = obj.uri or "/"
  local qidx = target_uri:find("?", 1, true)
  if qidx then
    ngx.req.set_uri(target_uri:sub(1, qidx - 1), false)
    ngx.req.set_uri_args(target_uri:sub(qidx + 1))
  else
    ngx.req.set_uri(target_uri, false)
    ngx.req.set_uri_args(nil)
  end

  -- Flag so downstream steps (WAF, bridge, cookie fast-path) know this is a
  -- replay and must not skip inspection or loop back into another challenge.
  ngx.ctx.cfm_resumed_post = true
  log_route(ngx.INFO, "post_resume_applied ip=" .. tostring(ip) ..
    " host=" .. tostring(host) .. " uri=" .. tostring(target_uri))
  return true
end

-- ─────────────────────────────────────────────────────────────────────────────
-- NETWORK LAYER  (Unix socket, keepalive, chunked transfer)
-- ─────────────────────────────────────────────────────────────────────────────

-- Read a chunked HTTP response body from an already-connected socket.
-- Called by http_unix when the bridge responds with Transfer-Encoding: chunked.
local function read_chunked(sock)
  local out = {}
  while true do
    local line, err = sock:receive("*l")
    if not line then return nil, "chunked size line: " .. (err or "?") end

    local hex = line:match("^%s*([0-9a-fA-F]+)")
    if not hex then return nil, "bad chunk size line: " .. tostring(line) end

    local n = tonumber(hex, 16)
    if not n then return nil, "bad chunk size hex: " .. tostring(hex) end

    if n == 0 then
      -- Terminal chunk: drain optional trailers until blank line.
      while true do
        local tline = sock:receive("*l")
        if not tline or tline == "" then break end
      end
      break
    end

    local data, derr = sock:receive(n)
    if not data then return nil, "chunk read: " .. (derr or "?") end
    table.insert(out, data)
    sock:receive(2) -- trailing CRLF after each chunk
  end
  return table.concat(out), nil
end

-- Low-level HTTP/1.1 request over the cfm unix socket.
-- Uses a per-worker keepalive pool to avoid a connect() syscall on every
-- request (critical for the 80ms decision timeout).
local function http_unix(method, path, body)
  local s, err = ngx.socket.tcp()
  if not s then return nil, "socket.tcp: " .. (err or "unknown") end

  s:settimeouts(CFG.decision_timeout_ms, CFG.decision_timeout_ms, CFG.decision_timeout_ms)

  local ok, cerr = s:connect("unix:" .. CFG.sock_path)
  if not ok then s:close(); return nil, "connect: " .. (cerr or "unknown") end

  body = body or ""
  local req = method .. " " .. path .. " HTTP/1.1\r\n" ..
              "Host: localhost\r\n" ..
              "Connection: keep-alive\r\n"

  if CFG.token and CFG.token ~= "" then
    req = req .. CFG.token_header .. ": " .. CFG.token .. "\r\n"
  end

  if method == "POST" then
    req = req .. "Content-Type: application/json\r\n" ..
                 "Content-Length: " .. tostring(#body) .. "\r\n"
  end

  req = req .. "\r\n" .. body

  local _, werr = s:send(req)
  if werr then s:close(); return nil, "send: " .. (werr or "unknown") end

  local status_line, rerr = s:receive("*l")
  if not status_line then s:close(); return nil, "recv status: " .. (rerr or "unknown") end

  local code = tonumber(status_line:match("%s(%d%d%d)%s"))
  if not code then s:close(); return nil, "bad status line: " .. status_line end

  local content_length
  local is_chunked = false

  while true do
    local line, _ = s:receive("*l")
    if not line or line == "" then break end
    local k, v = line:match("^([^:]+):%s*(.*)$")
    if k and v then
      local kl = k:lower()
      if kl == "content-length" then
        content_length = tonumber(v)
      elseif kl == "transfer-encoding" and v:lower():find("chunked", 1, true) then
        is_chunked = true
      end
    end
  end

  local resp = ""
  if method == "HEAD" or code == 204 or code == 304 then
    resp = ""
  elseif content_length and content_length > 0 then
    resp = s:receive(content_length)
  elseif is_chunked then
    local b, berr = read_chunked(s)
    if not b then s:close(); return nil, berr end
    resp = b
  else
    resp = s:receive("*a") or ""
  end

  local ok_ka = s:setkeepalive(CFG.keepalive_idle_ms, CFG.keepalive_pool)
  if not ok_ka then s:close() end

  if code ~= 200 then
    return nil, "http " .. tostring(code) .. " body=" .. tostring(resp)
  end
  return resp, nil
end

local function http_get_unix(path_qs)  return http_unix("GET",  path_qs, nil) end
local function http_post_unix(path, b) return http_unix("POST", path,    b)   end

-- ─────────────────────────────────────────────────────────────────────────────
-- HELPERS
-- ─────────────────────────────────────────────────────────────────────────────

-- Report an observed WAF outcome to the Go bridge so it can be counted against
-- the IP's error ratio and potentially trigger further action (challenge/block).
-- FIX [3]: reuses the keepalive pool instead of opening a raw socket with
-- Connection: close, which was causing spurious keepalive pool exhaustion.
local function observe_waf(ip, host, uri, method, status, reason)
  if not ip or ip == "" then return end
  local payload = cjson.encode({
    ip     = ip,
    host   = host   or "",
    uri    = uri    or "/",
    method = method or "",
    status = status or 403,
    reason = reason or "",
  })
  http_post_unix("/nginx/observe", payload) -- best-effort; errors ignored
end

-- Extend the Go bridge's okState TTL for a solved IP, rate-limited to at most
-- once per ok_touch_every_sec to avoid hammering the socket on every request.
local function touch_ok(ip)
  if not SH then return end
  local k   = "ok_touch|" .. (ip or "-")
  local now = ngx.now()
  local last = SH:get(k)
  if last and (now - last) < CFG.ok_touch_every_sec then return end
  SH:set(k, now, CFG.ok_touch_every_sec)
  local payload = cjson.encode({ ip = ip, ttl_sec = CFG.ok_ttl_sec })
  http_post_unix("/nginx/ok/touch", payload)
end

-- Slide the cfm_ok cookie TTL forward on every request so an active browser
-- session never expires the cookie mid-use. Only appends; does not replace.
local function refresh_ok_cookie(cookie_val)
  if not cookie_val or cookie_val == "" then return end
  local attrs = "Path=/; Max-Age=" .. tostring(CFG.ok_ttl_sec) .. "; HttpOnly; SameSite=Lax"
  if ngx.var.scheme == "https" then attrs = attrs .. "; Secure" end
  append_set_cookie("cfm_ok=" .. cookie_val .. "; " .. attrs)
end

-- Return a safe allow decision when the bridge is unreachable.
-- fail_open = true (default): pass traffic through so a bridge restart does
--   not take the site down.
-- fail_open = false: block everything until the bridge recovers (high-security).
local function fail_decision(errmsg)
  if CFG.fail_open then
    return { ip_action = "allow", vhost_action = "allow", err = errmsg }
  else
    return { ip_action = "block", vhost_action = "block", err = errmsg }
  end
end

-- Query the Go bridge for a per-IP + per-vhost decision, with a short-lived
-- shared-dict cache for clean allows.
-- FIX [2]: URI is included in the cache key (capped at 64 chars) to prevent
-- a cached allow for "/" from masking a challenge on /wp-admin or /xmlrpc.php
-- within the same 9-second TTL window.
-- Challenges and blocks are never cached — they must always reach the bridge.
local function get_decision(ip, host, uri, method, scheme)
  local uri_part = (uri or "-"):sub(1, 64)
  local key = "d|" .. ip .. "|" .. host .. "|" .. method .. "|" .. scheme .. "|" .. uri_part

  if SH then
    local cached = SH:get(key)
    if cached then
      local obj = cjson.decode(cached)
      if obj then obj._cache = true; return obj end
    end
  end

  local path = "/nginx/decision?ip=" .. esc(ip)   ..
               "&host="   .. esc(host)   ..
               "&uri="    .. esc(uri)    ..
               "&method=" .. esc(method) ..
               "&scheme=" .. esc(scheme)

  local body, err = http_get_unix(path)
  if not body then return fail_decision(err) end

  local obj = cjson.decode(body)
  if not obj then return fail_decision("decode_failed") end

  if SH and obj.ip_action == "allow" and obj.vhost_action == "allow" then
    SH:set(key, body, CFG.decision_cache_ttl_ms / 1000)
  end
  return obj
end

-- Refresh dynamic WAF exclude snapshot from bridge into shared dict.
-- Snapshot keys:
--   wxhosts -> JSON array of host patterns
--   wxpaths -> JSON array of path patterns
--   wxsnap_ts -> last refresh epoch seconds
local function refresh_waf_excludes_if_needed()
  if not SH then return end

  local now = ngx.now()
  local last = tonumber(SH:get("wxsnap_ts") or "0") or 0
  if (now - last) < CFG.waf_excl_refresh_sec then
    return
  end

  -- single-worker refresher lock for a short time
  if not SH:add("wxsnap_lock", "1", 1) then
    return
  end

  local body, err = http_get_unix("/nginx/waf/excludes")
  if not body then
    if CFG.debug then
      log_route(ngx.INFO, "waf_excludes_snapshot_fail err=" .. tostring(err))
    end
    SH:set("wxsnap_ts", now, math.max(1, CFG.waf_excl_refresh_sec))
    SH:delete("wxsnap_lock")
    return
  end

  local obj = cjson.decode(body) or {}
  local entries = obj.entries or {}
  local hosts, paths = {}, {}
  for _, e in ipairs(entries) do
    local t = lower(e.type or "")
    local v = lower(tostring(e.value or ""))
    if v ~= "" then
      if t == "host" then
        hosts[#hosts+1] = v
      elseif t == "path" then
        paths[#paths+1] = v
      end
    end
  end

  SH:set("wxhosts", cjson.encode(hosts), math.max(1, CFG.waf_excl_meta_ttl_sec))
  SH:set("wxpaths", cjson.encode(paths), math.max(1, CFG.waf_excl_meta_ttl_sec))
  SH:set("wxsnap_ts", now, math.max(1, CFG.waf_excl_refresh_sec))
  SH:delete("wxsnap_lock")
end

local wx_local_ts = 0
local wx_local_hosts = {}
local wx_local_paths = {}

local function glob_to_lua_pattern(glob)
  local p = tostring(glob or "")
  -- Escape Lua magic chars first, including glob wildcards.
  p = p:gsub("([%^%$%(%)%%%.%[%]%+%-%*%?])", "%%%1")
  p = p:gsub("%%%*", ".*")
  p = p:gsub("%%%?", ".")
  return "^" .. p .. "$"
end

local function matches_rule(value, rule)
  value = lower(tostring(value or ""))
  rule  = lower(tostring(rule or ""))
  if value == "" or rule == "" then return false end

  if rule:find("*", 1, true) or rule:find("?", 1, true) then
    local ok, res = pcall(function()
      return value:match(glob_to_lua_pattern(rule)) ~= nil
    end)
    return ok and res or false
  end
  return value:find(rule, 1, true) ~= nil
end

local function load_waf_excludes_local_cache()
  if not SH then
    wx_local_ts = 0
    wx_local_hosts = {}
    wx_local_paths = {}
    return
  end
  local ts = tonumber(SH:get("wxsnap_ts") or "0") or 0
  if ts == wx_local_ts then
    return
  end
  wx_local_ts = ts

  local hosts_raw = SH:get("wxhosts") or "[]"
  local paths_raw = SH:get("wxpaths") or "[]"
  wx_local_hosts = cjson.decode(hosts_raw) or {}
  wx_local_paths = cjson.decode(paths_raw) or {}
end

-- Query dynamic WAF excludes from shared snapshot and check host+uri.
local function waf_is_excluded(host, uri)
  refresh_waf_excludes_if_needed()
  load_waf_excludes_local_cache()

  host = lower(host or "")
  uri  = lower(tostring(uri or "/"))

  for _, r in ipairs(wx_local_hosts) do
    if matches_rule(host, r) then return true end
  end
  for _, r in ipairs(wx_local_paths) do
    if matches_rule(uri, r) then return true end
  end
  return false
end

-- ─────────────────────────────────────────────────────────────────────────────
-- MAIN ENFORCEMENT
-- Request variables captured once here; method and uri are re-read after
-- try_apply_post_resume may have mutated them.
-- ─────────────────────────────────────────────────────────────────────────────

local ip      = real_ip()
local peer_ip = ngx.var.realip_remote_addr or ""   -- raw TCP peer (before real_ip override)
local cf_ip   = ngx.var.http_cf_connecting_ip or "" -- Cloudflare edge IP if present
local host    = ngx.var.host   or "-"
local uri     = ngx.var.uri    or "-"
local method  = ngx.req.get_method() or "-"
local scheme  = ngx.var.scheme or "http"

-- Build the proxy target URL for the origin server.
-- Uses $server_addr (the IP the request arrived on) so that per-site dedicated
-- IPs are honoured correctly — no hardcoded 127.0.0.1.
local function origin_pass_for(s_in)
  local dst = ngx.var.server_addr or "127.0.0.1"
  return (s_in == "https" and "https://" or "http://") .. dst ..
         (s_in == "https" and ":443" or ":80")
end

-- ── Step 0: cPanel / webmail hard bypass ─────────────────────────────────────
-- These management interfaces must never be challenged or blocked.
-- Matches: cpanel.*, webmail.*, whm.*, mail.* subdomains and /cpanel /webmail /whm path prefixes.
do
  local h   = lower(host)
  local u   = lower(uri)
  local pfx = h:match("^([^%.]+)%.")   -- first label of the hostname

  local skip = (pfx == "cpanel" or pfx == "webmail" or pfx == "whm" or pfx == "mail")
            or (u:sub(1, 7) == "/cpanel")
            or (u:sub(1, 8) == "/webmail")
            or (u:sub(1, 4) == "/whm")

  if skip then
    ngx.var.cfm_upstream = "cfm_apache"
    ngx.var.cfm_pass     = origin_pass_for(scheme)
    if CFG.debug then
      log_route(ngx.INFO, "cpanel_bypass host=" .. host .. " uri=" .. uri)
    end
    return
  end
end

-- ── Step 0a: Local-origin hard bypass ────────────────────────────────────────
-- Any request whose raw TCP peer is loopback or RFC-1918 private, AND that did
-- not arrive via Cloudflare (no CF-Connecting-IP header), is an internal server
-- request: wp-cron, Joomla cron, Drupal cron, custom PHP HTTP calls, health
-- checks, etc. These processes have no browser and cannot solve a PoW challenge.
--
-- Security guard: the CF-Connecting-IP absence check is critical.
-- Without it an external attacker could pass X-Real-IP: 127.0.0.1 through
-- Cloudflare and bypass enforcement. When CF-Connecting-IP is present the
-- request is external (regardless of other headers) and must not be bypassed.
--
-- peer_ip = $realip_remote_addr = the raw TCP connection source, already
-- captured above before any header-based override. For a local PHP curl call
-- this will be 127.0.0.1 or ::1. For an external request via Cloudflare this
-- will be a Cloudflare edge IP.
-- ── Step 0a: Local-origin hard bypass ────────────────────────────────────────
do
  local p      = peer_ip
  local has_cf = cf_ip ~= ""
  local srv    = ngx.var.server_addr or ""

  -- Case 1: direct connection (no Cloudflare in path)
  -- peer_ip is the raw TCP source — loopback or RFC-1918 = internal request.
  if not has_cf and p ~= "" then
    if p:sub(1, 1) == "[" then p = p:sub(2, -2) end
    local b2 = tonumber(p:match("^172%.(%d+)%."))
    local is_local = (p == "127.0.0.1")
                  or (p == "::1")
                  or (p == srv)
                  or (p:sub(1, 8) == "192.168.")
                  or (p:sub(1, 3) == "10.")
                  or (b2 and b2 >= 16 and b2 <= 31)
    if is_local then
      ngx.var.cfm_upstream = "cfm_apache"
      ngx.var.cfm_pass     = origin_pass_for(scheme)
      if CFG.debug then
        log_route(ngx.INFO, "local_bypass peer=" .. peer_ip ..
          " srv=" .. srv .. " host=" .. host .. " uri=" .. uri)
      end
      return
    end
  end

  -- Case 2: self-request routed via Cloudflare
  -- wp-cron (and similar) on a CF-proxied domain resolve their own hostname
  -- to a CF edge IP, so the request goes: server → CF → back to server.
  -- CF-Connecting-IP is set by Cloudflare to the actual TCP source it saw
  -- (the server's own public IP) — this header cannot be forged by clients.
  -- If the resolved real IP equals our own server_addr, it is a self-request.
  if has_cf and srv ~= "" and ip == srv then
    ngx.var.cfm_upstream = "cfm_apache"
    ngx.var.cfm_pass     = origin_pass_for(scheme)
    if CFG.debug then
      log_route(ngx.INFO, "local_bypass_via_cf ip=" .. ip ..
        " srv=" .. srv .. " host=" .. host .. " uri=" .. uri)
    end
    return
  end
end



-- ── POST resume: attempt to replay a previously stashed POST ─────────────────
-- Must run BEFORE the solved-cookie fast-path (Step 1) so that replayed
-- requests still pass through WAF and bridge checks rather than bypassing them.
-- If a stash entry is found, the request is mutated into a POST in-place and
-- ngx.ctx.cfm_resumed_post is set; method and uri are re-read to reflect that.
try_apply_post_resume(ip, host)
method = ngx.req.get_method() or method
uri    = ngx.var.uri          or uri

-- ── Step 1: Fast-path — Solved Cookie ────────────────────────────────────────
-- If the visitor already has a valid cfm_ok cookie, let them through immediately
-- without querying the bridge. Skip this fast-path for replayed POSTs so the
-- WAF and bridge still inspect the re-submitted request.
local cfm_ok_cookie = ngx.var.cookie_cfm_ok
if cfm_ok_cookie and cfm_ok_cookie ~= "" and not ngx.ctx.cfm_resumed_post then
  refresh_ok_cookie(cfm_ok_cookie)
  touch_ok(ip)
  ngx.header["X-CFM-Action"] = "allow_cookie"
  ngx.var.cfm_upstream = "cfm_apache"
  ngx.var.cfm_pass     = origin_pass_for(scheme)
  return
end

-- ── Step 2: Inline WAF ───────────────────────────────────────────────────────
local waf_ok, waf = pcall(require, "cfm_waf")
if waf_ok and waf and waf.enabled and waf.enabled() then
  if waf_is_excluded(host, uri) then
    if CFG.debug_headers then
      ngx.header["X-CFM-WAF-Excluded"] = "1"
    end
  else
    local req_headers = ngx.req.get_headers()
    local req_body    = get_req_body_for_waf(uri, method, CFG.waf_body_max_len)

  local hit, reason, ttl, waf_action = waf.check({
    uri     = uri,
    args    = ngx.var.args or "",
    method  = method,
    host    = host,
    ip      = ip,
    cookie  = ngx.var.http_cookie or "",
    peer    = peer_ip,
    cf_ip   = cf_ip,
    shdict  = SH,
    headers = req_headers,
    body    = req_body,
  })


 -- Async ClamAV scan for multipart uploads. Passes WAF reason if one fired.
  if clamav_ok then clamav.notify(ip, hit and reason or nil) end


  if hit then
    waf_action = waf_action or "challenge"
    local p_host = ngx.var.host        or host
    local p_uri  = ngx.var.request_uri or uri
    local p_meth = method

    if waf_action == "logonly" then
      -- Log only: pass the request through without blocking or challenging.
      ngx.header["X-CFM-Action"] = "logonly"
      ngx.var.cfm_upstream = "cfm_apache"
      ngx.var.cfm_pass     = origin_pass_for(scheme)

    elseif waf_action == "block" then
      ngx.header["X-CFM-Action"] = "block"
      ngx.var.cfm_upstream = "cfm_block"
      ngx.var.cfm_pass     = ""
      observe_waf(ip, host, p_uri, p_meth, 403, reason)

    else -- challenge
      -- Safety: if WAF still fires on a replayed POST, block rather than
      -- looping (challenge → solve → replay → challenge → ...).
      if ngx.ctx.cfm_resumed_post then
        ngx.header["X-CFM-Action"] = "block_replayed"
        ngx.var.cfm_upstream = "cfm_block"
        ngx.var.cfm_pass     = ""
        observe_waf(ip, host, p_uri, p_meth, 403, "REPLAYED_POST_RECHALLENGED")
        log_route(ngx.WARN, "replayed_post_rechallenged_block ip=" .. ip ..
          " host=" .. host .. " uri=" .. tostring(p_uri))
        return ngx.exit(CFG.block_code)
      end

      -- Try to stash the POST body before redirecting to the challenge page.
      -- On success, ?cfm_rt=<token> is appended to ?next= so the token
      -- survives the round-trip and try_apply_post_resume can replay it.
      local rtok, rerr = store_post_resume(ip, host, ngx.var.request_uri or uri, method)
      if rtok then
        ngx.header["X-CFM-Action"] = "challenge_resume"
        ngx.header["Cache-Control"] = "no-store"
        return ngx.redirect(
          "/?next=" .. esc(with_query_arg((ngx.var.request_uri or uri), "cfm_rt", rtok)),
          ngx.HTTP_SEE_OTHER
        )
      end

      -- Stash failed (empty body, wrong content-type, too large, etc.) —
      -- fall through to normal challenge; body will be lost.
      ngx.header["X-CFM-Action"] = "challenge"
      ngx.var.cfm_upstream = "cfm_challenge"
      ngx.var.cfm_pass     = "http://cfm_challenge"
      if CFG.debug then
        log_route(ngx.INFO, "post_resume_skip reason=" .. tostring(rerr or "unknown") ..
          " method=" .. tostring(method) .. " uri=" .. tostring(uri))
      end
    end

    if waf.should_push and waf.should_push(SH, ip, reason) then
      local payload = cjson.encode({
        ip      = ip,
        action  = waf_action,
        ttl_sec = ttl or 600,
        reason  = reason,
        host    = p_host,
        uri     = p_uri,
        method  = p_meth,
      })
      http_post_unix("/nginx/ip", payload)
    end

    log_route(ngx.INFO, "waf_" .. waf_action .. " ip=" .. ip ..
      " host=" .. host .. " reason=" .. tostring(reason))

    if waf_action == "block" then return ngx.exit(CFG.block_code) end
    return
  end
  end
end


-- ClamAV notify for paths where WAF was not loaded/enabled
if not waf_ok and clamav_ok then clamav.notify(ip, nil) end


-- ── Step 3: Bridge Decision ───────────────────────────────────────────────────
local d          = get_decision(ip, host, uri, method, scheme)
local ip_action  = d.ip_action    or "allow"
local vh_action  = d.vhost_action or "allow"
local cache_flag = d._cache and " cache=1" or ""

if CFG.debug_headers then
  ngx.header["X-CFM-IP"]     = ip
  ngx.header["X-CFM-Host"]   = host
  ngx.header["X-CFM-Dec-IP"] = ip_action
  ngx.header["X-CFM-Dec-VH"] = vh_action
  if d.err    then ngx.header["X-CFM-Err"]   = tostring(d.err) end
  if d._cache then ngx.header["X-CFM-Cache"] = "1" end
end

if ip_action == "block" or vh_action == "block" then
  ngx.header["X-CFM-Action"] = "block"
  ngx.var.cfm_upstream = "cfm_block"
  ngx.var.cfm_pass     = ""
  log_route(ngx.WARN, "block ip=" .. ip .. " host=" .. host .. cache_flag ..
    (d.err and (" err=" .. tostring(d.err)) or ""))
  return ngx.exit(CFG.block_code)
end

if ip_action == "challenge" or vh_action == "challenge" then
  -- Same re-challenge guard as in the WAF path above.
  if ngx.ctx.cfm_resumed_post then
    ngx.header["X-CFM-Action"] = "block_replayed"
    ngx.var.cfm_upstream = "cfm_block"
    ngx.var.cfm_pass     = ""
    log_route(ngx.WARN, "replayed_post_rechallenged_block ip=" .. ip ..
      " host=" .. host .. cache_flag)
    return ngx.exit(CFG.block_code)
  end

  -- Try POST resume stash (same logic as WAF challenge path).
  local rtok, rerr = store_post_resume(ip, host, ngx.var.request_uri or uri, method)
  if rtok then
    ngx.header["X-CFM-Action"] = "challenge_resume"
    ngx.header["Cache-Control"] = "no-store"
    return ngx.redirect(
      "/?next=" .. esc(with_query_arg((ngx.var.request_uri or uri), "cfm_rt", rtok)),
      ngx.HTTP_SEE_OTHER
    )
  end

  ngx.header["X-CFM-Action"] = "challenge"
  ngx.var.cfm_upstream = "cfm_challenge"
  ngx.var.cfm_pass     = "http://cfm_challenge"
  log_route(ngx.INFO, "challenge ip=" .. ip .. " host=" .. host .. cache_flag ..
    (rerr and (" resume_skip=" .. tostring(rerr)) or ""))
  return
end

-- ── Step 4: Allow ─────────────────────────────────────────────────────────────
ngx.header["X-CFM-Action"] = "allow"
ngx.var.cfm_upstream = "cfm_apache"
ngx.var.cfm_pass     = origin_pass_for(scheme)

if CFG.log_allows or CFG.debug then
  log_route(ngx.INFO, "allow ip=" .. ip .. " host=" .. host ..
    " pass=" .. ngx.var.cfm_pass .. cache_flag)
end

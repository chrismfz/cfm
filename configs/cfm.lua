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

local function env_num(name, default, minv, maxv)
  local raw = os.getenv(name)
  local n = tonumber(raw or "")
  if not n then n = default end
  if minv and n < minv then n = minv end
  if maxv and n > maxv then n = maxv end
  return n
end


-- ─────────────────────────────────────────────────────────────────────────────
-- CONFIG
-- ─────────────────────────────────────────────────────────────────────────────
local CFG = {
  sock_path = "/var/run/cfm/cfm_nginx.sock",

  token        = "cfm",
  token_header = "X-CFM-Token",

  -- Bridge socket timeout policy:
  --   connect timeout is intentionally tighter than send/read timeout.
  -- New env names:
  --   CFM_BRIDGE_CONNECT_TIMEOUT_MS, CFM_BRIDGE_SEND_TIMEOUT_MS, CFM_BRIDGE_READ_TIMEOUT_MS
  -- Legacy CFM_DECISION_* and CFM_DECISION_TIMEOUT_MS are still honored as fallback.
  bridge_connect_timeout_ms = env_num(
    "CFM_BRIDGE_CONNECT_TIMEOUT_MS",
    env_num("CFM_DECISION_CONNECT_TIMEOUT_MS", env_num("CFM_DECISION_TIMEOUT_MS", 75, 1, 60000), 1, 60000),
    1,
    60000
  ),
  bridge_send_timeout_ms = env_num(
    "CFM_BRIDGE_SEND_TIMEOUT_MS",
    env_num("CFM_DECISION_SEND_TIMEOUT_MS", env_num("CFM_DECISION_TIMEOUT_MS", 100, 1, 60000), 1, 60000),
    1,
    60000
  ),
  bridge_read_timeout_ms = env_num(
    "CFM_BRIDGE_READ_TIMEOUT_MS",
    env_num("CFM_DECISION_READ_TIMEOUT_MS", env_num("CFM_DECISION_TIMEOUT_MS", 350, 1, 60000), 1, 60000),
    1,
    60000
  ),
  snapshot_refresh_sec  = env_num("CFM_SNAPSHOT_REFRESH_SEC", 15, 1, 300),
  snapshot_jitter_max_sec = env_num("CFM_SNAPSHOT_JITTER_MAX_SEC", 2, 0, 10),
  snapshot_lock_ttl_sec = env_num(
    "CFM_SNAPSHOT_LOCK_TTL_SEC",
    math.max(3, math.ceil((
      env_num("CFM_BRIDGE_CONNECT_TIMEOUT_MS", env_num("CFM_DECISION_CONNECT_TIMEOUT_MS", env_num("CFM_DECISION_TIMEOUT_MS", 75, 1, 60000), 1, 60000), 1, 60000) +
      env_num("CFM_BRIDGE_SEND_TIMEOUT_MS", env_num("CFM_DECISION_SEND_TIMEOUT_MS", env_num("CFM_DECISION_TIMEOUT_MS", 100, 1, 60000), 1, 60000), 1, 60000) +
      env_num("CFM_BRIDGE_READ_TIMEOUT_MS", env_num("CFM_DECISION_READ_TIMEOUT_MS", env_num("CFM_DECISION_TIMEOUT_MS", 350, 1, 60000), 1, 60000), 1, 60000)
    ) / 1000) + 2),
    1,
    300
  ),
  snapshot_age_warn_sec = env_num("CFM_SNAPSHOT_AGE_WARN_SEC", 45, 5, 600),
  snapshot_stale_failover_sec = env_num("CFM_SNAPSHOT_STALE_FAILOVER_SEC", 120, 10, 3600),
  snapshot_policy_delay_warn_sec = env_num("CFM_SNAPSHOT_POLICY_DELAY_WARN_SEC", 30, 1, 600),

  block_code = 403,
  fail_open  = true,

  -- Debugging (set env vars in systemd/env if needed)
  debug         = (os.getenv("CFM_DEBUG") == "1"),
  debug_headers = (os.getenv("CFM_DEBUG_HEADERS") == "1"),
  log_allows    = (os.getenv("CFM_LOG_ALLOWS") == "1"),

  -- Sliding OK TTL (cookie + bridge okState)
  ok_ttl_sec         = env_num("CFM_OK_TTL_SEC", 1800, 1, 604800),
  ok_touch_every_sec = env_num("CFM_OK_TOUCH_EVERY_SEC", 120, 1, 3600),

  -- Keepalive pool (per nginx worker)
  keepalive_idle_ms = env_num("CFM_BRIDGE_KA_IDLE_MS", 15000, 1, 600000),
  keepalive_pool    = env_num("CFM_BRIDGE_KA_POOL", 128, 1, 8192),

  -- Narrow body read for inline WAF (only where needed)
  waf_body_max_len = env_num("CFM_WAF_BODY_MAX_LEN", 8192, 0, 1048576),

  -- Non-critical bridge events are queued in shared dict and flushed by timer.
  event_flush_interval_sec = env_num("CFM_EVENT_FLUSH_INTERVAL_SEC", 1, 0.5, 2),
  event_queue_max_depth    = env_num("CFM_EVENT_QUEUE_MAX_DEPTH", 2048, 64, 20000),
  event_batch_size         = env_num("CFM_EVENT_BATCH_SIZE", 64, 1, 500),
  event_retry_budget       = env_num("CFM_EVENT_RETRY_BUDGET", 1, 0, 5),
  event_drop_policy        = string.lower(os.getenv("CFM_EVENT_DROP_POLICY") or "oldest"), -- oldest|newest
  events_batch_endpoint    = os.getenv("CFM_EVENTS_BATCH_ENDPOINT") or "/nginx/events/batch",
  breaker_window_sec       = env_num("CFM_BRIDGE_BREAKER_WINDOW_SEC", 15, 1, 300),
  breaker_min_samples      = env_num("CFM_BRIDGE_BREAKER_MIN_SAMPLES", 20, 1, 100000),
  breaker_error_rate_pct   = env_num("CFM_BRIDGE_BREAKER_ERROR_RATE_PCT", 60, 1, 100),
  breaker_open_sec         = env_num("CFM_BRIDGE_BREAKER_OPEN_SEC", 8, 1, 120),

  -- POST resume: stash challenged POST bodies so they can be replayed after solve.
  -- Enabled by default. Only covers allowlisted content types (form, JSON, text).
  -- Multipart / file uploads are intentionally excluded (size + complexity).
  -- Env overrides:
  --   CFM_POST_RESUME_ENABLE  = 0    disable entirely
  --   CFM_POST_RESUME_MAX_LEN = N    max body bytes to stash (default 64KB)
  --   CFM_POST_RESUME_TTL_SEC = N    seconds stash entry lives (default 90)
  post_resume_enable  = (os.getenv("CFM_POST_RESUME_ENABLE") or "1") == "1",
  post_resume_max_len = env_num("CFM_POST_RESUME_MAX_LEN", 65536, 0, 10485760),
  post_resume_ttl_sec = env_num("CFM_POST_RESUME_TTL_SEC", 90, 1, 3600),
}


-- cfm_clamav is optional: if the file is missing cfm continues normally
local clamav_ok, clamav = pcall(require, "cfm_clamav")
if clamav_ok then clamav.init({ token = CFG.token, sock_path = CFG.sock_path  }) end

local rules_ok, rules = pcall(require, "cfm_rules")
if rules_ok and rules and rules.init then
  rules.init(CFG)
end


-- Shared dict used for local control-plane snapshot + POST resume stash.
local SH = ngx.shared.cfm_decisions

-- ─────────────────────────────────────────────────────────────────────────────
-- UTILS
-- ─────────────────────────────────────────────────────────────────────────────

local function log_route(level, msg)
  ngx.log(level or ngx.WARN, "[cfm] ", msg)
end

local function incr_metric(name)
  if not SH or not name or name == "" then return end
  SH:incr(name, 1, 0)
end

local function is_timeout_err(err)
  if not err then return false end
  if err == "timeout" then return true end
  return tostring(err):find("timed out", 1, true) ~= nil
end

local function optional_bridge_breaker_is_open()
  if not SH then return false end
  local until_ts = tonumber(SH:get("bridge_breaker_optional_until") or "0") or 0
  local open_now = until_ts > ngx.now()
  SH:set("bridge_breaker_optional_open", open_now and 1 or 0, math.max(1, CFG.breaker_open_sec))
  if open_now then
    incr_metric("bridge_breaker_optional_open")
  end
  return open_now
end

local function optional_bridge_breaker_record(ok)
  if not SH then return end
  local ttl = math.max(CFG.breaker_window_sec, CFG.breaker_open_sec) + 2
  local total = SH:incr("bridge_breaker_optional_total", 1, 0, ttl)
  if not total then return end
  local errors = SH:incr("bridge_breaker_optional_errors", ok and 0 or 1, 0, ttl) or 0
  if total < CFG.breaker_min_samples then return end

  local error_rate_pct = (errors / math.max(1, total)) * 100.0
  if error_rate_pct >= CFG.breaker_error_rate_pct then
    local until_ts = ngx.now() + CFG.breaker_open_sec
    SH:set("bridge_breaker_optional_until", until_ts, math.max(1, CFG.breaker_open_sec))
    SH:set("bridge_breaker_optional_open", 1, math.max(1, CFG.breaker_open_sec))
    incr_metric("bridge_breaker_optional_opened")
    if CFG.debug then
      log_route(ngx.WARN, "bridge_breaker_optional_opened error_rate_pct=" ..
        tostring(math.floor(error_rate_pct)) ..
        " total=" .. tostring(total) ..
        " errors=" .. tostring(errors) ..
        " open_sec=" .. tostring(CFG.breaker_open_sec))
    end
  end
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
    if not line then
      if is_timeout_err(err) then incr_metric("bridge_timeout_read") end
      return nil, "chunked size line: " .. (err or "?")
    end

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
    if not data then
      if is_timeout_err(derr) then incr_metric("bridge_timeout_read") end
      return nil, "chunk read: " .. (derr or "?")
    end
    table.insert(out, data)
    sock:receive(2) -- trailing CRLF after each chunk
  end
  return table.concat(out), nil
end

-- Low-level HTTP/1.1 request over the cfm unix socket.
-- Uses a per-worker keepalive pool to avoid a connect() syscall on every
-- request (critical for low-latency bridge decisions).
local function http_unix(method, path, body, opts)
  opts = opts or {}
  if opts.optional and optional_bridge_breaker_is_open() then
    incr_metric("bridge_breaker_optional_skipped")
    return nil, "breaker_open"
  end

  local s, err = ngx.socket.tcp()
  if not s then return nil, "socket.tcp: " .. (err or "unknown") end

  s:settimeouts(
    opts.connect_timeout_ms or CFG.bridge_connect_timeout_ms,
    opts.send_timeout_ms or CFG.bridge_send_timeout_ms,
    opts.read_timeout_ms or CFG.bridge_read_timeout_ms
  )

  local ok, cerr = s:connect("unix:" .. CFG.sock_path)
  if not ok then
    s:close()
    if is_timeout_err(cerr) then
      incr_metric("bridge_timeout_connect")
    end
    if opts.optional then optional_bridge_breaker_record(false) end
    return nil, "connect: " .. (cerr or "unknown")
  end

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
  if werr then
    s:close()
    if is_timeout_err(werr) then
      incr_metric("bridge_timeout_send")
    end
    if opts.optional then optional_bridge_breaker_record(false) end
    return nil, "send: " .. (werr or "unknown")
  end

  local status_line, rerr = s:receive("*l")
  if not status_line then
    s:close()
    if is_timeout_err(rerr) then
      incr_metric("bridge_timeout_read")
    end
    if opts.optional then optional_bridge_breaker_record(false) end
    return nil, "recv status: " .. (rerr or "unknown")
  end

  local code = tonumber(status_line:match("%s(%d%d%d)%s"))
  if not code then
    s:close()
    if opts.optional then optional_bridge_breaker_record(false) end
    return nil, "bad status line: " .. status_line
  end

  local content_length
  local is_chunked = false

  while true do
    local line, herr = s:receive("*l")
    if not line then
      if is_timeout_err(herr) then incr_metric("bridge_timeout_read") end
      s:close()
      if opts.optional then optional_bridge_breaker_record(false) end
      return nil, "recv header: " .. (herr or "unknown")
    end
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
    local b, berr = s:receive(content_length)
    if not b then
      if is_timeout_err(berr) then incr_metric("bridge_timeout_read") end
      s:close()
      if opts.optional then optional_bridge_breaker_record(false) end
      return nil, "recv body: " .. (berr or "unknown")
    end
    resp = b
  elseif is_chunked then
    local b, berr = read_chunked(s)
    if not b then
      s:close()
      if opts.optional then optional_bridge_breaker_record(false) end
      return nil, berr
    end
    resp = b
  else
    local b, berr = s:receive("*a")
    if not b then
      if is_timeout_err(berr) then incr_metric("bridge_timeout_read") end
      s:close()
      if opts.optional then optional_bridge_breaker_record(false) end
      return nil, "recv body: " .. (berr or "unknown")
    end
    resp = b or ""
  end

  local ok_ka = s:setkeepalive(CFG.keepalive_idle_ms, CFG.keepalive_pool)
  if not ok_ka then s:close() end

  if code ~= 200 then
    if opts.optional then optional_bridge_breaker_record(false) end
    return nil, "http " .. tostring(code) .. " body=" .. tostring(resp)
  end
  if opts.optional then optional_bridge_breaker_record(true) end
  return resp, nil
end

local function http_get_snapshot_unix(path_qs)
  return http_unix("GET", path_qs, nil, { optional = false })
end

local function http_post_optional_unix(path, b)
  return http_unix("POST", path, b, { optional = true })
end

local event_flusher_started = false

local function queue_depth(head, tail)
  if not head or not tail or tail < head then return 0 end
  return (tail - head + 1)
end

local function event_q_key(seq)
  return "evtq|" .. tostring(seq or 0)
end

local function enqueue_bridge_event(path, payload)
  if not SH then
    incr_metric("event_queue_unavailable")
    return nil, "shared_dict_unavailable"
  end

  local seq, seq_err = SH:incr("evtq_seq", 1, 0)
  if not seq then
    incr_metric("event_queue_seq_fail")
    return nil, "seq:" .. tostring(seq_err or "unknown")
  end

  local head = tonumber(SH:get("evtq_head") or "0") or 0
  local tail = tonumber(SH:get("evtq_tail") or "0") or 0
  if head <= 0 or tail < head then
    head = seq
    tail = seq - 1
    SH:set("evtq_head", head)
    SH:set("evtq_tail", tail)
  end

  if queue_depth(head, tail) >= CFG.event_queue_max_depth then
    if CFG.event_drop_policy == "newest" then
      incr_metric("event_queue_drop_newest")
      incr_metric("event_queue_dropped_total")
      SH:incr("event_queue_dropped_total", 1, 0)
      return nil, "queue_full_drop_newest"
    end
    SH:delete(event_q_key(head))
    head = head + 1
    SH:set("evtq_head", head)
    incr_metric("event_queue_drop_oldest")
    incr_metric("event_queue_dropped_total")
    SH:incr("event_queue_dropped_total", 1, 0)
  end

  local rec = cjson.encode({
    p = path or "",
    b = payload or "",
    t = ngx.now(),
  })
  local ok, set_err = SH:set(event_q_key(seq), rec)
  if not ok then
    incr_metric("event_queue_set_fail")
    return nil, "set:" .. tostring(set_err or "unknown")
  end
  SH:set("evtq_tail", seq)
  incr_metric("event_queue_enqueued")
  return true, nil
end

local function flush_bridge_events_once()
  if not SH then return end

  local lock_ok = SH:add("evtq_flush_lock", true, math.max(0.2, CFG.event_flush_interval_sec * 0.9))
  if not lock_ok then return end

  local head = tonumber(SH:get("evtq_head") or "0") or 0
  local tail = tonumber(SH:get("evtq_tail") or "0") or 0
  if head <= 0 or tail < head then return end

  local max_seq = math.min(tail, head + CFG.event_batch_size - 1)
  local seqs, events = {}, {}
  for seq = head, max_seq do
    local raw = SH:get(event_q_key(seq))
    seqs[#seqs + 1] = seq
    if raw and raw ~= "" then
      local ev = cjson.decode(raw)
      if ev and ev.p then
        events[#events + 1] = ev
      end
    end
  end
  if #seqs == 0 then return end

  local sent = false
  if #events > 0 then
    local batch_payload = cjson.encode({ events = events })
    for _ = 0, CFG.event_retry_budget do
      local _, berr = http_post_optional_unix(CFG.events_batch_endpoint, batch_payload)
      if not berr then
        sent = true
        break
      end
    end
  else
    sent = true
  end

  if not sent and #events > 0 then
    sent = true
    for _, ev in ipairs(events) do
      local ok_item = false
      for _ = 0, CFG.event_retry_budget do
        local _, ierr = http_post_optional_unix(ev.p, ev.b)
        if not ierr then
          ok_item = true
          break
        end
      end
      if not ok_item then
        sent = false
        break
      end
    end
  end

  if not sent then
    incr_metric("event_queue_flush_fail")
    return
  end

  for _, seq in ipairs(seqs) do
    SH:delete(event_q_key(seq))
  end
  SH:set("evtq_head", max_seq + 1)
  incr_metric("event_queue_flushed_batches")
  SH:incr("event_queue_flushed_events", #seqs, 0)
end

local function schedule_event_flusher(delay)
  local ok, terr = ngx.timer.at(delay or CFG.event_flush_interval_sec, function(premature)
    if premature then return end
    local ok_run, run_err = pcall(flush_bridge_events_once)
    if not ok_run then
      incr_metric("event_queue_flush_panic")
      if CFG.debug then
        log_route(ngx.WARN, "event_queue_flush_panic err=" .. tostring(run_err))
      end
    end
    schedule_event_flusher(CFG.event_flush_interval_sec)
  end)
  if not ok then
    incr_metric("event_queue_schedule_fail")
    if CFG.debug then
      log_route(ngx.WARN, "event_queue_schedule_fail err=" .. tostring(terr))
    end
  end
end

local function ensure_event_flusher_started()
  if event_flusher_started then return end
  event_flusher_started = true
  schedule_event_flusher(0.05)
end

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
  local _, qerr = enqueue_bridge_event("/nginx/observe", payload)
  if qerr then incr_metric("event_queue_drop_observe") end
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
  local _, qerr = enqueue_bridge_event("/nginx/ok/touch", payload)
  if qerr then incr_metric("event_queue_drop_ok_touch") end
end

-- Slide the cfm_ok cookie TTL forward on every request so an active browser
-- session never expires the cookie mid-use. Only appends; does not replace.
local function refresh_ok_cookie(cookie_val)
  if not cookie_val or cookie_val == "" then return end
  local attrs = "Path=/; Max-Age=" .. tostring(CFG.ok_ttl_sec) .. "; HttpOnly; SameSite=Lax"
  if ngx.var.scheme == "https" then attrs = attrs .. "; Secure" end
  append_set_cookie("cfm_ok=" .. cookie_val .. "; " .. attrs)
end

local function fail_action()
  return CFG.fail_open and "allow" or "block"
end

local function fail_policy_label()
  return CFG.fail_open and "fail_open_allow" or "fail_closed_block"
end

-- Local snapshot cache (worker-local views backed by shared-dict payload).
local snap_local_ts = 0
local snap_local_ver = ""
local snap_local_ips = {}     -- [ip] = "challenge"|"block"
local snap_local_vhosts = {}  -- array { {host=pattern, action=...}, ... }
local snap_local_rules = {}   -- ordered TrafficRule rows (Go-sorted)
local snap_local_waf_hosts = {}
local snap_local_waf_paths = {}
local snap_refresh_jitter_sec = -1

local function worker_refresh_jitter_sec(now)
  if CFG.snapshot_jitter_max_sec <= 0 then return 0 end
  if snap_refresh_jitter_sec >= 0 then return snap_refresh_jitter_sec end
  local wid = 0
  if ngx.worker and ngx.worker.id then
    wid = tonumber(ngx.worker.id() or 0) or 0
  end
  local seed = math.floor((now or ngx.now()) * 1000) + (wid * 131)
  local span_ms = math.floor(CFG.snapshot_jitter_max_sec * 1000)
  if span_ms <= 0 then
    snap_refresh_jitter_sec = 0
  else
    snap_refresh_jitter_sec = (seed % (span_ms + 1)) / 1000
  end
  return snap_refresh_jitter_sec
end

local function maybe_warn_snapshot_age(age_sec, reason)
  if not SH then return end
  SH:set("snap_age_sec", age_sec)
  if age_sec <= CFG.snapshot_age_warn_sec then return end
  local now = ngx.now()
  local last_warn = tonumber(SH:get("snap_age_warn_ts") or "0") or 0
  if (now - last_warn) < 10 then return end
  SH:set("snap_age_warn_ts", now, 30)
  log_route(ngx.WARN,
    "snapshot_age_high age_sec=" .. tostring(math.floor(age_sec)) ..
    " threshold_sec=" .. tostring(CFG.snapshot_age_warn_sec) ..
    " reason=" .. tostring(reason or "unknown") ..
    " policy=" .. fail_policy_label())
end

-- Refresh local enforcement snapshot from bridge:
--   GET /nginx/snapshot -> { ips:[...], vhosts:[...], rules:[...], version:"...", ts_unix:N }
-- One worker refreshes at a time; all workers consume from shared dict.
local function refresh_snapshot_if_needed()
  if not SH then return end

  local now = ngx.now()
  local last_hb = tonumber(SH:get("snap_hb_ts") or "0") or 0
  local fail_until = tonumber(SH:get("snap_fail_until") or "0") or 0
  if now < fail_until then
    return
  end

  local jitter_sec = worker_refresh_jitter_sec(now)
  if (now - last_hb) < (CFG.snapshot_refresh_sec + jitter_sec) then
    return
  end

  if not SH:add("snap_lock", "1", CFG.snapshot_lock_ttl_sec) then
    return
  end

  local function mark_snapshot_refresh_failure(reason)
    if CFG.debug then
      log_route(ngx.INFO, "snapshot_refresh_fail reason=" .. tostring(reason or "unknown"))
    end
    SH:incr("snap_fail_count", 1, 0)
    SH:set("snap_fail_ts", now, math.max(1, CFG.snapshot_refresh_sec))
    SH:set("snap_fail_until", now + CFG.snapshot_refresh_sec, math.max(1, CFG.snapshot_refresh_sec * 2))
    maybe_warn_snapshot_age(math.max(0, now - (tonumber(SH:get("snap_ts") or "0") or 0)), "refresh_fail")
    SH:delete("snap_lock")
  end

  local body, err = http_get_snapshot_unix("/nginx/snapshot")
  if not body then
    mark_snapshot_refresh_failure("http:" .. tostring(err))
    return
  end

  local obj = cjson.decode(body)
  if not obj then
    mark_snapshot_refresh_failure("decode")
    return
  end

  local new_ver = tostring(obj.version or "")
  if new_ver == "" then
    mark_snapshot_refresh_failure("empty_version")
    return
  end

  local cur_ver = tostring(SH:get("snap_ver") or "")
  if new_ver ~= cur_ver then
    local snap_ttl = math.max(2, CFG.snapshot_refresh_sec * 2)
    local encoded_ips = cjson.encode(obj.ips or {})
    local encoded_vhosts = cjson.encode(obj.vhosts or {})
    local encoded_rules = cjson.encode(obj.rules or {})
    local encoded_waf_excludes = cjson.encode(obj.waf_excludes or {})
    if not encoded_ips or not encoded_vhosts or not encoded_rules or not encoded_waf_excludes then
      mark_snapshot_refresh_failure("encode")
      return
    end

    local ok_ips = SH:set("snap_ips", encoded_ips, snap_ttl)
    local ok_vhosts = SH:set("snap_vhosts", encoded_vhosts, snap_ttl)
    local ok_rules = SH:set("snap_rules", encoded_rules, snap_ttl)
    local ok_waf = SH:set("snap_waf_excludes", encoded_waf_excludes, snap_ttl)
    local ok_ver = SH:set("snap_ver", new_ver, snap_ttl)
    if not (ok_ips and ok_vhosts and ok_rules and ok_waf and ok_ver) then
      mark_snapshot_refresh_failure("store")
      return
    end
    SH:set("snap_ts", now, snap_ttl)
  else
    SH:set("snap_ver", new_ver, math.max(2, CFG.snapshot_refresh_sec * 2))
  end
  local cp_ts = tonumber(obj.ts_unix or "0") or 0
  if cp_ts > 0 then
    local policy_delay_sec = math.max(0, now - cp_ts)
    SH:set("snap_policy_delay_sec", policy_delay_sec)
    if policy_delay_sec > CFG.snapshot_policy_delay_warn_sec then
      log_route(ngx.WARN,
        "snapshot_policy_delay_high delay_sec=" .. tostring(math.floor(policy_delay_sec)) ..
        " threshold_sec=" .. tostring(CFG.snapshot_policy_delay_warn_sec) ..
        " version=" .. tostring(new_ver))
    end
  end
  local snap_age = math.max(0, now - (tonumber(SH:get("snap_ts") or "0") or now))
  SH:set("snap_age_sec", snap_age)
  SH:set("snap_hb_ts", now, math.max(2, CFG.snapshot_refresh_sec * 2))
  SH:delete("snap_fail_ts")
  SH:delete("snap_fail_until")
  SH:delete("snap_lock")
end

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

local function load_snapshot_local_cache()
  refresh_snapshot_if_needed()
  if not SH then return end

  if SH:get("snap_fail_ts") and snap_local_ver ~= "" then
    local stale_age = math.max(0, ngx.now() - snap_local_ts)
    maybe_warn_snapshot_age(stale_age, "refresh_fail")
    if CFG.debug then
      log_route(ngx.INFO, "snapshot_serving_stale marker=stale_snapshot ver=" .. snap_local_ver .. " age_sec=" .. tostring(math.floor(stale_age)))
    end
    if CFG.debug_headers then
      ngx.header["X-CFM-Snapshot-Stale"] = "1"
      ngx.header["X-CFM-Snapshot-Stale-Age"] = tostring(math.floor(stale_age))
    end
  end

  local ver = tostring(SH:get("snap_ver") or "")
  if ver == "" or ver == snap_local_ver then
    return
  end

  local snap_ips_raw = SH:get("snap_ips")
  local snap_vhosts_raw = SH:get("snap_vhosts")
  local snap_rules_raw = SH:get("snap_rules")
  local snap_waf_raw = SH:get("snap_waf_excludes")
  if not snap_ips_raw or not snap_vhosts_raw or not snap_rules_raw or not snap_waf_raw then
    return
  end

  local ip_rows = cjson.decode(snap_ips_raw)
  local vh_rows = cjson.decode(snap_vhosts_raw)
  local rules_rows = cjson.decode(snap_rules_raw)
  local waf_rows = cjson.decode(snap_waf_raw)
  if type(ip_rows) ~= "table" or type(vh_rows) ~= "table" or type(rules_rows) ~= "table" or type(waf_rows) ~= "table" then
    return
  end

  local ip_map = {}
  for _, row in ipairs(ip_rows) do
    local rip = tostring(row.ip or "")
    local act = tostring(row.action or "")
    if rip ~= "" and (act == "challenge" or act == "block") then
      ip_map[rip] = act
    end
  end
  snap_local_ips = ip_map
  snap_local_vhosts = vh_rows
  snap_local_rules = rules_rows

  local hosts, paths = {}, {}
  for _, e in ipairs(waf_rows) do
    local t = lower(e.type or "")
    local v = lower(tostring(e.value or ""))
    if v ~= "" then
      if t == "host" then
        hosts[#hosts + 1] = v
      elseif t == "path" then
        paths[#paths + 1] = v
      end
    end
  end
  snap_local_ver = ver
  snap_local_ts = tonumber(SH:get("snap_ts") or "0") or ngx.now()
  snap_local_waf_hosts = hosts
  snap_local_waf_paths = paths
end

local function waf_is_excluded(host, uri)
  host = lower(host or "")
  uri  = lower(tostring(uri or "/"))
  for _, r in ipairs(snap_local_waf_hosts) do
    if matches_rule(host, r) then return true end
  end
  for _, r in ipairs(snap_local_waf_paths) do
    if matches_rule(uri, r) then return true end
  end
  return false
end

local function wildcard_match(pattern, s)
  pattern = tostring(pattern or "")
  s = tostring(s or "")
  if pattern == "" or s == "" then return false end
  if pattern == "*" then return true end
  local lua_pat = glob_to_lua_pattern(pattern)
  local ok, res = pcall(function() return s:match(lua_pat) ~= nil end)
  return ok and res or false
end

local function host_matches(pattern, host)
  pattern = lower(tostring(pattern or ""))
  host = lower(tostring(host or ""))
  if pattern == "" or host == "" then return false end
  if wildcard_match(pattern, host) then return true end
  if pattern:sub(1, 2) == "*." then
    local suf = pattern:sub(2) -- ".example.com"
    return #host > #suf and host:sub(-#suf) == suf
  end
  return host == pattern
end

local function vhost_action_for(host)
  host = lower(tostring(host or ""))
  if host == "" then return "allow" end
  for _, row in ipairs(snap_local_vhosts) do
    local pat = tostring(row.host or "")
    if host_matches(pat, host) then
      local act = tostring(row.action or "")
      if act == "challenge" or act == "block" then
        return act
      end
    end
  end
  return "allow"
end

local function list_contains(list, value)
  if type(list) ~= "table" then return false end
  for _, v in ipairs(list) do
    if tostring(v) == tostring(value) then return true end
  end
  return false
end

local function rule_match_filters(rule, country, ua, path, method)
  local m = rule and rule.match or {}
  if type(m.country_in) == "table" and #m.country_in > 0 and not list_contains(m.country_in, country) then
    return false
  end
  if type(m.methods) == "table" and #m.methods > 0 and not list_contains(m.methods, method) then
    return false
  end
  if type(m.ua_any) == "table" and #m.ua_any > 0 then
    local ok = false
    for _, pat in ipairs(m.ua_any) do
      local p = lower(tostring(pat or ""))
      if p ~= "" then
        if wildcard_match(p, ua) or (not has(p, "*") and not has(p, "?") and has(ua, p)) then
          ok = true
          break
        end
      end
    end
    if not ok then return false end
  end
  if type(m.path_any) == "table" and #m.path_any > 0 then
    local ok = false
    for _, pat in ipairs(m.path_any) do
      local p = tostring(pat or "")
      if p ~= "" then
        if wildcard_match(p, path) or (not has(p, "*") and not has(p, "?") and path:sub(1, #p) == p) then
          ok = true
          break
        end
      end
    end
    if not ok then return false end
  end
  return true
end

local function local_rule_decision(host, ip, ua, path, method, country)
  for _, rule in ipairs(snap_local_rules) do
    if rule and rule.enabled then
      local scope = rule.scope or {}
      local vhosts = scope.vhosts or {}
      local matched_host = false
      for _, pat in ipairs(vhosts) do
        if host_matches(pat, host) then matched_host = true; break end
      end
      if matched_host and rule_match_filters(rule, country, ua, path, method) then
        local action = tostring((rule.action and rule.action.type) or "allow")
        local profile = tostring((rule.action and rule.action.profile) or "")
        return {
          matched = true,
          action = action,
          profile = profile,
          id = tostring(rule.id or ""),
        }
      end
    end
  end
  return { matched = false, action = "allow", profile = "", id = "" }
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

-- Non-blocking telemetry/event flusher is worker-local and lazily started.
ensure_event_flusher_started()


-- Build the proxy target URL for the origin server.
-- Uses $server_addr (the IP the request arrived on) so that per-site dedicated
-- IPs are honoured correctly — no hardcoded 127.0.0.1.
local function origin_pass_for(s_in)
  local dst = ngx.var.server_addr or "127.0.0.1"
  return (s_in == "https" and "https://" or "http://") .. dst ..
         (s_in == "https" and ":443" or ":80")
end


-- ── Step 0: Static IP/CIDR bypass ───────────────────────────────────────────
do
  if ngx.var.cfm_bypass_ip == "1" then
    ngx.var.cfm_upstream = "cfm_apache"
    ngx.var.cfm_pass     = origin_pass_for(scheme)
    if CFG.debug then
      log_route(ngx.INFO, "static_bypass ip=" .. ip ..
        " host=" .. host .. " uri=" .. uri)
    end
    return
  end
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

-- Refresh local control-plane snapshot once before WAF and rule decisions.
load_snapshot_local_cache()

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
      local _, qerr = enqueue_bridge_event("/nginx/ip", payload)
      if qerr then incr_metric("event_queue_drop_ip_push") end
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


-- ── Step 3: Local Snapshot Decision (no per-request bridge RPC) ──────────────
local ua_l = lower(ngx.var.http_user_agent or "")
local path_for_rule = tostring(ngx.var.request_uri or uri or "/")
local country = tostring(ngx.var.http_cf_ipcountry or "")
country = string.upper(country)

local ip_action = snap_local_ips[ip] or "allow"
local vh_action = vhost_action_for(host)
local rr = local_rule_decision(host, ip, ua_l, path_for_rule, string.upper(method or ""), country)
local rule_action = rr.action or "allow"
local rule_id = rr.id or ""
local throttle_profile = rr.profile or ""
local snap_flag = (snap_local_ts > 0) and " snap=1" or " snap=0"

if snap_local_ts == 0 then
  local fallback = fail_action()
  local now = ngx.now()
  local last = tonumber(SH and SH:get("snap_policy_log_ts") or "0") or 0
  if SH and (now - last) > 10 then
    SH:set("snap_policy_log_ts", now, 30)
    log_route(ngx.WARN, "snapshot_missing policy=" .. fail_policy_label() .. " action=" .. fallback)
  end
  ip_action = fallback
  vh_action = fallback
  rule_action = fallback
elseif SH and SH:get("snap_fail_ts") then
  local stale_age = math.max(0, ngx.now() - snap_local_ts)
  if stale_age > CFG.snapshot_stale_failover_sec then
    local fallback = fail_action()
    local now = ngx.now()
    local last = tonumber(SH:get("snap_policy_log_ts") or "0") or 0
    if (now - last) > 10 then
      SH:set("snap_policy_log_ts", now, 30)
      log_route(ngx.WARN,
        "snapshot_stale_failover age_sec=" .. tostring(math.floor(stale_age)) ..
        " threshold_sec=" .. tostring(CFG.snapshot_stale_failover_sec) ..
        " policy=" .. fail_policy_label() ..
        " action=" .. fallback)
    end
    ip_action = fallback
    vh_action = fallback
    rule_action = fallback
  end
end

if CFG.debug_headers then
  ngx.header["X-CFM-IP"]     = ip
  ngx.header["X-CFM-Host"]   = host
  ngx.header["X-CFM-Dec-IP"] = ip_action
  ngx.header["X-CFM-Dec-VH"] = vh_action
  ngx.header["X-CFM-Dec-Rule"] = rule_action
  ngx.header["X-CFM-Snapshot"] = snap_local_ts > 0 and "1" or "0"
  if rule_id ~= "" then ngx.header["X-CFM-Rule-ID"] = rule_id end
  if throttle_profile ~= "" then ngx.header["X-CFM-Throttle"] = throttle_profile end
end

if ip_action == "block" or vh_action == "block" or rule_action == "block" then
  ngx.header["X-CFM-Action"] = "block"
  ngx.var.cfm_upstream = "cfm_block"
  ngx.var.cfm_pass     = ""
  log_route(ngx.WARN, "block ip=" .. ip .. " host=" .. host .. snap_flag)
  return ngx.exit(CFG.block_code)
end

if ip_action == "challenge" or vh_action == "challenge" or rule_action == "challenge" then
  -- Same re-challenge guard as in the WAF path above.
  if ngx.ctx.cfm_resumed_post then
    ngx.header["X-CFM-Action"] = "block_replayed"
    ngx.var.cfm_upstream = "cfm_block"
    ngx.var.cfm_pass     = ""
    log_route(ngx.WARN, "replayed_post_rechallenged_block ip=" .. ip .. " host=" .. host .. snap_flag)
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
  log_route(ngx.INFO, "challenge ip=" .. ip .. " host=" .. host .. snap_flag ..
    (rerr and (" resume_skip=" .. tostring(rerr)) or ""))
  return
end

if rules_ok and rules and rules.apply then
  local r = rules.apply({
    rule_action = rule_action,
    throttle_profile = throttle_profile,
  }, {
    ip = ip,
    host = host,
    uri = uri,
    method = method,
    profile = throttle_profile,
  })
  if r and r.action == "throttle" then
    ngx.header["X-CFM-Action"] = "throttle"
    if r.retry_after and tonumber(r.retry_after) then
      ngx.header["Retry-After"] = tostring(math.max(1, math.floor(tonumber(r.retry_after))))
    end
    log_route(ngx.WARN, "throttle ip=" .. ip .. " host=" .. host ..
      (rule_id ~= "" and (" rule_id=" .. tostring(rule_id)) or "") ..
      (throttle_profile ~= "" and (" profile=" .. tostring(throttle_profile)) or "") .. snap_flag)
    return ngx.exit(429)
  end
end

-- ── Step 4: Allow ─────────────────────────────────────────────────────────────
ngx.header["X-CFM-Action"] = "allow"
ngx.var.cfm_upstream = "cfm_apache"
ngx.var.cfm_pass     = origin_pass_for(scheme)

if CFG.log_allows or CFG.debug then
  log_route(ngx.INFO, "allow ip=" .. ip .. " host=" .. host ..
    " pass=" .. ngx.var.cfm_pass .. snap_flag)
end

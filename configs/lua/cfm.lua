-- /var/lib/cfm/lua/cfm.lua (CFM-managed canonical location)
--
-- CFM OpenResty in-path enforcement
-- Based on the proven Mars version with minimal additions:
--   [R1] Traffic rules: ua/country passed to bridge, rule_action/throttle handled
--   [R2] pcall fail-open: any uncaught Lua error defaults to serving via Apache
--   [R3] cfm_rules throttle module support (optional)
--
-- Design principles:
--   - Per-request bridge RPC with 9-second shared-dict cache for allows
--   - No timer callbacks, no event queues, no snapshot polling
--   - Socket calls are best-effort with short timeouts and fail-open
--   - Cache means 95%+ of requests never touch the socket
--
-- ─────────────────────────────────────────────────────────────────────────────
-- PITFALL: access_by_lua_file top-level locals reset on every request.
-- Read this BEFORE adding new state to this file.
-- ─────────────────────────────────────────────────────────────────────────────
--
-- This file is loaded by openresty/angie via `access_by_lua_file`. With
-- the default `lua_code_cache on`, the openresty docs say "the code
-- chunk is cached per worker" — which is true. What's NOT obvious until
-- you trip on it: cached means COMPILED ONCE. The chunk's body is
-- RE-EXECUTED on every request. Top-level `local` declarations are
-- inside that body, so they re-initialise to their declared values on
-- every invocation.
--
-- The two failure modes this caused on production (May 2026):
--
--   (1) GeoIP mmap leak. `local _geo_init_done = false` reset every
--       request. The "have I initialised mmdb yet?" guard never
--       triggered, so lua-resty-maxminddb's `init` mmap'd the ~60 MB
--       GeoLite2-City.mmdb afresh each call. Lua's GC doesn't release
--       FFI mmaps without a `__gc` metamethod, so mappings accumulated:
--       200+ duplicate maps per worker, 13 GB virtual address space,
--       ~10 MB/min RSS growth. Confirmed via /proc/<pid>/maps captured
--       by `cfm debug`. Fixed by extracting state to `cfm_geo.lua`
--       (loaded via `require`, which uses `package.loaded[name]` —
--       per-worker cache that DOES survive across requests).
--
--   (2) WAF excludes cache miss. `local wx_local_ts = 0` reset every
--       request. The shortcut `if ts == wx_local_ts then return end`
--       in load_waf_excludes_local_cache was a permanent miss because
--       wx_local_ts was always 0 at the start of a request, while the
--       shdict's ts was non-zero (set by an earlier refresh on this or
--       another worker). Result: every WAF-eligible request paid an
--       unnecessary cjson.decode of the wxhosts/wxpaths shdict snapshot.
--       Not a leak (Lua tables GC cleanly) but a perf hit. Fixed by
--       moving the cache state to `cfm_waf_excl.lua`.
--
-- THE RULE for new code in this file:
--
--   * If a piece of state must persist across requests (init flags,
--     caches, FFI handles, anything created by an expensive operation
--     you don't want to repeat), put it in a separate `.lua` file and
--     load it via `require`. The module's top-level scope persists.
--   * If state is per-request (request-id, the response action being
--     decided, the matched rule, anything derived from `ngx.var.*` or
--     `ngx.req.*`), top-level locals here are fine — they're meant to
--     re-initialise per request.
--   * If you're not sure, default to "make it a module". The cost of
--     an extra `require` is one map lookup per request; the cost of
--     getting it wrong is the kind of thing operators only catch with
--     `cfm debug` after a memory chart turns the wrong shape.
--
-- See:
--   * configs/lua/cfm_geo.lua  — the geo-state module (case 1 above)
--   * configs/lua/cfm_waf_excl.lua  — the excludes-cache module (case 2)
--   * The two require sites in this file are commented to point back here.
-- ─────────────────────────────────────────────────────────────────────────────

local cjson = require "cjson.safe"
local function fallback_normalize_host(raw)
  local h = string.lower(tostring(raw or "")):gsub("%.$", "")
  if h == "" then return "" end
  if h:sub(1, 1) == "[" then
    local inner, rest = h:match("^%[([^%]]+)%](.*)$")
    if not inner then return "" end
    if rest ~= "" and rest:sub(1, 1) ~= ":" then return "" end
    return inner
  end
  local c = select(2, h:gsub(":", ""))
  if c == 1 then
    local host_no_port = h:match("^(.-):%d+$")
    if host_no_port then h = host_no_port end
  end
  return h
end
local ok_clearance, clearance_validator = pcall(require, "cfm_clearance")
if not ok_clearance then
  ngx.log(ngx.ERR, "[cfm] clearance module load failed module=cfm_clearance err=", tostring(clearance_validator))
  clearance_validator = {
    validate = function(...) return false, "module_error" end,
    normalize_host = fallback_normalize_host,
    panel_scope = function(...) return "web" end,
  }
end
local bit = require "bit"


-- ─────────────────────────────────────────────────────────────────────────────
-- BRIDGE TOKEN (auto-generated by cfm daemon, written to /var/lib/cfm/lua).
-- Deliberately loaded from one canonical path so stale legacy copies cannot
-- shadow the current token.
-- ─────────────────────────────────────────────────────────────────────────────
local _BRIDGE_TOKEN_FILE = "/var/lib/cfm/lua/cfm_bridge_token.lua"

local function load_token(path, tag)
  local chunk, load_err = loadfile(path)
  if not chunk then
    ngx.log(ngx.ERR, "[cfm] cannot load ", tag, " ", path, ": ", tostring(load_err))
    return nil, "load: " .. tostring(load_err)
  end
  local ok, val = pcall(chunk)
  if not ok or type(val) ~= "string" or #val < 32 then
    ngx.log(ngx.ERR, "[cfm] ", tag, " invalid or too short: ", path)
    return nil, "invalid/short token"
  end
  return val
end

local _bridge_token, _bridge_token_err = load_token(_BRIDGE_TOKEN_FILE, "bridge token file")
if not _bridge_token then
  error("[cfm] missing bridge token file — ensure cfm daemon has started; path: "
        .. _BRIDGE_TOKEN_FILE
        .. "; details: " .. tostring(_bridge_token_err))
end

-- Webdetector → Lua runtime knobs (sibling file to the bridge token).
-- Optional: if the file is missing or unloadable we fall back to safe defaults
-- so an upgrade lag (cfm daemon old, Lua new) doesn't break the request path.
local _BRIDGE_CONFIG_FILE = "/var/lib/cfm/lua/cfm_bridge_config.lua"
local _bridge_cfg = { clearance_refresh = true }
do
  local chunk = loadfile(_BRIDGE_CONFIG_FILE)
  if chunk then
    local ok, val = pcall(chunk)
    if ok and type(val) == "table" then
      if val.clearance_refresh ~= nil then
        _bridge_cfg.clearance_refresh = (val.clearance_refresh ~= false)
      end
    else
      ngx.log(ngx.WARN, "[cfm] bridge config file did not return a table: ", _BRIDGE_CONFIG_FILE)
    end
  end
end


-- ─────────────────────────────────────────────────────────────────────────────
-- CONFIG
-- ─────────────────────────────────────────────────────────────────────────────
local CFG = {
  sock_path = "/var/run/cfm/cfm_nginx.sock",

  token        = _bridge_token,
  token_header = "X-CFM-Token",

  -- Default 100ms: headroom for the first connect (no pooled socket yet),
  -- plus the bridge's synchronous-state mutation. Hook-backed work (WAF
  -- history, observations) is dispatched async on the Go side so this
  -- budget only needs to cover state mutation + JSON (sub-millisecond).
  decision_timeout_ms   = tonumber(os.getenv("CFM_DECISION_TIMEOUT_MS") or "300"),
  decision_cache_ttl_ms = 90000,
  waf_excl_cache_ttl_ms = tonumber(os.getenv("CFM_WAF_EXCL_CACHE_TTL_MS") or "6000"),
  waf_excl_meta_ttl_sec = tonumber(os.getenv("CFM_WAF_EXCL_META_TTL_SEC") or "15"),
  waf_excl_refresh_sec  = tonumber(os.getenv("CFM_WAF_EXCL_REFRESH_SEC") or "10"),

  block_code = 403,
  fail_open  = (os.getenv("CFM_FAIL_OPEN") or "1") ~= "0",

  debug         = (os.getenv("CFM_DEBUG") == "1"),
  debug_headers = (os.getenv("CFM_DEBUG_HEADERS") == "1"),
  log_allows    = (os.getenv("CFM_LOG_ALLOWS") == "1"),

  ok_ttl_sec         = tonumber(os.getenv("CFM_OK_TTL_SEC")         or "3600"),
  ok_touch_every_sec = tonumber(os.getenv("CFM_OK_TOUCH_EVERY_SEC") or "120"),

  -- Sliding clearance: when true, accepted requests re-mint cfm_clearance
  -- with exp = now + ok_ttl_sec so active panel/webmail users don't get
  -- re-challenged mid-session. Sourced from [webdetector] CHALLENGE_COOKIE_REFRESH
  -- via /var/lib/cfm/lua/cfm_bridge_config.lua. Defaults to true.
  clearance_refresh  = _bridge_cfg.clearance_refresh,

  keepalive_idle_ms = tonumber(os.getenv("CFM_BRIDGE_KA_IDLE_MS") or "60000"),
  keepalive_pool    = tonumber(os.getenv("CFM_BRIDGE_KA_POOL")    or "512"),

  waf_body_max_len = tonumber(os.getenv("CFM_WAF_BODY_MAX_LEN") or "8192"),

  post_resume_enable  = (os.getenv("CFM_POST_RESUME_ENABLE") or "1") == "1",
  post_resume_max_len = tonumber(os.getenv("CFM_POST_RESUME_MAX_LEN") or "65536"),
  post_resume_ttl_sec = tonumber(os.getenv("CFM_POST_RESUME_TTL_SEC") or "90"),

  -- Post-clearance WAF policy. cfm_clearance proves the client passed the
  -- challenge gate, NOT that the payload is safe. So when WAF wants to
  -- challenge a request that already has clearance we must NOT re-challenge
  -- (would loop), but we also must not silently allow. Convert via these
  -- knobs: high-risk reason families escalate, the rest degrade to logonly.
  -- Allowed values: "block" | "logonly". "challenge" is intentionally NOT
  -- accepted here because it would re-introduce the loop.
  waf_after_clearance_challenge =
      ({ block = "block", logonly = "logonly" })[os.getenv("CFM_WAF_AFTER_CLEARANCE_CHALLENGE") or ""]
      or "logonly",
  waf_after_clearance_high_risk =
      ({ block = "block", logonly = "logonly" })[os.getenv("CFM_WAF_AFTER_CLEARANCE_HIGH_RISK") or ""]
      or "block",

  -- Hit-rate counters: every WAF inspection increments a per-host bucketed
  -- shdict counter; one worker periodically flushes the snapshot to Go via
  -- /nginx/waf/stats. Required by the rollout playbook (gate promotions on
  -- <0.01% hit-rate evidence). See docs/waf.md "Hit-rate measurement".
  waf_stats_enable    = (os.getenv("CFM_WAF_STATS_ENABLE") or "1") == "1",
  waf_stats_flush_sec = tonumber(os.getenv("CFM_WAF_STATS_FLUSH_SEC") or "60"),

}

local clamav_ok, clamav = pcall(require, "cfm_clamav")
if clamav_ok then
  -- Hook on/off lives in /var/lib/cfm/lua/cfm_clamav_config.lua, written
  -- by the cfm daemon on every cfm.conf reload (CLAMD_ENABLED &&
  -- CLAMD_NGINX_HOOK_ENABLED). Missing/unloadable file falls back to
  -- enabled=true so an upgrade lag (cfm daemon old, Lua new) does not
  -- silently turn the hook off.
  local _CLAMAV_CONFIG_FILE = "/var/lib/cfm/lua/cfm_clamav_config.lua"
  local clamav_hook_enabled = true
  do
    local chunk = loadfile(_CLAMAV_CONFIG_FILE)
    if chunk then
      local ok, val = pcall(chunk)
      if ok and type(val) == "table" and val.enabled ~= nil then
        clamav_hook_enabled = (val.enabled ~= false)
      else
        ngx.log(ngx.WARN, "[cfm] clamav config file did not return a table: ", _CLAMAV_CONFIG_FILE)
      end
    end
  end
  clamav.init({
    token     = CFG.token,
    sock_path = CFG.sock_path,
    enabled   = clamav_hook_enabled,
  })
end

-- [R3] cfm_rules is optional (throttle enforcement)
local rules_ok, rules = pcall(require, "cfm_rules")
if rules_ok and rules and rules.init then rules.init(CFG) end

-- WAF module loaded once at worker init, not on every request.
-- pcall here behaves identically to the previous per-request pcall:
-- a load failure sets waf_ok=false and disables inline WAF checks.
local waf_ok, waf = pcall(require, "cfm_waf")

local SH = ngx.shared.cfm_decisions

-- ─────────────────────────────────────────────────────────────────────────────
-- UTILS
-- ─────────────────────────────────────────────────────────────────────────────

local function log_route(level, msg) ngx.log(level or ngx.WARN, "[cfm] ", msg) end
local function esc(s) return ngx.escape_uri(s or "") end

local function with_query_arg(u, k, v)
  u = tostring(u or "/")
  local sep = u:find("?", 1, true) and "&" or "?"
  return u .. sep .. tostring(k or "") .. "=" .. esc(v or "")
end

local function append_set_cookie(v)
  local h = ngx.header["Set-Cookie"]
  if not h then ngx.header["Set-Cookie"] = v; return end
  if type(h) == "table" then table.insert(h, v); ngx.header["Set-Cookie"] = h; return end
  ngx.header["Set-Cookie"] = { h, v }
end

local function real_ip()
  local rip = ngx.var.remote_addr
  if rip and rip ~= "" then return rip end
  local cf = ngx.var.http_cf_connecting_ip
  if cf and cf ~= "" then return cf end
  return "-"
end

local function lower(s) if not s then return "" end; return string.lower(s) end

local function has(s, pat)
  if not s or s == "" then return false end
  return string.find(s, pat, 1, true) ~= nil
end

local function normalize_host(raw)
  local h = lower(tostring(raw or "")):gsub("%.$", "")
  if h == "" then return "" end
  if h:sub(1, 1) == "[" then
    local inner, rest = h:match("^%[([^%]]+)%](.*)$")
    if not inner then return "" end
    if rest ~= "" and rest:sub(1, 1) ~= ":" then return "" end
    return inner
  end
  local c = select(2, h:gsub(":", ""))
  if c == 1 then
    local host_no_port = h:match("^(.-):%d+$")
    if host_no_port then h = host_no_port end
  end
  return h
end

local function b64url_decode(s)
  s = tostring(s or ""):gsub("-", "+"):gsub("_", "/")
  local pad = #s % 4
  if pad == 2 then s = s .. "=="
  elseif pad == 3 then s = s .. "="
  elseif pad == 1 then return nil end
  return ngx.decode_base64(s)
end

local function hex_from_bin(bin)
  if not bin then return "" end
  return (bin:gsub(".", function(c) return string.format("%02x", string.byte(c)) end))
end

local function ct_eq_hex(a, b)
  if #a ~= #b then return false end
  local diff = 0
  for i = 1, #a do
    diff = bit.bor(diff, bit.bxor(a:byte(i), b:byte(i)))
  end
  return diff == 0
end

local _SELF_IPS_FILE = "/var/lib/cfm/lua/cfm_self_ips.lua"
local _SELF_IPS_TTL_SEC = tonumber(os.getenv("CFM_SELF_IPS_TTL_SEC") or "30")
local _self_ip_cache = { expires_at = 0, map = {}, generated_at = "" }

-- Mirror of [global] IGNORE_IPS / IGNORE_NETS from cfm.cfg, written by Go
-- (detectors.IPIgnore.WriteLuaCache) so the Lua self-bypass honours the
-- same allowlist as the challenge-engine bypass predicate. The same TTL
-- as self-ips so config edits propagate within ~30s without nginx reload.
local _IGNORE_NETS_FILE = "/var/lib/cfm/lua/cfm_ignore_nets.lua"
local _ignore_cache = { expires_at = 0, ips = {}, v4_ranges = {}, generated_at = "" }

local function normalize_ip(raw)
  local ip = tostring(raw or "")
  if ip == "" then return "" end
  if ip:sub(1, 1) == "[" and ip:sub(-1) == "]" then
    ip = ip:sub(2, -2)
  end
  return lower(ip)
end

local function is_loopback_or_linklocal(ip)
  ip = normalize_ip(ip)
  if ip == "" then return false end
  local b2 = tonumber(ip:match("^169%.(%d+)%."))
  if ip == "::1" then return true end
  if ip:sub(1, 4) == "127." then return true end
  if ip:sub(1, 6) == "fe80::" or ip:sub(1, 6) == "fe90::" or ip:sub(1, 6) == "fea0::" or ip:sub(1, 6) == "feb0::" then
    return true
  end
  if b2 and b2 == 254 then return true end
  return false
end

local function load_self_ip_cache(force)
  local now = ngx.now()
  if not force and now < (_self_ip_cache.expires_at or 0) then
    return _self_ip_cache.map or {}
  end

  local map = {}
  local generated_at = ""
  local ok_load, chunk_or_err = pcall(loadfile, _SELF_IPS_FILE)
  if not ok_load then
    ngx.log(ngx.WARN, "[cfm] self-ip loadfile panic ", _SELF_IPS_FILE, ": ", tostring(chunk_or_err))
  elseif not chunk_or_err then
    if CFG.debug then
      log_route(ngx.NOTICE, "self-ip cache unavailable file=" .. _SELF_IPS_FILE)
    end
  else
    local ok_run, val = pcall(chunk_or_err)
    if ok_run and type(val) == "table" then
      generated_at = tostring(val.generated_at or "")
      if type(val.ips) == "table" then
        for k, v in pairs(val.ips) do
          if v then
            local nk = normalize_ip(k)
            if nk ~= "" then map[nk] = true end
          end
        end
      else
        ngx.log(ngx.WARN, "[cfm] invalid self-ip cache payload (missing ips table): ", _SELF_IPS_FILE)
      end
    else
      ngx.log(ngx.WARN, "[cfm] invalid self-ip cache file ", _SELF_IPS_FILE, ": ", tostring(ok_run and "non-table value" or val))
    end
  end

  _self_ip_cache.map = map
  _self_ip_cache.generated_at = generated_at
  _self_ip_cache.expires_at = now + _SELF_IPS_TTL_SEC
  return map
end

-- Short TTL applied when the cache file is missing on disk. The Go side
-- writes /var/lib/cfm/lua/cfm_ignore_nets.lua on engine startup and on
-- every config reload, but on a freshly-booted host there's a window
-- where the file doesn't exist yet. Falling all the way back to the
-- 30s SELF_IPS_TTL during that window means IGNORE_NETS is silently
-- ignored for the first half-minute. Re-poll every 2s instead.
local _IGNORE_NETS_MISSING_TTL_SEC = 2

local function load_ignore_cache(force)
  local now = ngx.now()
  if not force and now < (_ignore_cache.expires_at or 0) then
    return _ignore_cache
  end

  local ips, v4_ranges = {}, {}
  local generated_at = ""
  local file_present = false
  local ok_load, chunk_or_err = pcall(loadfile, _IGNORE_NETS_FILE)
  if not ok_load then
    ngx.log(ngx.WARN, "[cfm] ignore-nets loadfile panic ", _IGNORE_NETS_FILE, ": ", tostring(chunk_or_err))
  elseif chunk_or_err then
    file_present = true
    local ok_run, val = pcall(chunk_or_err)
    if ok_run and type(val) == "table" then
      generated_at = tostring(val.generated_at or "")
      if type(val.ips) == "table" then
        for k, v in pairs(val.ips) do
          if v then
            local nk = normalize_ip(k)
            if nk ~= "" then ips[nk] = true end
          end
        end
      end
      if type(val.v4_ranges) == "table" then
        for i = 1, #val.v4_ranges do
          local r = val.v4_ranges[i]
          if type(r) == "table" and type(r[1]) == "number" and type(r[2]) == "number" then
            v4_ranges[#v4_ranges + 1] = { r[1], r[2] }
          end
        end
      end
    else
      ngx.log(ngx.WARN, "[cfm] invalid ignore-nets cache file ", _IGNORE_NETS_FILE)
    end
  end

  _ignore_cache.ips = ips
  _ignore_cache.v4_ranges = v4_ranges
  _ignore_cache.generated_at = generated_at
  -- File missing → re-poll quickly so first-boot convergence isn't 30s.
  if file_present then
    _ignore_cache.expires_at = now + _SELF_IPS_TTL_SEC
  else
    _ignore_cache.expires_at = now + _IGNORE_NETS_MISSING_TTL_SEC
  end
  return _ignore_cache
end

local function ipv4_to_uint32(ip)
  local a, b, c, d = ip:match("^(%d+)%.(%d+)%.(%d+)%.(%d+)$")
  if not a then return nil end
  a, b, c, d = tonumber(a), tonumber(b), tonumber(c), tonumber(d)
  if not (a and b and c and d) then return nil end
  if a > 255 or b > 255 or c > 255 or d > 255 then return nil end
  return a * 16777216 + b * 65536 + c * 256 + d
end

local function is_in_ignore_nets(ip)
  local cache = load_ignore_cache(false)
  if cache.ips[ip] then return true end
  local n = ipv4_to_uint32(ip)
  if n then
    local ranges = cache.v4_ranges
    for i = 1, #ranges do
      if n >= ranges[i][1] and n <= ranges[i][2] then return true end
    end
  end
  return false
end

local function is_self_origin(ip)
  local nip = normalize_ip(ip)
  if nip == "" then return false end
  if is_loopback_or_linklocal(nip) then return true end
  local map = load_self_ip_cache(false)
  if map[nip] == true then return true end
  -- [global] IGNORE_IPS / IGNORE_NETS from cfm.cfg — same allowlist the
  -- Go challenge-engine bypass uses. Mirrors operator expectation that a
  -- network listed as ignored bypasses the whole CFM stack, not just the
  -- challenge step.
  if is_in_ignore_nets(nip) then return true end
  return false
end

-- ─────────────────────────────────────────────────────────────────────────────
-- WAF BODY INSPECTION
-- ─────────────────────────────────────────────────────────────────────────────

local function waf_should_read_body(uri, method)
  uri    = lower(uri    or "")
  method = lower(method or "")
  if method ~= "post" then return false end
  if has(uri, "/xmlrpc.php")      then return true end
  if has(uri, "/wp-login.php")    then return true end
  if has(uri, "/wp-signup.php")   then return true end
  if has(uri, "/wp-activate.php") then return true end
  if has(uri, "/admin-ajax.php")  then return true end
  if has(uri, "/ajax")            then return true end
  if has(uri, "/api/")            then return true end
  if has(uri, "/graphql")         then return true end
  if has(uri, "/rest/")           then return true end
  if has(uri, "/wp-json/")        then return true end
  if has(uri, "/wp-admin/")       then return true end
  if has(uri, "/wp-content/")     then return true end
  if has(uri, "/wp-includes/")    then return true end
  if has(uri, "/wc-api/")         then return true end
  if has(uri, "wc-ajax=")         then return true end
  if has(uri, "/administrator/")  then return true end
  if has(uri, "/components/")     then return true end
  if has(uri, "/modules/")        then return true end
  if has(uri, "/plugins/")        then return true end
  if has(uri, "/templates/")      then return true end
  if has(uri, "/media/")          then return true end
  if has(uri, "/user/login")      then return true end
  if has(uri, "/admin")           then return true end
  if has(uri, "/login")           then return true end
  if has(uri, "/auth")            then return true end
  if has(uri, "/upload")          then return true end
  if has(uri, "/import")          then return true end
  if has(uri, "/install")         then return true end
  if has(uri, "/setup")           then return true end
  if has(uri, "/update")          then return true end
  if has(uri, "/filemanager")     then return true end
  if has(uri, "/connector")       then return true end
  if has(uri, "/shell")           then return true end
  if has(uri, "/cmd")             then return true end
  if has(uri, "/cgi-bin/")        then return true end
  if has(uri, "/_ignition/")      then return true end
  if has(uri, "timthumb.php")     then return true end
  if has(uri, "/webservice/")     then return true end
  if has(uri, "/backend/")        then return true end
  if has(uri, "/catalog/")        then return true end
  if has(uri, "/system/")         then return true end
  if has(uri, "/extension/")      then return true end
  if has(uri, "/sites/default/")  then return true end
  if uri:match("/upload[s]?/.*%.php") then return true end
  if uri:match("/files/.*%.php")      then return true end
  if uri:match("%.php[%?/].*")   then return true end
  if uri:match("%.phtml[%?/].*") then return true end
  if uri:match("%.php$")         then return true end
  if uri:match("%.phtml$")       then return true end
  return false
end

local function get_req_body_for_waf(uri, method, max_len)
  if not waf_should_read_body(uri, method) then return "" end
  if ngx.ctx.waf_body ~= nil then return ngx.ctx.waf_body end
  ngx.req.read_body()
  local data = ngx.req.get_body_data()
  if data and data ~= "" then
    local result = (#data > max_len) and string.sub(data, 1, max_len) or data
    ngx.ctx.waf_body = result; return result
  end
  local body_file = ngx.req.get_body_file()
  if body_file and body_file ~= "" then
    local f = io.open(body_file, "rb")
    if f then local chunk = f:read(max_len) or ""; f:close(); ngx.ctx.waf_body = chunk; return chunk end
  end
  ngx.ctx.waf_body = ""; return ""
end

-- ─────────────────────────────────────────────────────────────────────────────
-- POST RESUME
-- ─────────────────────────────────────────────────────────────────────────────

local function ct_allows_resume(ct)
  ct = lower(ct or "")
  if ct == "" then return false end
  if has(ct, "application/x-www-form-urlencoded") then return true end
  if has(ct, "application/json")  then return true end
  if has(ct, "text/plain")        then return true end
  return false
end

local function build_resume_token()
  return ngx.md5(table.concat({
    ngx.var.request_id or "", tostring(ngx.worker.pid()), tostring(ngx.now()),
  }, "|"))
end

local function store_post_resume(ip, host, uri, method)
  if not CFG.post_resume_enable or not SH then return nil, "disabled" end
  if lower(method or "") ~= "post" then return nil, "not_post" end
  local ctype = ngx.var.content_type or ""
  if not ct_allows_resume(ctype) then return nil, "ctype_not_allowed" end
  local clen = tonumber(ngx.var.content_length or "0") or 0
  if clen <= 0 or clen > CFG.post_resume_max_len then return nil, "size_limit" end
  ngx.req.read_body()
  local body = ngx.req.get_body_data()
  if not body or #body == 0 or #body > CFG.post_resume_max_len then return nil, "body_size" end
  local token = build_resume_token()
  SH:set("pr|" .. token, cjson.encode({
    ip = ip, host = host, uri = uri, method = "POST",
    ctype = ctype, body_b64 = ngx.encode_base64(body), ts = ngx.time(),
  }), CFG.post_resume_ttl_sec)
  return token, nil
end

local function try_apply_post_resume(ip, host)
  if not CFG.post_resume_enable or not SH then return false end
  if lower(ngx.req.get_method() or "") ~= "get" then return false end
  local args = ngx.req.get_uri_args()
  local tok = args and args["cfm_rt"]
  if type(tok) == "table" then tok = tok[1] end
  tok = tostring(tok or "")
  if tok == "" then return false end
  local raw = SH:get("pr|" .. tok); SH:delete("pr|" .. tok)
  if not raw then return false end
  local obj = cjson.decode(raw)
  if not obj then return false end
  if tostring(obj.ip or "") ~= tostring(ip or "") then return false end
  if tostring(obj.host or "") ~= tostring(host or "") then return false end
  local body = ngx.decode_base64(obj.body_b64 or "")
  if not body or #body == 0 or #body > CFG.post_resume_max_len then return false end
  ngx.req.set_method(ngx.HTTP_POST)
  ngx.req.set_header("Content-Type", obj.ctype or "application/x-www-form-urlencoded")
  ngx.req.set_body_data(body)
  local target_uri = obj.uri or "/"
  local qidx = target_uri:find("?", 1, true)
  if qidx then
    ngx.req.set_uri(target_uri:sub(1, qidx - 1), false)
    ngx.req.set_uri_args(target_uri:sub(qidx + 1))
  else
    ngx.req.set_uri(target_uri, false); ngx.req.set_uri_args(nil)
  end
  ngx.ctx.cfm_resumed_post = true
  log_route(ngx.INFO, "post_resume_applied ip=" .. tostring(ip) ..
    " host=" .. tostring(host) .. " uri=" .. tostring(target_uri))
  return true
end

-- ─────────────────────────────────────────────────────────────────────────────
-- NETWORK LAYER
-- ─────────────────────────────────────────────────────────────────────────────

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
      while true do local tl = sock:receive("*l"); if not tl or tl == "" then break end end
      break
    end
    local data, derr = sock:receive(n)
    if not data then return nil, "chunk read: " .. (derr or "?") end
    table.insert(out, data); sock:receive(2)
  end
  return table.concat(out), nil
end

local function http_unix(method, path, body)
  local s, err = ngx.socket.tcp()
  if not s then return nil, "socket.tcp: " .. (err or "unknown") end
  s:settimeouts(CFG.decision_timeout_ms, CFG.decision_timeout_ms, CFG.decision_timeout_ms)
  local ok, cerr = s:connect("unix:" .. CFG.sock_path)
  if not ok then s:close(); return nil, "connect: " .. (cerr or "unknown") end
  body = body or ""
  local req = method .. " " .. path .. " HTTP/1.1\r\nHost: localhost\r\nConnection: keep-alive\r\n"
  if CFG.token and CFG.token ~= "" then
    req = req .. CFG.token_header .. ": " .. CFG.token .. "\r\n"
  end
  if method == "POST" then
    req = req .. "Content-Type: application/json\r\nContent-Length: " .. tostring(#body) .. "\r\n"
  end
  req = req .. "\r\n" .. body
  local _, werr = s:send(req)
  if werr then s:close(); return nil, "send: " .. (werr or "unknown") end
  local status_line, rerr = s:receive("*l")
  if not status_line then s:close(); return nil, "recv status: " .. (rerr or "unknown") end
  local code = tonumber(status_line:match("%s(%d%d%d)%s"))
  if not code then s:close(); return nil, "bad status line: " .. status_line end
  local content_length, is_chunked
  while true do
    local line, _ = s:receive("*l")
    if not line or line == "" then break end
    local k, v = line:match("^([^:]+):%s*(.*)$")
    if k and v then
      local kl = k:lower()
      if kl == "content-length" then content_length = tonumber(v)
      elseif kl == "transfer-encoding" and v:lower():find("chunked", 1, true) then is_chunked = true end
    end
  end
  local resp = ""
  if method == "HEAD" or code == 204 or code == 304 then resp = ""
  elseif content_length and content_length > 0 then resp = s:receive(content_length)
  elseif is_chunked then
    local b, berr = read_chunked(s); if not b then s:close(); return nil, berr end; resp = b
  else resp = s:receive("*a") or "" end
  local ok_ka = s:setkeepalive(CFG.keepalive_idle_ms, CFG.keepalive_pool)
  if not ok_ka then s:close() end
  if code ~= 200 then return nil, "http " .. tostring(code) .. " body=" .. tostring(resp) end
  return resp, nil
end

local function classify_bridge_err(err)
  local msg = lower(tostring(err or ""))
  if msg == "" then return "unknown" end
  if msg:find("timeout", 1, true) then return "timeout" end
  if msg:find("connect:", 1, true) then return "connect" end
  local code = msg:match("http%s+(%d%d%d)")
  if code then return "http_" .. code end
  if msg:find("decode", 1, true) or msg:find("json", 1, true) then return "json" end
  return "unknown"
end

local function rpc_call(kind, method, path, body, req_ctx)
  local t0 = ngx.now()
  local resp, err = http_unix(method, path, body)
  local elapsed_ms = math.floor((ngx.now() - t0) * 1000 + 0.5)
  if err then
    req_ctx = req_ctx or {}
    local ctx_ip = req_ctx.ip or real_ip()
    local ctx_host = req_ctx.host or (ngx.var.host or "-")
    local ctx_uri = req_ctx.uri or (ngx.var.request_uri or ngx.var.uri or "-")
    local err_class = classify_bridge_err(err)

    if CFG.debug or CFG.debug_headers then
      ngx.ctx.cfm_bridge_error = err_class
      ngx.ctx.cfm_bridge_latency_ms = elapsed_ms
      if CFG.debug_headers then
        ngx.header["X-CFM-Bridge-Error"] = err_class
        ngx.header["X-CFM-Bridge-Latency-Ms"] = tostring(elapsed_ms)
      end
    end

    if CFG.debug then
      log_route(ngx.WARN, "rpc_err kind=" .. tostring(kind or "-") ..
        " path=" .. tostring(path or "-") ..
        " class=" .. tostring(err_class) ..
        " elapsed_ms=" .. tostring(elapsed_ms) ..
        " ip=" .. tostring(ctx_ip or "-") ..
        " host=" .. tostring(ctx_host or "-") ..
        " uri=" .. tostring(ctx_uri or "-"))
    end
  end
  return resp, err
end

-- ─────────────────────────────────────────────────────────────────────────────
-- HELPERS
-- ─────────────────────────────────────────────────────────────────────────────

local function observe_waf(ip, host, uri, method, status, reason)
  if not ip or ip == "" then return end
  rpc_call("observe", "POST", "/nginx/observe", cjson.encode({
    ip = ip, host = host or "", uri = uri or "/",
    method = method or "", status = status or 403, reason = reason or "",
  }), { ip = ip, host = host, uri = uri, method = method })
end

-- ── WAF inspection counters (hit-rate denominator) ──────────────────────────
-- Counts every waf.check() call into per-host hour-bucketed shdict keys.
-- Operator queries via /api/v1/waf/hit-rates compute hit-count / inspections
-- per rule per window — needed by the rollout playbook to gate promotions.
--
-- Shdict layout (TTL 25h so the previous hour's bucket survives one rollover):
--   waf_insp:hr=<hour_unix>|host=<host>   per-host counter
--   waf_insp:hr=<hour_unix>|host=          empty host = global total
--   waf_insp:last_flush                   ngx.now() of the last successful flush
--   waf_insp:flush_lock                   one-worker mutex (TTL ~= flush window)
local function waf_insp_incr(host)
  if not SH or not CFG.waf_stats_enable then return end
  local hr = math.floor(ngx.time() / 3600) * 3600
  local h = host or ""
  -- 25h TTL so an hourly bucket lives long enough for the post-rollover flush
  -- to push its final value before SQLite-side eviction.
  SH:incr("waf_insp:hr=" .. hr .. "|host=" .. h, 1, 0, 90000)
  if h ~= "" then
    SH:incr("waf_insp:hr=" .. hr .. "|host=", 1, 0, 90000)
  end
end

-- maybe_flush_waf_insp opportunistically pushes the current shdict snapshot
-- to /nginx/waf/stats. Called inline from cfm.lua's request hot path; cheap
-- in the common case (one shdict get + numeric compare). Only runs the
-- flush body once per CFG.waf_stats_flush_sec across all workers, gated by
-- shdict:add() (atomic claim on the lock key).
--
-- The actual snapshot+RPC happens in a background light-thread via
-- ngx.timer.at(0, ...) so the originating request never pays the RPC
-- round-trip latency (~5-10ms typical, up to decision_timeout_ms worst
-- case). The lock-winning request pays only the lock-claim cost (~µs).
--
-- Pushes ABSOLUTE counts per (hour, host); Go upserts. Repeated pushes for
-- the same hour overwrite cleanly. At hour rollover the current bucket
-- starts fresh; the previous hour's bucket gets one more push then ages out.
local function maybe_flush_waf_insp()
  if not SH or not CFG.waf_stats_enable then return end
  local last = SH:get("waf_insp:last_flush") or 0
  local now = ngx.now()
  if (now - last) < CFG.waf_stats_flush_sec then return end
  -- Atomic claim: SH:add returns false if the key already exists. TTL on
  -- the lock matches the flush window so a crashed flusher unblocks others.
  local ok = SH:add("waf_insp:flush_lock", 1, CFG.waf_stats_flush_sec)
  if not ok then return end
  SH:set("waf_insp:last_flush", now)

  -- Off the request path. premature=true means the worker is exiting; in
  -- that case skip the RPC (the next worker / next minute will retry).
  -- cosocket APIs (used by http_unix → rpc_call) are supported in
  -- ngx.timer.at callbacks.
  local sched_ok, sched_err = ngx.timer.at(0, function(premature)
    if premature then return end
    local rows = {}
    local keys = SH:get_keys(2000) or {}
    for _, k in ipairs(keys) do
      if k:sub(1, 12) == "waf_insp:hr=" then
        local hr_str, h = k:match("^waf_insp:hr=(%d+)|host=(.*)$")
        local cnt = SH:get(k)
        if hr_str and cnt and cnt > 0 then
          rows[#rows + 1] = { hour_unix = tonumber(hr_str), host = h or "", count = cnt }
        end
      end
    end
    if #rows == 0 then return end
    rpc_call("waf_stats", "POST", "/nginx/waf/stats", cjson.encode({ rows = rows }))
  end)
  if not sched_ok and CFG.debug then
    ngx.log(ngx.WARN, "cfm: waf_insp flush schedule failed: ", tostring(sched_err))
  end
end

local function touch_ok_scoped(ip, host, scope)
  if not SH then return end
  local k = "ok_touch|" .. (ip or "-") .. "|" .. normalize_host(host) .. "|" .. tostring(scope or "")
  local now = ngx.now()
  local last = SH:get(k)
  if last and (now - last) < CFG.ok_touch_every_sec then return end
  SH:set(k, now, CFG.ok_touch_every_sec)
  rpc_call("ok_touch", "POST", "/nginx/ok/touch",
    cjson.encode({ ip = ip, host = normalize_host(host), scope = scope, ttl_sec = CFG.ok_ttl_sec }),
    { ip = ip, host = host })
end

local function refresh_clearance_cookie(cookie_val, ip, host, scope)
  if not cookie_val or cookie_val == "" then return end
  local attrs = "Path=/; Max-Age=" .. tostring(CFG.ok_ttl_sec) .. "; HttpOnly; SameSite=Lax"
  if ngx.var.scheme == "https" then attrs = attrs .. "; Secure" end

  local out_val = cookie_val
  if CFG.clearance_refresh and ip and host then
    local fresh, mint_err = clearance_validator.mint(ip, host, scope or "web", CFG.token, CFG.ok_ttl_sec)
    if fresh and fresh ~= "" then
      out_val = fresh
    elseif mint_err and not ngx.ctx.cfm_clearance_mint_err_logged then
      ngx.ctx.cfm_clearance_mint_err_logged = true
      ngx.log(ngx.WARN, "[cfm] clearance re-mint failed err=", tostring(mint_err),
        " host=", tostring(host or "-"), " scope=", tostring(scope or "-"),
        "; falling back to original cookie value")
    end
  end
  append_set_cookie("cfm_clearance=" .. out_val .. "; " .. attrs)
end

local function validate_clearance_token(token, ip, host, scope)
  local secret = CFG.token
  local ok_call, ok, reason = pcall(clearance_validator.validate, token, ip, host, scope, secret)
  if not ok_call then
    local validate_err = ok
    ok = false
    reason = "module_error"
    if not ngx.ctx.cfm_clearance_error_logged then
      ngx.ctx.cfm_clearance_error_logged = true
      ngx.log(ngx.ERR,
        "[cfm] clearance validator runtime error",
        " module=cfm_clearance",
        " err=", tostring(validate_err),
        " host=", tostring(host or "-"),
        " uri=", tostring(ngx.var.request_uri or "-"),
        " scope=", tostring(scope or "-"),
        " mode=", tostring(CFG.fail_open and "fail_open" or "fail_closed"))
    end
  end
  if reason == "module_error" then return false, "module_error" end
  return ok, reason
end

local function fail_decision(errmsg)
  if CFG.fail_open then
    return { ip_action = "allow", vhost_action = "allow", err = errmsg }
  else
    return { ip_action = "block", vhost_action = "block", err = errmsg }
  end
end

-- Static asset extensions whose bridge verdict is purely a function of
-- (ip, host, scope) — never CHALLENGE_PATHS-eligible (no .git/.env/wp-config
-- has a .png/.css/.woff suffix), no SQLi/XSS surface in the URL itself.
-- For these we share a single cache entry per (ip, host, scope) so a page
-- with 50 embedded assets makes 1 bridge call per visitor per 15s window
-- instead of 50. Massive reduction in cosocket scheduling pressure on the
-- nginx worker — this is what was causing intermittent
-- "lua tcp socket read timed out" under modest load even though the bridge
-- itself was responding in 0ms (verified via OPENRESTY_BRIDGE_TRACE=1).
local STATIC_ASSET_EXT = {
  css=true, js=true, mjs=true, map=true,
  png=true, jpg=true, jpeg=true, gif=true, webp=true, avif=true,
  svg=true, ico=true, bmp=true, tiff=true, tif=true,
  woff=true, woff2=true, ttf=true, otf=true, eot=true,
}

local function is_static_asset_uri(uri)
  if type(uri) ~= "string" or uri == "" then return false end
  -- Strip query string, then take the extension after the final dot.
  local path = uri:match("^([^?#]+)") or uri
  local ext = path:match("%.([%w]+)$")
  if not ext then return false end
  return STATIC_ASSET_EXT[ext:lower()] == true
end

-- [R1] Pass ua + country so Go evaluates traffic rules. Cache clean allows only.
local function get_decision(ip, host, uri, method, scheme, ua, country, scope)
  local key
  if is_static_asset_uri(uri) then
    -- Coalesced cache entry: shared by every static asset from this
    -- (ip, host, scope) combo. Prefix "ds|" keeps it disjoint from the
    -- per-URL "d|" namespace below.
    key = "ds|" .. ip .. "|" .. host .. "|" .. (scope or "web")
  else
    local uri_part = (uri or "-"):sub(1, 64)
    key = "d|" .. ip .. "|" .. host .. "|" .. method .. "|" .. scheme .. "|" .. uri_part
  end

  if SH then
    local cached = SH:get(key)
    if cached then
      local obj = cjson.decode(cached)
      if obj then obj._cache = true; return obj end
    end
  end

  local path = "/nginx/decision?ip=" .. esc(ip) ..
               "&host="    .. esc(host)    ..
               "&uri="     .. esc(uri)     ..
               "&method="  .. esc(method)  ..
               "&scheme="  .. esc(scheme)  ..
               "&ua="      .. esc(ua or "")      ..
               "&country=" .. esc(country or "") ..
               "&scope="   .. esc(scope or "web")

  local body, err = rpc_call("decision", "GET", path, nil, {
    ip = ip, host = host, uri = uri, method = method,
  })
  if not body then
    return fail_decision(err)
  end
  local obj = cjson.decode(body)
  if not obj then
    if CFG.debug or CFG.debug_headers then
      ngx.ctx.cfm_bridge_error = "json"
    end
    if CFG.debug_headers then
      ngx.header["X-CFM-Bridge-Error"] = "json"
    end
    if CFG.debug then
      log_route(ngx.WARN, "rpc_err kind=decision class=json elapsed_ms=- ip=" .. tostring(ip or "-") ..
        " host=" .. tostring(host or "-") ..
        " uri=" .. tostring(uri or "-"))
    end
    return fail_decision("decode_failed")
  end

  -- Only cache clean allows (no rule action = no challenge/block/throttle pending)
  if SH and obj.ip_action == "allow" and obj.vhost_action == "allow"
     and not obj.rule_action then
    SH:set(key, body, CFG.decision_cache_ttl_ms / 1000)
  end
  return obj
end

-- WAF excludes snapshot
--
-- Each entry from /nginx/waf/excludes has shape {type, value, rule_ids?}.
-- rule_ids is an optional array of integers; absent/empty means "whole-WAF
-- skip" (legacy semantics). Present means "skip only these rule IDs when
-- the WAF runs". The two cached lists below carry the rule_ids alongside
-- the value so per-request matching can route to either path.
local function refresh_waf_excludes_if_needed()
  if not SH then return end
  local now = ngx.now()
  local last = tonumber(SH:get("wxsnap_ts") or "0") or 0
  if (now - last) < CFG.waf_excl_refresh_sec then return end
  if not SH:add("wxsnap_lock", "1", 1) then return end
  local body, _ = rpc_call("waf_excludes", "GET", "/nginx/waf/excludes")
  if not body then
    SH:set("wxsnap_ts", now, math.max(1, CFG.waf_excl_refresh_sec))
    SH:delete("wxsnap_lock"); return
  end
  local entries = (cjson.decode(body) or {}).entries or {}
  local hosts, paths = {}, {}
  for _, e in ipairs(entries) do
    local t = lower(e.type or ""); local v = lower(tostring(e.value or ""))
    if v ~= "" then
      local row = { v = v, rule_ids = e.rule_ids }
      if t == "host" then hosts[#hosts+1] = row
      elseif t == "path" then paths[#paths+1] = row end
    end
  end
  SH:set("wxhosts", cjson.encode(hosts), math.max(1, CFG.waf_excl_meta_ttl_sec))
  SH:set("wxpaths", cjson.encode(paths), math.max(1, CFG.waf_excl_meta_ttl_sec))
  SH:set("wxsnap_ts", now, math.max(1, CFG.waf_excl_refresh_sec))
  SH:delete("wxsnap_lock")
end

-- WAF-excludes per-worker cache state. MUST be in a require'd module —
-- previously these were `local wx_local_ts = 0` etc. on this line, but
-- top-level locals reset on every request under access_by_lua_file
-- (see the "PITFALL" block at the top of this file). The reset made
-- the timestamp-equality shortcut in load_waf_excludes_local_cache a
-- permanent miss, so every WAF-eligible request paid an unnecessary
-- cjson.decode of the shdict snapshot. Moving the state to a require'd
-- module restores the cache.
local wx = require "cfm_waf_excl"

local function glob_to_lua_pattern(glob)
  local p = tostring(glob or "")
  p = p:gsub("([%^%$%(%)%%%.%[%]%+%-%*%?])", "%%%1")
  p = p:gsub("%%%*", ".*"); p = p:gsub("%%%?", ".")
  return "^" .. p .. "$"
end

local function matches_rule(value, rule)
  value = lower(tostring(value or "")); rule = lower(tostring(rule or ""))
  if value == "" or rule == "" then return false end
  if rule:find("*", 1, true) or rule:find("?", 1, true) then
    local ok, res = pcall(function() return value:match(glob_to_lua_pattern(rule)) ~= nil end)
    return ok and res or false
  end
  return value:find(rule, 1, true) ~= nil
end

local function load_waf_excludes_local_cache()
  if not SH then wx.ts = 0; wx.hosts = {}; wx.paths = {}; return end
  local ts = tonumber(SH:get("wxsnap_ts") or "0") or 0
  -- This shortcut is the whole point of the cache; before the
  -- access_by_lua_file pitfall fix, wx.ts (then `wx_local_ts`) reset
  -- to 0 on every request and this comparison was always false. Now
  -- wx.ts persists across requests via package.loaded, so subsequent
  -- requests on a worker that's already at the latest snapshot
  -- short-circuit here without re-decoding the shdict snapshot.
  if ts == wx.ts then return end
  wx.ts = ts
  wx.hosts = cjson.decode(SH:get("wxhosts") or "[]") or {}
  wx.paths = cjson.decode(SH:get("wxpaths") or "[]") or {}
end

-- waf_skip_for(host, uri) returns:
--   skip_all (bool)     true if any matching exclude is whole-WAF (no rule_ids)
--   skip_ids (table)    set of waf_rule_id integers to suppress when WAF runs;
--                        nil if no rule-scoped exclude applies
-- A whole-WAF exclude short-circuits: caller skips the WAF entirely. Otherwise
-- the WAF runs and skip_ids is passed through ctx.skip_rule_ids so cfm_waf
-- silently drops any rule-fire whose ID is in the set.
local function waf_skip_for(host, uri)
  refresh_waf_excludes_if_needed(); load_waf_excludes_local_cache()
  host = lower(host or ""); uri = lower(tostring(uri or "/"))
  local skip_ids = nil
  local function consider(target, row)
    -- Back-compat: previous Lua versions cached this list as bare strings.
    -- A graceful nginx reload during upgrade can briefly hand the new code
    -- the old cache shape (≤ waf_excl_refresh_sec until the next refresh
    -- overwrites). Treat a string entry as a whole-WAF exclude — its old
    -- meaning — so excludes don't silently lapse during the upgrade window.
    if type(row) == "string" then row = { v = row } end
    if not matches_rule(target, row.v) then return false end
    if not row.rule_ids or #row.rule_ids == 0 then
      return true -- whole-WAF skip; signal caller to short-circuit
    end
    if not skip_ids then skip_ids = {} end
    for _, id in ipairs(row.rule_ids) do
      local n = tonumber(id)
      if n then skip_ids[n] = true end
    end
    return false
  end
  for _, r in ipairs(wx.hosts) do
    if consider(host, r) then return true, nil end
  end
  for _, r in ipairs(wx.paths) do
    if consider(uri, r) then return true, nil end
  end
  return false, skip_ids
end

-- Back-compat shim: callers that just need the bool answer (existing
-- behavior was "skip whole WAF or not"). True only for whole-WAF excludes,
-- never for rule-scoped ones.
local function waf_is_excluded(host, uri)
  local skip_all, _ = waf_skip_for(host, uri)
  return skip_all
end

-- ─────────────────────────────────────────────────────────────────────────────
-- GEO LOOKUP (lazy, per-worker singleton — see cfm_geo.lua)
--
-- This is one of the two PITFALL: access_by_lua_file fixes documented
-- at the top of this file. The geo state lives in cfm_geo.lua because
-- `mmdb.init` opens an FFI mmap that Lua's GC won't release — a
-- per-request init was the cause of the 13 GB GeoIP mmap leak observed
-- on virgo 2026-05-09. The require'd module's state survives across
-- requests via package.loaded so init runs exactly once per worker.
local geo_ok, geo = pcall(require, "cfm_geo")
local function geo_country(ip_str)
  if not geo_ok or type(geo) ~= "table" or type(geo.country) ~= "function" then
    return ""
  end
  return geo.country(ip_str)
end

-- ─────────────────────────────────────────────────────────────────────────────
-- GEO CACHE  (shared-dict layer over the per-worker mmdb lookup)
-- ─────────────────────────────────────────────────────────────────────────────

-- geo_country() performs a MaxMind DB lookup on every call.  Cache the result
-- per source IP in cfm_decisions with a 5-minute TTL.  This eliminates repeated
-- lookups for the same IP across concurrent requests and across the 12-second
-- decision-cache window, which is especially important at high concurrency.
-- SH:get returns nil for a missing key; "" is a valid cached value meaning
-- "no country found", so we use nil as the cache-miss sentinel.
local function geo_country_cached(ip_str)
  if not SH or not ip_str or ip_str == "" or ip_str == "-" then
    return geo_country(ip_str)
  end
  local k      = "geo|" .. ip_str
  local cached = SH:get(k)
  if cached ~= nil then return cached end
  local cc = geo_country(ip_str) or ""
  SH:set(k, cc, 300)   -- 5-minute TTL
  return cc
end

-- ─────────────────────────────────────────────────────────────────────────────
-- MAIN ENFORCEMENT
-- ─────────────────────────────────────────────────────────────────────────────

local ip      = real_ip()
local peer_ip = ngx.var.realip_remote_addr or ""
local cf_ip   = ngx.var.http_cf_connecting_ip or ""
local host    = ngx.var.host   or "-"
local uri     = ngx.var.uri    or "-"
local method  = ngx.req.get_method() or "-"
local scheme  = ngx.var.scheme or "http"

local function origin_pass_for(s_in)
  local dst = ngx.var.server_addr or "127.0.0.1"
  return (s_in == "https" and "https://" or "http://") .. dst ..
         (s_in == "https" and ":443" or ":80")
end

-- ── Step 0: Static IP/CIDR bypass ───────────────────────────────────────────
do
  if ngx.var.cfm_bypass_ip == "1" then
    ngx.var.cfm_upstream = "cfm_apache"; ngx.var.cfm_pass = origin_pass_for(scheme)
    return
  end
end

-- ── Step 0: cPanel / webmail targeted bypass ──────────────────────────────────
do
  local function panel_challenge_policy_active(h)
    local mode = lower(ngx.var.cfm_panel_challenge_mode or "")
    if mode == "forced" then return true end

    -- If nginx maps host policy state into one of these vars, honor it.
    local host_policy = lower(
      ngx.var.cfm_panel_challenge_host
      or ngx.var.cfm_panel_challenge_policy
      or ngx.var.cfm_challenge_vhost
      or ""
    )
    if host_policy == "1" or host_policy == "on" or host_policy == "true"
       or host_policy == "active" or host_policy == "forced" or host_policy == "challenge" then
      return true
    end

    local mode_by_host = lower(ngx.var.cfm_panel_challenge_host_mode or "")
    if mode_by_host == "forced" or mode_by_host == "challenge" or mode_by_host == "active" then
      return true
    end

    return false
  end

  local h = lower(host); local u = lower(uri)
  local pfx = h:match("^([^%.]+)%.")

  local is_panel_host = (pfx == "cpanel" or pfx == "webmail" or pfx == "whm" or pfx == "mail")
  local is_panel_uri  = (u:sub(1, 7) == "/cpanel") or (u:sub(1, 8) == "/webmail") or (u:sub(1, 4) == "/whm")
  local panel_like_req = is_panel_host or is_panel_uri

  -- Keep Step 0 bypass only for explicit trusted/internal controls.
  local explicit_trusted_bypass = (ngx.var.cfm_panel_trusted_bypass == "1") or (ngx.var.cfm_bypass_panel == "1")

  if panel_like_req and explicit_trusted_bypass and not panel_challenge_policy_active(h) then
    ngx.var.cfm_upstream = "cfm_apache"; ngx.var.cfm_pass = origin_pass_for(scheme)
    return
  end
end

-- ── Step 0a: Local-origin hard bypass ────────────────────────────────────────
do
  local p = peer_ip; local has_cf = cf_ip ~= ""; local srv = ngx.var.server_addr or ""
  if is_self_origin(ip) then
    ngx.header["X-CFM-Bypass"] = "self_ip"
    log_route(ngx.INFO, "bypass=self_ip ip=" .. tostring(ip) .. " peer=" .. tostring(peer_ip) .. " host=" .. host)
    ngx.var.cfm_upstream = "cfm_apache"; ngx.var.cfm_pass = origin_pass_for(scheme)
    return
  end
  if not has_cf and p ~= "" then
    p = normalize_ip(p)
    local b2 = tonumber(p:match("^172%.(%d+)%."))
    if (p == normalize_ip(srv))
       or (p:sub(1, 8) == "192.168.") or (p:sub(1, 3) == "10.")
       or (b2 and b2 >= 16 and b2 <= 31) then
      ngx.var.cfm_upstream = "cfm_apache"; ngx.var.cfm_pass = origin_pass_for(scheme)
      return
    end
  end
  if has_cf and srv ~= "" and normalize_ip(ip) == normalize_ip(srv) then
    ngx.var.cfm_upstream = "cfm_apache"; ngx.var.cfm_pass = origin_pass_for(scheme)
    return
  end
end


-- ─────────────────────────────────────────────────────────────────────────────
-- [R2] pcall wrapper: Steps 1–4 wrapped so any error defaults to Apache.
-- ─────────────────────────────────────────────────────────────────────────────
local function cfm_enforce()

-- ── POST resume ──────────────────────────────────────────────────────────────
try_apply_post_resume(ip, host)
method = ngx.req.get_method() or method
uri    = ngx.var.uri          or uri

-- ── Step 1: Validate clearance (do NOT allow yet — WAF runs first) ──────────
-- cfm_clearance proves the client passed the challenge gate. It does not
-- prove the payload is safe, so the allow-to-origin is deferred until after
-- WAF inspection in Step 2. The validation result is captured in
-- `clearance_allow` and `ngx.ctx.cfm_clearance_ok` so downstream steps and
-- the post-clearance WAF challenge converter can see it.
local clearance_scope = "web"
local clearance_cookie = ngx.var.cookie_cfm_clearance
local clearance_ok, clearance_status = validate_clearance_token(clearance_cookie, ip, host, clearance_scope)
if CFG.debug_headers then ngx.header["X-CFM-Clearance"] = clearance_status end
local clearance_allow = clearance_ok and not ngx.ctx.cfm_resumed_post
ngx.ctx.cfm_clearance_ok = clearance_allow

-- ── Step 2: Inline WAF ───────────────────────────────────────────────────────
-- Runs even when clearance is valid: a solved challenge does not authorise
-- exploit payloads, and a logonly hit must not silently let a webshell
-- upload through just because the client is browser-capable.
if waf_ok and waf and waf.enabled and waf.enabled() then
  local skip_all, skip_rule_ids = waf_skip_for(host, uri)
  if skip_all then
    if CFG.debug_headers then ngx.header["X-CFM-WAF-Excluded"] = "1" end
  else
    if CFG.debug_headers and skip_rule_ids then
      -- Visibility for operators tuning per-vhost rule exclusions. Sorted
      -- output makes the header diffable across requests.
      local ids = {}
      for id in pairs(skip_rule_ids) do ids[#ids+1] = id end
      table.sort(ids)
      ngx.header["X-CFM-WAF-Skip-Rules"] = table.concat(ids, ",")
    end
    local req_headers = ngx.req.get_headers()
    local req_body    = get_req_body_for_waf(uri, method, CFG.waf_body_max_len)
    local self_origin = is_self_origin(ip)
    local hit, reason, ttl, waf_action, _waf_hits, waf_rule_id = waf.check({
      uri = uri, args = ngx.var.args or "", method = method,
      host = host, ip = ip, cookie = ngx.var.http_cookie or "",
      peer = peer_ip, cf_ip = cf_ip, shdict = SH,
      headers = req_headers, body = req_body, self_origin = self_origin,
      skip_rule_ids = skip_rule_ids,
    })
    -- Hit-rate denominator: every WAF inspection counts, regardless of
    -- whether a rule fired. maybe_flush_waf_insp piggybacks on the request
    -- to push the snapshot to Go without needing an init_worker timer.
    waf_insp_incr(host)
    maybe_flush_waf_insp()
    if clamav_ok then clamav.notify(ip, hit and reason or nil) end
    if hit then
      waf_action = waf_action or "challenge"
      local p_host = ngx.var.host or host
      local p_uri  = ngx.var.request_uri or uri
      local p_meth = method

      -- Post-clearance challenge-loop prevention: if the request already
      -- holds a valid cfm_clearance, re-challenging is pointless. Delegate
      -- the conversion to cfm_waf so the high-risk reason classifier stays
      -- next to the WAF code that emits the reason strings.
      local converted_from_challenge = false
      if clearance_allow and waf and waf.post_clearance_action then
        local converted, did_convert = waf.post_clearance_action(
          waf_action, reason,
          CFG.waf_after_clearance_challenge,
          CFG.waf_after_clearance_high_risk)
        if did_convert then
          log_route(ngx.INFO, "waf_post_clearance_convert ip=" .. ip ..
            " reason=" .. tostring(reason) ..
            " from=challenge to=" .. tostring(converted))
          waf_action = converted
          converted_from_challenge = true
          if CFG.debug_headers then ngx.header["X-CFM-WAF-Converted"] = converted end
        end
      end

      if waf_action == "logonly" then
        ngx.header["X-CFM-Action"] = converted_from_challenge and "logonly_pc" or "logonly"
        if clearance_allow then
          refresh_clearance_cookie(clearance_cookie, ip, host, clearance_scope)
          touch_ok_scoped(ip, host, clearance_scope)
        end
        ngx.var.cfm_upstream = "cfm_apache"; ngx.var.cfm_pass = origin_pass_for(scheme)
      elseif waf_action == "block" then
        ngx.header["X-CFM-Action"] = converted_from_challenge and "block_pc" or "block"
        ngx.var.cfm_upstream = "cfm_block"; ngx.var.cfm_pass = ""
        observe_waf(ip, host, p_uri, p_meth, 403, reason)
      else -- challenge (only reachable when clearance_allow == false)
        if ngx.ctx.cfm_resumed_post then
          ngx.header["X-CFM-Action"] = "block_replayed"
          ngx.var.cfm_upstream = "cfm_block"; ngx.var.cfm_pass = ""
          observe_waf(ip, host, p_uri, p_meth, 403, "REPLAYED_POST_RECHALLENGED")
          return ngx.exit(CFG.block_code)
        end
        local rtok, rerr = store_post_resume(ip, host, ngx.var.request_uri or uri, method)
        if rtok then
          ngx.header["X-CFM-Action"] = "challenge_resume"
          ngx.header["Cache-Control"] = "no-store"
          return ngx.redirect("/?next=" .. esc(with_query_arg((ngx.var.request_uri or uri), "cfm_rt", rtok)), ngx.HTTP_SEE_OTHER)
        end
        ngx.header["X-CFM-Action"] = "challenge"
        ngx.var.cfm_upstream = "cfm_challenge"; ngx.var.cfm_pass = "http://cfm_challenge"
      end

      if waf.should_push and waf.should_push(SH, ip, reason) then
        -- Forensic fields (UA / Referer / Content-Type) are always
        -- attached. The single cfm.waf.log now emits one JSON record
        -- per trigger carrying everything Go knows: timestamp, action,
        -- TTL, ASN/country enrichment + these per-request headers.
        local push = {
          ip = ip, action = waf_action, ttl_sec = ttl or 600,
          reason = reason, host = p_host, uri = p_uri, method = p_meth,
          waf_rule_id  = waf_rule_id,
          ua           = req_headers["user-agent"],
          referer      = req_headers["referer"],
          content_type = req_headers["content-type"],
        }
        rpc_call("ip_push", "POST", "/nginx/ip", cjson.encode(push),
          { ip = ip, host = p_host, uri = p_uri, method = p_meth })
      end
      log_route(ngx.INFO, "waf_" .. waf_action .. " ip=" .. ip .. " host=" .. host ..
        " reason=" .. tostring(reason) ..
        (waf_rule_id and (" waf_rule_id=" .. tostring(waf_rule_id)) or ""))
      if waf_action == "block" then return ngx.exit(CFG.block_code) end
      return
    end
  end
end
if not waf_ok and clamav_ok then clamav.notify(ip, nil) end

-- ── Step 2b: Honour clearance allow (deferred from Step 1) ──────────────────
-- WAF either passed cleanly or is disabled/excluded for this host. Now we
-- can safely apply the clearance fast-path: refresh the cookie, touch the
-- ok cache, and route to origin. This intentionally short-circuits the
-- forced-challenge and bridge-decision steps below — clearance means
-- "don't repeatedly challenge this client for the same gate."
if clearance_allow then
  refresh_clearance_cookie(clearance_cookie, ip, host, clearance_scope)
  touch_ok_scoped(ip, host, clearance_scope)
  ngx.header["X-CFM-Action"] = "allow_cookie"
  ngx.var.cfm_upstream = "cfm_apache"; ngx.var.cfm_pass = origin_pass_for(scheme)
  return
end

-- ── Step 2.5: Forced challenge for marked locations ──────────────────────────
-- Triggered via `set $cfm_force_challenge 1;` in nginx location blocks
-- (e.g. /cfm-admin/login). Runs AFTER WAF so rules still inspect the request,
-- and is skipped entirely when a valid cfm_clearance cookie is present
-- (Step 2b above returns before we reach this block).
if ngx.var.cfm_force_challenge == "1" then
  ngx.header["X-CFM-Action"]  = "challenge_forced"
  ngx.header["Cache-Control"] = "no-store"
  ngx.var.cfm_upstream = "cfm_challenge"
  ngx.var.cfm_pass     = "http://cfm_challenge"
  log_route(ngx.INFO, "challenge_forced ip=" .. ip .. " host=" .. host .. " uri=" .. uri)
  return
end

-- ── Step 3: Bridge Decision ──────────────────────────────────────────────────
-- [R1] ua + country passed so Go can evaluate traffic rules.
local ua_raw  = ngx.var.http_user_agent or ""
local country = geo_country_cached(ip)
local d       = get_decision(ip, host, uri, method, scheme, ua_raw, country, clearance_scope)

local ip_action        = d.ip_action        or "allow"
local vh_action        = d.vhost_action      or "allow"
local rule_action      = d.rule_action       or nil
local rule_id          = d.rule_id           or ""
local throttle_profile = d.throttle_profile  or ""
local cache_flag       = d._cache and " cache=1" or ""

if CFG.debug_headers then
  ngx.header["X-CFM-IP"] = ip; ngx.header["X-CFM-Host"] = host
  ngx.header["X-CFM-Dec-IP"] = ip_action; ngx.header["X-CFM-Dec-VH"] = vh_action
  if rule_action then ngx.header["X-CFM-Dec-Rule"] = rule_action end
  if rule_id ~= "" then ngx.header["X-CFM-Rule-ID"] = rule_id end
  if throttle_profile ~= "" then ngx.header["X-CFM-Throttle"] = throttle_profile end
  if d.err then ngx.header["X-CFM-Err"] = tostring(d.err) end
  if d._cache then ngx.header["X-CFM-Cache"] = "1" end
end

-- Block
if ip_action == "block" or vh_action == "block" or rule_action == "block" then
  ngx.header["X-CFM-Action"] = "block"
  ngx.var.cfm_upstream = "cfm_block"; ngx.var.cfm_pass = ""
  log_route(ngx.WARN, "block ip=" .. ip .. " host=" .. host .. cache_flag ..
    (rule_id ~= "" and (" rule_id=" .. rule_id) or ""))
  return ngx.exit(CFG.block_code)
end

-- Challenge
if ip_action == "challenge" or vh_action == "challenge" or rule_action == "challenge" then
  if ngx.ctx.cfm_resumed_post then
    ngx.header["X-CFM-Action"] = "block_replayed"
    ngx.var.cfm_upstream = "cfm_block"; ngx.var.cfm_pass = ""
    return ngx.exit(CFG.block_code)
  end
  local rtok, rerr = store_post_resume(ip, host, ngx.var.request_uri or uri, method)
  if rtok then
    ngx.header["X-CFM-Action"] = "challenge_resume"; ngx.header["Cache-Control"] = "no-store"
    return ngx.redirect("/?next=" .. esc(with_query_arg((ngx.var.request_uri or uri), "cfm_rt", rtok)), ngx.HTTP_SEE_OTHER)
  end
  ngx.header["X-CFM-Action"] = "challenge"
  ngx.var.cfm_upstream = "cfm_challenge"; ngx.var.cfm_pass = "http://cfm_challenge"
  log_route(ngx.INFO, "challenge ip=" .. ip .. " host=" .. host .. cache_flag)
  return
end

-- [R1] Throttle
if rule_action == "throttle" then
  if rules_ok and rules and rules.apply then
    local r = rules.apply({ rule_action = rule_action, throttle_profile = throttle_profile },
      { ip = ip, host = host, uri = uri, method = method, profile = throttle_profile })
    if r and r.action == "throttle" then
      ngx.header["X-CFM-Action"] = "throttle"
      if r.retry_after and tonumber(r.retry_after) then
        ngx.header["Retry-After"] = tostring(math.max(1, math.floor(tonumber(r.retry_after))))
      end
      log_route(ngx.WARN, "throttle ip=" .. ip .. " host=" .. host ..
        (rule_id ~= "" and (" rule_id=" .. rule_id) or ""))
      return ngx.exit(429)
    end
  else
    ngx.header["X-CFM-Action"] = "throttle"; ngx.header["Retry-After"] = "5"
    return ngx.exit(429)
  end
end

-- ── Step 4: Allow ────────────────────────────────────────────────────────────
ngx.header["X-CFM-Action"] = "allow"
ngx.var.cfm_upstream = "cfm_apache"; ngx.var.cfm_pass = origin_pass_for(scheme)
if CFG.log_allows or CFG.debug then
  log_route(ngx.INFO, "allow ip=" .. ip .. " host=" .. host .. " pass=" .. ngx.var.cfm_pass .. cache_flag)
end

end -- cfm_enforce()

local function main()
  return cfm_enforce()
end

local ok, err = xpcall(main, debug.traceback)
if not ok then
  local req_id = ngx.var.request_id or "-"
  local client = ngx.var.remote_addr or "-"
  local host_v = ngx.var.host or "-"
  local uri_v = ngx.var.request_uri or ngx.var.uri or "-"
  ngx.log(ngx.ERR, "[cfm] request_failure",
    " request_id=", req_id,
    " client=", client,
    " host=", host_v,
    " uri=", uri_v,
    " policy=", (CFG.fail_open and "fail_open" or "fail_closed"),
    " stack=", tostring(err))
  if CFG.fail_open then
    ngx.var.cfm_upstream = "cfm_apache"
    ngx.var.cfm_pass     = origin_pass_for(ngx.var.scheme)
    return
  end
  return ngx.exit(ngx.HTTP_INTERNAL_SERVER_ERROR)
end

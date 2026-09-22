-- /var/lib/cfm/lua/cfm.lua (CFM-managed canonical location)
--
-- CFM OpenResty in-path enforcement
-- Based on the proven Mars version with minimal additions:
--   [R1] Traffic rules: ua/country passed to bridge, rule_action/throttle handled
--   [R2] pcall fail-open: any uncaught Lua error defaults to serving via Apache
--   [R3] cfm_rules throttle module support (optional)
--
-- Design principles:
--   - Per-request bridge RPC with a 90-second shared-dict cache for allows
--     (decision_cache_ttl_ms; see the CFG note there)
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
-- Per-worker TTL cache for the small Lua data files read on the hot path
-- (bridge token/config, self-ips, ignore-nets, clamav config). Lives in a
-- require'd module because top-level locals here reset every request —
-- see the PITFALL block above and cfm_filecache.lua for the full story.
local fc = require "cfm_filecache"
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
-- Canonical panel-subdomain prefixes (shared with cfm_panel.lua — single
-- source, no drift). nil on upgrade lag → Step 0 falls back to its old
-- inline list below.
local ok_panel_hosts, panel_hosts = pcall(require, "cfm_panel_hosts")
if not ok_panel_hosts then panel_hosts = nil end

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
-- Both the token and the runtime knobs come through the canonical cached
-- accessor (cfm_bridge_cfg → cfm_filecache, 10s TTL / 2s missing-retry):
-- the validity rule and freshness policy live in one module shared by every
-- edge consumer. The token persists in detectors.conf and only rotates when
-- weak (internal/detectors/manager.go), so 10s staleness is safe.
local _bridge = require "cfm_bridge_cfg"

local _bridge_token, _bridge_token_err
if type(_bridge.token) == "function" then
  _bridge_token, _bridge_token_err = _bridge.token()
else
  -- Version skew (this file newer than the cfm_bridge_cfg.lua on disk, or
  -- the old module still cached in package.loaded): fail with a
  -- self-describing message instead of an "attempt to call field 'token'
  -- (a nil value)" traceback.
  _bridge_token_err = "cfm_bridge_cfg has no token() — module set older than cfm.lua; redeploy /var/lib/cfm/lua and reload the proxy"
end
-- A missing/unreadable bridge token is NOT fatal (audit F47). access_by_lua_file
-- re-runs this whole chunk per request, so error()ing here returned HTTP 500 for
-- EVERY request while the token was absent — e.g. on a reboot where nginx starts
-- before the cfm daemon writes the token. That fail-CLOSED behaviour also diverged
-- from the present-but-unreachable-daemon case (which fails OPEN under
-- CFG.fail_open) purely on token-file presence. Operator decision (F47): keep the
-- two uniform and NEVER interrupt service — a missing token now flows through the
-- SAME fail_decision() path in get_decision() (fail-open by default), logged
-- loudly but throttled so it is visible, and recovers on its own once the daemon
-- writes the token (cfm_bridge_cfg missing-retry). CFG.token stays nil: rpc_call()
-- omits the auth header (so other bridge RPCs just fail-and-degrade), and the
-- clearance mint/validate paths fail CLOSED on the resulting nil secret (mint
-- returns missing_secret and falls back to the original cookie; validate rejects
-- with missing_secret so a forged empty-key clearance can't validate — see
-- cfm_clearance.lua). `_bridge_token_err` is kept for the get_decision log line.

-- Webdetector → Lua runtime knobs (sibling file to the bridge token).
-- Optional: if the file is missing or unloadable we fall back to safe defaults
-- so an upgrade lag (cfm daemon old, Lua new) doesn't break the request path.
-- Operator edits propagate within the 10s cache TTL (see cfm_bridge_cfg.lua).
local _bridge_cfg = _bridge.get()


-- ─────────────────────────────────────────────────────────────────────────────
-- CONFIG
-- ─────────────────────────────────────────────────────────────────────────────
-- The request-INVARIANT fields (env reads + constants) are built ONCE per
-- worker in cfm_cfg.lua (require'd, so its body runs once and persists in
-- package.loaded). access_by_lua_file re-runs THIS chunk per request, so the old
-- inline CFG literal re-read ~21 os.getenv() and re-allocated temp tables + a
-- closure every request; those inputs are process-lifetime constants (and the
-- CFM_* knobs are never set — nginx strips env vars not declared with `env` —
-- so they always take the defaults), making the once-per-worker read
-- byte-identical. See cfm_cfg.lua.
--
-- Only the bridge-derived fields stay per-request: they refresh on the
-- bridge file's 10s TTL (_bridge_token / _bridge_cfg via cfm_bridge_cfg), so an
-- operator toggle (ORIGIN_KEEPALIVE, clearance refresh, cookie life) still takes
-- effect within 10s instead of freezing at worker start. They ride a small
-- per-request table whose metatable __index falls through to the static module,
-- so every existing `CFG.<field>` read is unchanged. CFG is only ever
-- field-READ (never iterated with pairs), and the single in-place mutation —
-- cfm_decision's `cfg.token = fresh` on a token rotation — writes the `token`
-- key that lives in THIS top table, so it never mutates the shared static module.
local _cfg_static = require "cfm_cfg"
local CFG = setmetatable({
  token             = _bridge_token,
  ok_ttl_sec        = _cfg_static.resolve_ok_ttl(_bridge_cfg.cookie_life_sec),
  -- Sliding clearance: when true, accepted requests re-mint cfm_clearance with
  -- exp = now + ok_ttl_sec so active panel/webmail users don't get re-challenged
  -- mid-session. Sourced from [webdetector] CHALLENGE_COOKIE_REFRESH via
  -- /var/lib/cfm/lua/cfm_bridge_config.lua. Defaults to true.
  clearance_refresh = _bridge_cfg.clearance_refresh,
  -- Opt-in origin keepalive: route allow-traffic through the
  -- cfm_origin_http/cfm_origin_https upstream blocks (pooled backend
  -- connections) instead of a fresh proxy_pass connection per request. Single
  -- knob: detectors.conf [webdetector] ORIGIN_KEEPALIVE, published via
  -- cfm_bridge_config.lua (field absent on older daemons = off). Routing also
  -- requires the live proxy conf to declare the cfm_origin_* upstreams — see the
  -- $cfm_origin_ka_conf sentinel in origin_pass_for(). Default OFF. See
  -- cfm_origin_ka.lua and docs/proxy-performance.md.
  origin_keepalive  = (_bridge_cfg.origin_keepalive == true),
  -- Fingerprint-policy edge gate (Step 0c). Bridge-derived, 10s TTL: flipping
  -- [webdetector] FP_POLICY=0 removes the WHOLE per-request Step-0c cost
  -- (tlsfp tuple build + md5 + dict + any /nginx/fppolicy lookup), not just
  -- the daemon's answers. Default on (nil/absent → true), fail-safe idiom.
  fp_policy = (_bridge_cfg.fp_policy ~= false),
}, { __index = _cfg_static })

local clamav_ok, clamav = pcall(require, "cfm_clamav")
if clamav_ok then
  -- Hook on/off lives in /var/lib/cfm/lua/cfm_clamav_config.lua, written
  -- by the cfm daemon on every cfm.conf reload (CLAMD_ENABLED &&
  -- CLAMD_NGINX_HOOK_ENABLED). Missing/unloadable file falls back to
  -- enabled=true so an upgrade lag (cfm daemon old, Lua new) does not
  -- silently turn the hook off. Cached (10s TTL) via cfm_filecache so the
  -- toggle no longer costs a loadfile() on every request.
  local _CLAMAV_CONFIG_FILE = "/var/lib/cfm/lua/cfm_clamav_config.lua"
  local clamav_hook_enabled = true
  local clamav_scan_default = false
  local clamav_scan_mode = "async"
  local clamav_inline_timeout_ms = 3000
  do
    local val = fc.get(_CLAMAV_CONFIG_FILE, {
      ttl = 10,
      transform = function(v)
        if type(v) ~= "table" then error("did not return a table") end
        -- enabled fails SAFE to true (upgrade lag must not silently disable the
        -- hook); scan_default fails SAFE to false — if the rendered config is
        -- missing/corrupt we do NOT scan (conservative in an unknown state; the
        -- ON deploy default lives in the Go config, not this degraded fallback).
        -- scan_mode fails SAFE to async — blocking must never arm through a
        -- corrupt render.
        return {
          enabled           = (v.enabled ~= false),
          scan_default      = (v.scan_default == true),
          scan_mode         = (v.scan_mode == "inline") and "inline" or "async",
          inline_timeout_ms = tonumber(v.inline_timeout_ms) or 3000,
        }
      end,
    })
    if type(val) == "table" then
      clamav_hook_enabled = val.enabled
      clamav_scan_default = val.scan_default
      clamav_scan_mode = val.scan_mode
      clamav_inline_timeout_ms = val.inline_timeout_ms
    end
  end
  clamav.init({
    token             = CFG.token,
    sock_path         = CFG.sock_path,
    enabled           = clamav_hook_enabled,
    scan_default      = clamav_scan_default,
    scan_mode         = clamav_scan_mode,
    inline_timeout_ms = clamav_inline_timeout_ms,
  })
end

-- [R3] cfm_rules is optional (throttle enforcement)
local rules_ok, rules = pcall(require, "cfm_rules")
if rules_ok and rules and rules.init then rules.init(CFG) end

-- Box-wide UA emergency rules. The module reads /var/lib/cfm/ua_emergency.json
-- lazily (per-worker, 3s refresh interval). When pcall fails, the check is
-- silently disabled and traffic flows through the normal pipeline.
local ua_emerg_ok, ua_emerg = pcall(require, "cfm_ua_emergency")

-- WAF module loaded once at worker init, not on every request.
-- pcall here behaves identically to the previous per-request pcall:
-- a load failure sets waf_ok=false and disables inline WAF checks.
local waf_ok, waf = pcall(require, "cfm_waf")

-- cfm_waf_util is a dependency of cfm_waf (already loaded); require it directly
-- for the pure ct_is_inspectable() classifier used by the body-read gate (F07).
-- If it fails to load, the F07 Content-Type branch fails closed (skips the read).
local wutil_ok, wutil = pcall(require, "cfm_waf_util")

-- HTTP/3 Alt-Svc emission is intentionally NOT hooked here. It lives in a
-- server-level header_filter_by_lua_block (see angie.conf / openresty.conf)
-- so every served response is covered regardless of which allow path fires
-- (Step 4, clearance-cookie fast-path, panel/self-IP bypass, ...). Wiring
-- it into the access phase would silently miss the clearance-cookie path
-- — which is the bulk of real production traffic on logged-in vhosts.

local SH = ngx.shared.cfm_decisions

-- ─────────────────────────────────────────────────────────────────────────────
-- UTILS
-- ─────────────────────────────────────────────────────────────────────────────

-- Neutralise ASCII control characters (NUL, C0 controls incl. CR/LF, DEL)
-- before they reach a log line. The live vector is ngx.var.uri, which nginx
-- serves percent-DECODED, so a request path with %0A/%0D decodes to a literal
-- newline inside `uri`; ngx.log does not sanitize, so an unauthenticated client
-- could otherwise forge extra "[cfm] ..." lines into error.log (F39).
-- (Sanitising $host/scope too is defence-in-depth: nginx's validate_host
-- already rejects control bytes in $host and scope is a controlled enum, but
-- it's cheap and keeps every logged value safe if some future value isn't
-- pre-validated.) Hex-escaping keeps the byte visible for forensics without
-- breaking one-line-per-event parsing. The find-first guard keeps the hot
-- path allocation-free for the normal (clean) case.
local function log_sanitize(s)
  if type(s) ~= "string" then return s end
  if s:find("[%z\1-\31\127]") then
    s = s:gsub("[%z\1-\31\127]", function(c) return string.format("\\x%02X", c:byte()) end)
  end
  return s
end
-- log_route is the hot path (one call per allow/challenge/block decision); the
-- caller pre-concatenates `msg`, so a single sanitize of the whole string is
-- the cheapest complete neutralisation (no per-arg table churn).
local function log_route(level, msg) ngx.log(level or ngx.WARN, "[cfm] ", log_sanitize(msg)) end
-- log_ev: ngx.log that neutralises control chars in EVERY argument, for the few
-- multi-arg direct-ngx.log sites (cold error paths) that log user-controlled
-- fields (host/uri/scope) without pre-concatenating — so those call sites can't
-- forge a "[cfm] ..." line either (F39). Unlike log_route it does NOT prepend
-- "[cfm] " — callers put the prefix in their first argument. ngx.log
-- concatenates its varargs; pre-sanitising each keeps a clean message
-- byte-identical.
local function log_ev(level, ...)
  local n = select("#", ...)
  local parts = {}
  for i = 1, n do
    local v = select(i, ...)
    parts[i] = log_sanitize(type(v) == "string" and v or tostring(v))
  end
  return ngx.log(level, table.concat(parts))
end
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

-- Self-origin / IGNORE_NETS bypass predicate — extracted to cfm_selfip so the
-- web edge and cfm_panel.lua share ONE implementation (no drift; §5). The module
-- encapsulates the cfm_filecache-backed self-ips + ignore-nets caches and the
-- loopback/link-local rule; see cfm_selfip.lua for the fc-cache PITFALL and the
-- IGNORE_NETS semantics. Deployed by the installer manifest, so require is safe.
local selfip = require("cfm_selfip")
local normalize_ip = selfip.normalize_ip
local is_self_origin = selfip.is_self_origin

-- ─────────────────────────────────────────────────────────────────────────────
-- WAF BODY INSPECTION
-- ─────────────────────────────────────────────────────────────────────────────

local function waf_should_read_body(uri, method)
  uri    = lower(uri    or "")
  method = lower(method or "")
  if method ~= "post" and method ~= "put" and method ~= "patch" then return false end

  -- A resumed POST (challenge replay, try_apply_post_resume) carries a body we
  -- captured and re-injected via ngx.req.set_body_data. Its length lives in the
  -- request's content_length_n, NOT in the $http_content_length HEADER the gate
  -- below reads — the resume carrier was a bodiless GET, so that header is nil and
  -- waf_body_gate() would return false on a clean-URL / non-allowlisted route,
  -- skipping WAF body inspection entirely. The captured body is bounded
  -- (post_resume_max_len) and already in memory, so inspect it on the SAME terms as
  -- any other POST (get_req_body_for_waf still caps the scan at waf_body_max_len)
  -- instead of skipping it wholesale — otherwise a solved-challenge client could
  -- replay a body-borne payload to a clean-URL route with no body inspection at all.
  if ngx.ctx.cfm_resumed_post then return true end

  local ct = lower(ngx.var.http_content_type or "")
  local cl = tonumber(ngx.var.http_content_length or "")

  -- F07: PUT/PATCH were NOT body-inspected before this change (the gate was
  -- POST-only), so there is no legacy "read regardless of size" expectation for
  -- them — bounding them now is strictly safer than the pre-F07 baseline. Route
  -- them through the size/CT gate BEFORE the POST allowlist so a large REST
  -- `PUT /uploads/x.zip` (which the allowlist would otherwise wave through)
  -- keeps STREAMING on a proxy_request_buffering=off location instead of being
  -- force-buffered just to scan its first waf_body_max_len bytes.
  if method ~= "post" then
    return wutil_ok and wutil.waf_body_gate(ct, cl, CFG.waf_body_read_max_cl) or false
  end

  -- POST: known-dynamic endpoints are read regardless of size. This is the
  -- pre-F07 status quo (these paths were already read+buffered), preserved
  -- verbatim so F07 introduces ZERO behavioural change for existing POST flows.
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
  -- F07: the allowlist above is a fast-path for known-dynamic endpoints. Beyond
  -- it, still inspect body-borne payloads on ANY other POST — extension-less /
  -- clean-URL app routes (/checkout, /order, /cart, custom routers) — which the
  -- old positive allowlist let smuggle a body-borne SQLi/RCE/webshell past the
  -- WAF entirely (the Go log engine sees no body). Gate on an inspectable
  -- Content-Type + a measured, bounded Content-Length so binary/media uploads
  -- and chunked/streaming bodies keep STREAMING (never force-buffer the
  -- proxy_request_buffering=off media location) and we don't buffer a large body
  -- just to scan its first waf_body_max_len bytes.
  return wutil_ok and wutil.waf_body_gate(ct, cl, CFG.waf_body_read_max_cl) or false
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
  -- multipart/form-data joined the allowlist 2026-07-21: ticket/forum forms
  -- with a (often unused) file field submit multipart, and a challenged reply
  -- was lost because only the challenge-server no-replay fallback ran. Replay
  -- is byte-identical (raw body + the original Content-Type keeps the
  -- boundary), so the origin reparses it fine. The post_resume_max_len cap
  -- (64KB default) still governs: a text-only reply fits; a real attachment
  -- overflows the cap (or spools to disk, where get_body_data returns nil)
  -- and falls back to no_replay exactly as before — the shared-dict memory
  -- posture is unchanged.
  if has(ct, "multipart/form-data") then return true end
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
  -- Cheap presence gate BEFORE the full query-string parse: ngx.var.arg_cfm_rt
  -- reads just this one arg without building the whole args table. The vast
  -- majority of GETs carry no cfm_rt (it rides only on our post-challenge resume
  -- redirect), so bail here before get_uri_args() parses+allocates. Behaviour-
  -- identical: an absent/empty cfm_rt made the old code fall through to tok=""
  -- and return false anyway; a raw non-empty value can only mean a present arg,
  -- so this never skips a real resume token (exact value extraction stays below).
  if (ngx.var.arg_cfm_rt or "") == "" then return false end
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
  -- set_body_data() requires the current request body to have been read first,
  -- or it raises "request body not read yet". The resume carrier is a bodiless
  -- GET (/…?cfm_rt=…), and nothing reads its (absent) body before this point —
  -- the WAF body-read gate only fires for POST/PUT/PATCH, not this GET. Without
  -- this read_body() the set_body_data() below THROWS; the access phase runs
  -- under xpcall+fail_open, so the throw is swallowed and the request proceeds
  -- as the original GET with NO body — post.php then sees an empty submit and
  -- WordPress bounces to edit.php, silently losing the user's save. read_body()
  -- on a bodiless GET is a cheap no-op that marks the body read; it must run
  -- BEFORE set_body_data(). Idempotent w.r.t. a later WAF body-read on the now
  -- POST-shaped request.
  ngx.req.read_body()
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

-- Bridge decision-RPC client (unix-socket transport + /nginx/decision verdict
-- with clean-allow caching) lives in cfm_decision.lua. Forward-declared here
-- and constructed once below, after its injected hooks (is_static_asset_uri,
-- real_ip, log_route, the token-refresh hook) are defined; the RPC callers
-- defined between here and the construction capture it as an upvalue.
local decision


-- ─────────────────────────────────────────────────────────────────────────────
-- HELPERS
-- ─────────────────────────────────────────────────────────────────────────────

local function observe_waf(ip, host, uri, method, status, reason, waf_rule_id)
  if not ip or ip == "" then return end
  decision:rpc("observe", "POST", "/nginx/observe", cjson.encode({
    ip = ip, host = host or "", uri = uri or "/",
    method = method or "", status = status or 403, reason = reason or "",
    waf_rule_id = waf_rule_id,
    ua = string.sub(ngx.var.http_user_agent or "", 1, 256),
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
  -- Bound the host used as a bucket key to the DNS maximum (253 octets).
  -- $host is taken untruncated from the request, so on a catch-all/default
  -- vhost a client can send multi-KB Host headers; unclamped, those inflate
  -- both this shdict key and the /nginx/waf/stats flush batch (which the Go
  -- MaxBytesReader would then reject wholesale, dropping co-resident legit
  -- rows). No legitimate FQDN exceeds 253 octets, so this is a no-op for real
  -- traffic.
  if #h > 253 then h = h:sub(1, 253) end
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
    decision:rpc("waf_stats", "POST", "/nginx/waf/stats", cjson.encode({ rows = rows }))
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
  decision:rpc("ok_touch", "POST", "/nginx/ok/touch",
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
      log_ev(ngx.WARN, "[cfm] clearance re-mint failed err=", tostring(mint_err),
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
      log_ev(ngx.ERR,
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



-- Static asset extensions whose bridge verdict is purely a function of
-- (ip, host, scope) — never CHALLENGE_PATHS-eligible (no .git/.env/wp-config
-- has a .png/.css/.woff suffix), no SQLi/XSS surface in the URL itself.
-- For these we share a single cache entry per (ip, host, scope) so a page
-- with 50 embedded assets makes 1 bridge call per visitor per 90s window
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

-- Build the cfm_decisions cache key for a request.
--   * Static assets share ONE coalesced entry per (ip, host, scope) — prefix
--     "ds|", disjoint from the per-URL "d|" namespace.
--   * The per-URL key hashes the FULL decoded path with ngx.md5. The old key
--     used uri:sub(1, 64), so two paths sharing a 64-byte prefix mapped to one
--     entry; since only clean allows are cached, an attacker could warm the
--     cache with a benign same-prefix request and reuse the "allow" for a longer
--     path whose per-path bridge rule would challenge/block — the bridge was
--     never consulted for the second path (audit F38). md5 keeps the key bounded
--     (a path can be kilobytes) while being per-path unique.
--
-- Verdict inputs vs key dimensions: get_decision's RPC also sends ua, country
-- and scope. This key must not conflate two requests the bridge would decide
-- differently, so:
--   * scope IS keyed (both branches) — a scoped verdict is never reused
--     cross-scope. (Today clearance_scope is the constant "web" at the call
--     site, so this is defensive symmetry, not yet load-bearing.)
--   * country is ip-derived (geo_country_cached(ip)) and ip is already keyed,
--     so two key-colliding requests share a country — safe to omit.
--   * the query string IS part of the key (the RPC carries the decoded path in
--     "uri" and the raw query in a separate "qs" param) so traffic rules can
--     match on it. It is folded into the hashed per-URL key below, so a
--     clean-allow warmed by "/x" is never reused for "/x?mode=register" whose
--     query-scoped rule would challenge/block. A query-less request hashes
--     exactly the path (== the old key), so no-query traffic keeps its previous
--     cache entry; static assets still coalesce (is_static_asset_uri strips the
--     query first). Only dynamic endpoints — where query-scoped rules live —
--     pay the extra per-query cache cardinality.
--   * ua IS a verdict input (UAAny traffic rules can block/challenge) yet is
--     deliberately omitted: it is client-controlled (a determined attacker sets
--     any UA anyway), only clean allows are cached, and the TTL is short, so the
--     residual exposure is a benign shared-IP client reusing a browser-warmed
--     allow. Tightening this (fold ngx.md5(ua) in, or skip caching when
--     UA-sensitive rules exist) is a tracked audit follow-up, separate from the
--     F38 path-truncation fix — do not silently assume the key covers ua.
-- Construct the shared bridge decision client now that its injected hooks
-- exist. CFG is passed BY REFERENCE: cfm_decision reads cfg.token live and
-- mutates it in place on a token rotation, exactly as the inline get_decision
-- did (so this file's other bridge RPCs pick up the fresh token too).
decision = require("cfm_decision").new(CFG, {
  shdict       = SH,
  is_static    = is_static_asset_uri,
  real_ip      = real_ip,
  log_route    = log_route,
  on_token_403 = function() return _bridge.refresh_token_throttled(2) end,
  token_path   = _bridge.TOKEN_PATH,
  token_err    = function() return _bridge_token_err end,
})


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
  local body, _ = decision:rpc("waf_excludes", "GET", "/nginx/waf/excludes")
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

-- Exclude value matching lives in cfm_waf_excl (the excludes module) so it is
-- unit-testable and has one canonical Lua home; it mirrors the Go enforcement
-- matcher (internal/webdetector/exclude_store.go compiledValueMatcher). See
-- that module for the host/path boundary semantics.
local matches_rule = wx.matches_rule

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
  local function consider(target, row, kind)
    -- Back-compat: previous Lua versions cached this list as bare strings.
    -- A graceful nginx reload during upgrade can briefly hand the new code
    -- the old cache shape (≤ waf_excl_refresh_sec until the next refresh
    -- overwrites). Treat a string entry as a whole-WAF exclude — its old
    -- meaning — so excludes don't silently lapse during the upgrade window.
    if type(row) == "string" then row = { v = row } end
    if not matches_rule(target, row.v, kind) then return false end
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
    if consider(host, r, "host") then return true, nil end
  end
  for _, r in ipairs(wx.paths) do
    if consider(uri, r, "path") then return true, nil end
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
-- Returns (country, resolved). `resolved` is true only when an mmdb lookup
-- completed (a real code or a definitive ""); false when geo is unavailable or
-- the lookup could not be performed. The module require failing is itself a
-- not-resolved case. See cfm_geo.country.
local function geo_country(ip_str)
  if not geo_ok or type(geo) ~= "table" or type(geo.country) ~= "function" then
    return "", false
  end
  return geo.country(ip_str)
end

-- ─────────────────────────────────────────────────────────────────────────────
-- GEO CACHE  (shared-dict layer over the per-worker mmdb lookup)
-- ─────────────────────────────────────────────────────────────────────────────

-- geo_country() performs a MaxMind DB lookup on every call.  Cache the result
-- per source IP so repeated lookups for the same IP (across concurrent requests
-- and across the decision-cache window) are cheap.
--
-- The cache lives in its OWN shared dict (cfm_geocache), NOT cfm_decisions
-- (audit F25): geo writes one entry per source IP, so under a high-distinct-IP
-- flood they would dominate cfm_decisions and LRU-evict the 90s decision allows
-- AND the abuse counters that also live there (cfm_rules throttle buckets,
-- ua_emergency state, waf-push dedup) — silently weakening rate/abuse protection
-- during exactly the flood the decision cache exists to shed. Isolating geo
-- keeps that eviction pressure off the security state. TTL is aligned to the 90s
-- decision-allow window (was 5 min); geo is stable per-IP, so the extra lookups
-- are a cheap mmap FFI call. gsh:get returns nil for a missing key; "" is a valid
-- cached value meaning "no country found", so nil is the cache-miss sentinel.
--
-- Only a RESOLVED lookup is cached (F25 part 2): geo_country returns a second
-- value that is true only when an mmdb lookup completed (a real code, or ""
-- meaning definitively no country). A not-resolved result — geo down, DB caught
-- mid atomic-rename, or within the retry cooldown — still returns "" fail-open
-- but is NOT cached, so a transient hiccup can't pin an IP's country as "" for
-- the whole TTL; the next request retries (cfm_geo's cooldown bounds any storm).
-- If the dict is absent (a conf not yet reloaded to declare it) fall back to an
-- uncached lookup so geo still works.
local function geo_country_cached(ip_str)
  local gsh = ngx.shared.cfm_geocache
  if not gsh or not ip_str or ip_str == "" or ip_str == "-" then
    return (geo_country(ip_str))
  end
  local k      = "geo|" .. ip_str
  local cached = gsh:get(k)
  if cached ~= nil then return cached end
  local cc, resolved = geo_country(ip_str)
  cc = cc or ""
  if resolved then
    gsh:set(k, cc, 90)   -- cache definitive answers only; aligned to the 90s decision-cache TTL
  end
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
  -- Instrumentation: total access-phase time (header read + all Lua above
  -- + this routing decision) in ms, logged as luams= in the cfm access-log
  -- format. Only stamped on origin-allow paths — challenge/block responses
  -- keep the "-" default. Reading an undeclared nginx var returns nil
  -- (writes would throw), so this degrades cleanly under an older conf
  -- that lacks `set $cfm_lua_ms`.
  if ngx.var.cfm_lua_ms ~= nil then
    ngx.var.cfm_lua_ms = string.format("%.1f", (ngx.now() - ngx.req.start_time()) * 1000)
  end
  -- Opt-in origin keepalive (detectors.conf [webdetector] ORIGIN_KEEPALIVE):
  -- route through the cfm_origin_* upstream blocks. This routes by CLIENT
  -- scheme (below): HTTP goes to cfm_origin_http:80, which cfm_origin_ka.lua
  -- POOLS (reused TCP to Apache). HTTPS goes to cfm_origin_https:443, which is
  -- deliberately NOT pooled — a fresh TCP + TLS/SNI connection per request, to
  -- avoid cross-vhost 443 reuse (Apache 421). So only the HTTP origin hop saves
  -- a connection here; 443 keeps its per-request handshake by design. See
  -- cfm_origin_ka.lua for the full SNI-safety rules (native keepalive off,
  -- Lua pool off on 443, TLS session reuse off).
  --
  -- $cfm_origin_ka_conf is a sentinel set ONLY by proxy confs that declare
  -- the cfm_origin_* upstream blocks. The knob travels the fast channel
  -- (bridge-config file, ~10s) but the upstreams travel the slow one (live
  -- proxy conf + reload); without this guard, arming the knob against an
  -- older live conf would proxy_pass to a nonexistent upstream and 502
  -- every allowed request. With the guard it degrades to direct proxying.
  if CFG.origin_keepalive and ngx.var.cfm_origin_ka_conf == "1" then
    return (s_in == "https") and "https://cfm_origin_https" or "http://cfm_origin_http"
  end
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

  -- Shared canonical list (cfm_panel_hosts.lua); inline fallback for deploy lag.
  local is_panel_host
  if panel_hosts then
    is_panel_host = panel_hosts.is_panel_prefix(pfx)
  else
    is_panel_host = (pfx == "cpanel" or pfx == "webmail" or pfx == "whm" or pfx == "mail")
  end
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

-- ── Step 0a1: /.well-known/ carve-out (ACME + CA HTTP DCV + RFC 8615) ─────────
-- /.well-known/ is the IETF-reserved namespace (RFC 8615) for site-wide
-- validation and metadata. The load-bearing case is domain-control validation,
-- fetched by the CA over plain HTTP and which MUST reach the origin
-- (Apache/cPanel serves the file from the docroot):
--   - Let's Encrypt / AutoSSL HTTP-01:  /.well-known/acme-challenge/<token>
--   - commercial CAs (Sectigo/DigiCert) HTTP DCV: /.well-known/pki-validation/<file>
-- If a forced/auto vhost challenge — e.g.
--   detectors.conf: CHALLENGE_VHOST = cpanel.*, whm.*, webmail.*
-- — or any per-IP challenge intercepts these, the CA receives the CFM
-- interstitial HTML instead of the token and validation fails with
--   403 urn:ietf:params:acme:error:unauthorized
-- on exactly the cpanel./webmail./whm. service subdomains.
--
-- The whole prefix is exempted (not just acme-challenge): it also covers
-- pki-validation, security.txt, mta-sts, apple-app-site-association, etc.; it
-- is a standardized static/metadata namespace; and it matches what the HTTPS
-- panel listeners already do (cfm_panel.lua is_exempt_path) and what
-- cPanel/Imunify/ModSecurity-CRS do.
--
-- TRADE-OFF (accepted): this skips the WAF rule engine for the whole prefix,
-- not only the challenge. A few /.well-known/ endpoints can be app-routed
-- (e.g. /.well-known/webfinger, /.well-known/openid-configuration) and thus
-- lose WAF inspection. This is bounded: `uri` is nginx-decoded and
-- dot-segment-normalized, so /.well-known/acme-challenge/../../x collapses out
-- of the prefix and is NOT exempted (no traversal-out evasion); the request
-- still reaches the normal origin (this is a WAF-skip, not an auth bypass);
-- and the same pattern is already used for static-asset classes. If you ever
-- need WAF on app-routed .well-known endpoints, scope this to
-- acme-challenge/ + pki-validation/ instead.
do
  if lower(uri):find("/.well-known/", 1, true) == 1 then
    ngx.header["X-CFM-Bypass"] = "well-known"
    log_route(ngx.INFO, "bypass=well-known host=" .. host .. " uri=" .. uri)
    ngx.var.cfm_upstream = "cfm_apache"; ngx.var.cfm_pass = origin_pass_for(scheme)
    return
  end
end

-- ── Step 0b: Box-wide UA emergency rules ─────────────────────────────────────
-- Operators install these via the bot-top control surface. Matches happen
-- on the normalized User-Agent only (one bucket per UA across all vhosts).
-- Empty UA / unknown UA → falls through to the normal pipeline.
--
-- Only "throttle" and "block" are supported. An "allow" action keyed on
-- the UA string would be a trivially spoofable WAF bypass.
if ua_emerg_ok and ua_emerg then
  local emerg = ua_emerg.check(ngx.var.http_user_agent)
  if emerg then
    if emerg.action == "block" then
      log_route(ngx.WARN, "ua_emerg=block ua=" .. tostring(emerg.ua) ..
        " ip=" .. tostring(ip) .. " host=" .. host)
      return ngx.exit(444)
    elseif emerg.action == "throttle" then
      local hit, retry = ua_emerg.throttle(emerg.ua)
      if hit then
        ngx.header["X-CFM-UA-Emergency"] = "throttle"
        ngx.header["Retry-After"] = tostring(math.max(1, math.floor(retry + 0.5)))
        log_route(ngx.WARN, "ua_emerg=throttle ua=" .. tostring(emerg.ua) ..
          " retry=" .. tostring(retry) .. " ip=" .. tostring(ip))
        return ngx.exit(429)
      end
    end
  end
end


-- ─────────────────────────────────────────────────────────────────────────────
-- [R2] pcall wrapper: Steps 1–4 wrapped so any error defaults to Apache.
-- ─────────────────────────────────────────────────────────────────────────────
local function cfm_enforce()

-- ── Step 0c: Fleet-armed fingerprint policy (Phase C, master plan E3) ────────
-- The operator arms a per-fingerprint action in cfm-web; the daemon pulls the
-- list and answers /nginx/fppolicy lookups; cfm_fppolicy caches per distinct
-- fingerprint so the hot path pays one shdict get. Runs BEFORE clearance on
-- purpose: `deny` must bite a client that SOLVED the challenge (the farm
-- does), and the fingerprint rides every request's handshake. challenge /
-- challenge_v2 are a FLOOR only — recorded here, honoured at Step 3 for
-- uncleared clients (valid clearance still passes at Step 2b: the floor is
-- satisfied by solving; v2 behaves as v1 until the Rung-1 engine ships).
-- pcall-guarded + fail-open: any failure means no fingerprint action.
-- CFG.fp_policy (bridge-published FP_POLICY, 10s TTL) gates the whole step:
-- off = zero per-request cost here, not merely empty answers.
local fp_action = ""
if CFG.fp_policy then
  local ok_fp, act, fpid = pcall(function()
    -- Stashed in ngx.ctx so the WAF push (Step 2) reuses the tuple instead of
    -- rebuilding it from the ssl_* vars.
    local raw = require("cfm_tlsfp").value()
    ngx.ctx.cfm_tlsfp_raw = raw or false
    if not raw then return "", nil end
    return require("cfm_fppolicy").lookup({
      raw = raw,
      -- Dedicated dict (churn isolation — see cfm_fppolicy.lua); fall back to
      -- the decisions dict only on upgrade lag before the proxy reloads the
      -- conf that declares it.
      sh  = ngx.shared.cfm_fppolicy or SH,
      rpc = function(path)
        return decision:rpc("fppolicy", "GET", path, nil, { ip = ip, host = host })
      end,
    })
  end)
  if ok_fp and type(act) == "string" and act ~= "" then
    fp_action = act
    if fp_action == "deny" then
      ngx.header["X-CFM-Action"] = "fp_deny"
      ngx.var.cfm_upstream = "cfm_block"; ngx.var.cfm_pass = ""
      log_route(ngx.WARN, "fp_deny ip=" .. ip .. " host=" .. host ..
        " fpid=" .. tostring(fpid or "-"))
      return ngx.exit(CFG.block_code)
    end
  end
end

-- ── POST resume ──────────────────────────────────────────────────────────────
try_apply_post_resume(ip, host)
method = ngx.req.get_method() or method
uri    = ngx.var.uri          or uri

-- ── Step 1: Validate clearance (do NOT allow yet — WAF runs first) ──────────
-- cfm_clearance proves the client passed the challenge gate. It does not
-- prove the payload is safe, so the allow-to-origin is deferred until after
-- WAF inspection in Step 2. The validation result is captured in
-- `clearance_allow`, which the post-clearance WAF challenge converter (Step 2)
-- and the Step 2b clearance fast-path read.
local clearance_scope = "web"
local clearance_cookie = ngx.var.cookie_cfm_clearance
local clearance_ok, clearance_status = validate_clearance_token(clearance_cookie, ip, host, clearance_scope)
if CFG.debug_headers then ngx.header["X-CFM-Clearance"] = clearance_status end
-- A resumed POST (challenge replay) holding valid clearance is treated EXACTLY
-- like any cleared client: the WAF still runs unconditionally in Step 2 (a solved
-- challenge never authorises an exploit — a block-tier hit blocks, and
-- post_clearance_action risk-downgrades a challenge-tier hit: high-risk → block,
-- low-risk → logonly), then a clean request takes the Step 2b clearance fast-path
-- so the stashed save lands at origin. Keying on clearance_ok (NOT the former
-- `and not ngx.ctx.cfm_resumed_post`) is the fix: that exclusion pushed a cleared
-- replay past Step 2b into the Step 3 block_replayed guard and 403'd the save. The
-- block_replayed guards (Step 2 challenge branch + Step 3) now fire only for an
-- UNCLEARED replay — the loop they exist to stop.
local clearance_allow = clearance_ok

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
            " from=" .. tostring(waf_action) .. " to=" .. tostring(converted))
          waf_action = converted
          converted_from_challenge = true
          if CFG.debug_headers then ngx.header["X-CFM-WAF-Converted"] = converted end
        end
      end

      -- ClamAV upload scan (notify-only): spend it only when the WAF did NOT
      -- block this request. A `block` already stops the malware at the edge,
      -- so rescanning the same payload wastes ClamAV resources and produces a
      -- redundant infected-upload notification. For everything else — a clean
      -- pass, a logonly hit, or a challenge — the payload either reaches origin
      -- or is a rule-gap signal worth an alert, which is exactly what the scan
      -- is for. (Gated on the routing action, taken after the post-clearance
      -- challenge→block promotion so a promoted block is correctly skipped.)
      -- An UNCLEARED resumed POST that re-hits a CHALLENGE-tier rule (either
      -- rung) is force-blocked below (block_replayed) while waf_action is still
      -- challenge/challenge_v2, so exclude that combination too — otherwise
      -- we'd scan a payload we're about to 403. (A CLEARED resumed POST never
      -- keeps a challenge-tier waf_action here: post_clearance_action converts
      -- it to logonly/block above.) The exclusion must stay challenge-tier-only:
      -- a resumed POST whose hit degraded to logonly on replay — the
      -- post-clearance downgrade, or a burst-window rule that is quiet now
      -- while a logonly rule still matches — DOES reach origin and must still
      -- be scanned.
      local waf_challenge_tier = (waf_action == "challenge" or waf_action == "challenge_v2")
      if clamav_ok and waf_action ~= "block"
         and not (waf_challenge_tier and ngx.ctx.cfm_resumed_post) then
        -- notify() returns non-nil ONLY when the vhost runs in inline mode and
        -- the bridge answered block=true (infected, not sig-ignored, not
        -- dry-run). Every failure inside is fail-open (nil) by contract.
        local cv = clamav.notify(ip, reason)
        if cv and cv.block then
          ngx.header["X-CFM-Action"] = "clam_block"
          log_route(ngx.WARN, "clam_block ip=" .. ip .. " host=" .. host ..
            " sig=" .. tostring(cv.signature))
          return ngx.exit(CFG.block_code)
        end
      end

      -- ONE place for the ip_push + the waf_<action> log line, so every route
      -- that issues this hit's decision reports it — including the
      -- challenge-resume redirect, which returns before the shared
      -- fallthrough. (The one exception is the block_replayed 403: an
      -- uncleared resumed POST re-hitting a challenge-tier rule reports via
      -- observe_waf instead — the original challenge that minted its resume
      -- token already pushed+logged, and a blocked client never reaches
      -- verify, so no v2 mark is owed.) The resume path used to skip both
      -- (an under-report: a
      -- challenged POST left no cfm.waf.log record, no waf_trigger history
      -- and no ipState decision), and for challenge_v2 the push is
      -- load-bearing: it is what writes the per-(ip,host) rung mark the
      -- verify gate keys on, so a body-carried payload must not dodge it.
      local function push_and_log_waf_hit()
        if waf.should_push and waf.should_push(SH, ip, reason, waf_action) then
          -- Forensic fields (UA / Referer / Content-Type) are always
          -- attached. The single cfm.waf.log now emits one JSON record
          -- per trigger carrying everything Go knows: timestamp, action,
          -- TTL, ASN/country enrichment + these per-request headers.
          -- Client TLS fingerprint for the fleet reputation ledger (source #3),
          -- computed edge-side from the handshake ($ssl_* via cfm_tlsfp.value()) —
          -- NOT the client-supplied X-CFM-TLS header, which this WAF path does not
          -- clear (only /__cfm_verify does) and so would be client-SPOOFABLE. value()
          -- is unspoofable and charset/length-bounded; Go parses it to the canonical
          -- fp id. Step 0c (the fingerprint-policy lookup) already computed the
          -- tuple and stashed it in ngx.ctx.cfm_tlsfp_raw (false = plain-HTTP/
          -- none), so reuse it and rebuild only when the stash is absent (Step 0c
          -- pcall failed, or skipped entirely under FP_POLICY=0 — WAF-hit fp
          -- attribution keeps working either way, paid only on WAF-hit
          -- requests). pcall-guarded (like the /__cfm_verify stamp) so a
          -- missing/broken cfm_tlsfp module can never 500 the request.
          local stash = ngx.ctx.cfm_tlsfp_raw
          local ok_fp, tls_fp
          if stash ~= nil then
            ok_fp, tls_fp = true, (stash or nil)
          else
            ok_fp, tls_fp = pcall(function() return require("cfm_tlsfp").value() end)
          end
          if not ok_fp then tls_fp = nil end
          local push = {
            ip = ip, action = waf_action, ttl_sec = ttl or 600,
            reason = reason, host = p_host, uri = p_uri, method = p_meth,
            waf_rule_id  = waf_rule_id,
            ua           = req_headers["user-agent"],
            referer      = req_headers["referer"],
            content_type = req_headers["content-type"],
            fingerprint  = tls_fp,
          }
          decision:rpc("ip_push", "POST", "/nginx/ip", cjson.encode(push),
            { ip = ip, host = p_host, uri = p_uri, method = p_meth })
        end
        log_route(ngx.INFO, "waf_" .. waf_action .. " ip=" .. ip .. " host=" .. host ..
          " reason=" .. tostring(reason) ..
          (waf_rule_id and (" waf_rule_id=" .. tostring(waf_rule_id)) or ""))
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
        observe_waf(ip, host, p_uri, p_meth, 403, reason, waf_rule_id)
      else -- challenge tier: "challenge" or "challenge_v2" (only reachable when
           -- clearance_allow == false). Both rungs serve the SAME challenge
           -- page here — the v2 rung difference bites at verify, keyed on the
           -- per-(ip,host) mark the ip_push below records daemon-side.
        if ngx.ctx.cfm_resumed_post then
          ngx.header["X-CFM-Action"] = "block_replayed"
          ngx.var.cfm_upstream = "cfm_block"; ngx.var.cfm_pass = ""
          observe_waf(ip, host, p_uri, p_meth, 403, "REPLAYED_POST_RECHALLENGED", waf_rule_id)
          return ngx.exit(CFG.block_code)
        end
        local rtok, rerr = store_post_resume(ip, host, ngx.var.request_uri or uri, method)
        if rtok then
          -- This return leaves the branch before the shared fallthrough, so
          -- push+log NOW: a body-carried challenge_v2 hit must still write
          -- its rung mark (and every resumed challenge must still be
          -- visible in cfm.waf.log / history).
          push_and_log_waf_hit()
          ngx.header["X-CFM-Action"] = "challenge_resume"
          ngx.header["Cache-Control"] = "no-store"
          return ngx.redirect("/?next=" .. esc(with_query_arg((ngx.var.request_uri or uri), "cfm_rt", rtok)), ngx.HTTP_SEE_OTHER)
        end
        -- Both rungs present to the CLIENT as a plain challenge: echoing
        -- "challenge_v2" here would hand a signal-aware solver farm the
        -- exact solves that face v2 scrutiny (it could fabricate a clean
        -- humanity report only where needed, and A/B-probe which rules are
        -- v2-armed). The rung is visible operator-side in cfm.waf.log and
        -- the waf_trigger history; CFM_DEBUG_HEADERS=1 exposes it here too.
        ngx.header["X-CFM-Action"] = CFG.debug_headers and waf_action or "challenge"
        ngx.var.cfm_upstream = "cfm_challenge"; ngx.var.cfm_pass = "http://cfm_challenge"
      end

      push_and_log_waf_hit()
      if waf_action == "block" then return ngx.exit(CFG.block_code) end
      return
    else
      -- No WAF rule fired: the upload passed the WAF cleanly, so scan it.
      if clamav_ok then
        local cv = clamav.notify(ip, nil)
        if cv and cv.block then
          ngx.header["X-CFM-Action"] = "clam_block"
          log_route(ngx.WARN, "clam_block ip=" .. ip .. " host=" .. host ..
            " sig=" .. tostring(cv.signature))
          return ngx.exit(CFG.block_code)
        end
      end
    end
  end
end
if not waf_ok and clamav_ok then
  local cv = clamav.notify(ip, nil)
  if cv and cv.block then
    ngx.header["X-CFM-Action"] = "clam_block"
    log_route(ngx.WARN, "clam_block ip=" .. ip .. " host=" .. host ..
      " sig=" .. tostring(cv.signature))
    return ngx.exit(CFG.block_code)
  end
end

-- ── Step 2b: Honour clearance allow (deferred from Step 1) ──────────────────
-- WAF either passed cleanly or is disabled/excluded for this host. Now we
-- can safely apply the clearance fast-path: refresh the cookie, touch the
-- ok cache, and route to origin. This intentionally short-circuits the
-- forced-challenge and bridge-decision steps below — clearance means
-- "don't repeatedly challenge this client for the same gate."
if clearance_allow then
  refresh_clearance_cookie(clearance_cookie, ip, host, clearance_scope)
  touch_ok_scoped(ip, host, clearance_scope)
  -- (A post-clearance nav-cadence shadow, cfm_pcw/B2, used to run here. RETIRED
  -- 2026-09-22: static assets bypass cfm.lua entirely, so its "cleared then
  -- silent" discriminator saw every real browser as silent — docs/challenge-score-b2.md.)
  ngx.header["X-CFM-Action"] = "allow_cookie"
  ngx.var.cfm_upstream = "cfm_apache"; ngx.var.cfm_pass = origin_pass_for(scheme)
  return
end

-- ── Step 2.5: Forced challenge for marked locations ──────────────────────────
-- Triggered via `set $cfm_force_challenge 1;` in nginx location blocks
-- (e.g. /cfm-admin/login). Runs AFTER WAF so rules still inspect the request,
-- and is skipped entirely when a valid cfm_clearance cookie is present
-- (Step 2b above returns before we reach this block).
-- NOTE: /.well-known/ never reaches here — Step 0a1 routes the whole prefix
-- to the origin upstream before WAF/forced/bridge challenge, so neither the
-- WAF rule engine nor a forced challenge inspects it (see Step 0a1 for the
-- ACME/CA-DCV rationale and the accepted WAF-coverage trade-off).
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
-- Pass the DECODED path (ngx.var.uri) and the raw query (ngx.var.args) as
-- SEPARATE arguments so the bridge can match traffic rules on the query
-- (has_qs / qs pass-through, and "/path?token" patterns) without re-splitting a
-- concat. Keep the path DECODED: do NOT use ngx.var.request_uri, whose path
-- segment is raw/undecoded and would let path_any rules be evaded by
-- percent-encoding (e.g. /wp-%6cogin.php). ngx.var.uri stays the WAF/excludes
-- source; only the decision RPC additionally carries the query.
local ua_raw   = ngx.var.http_user_agent or ""
local country  = geo_country_cached(ip)
local qs_raw    = ngx.var.args or ""
local d        = decision:get(ip, host, uri, qs_raw, method, scheme, ua_raw, country, clearance_scope)

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

-- Challenge — fp_action is the Step-0c fingerprint-policy FLOOR: an uncleared
-- client whose fingerprint is armed challenge/challenge_v2 is challenged as if
-- the vhost were challenge-armed (a cleared one already passed at Step 2b).
if ip_action == "challenge" or vh_action == "challenge" or rule_action == "challenge"
  or fp_action == "challenge" or fp_action == "challenge_v2" then
  if ngx.ctx.cfm_resumed_post then
    -- Only an UNCLEARED replay reaches here: a resumed POST that holds valid
    -- clearance took the Step 2b fast-path to origin (clearance_allow now keys on
    -- clearance_ok), and a WAF hit exited in Step 2. A replay that is still being
    -- challenged and holds no clearance is the loop block_replayed exists to stop.
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
  log_route(ngx.INFO, "challenge ip=" .. ip .. " host=" .. host .. cache_flag ..
    ((fp_action == "challenge" or fp_action == "challenge_v2") and (" fp_floor=" .. fp_action) or ""))
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
  -- host/uri are client-controlled and ngx.var.uri is percent-decoded (can
  -- carry literal CR/LF); log_ev() neutralises control chars in every arg to
  -- prevent log forging (F39).
  local host_v = ngx.var.host or "-"
  local uri_v = ngx.var.request_uri or ngx.var.uri or "-"
  log_ev(ngx.ERR, "[cfm] request_failure",
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

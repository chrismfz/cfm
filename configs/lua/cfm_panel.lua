-- Panel-specific CFM guard/router for cPanel/WHM/Webmail ports.
--
-- Single simplified policy:
--   1) API / SSO / cPanel internal flows: always pass to cpsrvd.
--   2) Human panel entrypoints: browser challenge.
--   3) Non-browser entrypoint clients: pass to cpsrvd, do not 403.
--   4) Everything else: pass to cpsrvd.
--
-- Important:
--   - The WAF here is LOGONLY (Phase 2e): it records would-be hits on
--     human-entry/generic requests and never blocks or alters the flow. Do NOT
--     turn it into an enforcing in-path WAF without the burn-in + enforce step
--     (see docs/edge-unification-plan.md).
--   - Do not validate WHM/API auth here. cpsrvd does that.
--   - Do not require User-Agent or Authorization for API passthrough.

local function fallback_normalize_host(raw)
    local h = (tostring(raw or ""):lower()):gsub("%.$", "")
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
local clearance_module_error_reported = false
if not ok_clearance then
    ngx.log(ngx.ERR, "[cfm_panel] clearance module load failed module=cfm_clearance err=", tostring(clearance_validator))
    clearance_validator = {
        validate = function(...) return false, "module_error" end,
        normalize_host = fallback_normalize_host,
        panel_scope = function(...) return "panel" end,
    }
end


-- Referenced by the selftest hook below, which deliberately probes the RAW
-- file (install preflight: "is the token file present and valid on disk?")
-- rather than the cached accessor.
local _BRIDGE_TOKEN_FILE = "/var/lib/cfm/lua/cfm_bridge_token.lua"

-- Bridge token + webdetector runtime knobs, both read through the canonical
-- cached accessor (cfm_bridge_cfg → cfm_filecache, 10s TTL / 2s
-- missing-retry). The previous inline load_token/loadfile here ran once per
-- panel request — this file is loaded via access_by_lua_file, so its top
-- level re-executes per request (see the PITFALL block in cfm.lua) — and
-- duplicated the token-validity rule and the bridge-config parse. pcall
-- keeps the panel path alive through an upgrade lag where the module set is
-- older than this file; a nil token means "bridge unavailable", same as the
-- old loader's failure mode (panel decide then follows panel_fail_mode).
local panel_bridge_token
local panel_bridge_cfg
do
    local ok, bc = pcall(require, "cfm_bridge_cfg")
    if ok and type(bc) == "table" and bc.get then
        panel_bridge_cfg = bc.get()
        if bc.token then
            local tok, terr = bc.token()
            panel_bridge_token = tok
            if not tok then
                ngx.log(ngx.ERR, "[cfm_panel] bridge token unavailable (",
                    tostring(bc.TOKEN_PATH or "/var/lib/cfm/lua/cfm_bridge_token.lua"),
                    "): ", tostring(terr))
            end
        else
            -- Old cfm_bridge_cfg without token() (partial file copy /
            -- stale package.loaded): the token doubles as the clearance
            -- secret, so a silent nil here surfaces only as per-request
            -- missing_clearance_secret churn — name the real cause loudly.
            ngx.log(ngx.ERR, "[cfm_panel] cfm_bridge_cfg has no token() — ",
                "module set older than cfm_panel.lua; redeploy /var/lib/cfm/lua ",
                "and reload the proxy; panel bridge auth disabled until then")
        end
    else
        ngx.log(ngx.WARN, "[cfm_panel] cfm_bridge_cfg unavailable, using defaults: ", tostring(bc))
    end
    panel_bridge_cfg = panel_bridge_cfg or { clearance_refresh = true }
end

-- ── Panel enforce-mode resolution (shared by panel WAF + panel decision) ──────
-- Both the panel WAF (Phase 4a) and the panel bridge decision (Phase 4b) have
-- three modes: off · logonly · enforce. The mode is resolved PER REQUEST from,
-- in priority order:
--   1. the env override (CFM_PANEL_WAF / CFM_PANEL_DECISION) — the emergency
--      kill switch; wins over everything when set to a recognised value;
--   2. the daemon-published config (detectors.conf [webdetector]
--      PANEL_WAF_MODE / PANEL_DECISION_MODE → cfm_bridge_config.lua, read via
--      cfm_bridge_cfg with a 10s TTL, so `cfm reload` propagates within ~10s
--      with NO proxy reload);
--   3. the DEFAULT, which is **enforce** — the fleet posture is enforce unless a
--      specific node opts down. This is deliberate: the operator runs ~20 nodes
--      and wants panel enforcement on by default without editing 20 configs; if
--      one node misbehaves, set PANEL_*_MODE = off|logonly there (or the env) and
--      `cfm reload`. A missing key, a missing/old daemon file, or an unknown
--      token all fall through to enforce.
-- Everything downstream is still pcall'd + fail-open: an "enforce" mode with a
-- broken WAF/bridge fails OPEN (no deny), so defaulting to enforce cannot turn a
-- fault into a panel lockout — only a genuine block verdict denies.
local function normalize_panel_mode(v)
    if v == nil then return nil end
    v = tostring(v):lower()
    if v == "0" or v == "off"      then return "off"     end
    if v == "1" or v == "logonly"  then return "logonly" end
    if v == "2" or v == "enforce"  then return "enforce" end
    return nil  -- unrecognised → let the next source decide
end

-- resolve_panel_mode: env override → config value → "enforce" default.
local function resolve_panel_mode(env_name, cfg_mode)
    return normalize_panel_mode(os.getenv(env_name))
        or normalize_panel_mode(cfg_mode)
        or "enforce"
end

-- Bridge decision (edge-unification Phase 2d LOGONLY → Phase 4b enforce). The
-- panel consults the SAME /nginx/decision the web edge uses (via the shared
-- cfm_decision module, scope=panel:<port>). Mode is resolved per request by
-- resolve_panel_mode("CFM_PANEL_DECISION", panel_decision_mode) at the call site;
-- in `enforce`, a bridge `block` (ip/vhost/rule) → deny. The module is loaded
-- whenever cfm_decision/cjson are available (mode is decided per request, not at
-- load), so a config flip off→enforce takes effect within the bridge-cfg TTL with
-- no proxy reload. Everything is pcall'd and fail-open: a missing module/cjson
-- (upgrade lag) leaves panel_decision nil (no probe, no deny), and a bridge RPC
-- error is swallowed, so a bridge hiccup can never lock the panel.
local panel_decision
local panel_decision_cjson
do
    local ok_cjson, cj = pcall(require, "cjson.safe")
    local ok_mod, dec_mod = pcall(require, "cfm_decision")
    local ok_bmod, bmod = pcall(require, "cfm_bridge_cfg")
    if ok_cjson and ok_mod and type(dec_mod) == "table" and dec_mod.new then
        panel_decision_cjson = cj
        -- Transport values mirror cfm.lua's CFG so the panel's bridge RPC
        -- behaves identically to the web edge's.
        local dcfg = {
            sock_path             = "/var/run/cfm/cfm_nginx.sock",
            token                 = panel_bridge_token,
            token_header          = "X-CFM-Token",
            decision_timeout_ms   = tonumber(os.getenv("CFM_DECISION_TIMEOUT_MS") or "300"),
            keepalive_idle_ms     = tonumber(os.getenv("CFM_BRIDGE_KA_IDLE_MS") or "60000"),
            keepalive_pool        = tonumber(os.getenv("CFM_BRIDGE_KA_POOL") or "512"),
            fail_open             = (os.getenv("CFM_FAIL_OPEN") or "1") ~= "0",
            decision_cache_ttl_ms = 90000,
            debug                 = false,
            debug_headers         = false,
        }
        panel_decision = dec_mod.new(dcfg, {
            shdict       = ngx.shared.cfm_decisions,
            is_static    = function() return false end,  -- panel human-entry is never a static asset
            real_ip      = function() return ngx.var.remote_addr end,
            log_route    = function(lvl, msg) ngx.log(lvl, "[cfm_panel] ", tostring(msg)) end,
            on_token_403 = (ok_bmod and bmod and bmod.refresh_token_throttled)
                             and function() return bmod.refresh_token_throttled(2) end or nil,
            token_path   = ok_bmod and bmod and bmod.TOKEN_PATH or nil,
            token_err    = function() return nil end,
        })
    end
end

-- panel_touch_ok mirrors cfm.lua's touch_ok_scoped: after a valid clearance it
-- POSTs /nginx/ok/touch so the bridge records that this IP passed on this panel
-- scope. LOGONLY: this is a bypass HINT for a future enforcement phase; it never
-- blocks or challenges. Throttled per (ip,host,scope), best-effort, pcall'd.
local function panel_touch_ok(ip, host, scope, ttl_sec)
    if not panel_decision then return end
    local sh = ngx.shared.cfm_decisions
    if sh then
        local k = "ok_touch|panel|" .. (ip or "-") .. "|" .. (host or "-") .. "|" .. tostring(scope or "")
        local now = ngx.now()
        local last = sh:get(k)
        if last and (now - last) < 120 then return end
        sh:set(k, now, 120)
    end
    panel_decision:rpc("ok_touch", "POST", "/nginx/ok/touch",
        panel_decision_cjson.encode({ ip = ip, host = host, scope = scope, ttl_sec = ttl_sec }),
        { ip = ip, host = host })
end

-- panel_decision_probe fires the bridge decision on a panel human-entry request.
-- It returns `(is_block, why)` when the verdict is the HIGH-CONFIDENCE block tier
-- (ip/vhost/rule action == "block"), so the caller can hard-deny in enforce mode;
-- it returns nil when the probe is disabled, the bridge errors (fail-open — no
-- deny), or the verdict is anything other than block. Every non-allow verdict is
-- LOGGED with a mode-aware marker (`enforce=block` when it will actually deny,
-- else the observe-only `logonly=would_enforce` — waf_fp_hunt parses the
-- ip/vhost/rule_action fields, not the marker, so the FP picture is unchanged).
--
-- Only the block tier is returned for enforcement. The CHALLENGE tier is
-- deliberately NOT surfaced here: the clearance-aware human-entry challenge in
-- section 3 already challenges un-cleared browsers and passes non-browsers
-- through, so deriving a challenge from the verdict would duplicate it and risk
-- the exact loop Phase 4a avoided (a solved cookie doesn't clear the verdict).
-- throttle/other verdicts stay observe-only in Phase 4b.
local function panel_decision_probe(ip, host, uri, method, ua, scope, enforce)
    if not panel_decision then return end
    local okd, d = pcall(function()
        return panel_decision:get(ip, host, uri, ngx.var.args or "",
                                  method, ngx.var.scheme or "https", ua, "", scope)
    end)
    if not okd or type(d) ~= "table" then return end
    local ipa = d.ip_action or "allow"
    local vha = d.vhost_action or "allow"
    local ra  = d.rule_action
    local is_block = (ipa == "block" or vha == "block" or ra == "block")
    local will_enforce = enforce and is_block
    if ipa ~= "allow" or vha ~= "allow" or ra then
        ngx.log(ngx.WARN,
            "[cfm_panel_decision] ", (will_enforce and "enforce=block" or "logonly=would_enforce"),
            " scope=", tostring(scope),
            " ip=", tostring(ip), " host=", tostring(host), " uri=", tostring(uri),
            " ip_action=", tostring(ipa), " vhost_action=", tostring(vha),
            " rule_action=", tostring(ra or "-"),
            " cached=", d._cache and "1" or "0")
    end
    if is_block then
        -- Name the tier that blocked for the deny reason (ip > vhost > rule).
        local why = (ipa == "block" and "ip") or (vha == "block" and "vhost") or "rule"
        return true, why
    end
end

-- ─────────────────────────────────────────────────────────────────────────────
-- Panel WAF (edge-unification Phase 2e) — LOGONLY.
--
-- Runs the SAME cfm_waf ruleset the web edge uses against panel human-entry +
-- generic requests and RECORDS what it WOULD do — it never blocks, challenges,
-- or alters the flow (parallel to panel_decision_probe). The point is to gather
-- false-positive data on real panel traffic before any enforcement phase.
--
-- Reduced profile, deliberately:
--   * Header / URI / args / cookie only — NO request body is read, so panel
--     upload/rsync/websocket streams are never buffered. The api/sso/acctxfer/
--     /cgi/transfer//cgi/live_tail_log/websocket allowlist (is_panel_api_or_sso)
--     is already hard-skipped upstream, so those paths never reach this probe.
--   * Self / self-IP / IGNORE_NETS traffic is skipped (panel_is_self) using the
--     SAME cfm_selfip.is_self_origin the web edge uses — so an operator-ignored
--     network (cfm.cfg [global] IGNORE_IPS/IGNORE_NETS) and the box's own IPs
--     bypass the panel WAF exactly as they bypass the web WAF, no drift. Falls
--     back to a loopback-only check only if cfm_selfip is missing on upgrade lag.
--   * Per-(ip,rule) log throttle so a noisy scanner can't flood the error log.
--
-- Mode is resolved per request by resolve_panel_mode("CFM_PANEL_WAF",
-- panel_waf_mode) at the call site (env override → detectors.conf PANEL_WAF_MODE
-- → default ENFORCE). In `enforce` a high-confidence `block` hit → deny; logonly
-- records only; off skips the probe. The module is loaded whenever cfm_waf is
-- available (mode is decided per request, not at load), so a config flip
-- off→enforce takes effect within the bridge-cfg TTL with no proxy reload.
-- Everything is pcall'd + fail-open; a cfm_waf module missing on upgrade lag
-- leaves panel_waf nil so nothing runs (no deny). See
-- docs/edge-unification-plan.md Phase 4a.
local panel_waf
do
    local ok_waf, w = pcall(require, "cfm_waf")
    if ok_waf and type(w) == "table" and w.check and w.enabled then
        panel_waf = w
    end
end

-- Shared self-origin predicate (self-IP set + [global] IGNORE_IPS/IGNORE_NETS +
-- loopback), identical to the web edge — single source, no drift (§5). pcall'd
-- so an upgrade-lag copy without cfm_selfip degrades to loopback-only rather
-- than erroring the panel path.
local ok_selfip, selfip = pcall(require, "cfm_selfip")
if not ok_selfip then selfip = nil end

-- Fallback loopback/link-local check for when cfm_selfip is absent (upgrade lag).
local function panel_is_loopback(ip)
    local s = tostring(ip or ""):lower()
    if s == "" then return false end
    if s:sub(1, 1) == "[" and s:sub(-1) == "]" then s = s:sub(2, -2) end
    if s == "::1" then return true end
    if s:sub(1, 4) == "127." then return true end
    if s:sub(1, 6) == "fe80::" then return true end
    if s:sub(1, 8) == "169.254." then return true end
    return false
end

-- panel_is_self prefers the shared cfm_selfip.is_self_origin (full parity with
-- the web edge); pcall-guarded, falling back to loopback-only if the module is
-- absent or errors, so a self-check hiccup can never break the probe.
local function panel_is_self(ip)
    if selfip and selfip.is_self_origin then
        local ok, res = pcall(selfip.is_self_origin, ip)
        if ok then return res end
    end
    return panel_is_loopback(ip)
end

-- panel_waf_probe runs the reduced panel WAF. On a hit it returns
-- (action, reason, rule_id) so the caller can enforce; it returns nil when the
-- WAF is off/disabled, the source is self/IGNORE, there is no hit, or cfm_waf
-- errors (fail-open — no line, no action). It LOGS every counted hit (throttled
-- per (ip,rule)) with a mode-aware marker: `logonly=would_<action>` in logonly
-- mode (unchanged — waf_fp_hunt parses this) or `enforce=<action>` when
-- enforcing. Logging is throttled; the returned action is NOT (enforcement acts
-- on every hit regardless of the log-throttle window).
local function panel_waf_probe(ip, host, uri, args, method, ua, scope, enforce)
    if not panel_waf then return end
    if not panel_waf.enabled() then return end
    if panel_is_self(ip) then return end

    local okc, hit, reason, _ttl, action, _hits, rule_id = pcall(function()
        return panel_waf.check({
            uri = uri, args = args or "", method = method,
            host = host, ip = ip, peer = ip,
            cookie = ngx.var.http_cookie or "",
            headers = ngx.req.get_headers(),
            body = "",  -- reduced profile: never buffer the panel body
            -- Same dict the web edge passes as SH. cfm_waf's burst detectors
            -- mutate counters here, but they are gated on web-app auth markers
            -- (/wp-login.php, /xmlrpc.php, …) AND keyed by (ip,host), so a panel
            -- URI on a panel Host never tips a web vhost's enforced burst state.
            shdict = ngx.shared.cfm_decisions,
            self_origin = false,
        })
    end)
    if not okc or not hit then return end
    action = tostring(action or "block")

    -- Throttle only the LOG line per (ip, rule_id) so a scanner cannot flood the
    -- error log; the action return below is unaffected.
    local sh = ngx.shared.cfm_decisions
    local do_log = true
    if sh then
        local k = "waf_ll|" .. (ip or "-") .. "|" .. tostring(rule_id or reason or "-")
        if not sh:add(k, 1, 60) then do_log = false end
    end
    -- Only the high-confidence BLOCK tier is enforced (see the call site); mark
    -- the log line `enforce=block` only when it will actually act, else keep the
    -- observe-only `logonly=would_<action>` marker (which waf_fp_hunt parses and
    -- which stays accurate for the still-unenforced challenge/logonly tiers).
    local will_enforce = enforce and action == "block"
    if do_log then
        ngx.log(ngx.WARN,
            "[cfm_panel_waf] ", (will_enforce and "enforce=" or "logonly=would_"), action,
            " scope=", tostring(scope),
            " ip=", tostring(ip), " host=", tostring(host),
            " uri=", tostring(uri), " method=", tostring(method),
            " reason=", tostring(reason), " rule_id=", tostring(rule_id or "-"),
            " ua=", tostring(ua or "-"))
    end

    return action, reason, rule_id
end

local function starts_with(s, p)
    return s and p and s:sub(1, #p) == p
end

local function decision_log(level, fields)
    ngx.log(level,
        "CFM_PANEL decision",
        " mode=", fields.mode or "-",
        " host=", fields.host or "-",
        " uri=", fields.uri or "-",
        " method=", fields.method or "-",
        " ua=", fields.ua or "-",
        " ip=", fields.ip or "-",
        " decision=", fields.decision or "-",
        " reason=", fields.reason or "-",
        " subreq_uri=", fields.subreq_uri or "-",
        " subreq_status=", fields.subreq_status or "-",
        " subreq_location=", fields.subreq_location or "-",
        " decision_source=", fields.decision_source or "-",
        " decision_reason=", fields.decision_reason or "-",
        " allow_origin=", fields.allow_origin or "0",
        " challenge_issued=", fields.challenge_issued or "0",
        " challenge_entry=", fields.challenge_entry or "0",
        " challenge_solved=", fields.challenge_solved or "0",
        " challenge_resume=", fields.challenge_resume or "0",
        " deny_fail_closed=", fields.deny_fail_closed or "0",
        " target=", fields.target or "-"
    )
end

local function parse_duration_seconds(raw, fallback)
    if raw == nil or raw == "" then return fallback end

    local n, unit = tostring(raw):match("^%s*(%d+)%s*([smhdSMHD]?)%s*$")
    n = tonumber(n)
    if not n then return fallback end

    unit = (unit or "s"):lower()

    if unit == "m" then return n * 60 end
    if unit == "h" then return n * 3600 end
    if unit == "d" then return n * 86400 end

    return n
end

local function challenge_state()
    local sh = ngx.shared and (ngx.shared.cfm_decisions or ngx.shared.cfm_stats)
    if not sh then return nil end
    return sh
end

local function ttl_key(ip, host)
    return "panel_ok|" .. tostring(ip or "-") .. "|" .. tostring(host or "-")
end

local function cooldown_key(ip, host)
    return "panel_cooldown|" .. tostring(ip or "-") .. "|" .. tostring(host or "-")
end

local function validator_degraded_reason(reason)
    return reason == "module_error" or reason == "crypto_unavailable"
end

local function loop_marker_present()
    local args = ngx.req.get_uri_args() or {}
    local arg_val = args.cfm_vd_loop
    if type(arg_val) == "table" then arg_val = arg_val[1] end
    if tostring(arg_val or "") == "1" then return true end
    return tostring(ngx.var.cookie_cfm_vd_loop or "") == "1"
end

-- Forward-declared as locals so set_loop_marker_cookie/refresh_clearance_cookie
-- below capture them as upvalues. Real bodies are assigned further down (next
-- to clearance_cookie_state, where they belong logically). If these were left
-- as the original forward declarations near line ~460, the Lua compiler would
-- treat the references inside set_loop_marker_cookie() as global lookups and
-- they'd resolve to nil at runtime — that's the
--   "attempt to call global 'append_set_cookie' (a nil value)"
-- crash that the panel circuit breaker exposed.
local safe_cookie_value
local append_set_cookie

local function set_loop_marker_cookie(ttl)
    ttl = tonumber(ttl or 15) or 15
    if ttl <= 0 then ttl = 15 end
    local attrs = "Path=/; Max-Age=" .. tostring(ttl) .. "; HttpOnly; SameSite=Lax"
    if ngx.var.https == "on" or ngx.var.scheme == "https" then
        attrs = attrs .. "; Secure"
    end
    append_set_cookie("cfm_vd_loop=1; " .. attrs)
end
local function mark_challenge_issued(ip, host, cooldown_ttl)
    local ttl = tonumber(cooldown_ttl or 0) or 0
    if ttl <= 0 then return end

    local sh = challenge_state()
    if not sh then return end

    sh:set(cooldown_key(ip, host), 1, ttl)
end

local function mark_passed(ip, host, ok_ttl)
    local ttl = tonumber(ok_ttl or 0) or 0
    if ttl <= 0 then return end

    local sh = challenge_state()
    if not sh then return end

    sh:set(ttl_key(ip, host), 1, ttl)
end

local function has_bypass_ttl(ip, host)
    local sh = challenge_state()
    if not sh then return false end

    return sh:get(ttl_key(ip, host)) ~= nil
end

local function cooldown_active(ip, host)
    local sh = challenge_state()
    if not sh then return false end

    return sh:get(cooldown_key(ip, host)) ~= nil
end

local decision_uri = "/__cfm_panel_decide"

local function is_internal_decision_uri(candidate)
    if type(candidate) ~= "string" then return false end

    local c = candidate:gsub("^%s+", ""):gsub("%s+$", "")
    if c == "" then return false end

    if c == decision_uri or starts_with(c, decision_uri .. "?") then return true end
    if c:find("/__cfm_panel_decide", 1, true) then return true end
    if c:match("^https?://[^/]+/__cfm_panel_decide([/?#].*)?$") then return true end

    return false
end

local function is_internal_challenge_uri(candidate)
    if type(candidate) ~= "string" then return false end

    local c = candidate:gsub("^%s+", ""):gsub("%s+$", "")
    if c == "" then return false end

    if c == "/__cfm_challenge" or starts_with(c, "/__cfm_challenge?") or starts_with(c, "/__cfm_challenge/") then return true end
    if c == "/__cfm_verify" or starts_with(c, "/__cfm_verify?") or starts_with(c, "/__cfm_verify/") then return true end
    if c:match("^https?://[^/]+/__cfm_challenge([/?#].*)?$") then return true end
    if c:match("^https?://[^/]+/__cfm_verify([/?#].*)?$") then return true end

    return false
end

local function is_internal_guard_uri(candidate)
    return is_internal_challenge_uri(candidate) or is_internal_decision_uri(candidate)
end

local function sanitize_panel_next_target(raw_next, fallback)
    local candidate = raw_next

    for _ = 1, 6 do
        if type(candidate) ~= "string" or candidate == "" then break end

        local decoded = ngx.unescape_uri(candidate)
        if decoded == candidate then
            candidate = decoded
            break
        end

        candidate = decoded
    end

    if is_internal_guard_uri(candidate) then
        return fallback or "/"
    end

    return candidate or fallback or "/"
end

local function strip_nested_next_chain(raw_next)
    local candidate = sanitize_panel_next_target(raw_next, "/")

    if is_internal_decision_uri(candidate) then return "/" end
    if type(candidate) ~= "string" or candidate == "" then return "/" end
    if not starts_with(candidate, "/") then return "/" end

    local path, query = candidate:match("^([^?]*)%??(.*)$")
    if not query or query == "" then return candidate end

    local cleaned = {}

    for pair in query:gmatch("[^&]+") do
        local key = pair:match("^([^=]+)=?.*$") or ""
        local decoded_key = ngx.unescape_uri(key)

        if decoded_key ~= "next" then
            cleaned[#cleaned + 1] = pair
        end
    end

    if #cleaned == 0 then return path end

    return path .. "?" .. table.concat(cleaned, "&")
end

local function normalize_challenge_next_arg(next_arg)
    local candidates = {}

    if type(next_arg) == "table" then
        candidates = next_arg
    else
        candidates = { next_arg }
    end

    for _, raw in ipairs(candidates) do
        if type(raw) == "string" and raw ~= "" then
            if not is_internal_guard_uri(raw) then
                local sanitized = strip_nested_next_chain(raw)

                if type(sanitized) == "string" and sanitized ~= "" and not is_internal_guard_uri(sanitized) then
                    return sanitized
                end
            end
        end
    end

    return "/"
end

local function safe_next_from_request(default_next)
    local args = ngx.req.get_uri_args() or {}
    local normalized = normalize_challenge_next_arg(args.next)

    if normalized ~= "/" then
        return normalized
    end

    return strip_nested_next_chain(default_next or "/")
end

local function with_single_next_arg(url, next_value, include_loop_marker)
    local safe_next = sanitize_panel_next_target(next_value, "/")

    if is_internal_guard_uri(safe_next) or is_internal_decision_uri(safe_next) then
        safe_next = "/"
    end

    local base, frag = url:match("^([^#]*)(#.*)$")
    if not base then
        base = url
        frag = ""
    end

    local path, query = base:match("^([^?]*)%??(.*)$")
    local kept = {}

    if query and query ~= "" then
        for pair in query:gmatch("[^&]+") do
            local key = pair:match("^([^=]+)=?.*$") or ""
            local decoded_key = ngx.unescape_uri(key)

            if decoded_key ~= "next" then
                kept[#kept + 1] = pair
            end
        end
    end

    kept[#kept + 1] = "next=" .. ngx.escape_uri(safe_next)
    if include_loop_marker then
        kept[#kept + 1] = "cfm_vd_loop=1"
    end

    return path .. "?" .. table.concat(kept, "&") .. frag
end

local function challenge_redirect_target(decision, include_loop_marker)
    local req_uri = ngx.var.request_uri or ngx.var.uri or "/"
    req_uri = strip_nested_next_chain(req_uri)

    local challenge_location = ngx.var.cfm_panel_challenge_location or "/__cfm_challenge"

    if challenge_location == decision_uri then
        challenge_location = "/__cfm_challenge"
    end

    local loc = challenge_location

    if decision and decision.subreq_location and decision.subreq_location ~= "-" then
        loc = decision.subreq_location
    end

    if is_internal_decision_uri(loc) then
        return challenge_location
    end

    local host = ngx.var.host or ""
    local full_decisions = {
        "http://" .. host .. decision_uri,
        "https://" .. host .. decision_uri,
    }

    for _, candidate in ipairs(full_decisions) do
        if starts_with(loc, candidate) then
            return challenge_location
        end
    end

    local safe_next = safe_next_from_request(req_uri)

    return with_single_next_arg(loc, safe_next, include_loop_marker)
end

local function issue_challenge(mode, reason, decision, cooldown_ttl, include_loop_marker)
    local loc = challenge_redirect_target(decision, include_loop_marker)

    mark_challenge_issued(ngx.var.remote_addr, ngx.var.host or "", cooldown_ttl or 0)

    decision_log(ngx.INFO, {
        mode = mode,
        host = ngx.var.host,
        uri = ngx.var.request_uri,
        method = ngx.req.get_method(),
        ua = ngx.var.http_user_agent,
        ip = ngx.var.remote_addr,
        decision = "challenge",
        reason = reason,
        decision_reason = decision and decision.reason or "-",
        subreq_uri = decision and decision.subreq_uri or "-",
        subreq_status = decision and decision.subreq_status or "-",
        subreq_location = decision and decision.subreq_location or "-",
        decision_source = decision and decision.decision_source or "-",
        allow_origin = "0",
        challenge_issued = "1",
        challenge_entry = "1",
        challenge_solved = "0",
        challenge_resume = "0",
        deny_fail_closed = "0",
        target = loc,
    })

    return ngx.redirect(loc, ngx.HTTP_TEMPORARY_REDIRECT)
end

local function deny(mode, reason)
    decision_log(ngx.INFO, {
        mode = mode,
        host = ngx.var.host,
        uri = ngx.var.request_uri,
        method = ngx.req.get_method(),
        ua = ngx.var.http_user_agent,
        ip = ngx.var.remote_addr,
        decision = "deny",
        reason = reason,
        target = "-",
    })

    return ngx.exit(ngx.HTTP_FORBIDDEN)
end

local function run_basic_guard()
    local auth = ngx.var.http_authorization or ""
    local b64 = auth:match("^[Bb]asic%s+(.+)$")

    if not b64 then return true end

    local decoded = ngx.decode_base64(b64)

    if not decoded then return nil, "basic_bad_base64" end
    if decoded:find("\r", 1, true) or decoded:find("\n", 1, true) then return nil, "basic_decoded_crlf" end
    if decoded:find("\0", 1, true) then return nil, "basic_decoded_nul" end
    if #decoded > 4096 then return nil, "basic_decoded_too_large" end

    return true
end

local function is_browser_like(ua)
    ua = (ua or ""):lower()

    return ua:find("mozilla", 1, true)
        or ua:find("chrome", 1, true)
        or ua:find("safari", 1, true)
        or ua:find("firefox", 1, true)
        or ua:find("edg", 1, true)
end

-- safe_cookie_value / append_set_cookie are forward-declared earlier in the
-- file (above set_loop_marker_cookie) so closures there can capture them as
-- upvalues. Their real bodies are assigned just below clearance_cookie_state.
local clearance_debug = (os.getenv("CFM_CLEARANCE_DEBUG") or "0") == "1"
local clearance_trace = ngx.shared and ngx.shared.cfm_panel_state

local function trace_verify_success(req_id, ip, host, scope, exp_unix, set_cookie_sent)
    if not clearance_trace then return end
    local corr = tostring(req_id or "-")
    local key = "trace_verify:" .. tostring(ip or "-")
    local payload = table.concat({
        corr,
        tostring(host or "-"),
        tostring(scope or "-"),
        tostring(exp_unix or 0),
        set_cookie_sent and "1" or "0",
    }, "|")
    clearance_trace:set(key, payload, 30)
end

local function pop_verify_trace(ip)
    if not clearance_trace then return nil end
    local key = "trace_verify:" .. tostring(ip or "-")
    local payload = clearance_trace:get(key)
    if payload then
        clearance_trace:delete(key)
    end
    return payload
end

local function normalize_validator_reason(reason)
    -- Keep "module_error" and "crypto_unavailable" *separately* from
    -- "validator_error" so validator_degraded_reason() (below) can route
    -- them to the fail-open path. Previously this collapsed both into
    -- "validator_error", which made the degraded check always miss when
    -- HMAC was unavailable in the OpenResty install (no resty.openssl.hmac
    -- and no ngx.hmac_sha256 from lua-resty-core) — symptom: cookie present,
    -- validator_reason=validator_error, infinite challenge loop.
    local buckets = {
        missing = true,
        bad_sig = true,
        expired = true,
        ip_mismatch = true,
        host_mismatch = true,
        scope_mismatch = true,
        validator_error = true,
        decision_timeout = true,
        missing_clearance_secret = true,
        module_error = true,
        crypto_unavailable = true,
    }
    reason = tostring(reason or "")
    if reason == "error" then
        return "validator_error"
    end
    if buckets[reason] then
        return reason
    end
    return "validator_error"
end

-- Per-scope clearance cookie name: the Go challenge server mints panel
-- clearances as cfm_clearance_p<port> (web keeps cfm_clearance) so web and
-- panel tokens no longer clobber each other in the port-agnostic browser
-- cookie jar (edge-unification Phase 2a). Must mirror clearanceCookieName
-- in challenge_server.go.
local function scoped_clearance_cookie_name(scope)
    local port = tostring(scope or ""):match("^panel:(%d+)$")
    if port then return "cfm_clearance_p" .. port end
    return "cfm_clearance"
end

-- Read the clearance token for this scope: the per-scope cookie only.
-- The legacy shared-name (cfm_clearance) fallback was dropped in the Phase 3
-- cookie-net cleanup (docs/edge-unification-plan.md) once the per-scope cookie
-- scheme proved itself fleet-wide (burn-in clean on orion+titan). A stale
-- legacy-name cookie now costs at most a one-time re-challenge, never a lockout.
local function read_clearance_cookie(scope)
    local name = scoped_clearance_cookie_name(scope)
    local token = safe_cookie_value(ngx.var["cookie_" .. name])
    if token then return token, name end
    return nil, name
end

local function clearance_cookie_state(ip, host, scope)
    local token = read_clearance_cookie(scope)
    local secret = panel_bridge_token
    if not secret or secret == "" then
        ngx.log(ngx.ERR, "[cfm_panel_clearance_debug] reason=missing_clearance_secret ip=", tostring(ip or "-"), " host=", tostring(host or "-"), " scope=", tostring(scope or "-"), " has_cookie=", token and "true" or "false")
        return false, "missing_clearance_secret"
    end
    if clearance_debug then
        ngx.log(
            ngx.NOTICE,
            "[cfm_panel_clearance_debug] phase=validate_pre",
            " req_id=", tostring(ngx.var.request_id or "-"),
            " host=", tostring(host or "-"),
            " panel_scope=", tostring(scope or "-"),
            " cookie_present=", token and "1" or "0"
        )
    end
    local ok_call, ok, reason = pcall(clearance_validator.validate, token, ip, host, scope, secret)

    if not ok_call then
        local validate_err = ok
        reason = "validator_error"
        ok = false
        if not ngx.ctx.cfm_panel_clearance_error_logged then
            ngx.ctx.cfm_panel_clearance_error_logged = true
            ngx.log(
                ngx.ERR,
                "[cfm_panel] clearance validator runtime error",
                " module=cfm_clearance",
                " err=", tostring(validate_err),
                " host=", tostring(host or "-"),
                " uri=", tostring(ngx.var.request_uri or "-"),
                " scope=", tostring(scope or "-"),
                " mode=", tostring(ngx.var.cfm_panel_mode or ngx.var.server_port or "-")
            )
        end
    end
    if clearance_debug then
        ngx.log(
            ngx.NOTICE,
            "[cfm_panel_clearance_debug] phase=validate_post",
            " req_id=", tostring(ngx.var.request_id or "-"),
            " host=", tostring(host or "-"),
            " panel_scope=", tostring(scope or "-"),
            " cookie_present=", token and "1" or "0",
            " result_ok=", ok and "1" or "0",
            " reason=", tostring(reason or "-")
        )
    end

    if reason == "validator_error" and not clearance_module_error_reported then
        clearance_module_error_reported = true
        ngx.log(ngx.ERR, "[cfm_panel] clearance validator unavailable; continuing with challenge/passthrough flow")
    end

    reason = normalize_validator_reason(reason)
    if not ok then
        ngx.log(ngx.NOTICE, "[cfm_panel_clearance_reject] reason=", tostring(reason or "-"), " ip=", tostring(ip or "-"), " host=", tostring(host or "-"), " scope=", tostring(scope or "-"), " has_cookie=", token and "true" or "false")
        return false, reason
    end

    return true, "clearance_valid"
end

append_set_cookie = function(v)
    local h = ngx.header["Set-Cookie"]

    if not h then
        ngx.header["Set-Cookie"] = v
        return
    end

    if type(h) == "table" then
        table.insert(h, v)
        ngx.header["Set-Cookie"] = h
        return
    end

    ngx.header["Set-Cookie"] = { h, v }
end

safe_cookie_value = function(v)
    if not v or v == "" then return nil end
    if v:find("[%c;]") then return nil end

    return v
end

-- Clearance-cookie TTL, in priority order:
--   1. nginx var escape hatch ($cfm_challenge_cookie_life) — explicit local
--      operator override, set by no shipped config;
--   2. the daemon-published authoritative value (cfm_bridge_config.lua
--      cookie_life_sec — the same CHALLENGE_COOKIE_LIFE chain the challenge
--      server mints tokens with), so panel re-mints stop diverging from the
--      operator-configured clearance lifetime;
--   3. the historical 45m fallback (upgrade lag: old daemon, new Lua).
local function clearance_cookie_ttl()
    local v = ngx.var.cfm_challenge_cookie_life or ngx.var.CHALLENGE_COOKIE_LIFE
    if v and v ~= "" then return parse_duration_seconds(v, 2700) end
    local pub = panel_bridge_cfg and tonumber(panel_bridge_cfg.cookie_life_sec)
    if pub and pub > 0 then return pub end
    return 2700
end

local function refresh_clearance_cookie(ip, host, scope)
    local ttl = clearance_cookie_ttl()

    local attrs = "Path=/; Max-Age=" .. tostring(ttl) .. "; HttpOnly; SameSite=Lax"

    if ngx.var.https == "on" or ngx.var.scheme == "https" then
        attrs = attrs .. "; Secure"
    end

    local refreshed = false

    -- Read via the per-scope helper and RE-SET under the scoped name to slide
    -- the clearance TTL forward on each cleared request.
    local cfm_clearance = read_clearance_cookie(scope)
    if cfm_clearance then
        local out_val = tostring(cfm_clearance)
        if panel_bridge_cfg.clearance_refresh and ip and host and ok_clearance and clearance_validator and type(clearance_validator.mint) == "function" then
            local secret = panel_bridge_token
            if secret and secret ~= "" then
                local fresh, mint_err = clearance_validator.mint(ip, host, scope or "", secret, ttl)
                if fresh and fresh ~= "" then
                    out_val = fresh
                elseif mint_err and not ngx.ctx.cfm_panel_clearance_mint_err_logged then
                    ngx.ctx.cfm_panel_clearance_mint_err_logged = true
                    ngx.log(ngx.WARN, "[cfm_panel] clearance re-mint failed err=", tostring(mint_err),
                        " host=", tostring(host or "-"), " scope=", tostring(scope or "-"),
                        "; falling back to original cookie value")
                end
            end
        end
        append_set_cookie(scoped_clearance_cookie_name(scope) .. "=" .. out_val .. "; " .. attrs)
        refreshed = true
    end

    return refreshed
end

local function is_exempt_path(uri)
    return uri == "/healthz"
        or uri == "/ping"
        or uri == "/__cfm_challenge"
        or starts_with(uri, "/__cfm_challenge/")
        or starts_with(uri, "/.well-known/")
end

local function is_panel_api_or_sso(uri)
    return starts_with(uri, "/json-api/")
        or uri == "/json-api/cpanel"
        or starts_with(uri, "/json-api/cpanel/")
        or starts_with(uri, "/execute/")
        or starts_with(uri, "/xml-api/")
        or starts_with(uri, "/cpanelwebcall")
        or starts_with(uri, "/openid_connect/")
        or uri:match("^/cpsess%d+/json%-api/")
        or uri:match("^/cpsess%d+/execute/")
        or uri:match("^/cpsess%d+/xml%-api/")
        or uri:match("^/cpsess%d+/login/")
        or uri:match("^/cpsess%d+/websocket/")
        or uri == "/session"
        or starts_with(uri, "/session/")
        or uri == "/xfercpanel"
        or uri == "/xfercpsess"
        or uri == "/api"
        or starts_with(uri, "/api/")
        -- WHM live-transfer file / rsync streams. cPanel's transfer tool
        -- pulls account archives and tunnels rsync over these endpoints
        -- on port 2087; routing them through the challenge layer breaks
        -- the binary stream with a 300s upstream timeout, which the
        -- receiving side reports as `failed to read up to 64 KB from a
        -- file handle ... Is a directory`.
        or starts_with(uri, "/acctxfer")
        or starts_with(uri, "/cgi/transfer")
        or starts_with(uri, "/cgi/live_tail_log")
end

local function is_human_entry_uri(uri)
    return uri == "/"
        or uri == "/login"
        or uri == "/login/"
        or uri == "/cpanel"
        or uri == "/cpanel/"
        or uri == "/whm"
        or uri == "/whm/"
        or uri == "/webmail"
        or uri == "/webmail/"
end

-- Canonical panel-subdomain prefixes (shared with cfm.lua — single source,
-- no drift). nil on upgrade lag → fall back to the old inline list.
local ok_panel_hosts, panel_hosts_mod = pcall(require, "cfm_panel_hosts")
if not ok_panel_hosts then panel_hosts_mod = nil end

local function has_panel_prefix(host)
    if panel_hosts_mod then return panel_hosts_mod.has_panel_prefix(host) end
    local h = (host or ""):lower()

    return starts_with(h, "cpanel.")
        or starts_with(h, "whm.")
        or starts_with(h, "webmail.")
        or starts_with(h, "webdisk.")
end

local function is_ip_host(host)
    local h = (host or ""):lower()

    return h:match("^%d+%.%d+%.%d+%.%d+$") ~= nil
        or h:match("^%[[0-9a-f:]+%]$") ~= nil
        or h:find(":", 1, true) ~= nil
end

local function is_human_panel_entry(host, uri)
    if not is_human_entry_uri(uri) then return false end

    -- Explicit panel subdomains.
    if has_panel_prefix(host) then return true end

    -- Direct IP or Host header with :2087/:2083/etc.
    if is_ip_host(host) then return true end

    -- This Lua file runs only on panel DNAT listeners, so "/" and "/login"
    -- are direct human panel entrypoints even for normal hostnames.
    return true
end

local function allow_origin(mode, reason, origin, method, ua)
    ngx.var.cfm_pass = origin
    ngx.var.cfm_upstream = "cfm_panel_origin"

    decision_log(ngx.INFO, {
        mode = mode,
        host = ngx.var.host,
        uri = ngx.var.request_uri,
        method = method,
        ua = ua,
        ip = ngx.var.remote_addr,
        decision = "allow",
        reason = reason,
        target = origin,
    })

    return
end

local function allow_passthrough(mode, reason, origin, method, ua)
    ngx.var.cfm_pass = origin
    ngx.var.cfm_upstream = "cfm_panel_passthrough"

    decision_log(ngx.INFO, {
        mode = mode,
        host = ngx.var.host,
        uri = ngx.var.request_uri,
        method = method,
        ua = ua,
        ip = ngx.var.remote_addr,
        decision = "allow",
        reason = reason,
        target = origin,
    })

    return
end

local PANEL_FAIL_OPEN = (os.getenv("CFM_PANEL_FAIL_OPEN") or os.getenv("CFM_FAIL_OPEN") or "1") ~= "0"

-- ─────────────────────────────────────────────────────────────────────────────
-- Main request flow
-- ─────────────────────────────────────────────────────────────────────────────


-- Selftest hook used by install-openresty.sh preflight (`resty -e ...`),
-- which loads this file via dofile() and expects cfm_panel_selftest in _G.
-- access_by_lua_file re-runs the chunk on every request, so guard the
-- assignment to once per worker and use rawset() to bypass OpenResty's
-- _G write guard (otherwise every request emits:
--   "writing a global Lua variable ('cfm_panel_selftest')").
if rawget(_G, "cfm_panel_selftest") == nil then
    rawset(_G, "cfm_panel_selftest", function()
        local ok_dep, dep_err = pcall(require, "cfm_clearance")
        if not ok_dep then return false, "require cfm_clearance failed: " .. tostring(dep_err) end
        local chunk, load_err = loadfile(_BRIDGE_TOKEN_FILE)
        if not chunk then return false, "bridge token load failed: " .. tostring(load_err) end
        local ok_token, tok = pcall(chunk)
        if not ok_token or type(tok) ~= "string" or #tok < 32 then
            return false, "bridge token invalid"
        end
        return true, "ok"
    end)
end

-- CLI/package diagnostics can set this flag to validate the module without
-- falling through into request handling. This keeps Angie-only installs from
-- depending on OpenResty's `resty` runner; plain lua/luajit can load the file
-- with a small ngx stub and receive the selftest result as dofile() returns.
if os.getenv("CFM_PANEL_SELFTEST_ONLY") == "1" then
    return cfm_panel_selftest()
end

local function main()
local uri = ngx.var.uri or "/"
local method = ngx.req.get_method()
local ua = ngx.var.http_user_agent or "-"
local origin = ngx.var.cfm_panel_origin or ""
local mode = ngx.var.cfm_panel_challenge_mode or ngx.var.cfm_panel_policy or "human-entry-only"
-- Derive the panel scope from the TRUSTED per-listener $cfm_panel_origin port,
-- NOT the client-suppliable X-CFM-Panel-Port / X-Forwarded-Port headers (audit
-- F41). cfm_panel.lua runs only on the MAIN external panel request — the /__cfm_*
-- sub-locations that carry a listener-injected (trusted) X-CFM-Panel-Port return
-- early via `access_by_lua_block { return; }` — so here those headers are whatever
-- the client sent. Honouring them let a clearance solved on one panel port be
-- replayed on another (e.g. `X-CFM-Panel-Port: 2083` on the 2087 listener →
-- scope panel:2083 → the 2087 challenge is skipped), voiding per-port isolation.
-- $cfm_panel_origin is set per listener by the config, and its port equals the
-- trusted X-CFM-Panel-Port the sub-locations inject — which is exactly what the
-- Go challenge server mints the scope from (challenge_server.go clearanceScope) —
-- so mint and validate agree per listener while ignoring client input.
-- (server_port stays a last-resort fallback; origin always carries the port.)
local panel_scope = clearance_validator.panel_scope(nil, nil, origin, ngx.var.server_port)
local client_ip = ngx.var.remote_addr
local normalized_host = clearance_validator.normalize_host(ngx.var.host or "")
local req_id = ngx.var.request_id or ngx.var.http_x_request_id or ngx.var.http_x_cfm_request_id or "-"

local ok, reason = run_basic_guard()
if not ok then
    return deny(mode, reason)
end

if origin == "" then
    return deny(mode, "panel_origin_empty")
end

-- Protect internal CFM endpoints from direct external access.
if uri == decision_uri or uri == "/__cfm_verify" then
    local is_internal = ngx.req and ngx.req.is_internal and ngx.req.is_internal()

    if not is_internal then
        return ngx.exit(ngx.HTTP_NOT_FOUND or ngx.HTTP_FORBIDDEN)
    end
end

-- 1) API / SSO / cPanel internal flows must bypass CFM challenge completely.
-- This must happen before any host/panel-entry checks.
if is_panel_api_or_sso(uri) then
    return allow_passthrough(mode, "api_sso_passthrough", origin, method, ua)
end

-- 2) Local challenge/support endpoints and well-known paths.
if is_exempt_path(uri) then
    local exempt_reason = "path_exempt"

    if uri == "/__cfm_challenge" or starts_with(uri, "/__cfm_challenge/") then
        exempt_reason = "challenge_endpoint_exempt"
    end

    return allow_origin(mode, exempt_reason, origin, method, ua)
end

-- 2e) Panel WAF. Runs after the api/sso + exempt-path hard-skips above (so those
-- paths are never inspected) and covers human-entry AND generic passthrough in
-- one place; skips the internal verify/decision sub-locations. Mode is resolved
-- per request (env → detectors.conf PANEL_WAF_MODE → default ENFORCE): `off`
-- skips the probe entirely; `logonly` records the would-be action only; `enforce`
-- acts.
--
-- ENFORCE acts on the HIGH-CONFIDENCE BLOCK tier ONLY: `block` → deny. This is
-- deliberately narrow:
--   * `logonly`-tier hits are observe-only by definition — never enforced (they
--     are held at logonly precisely because they haven't passed FP burn-in);
--   * `challenge`-tier hits are NOT converted to a standalone WAF challenge here
--     — that would LOOP (a solved clearance cookie doesn't clear the WAF match,
--     so the request re-trips and re-challenges, and this returns before the
--     section-3 loop-breaker) and would hand non-browser clients an unsolvable
--     PoW. Challenge-tier enforcement is deferred to the clearance-aware Phase 4b
--     decision path; the existing human-entry challenge (section 3) is unchanged.
-- `deny` can't loop (no redirect). Self/IGNORE_NETS sources never reach here
-- (panel_waf_probe skips them), and the probe is pcall'd so any WAF error fails
-- OPEN to the normal flow — a WAF fault can never lock the panel, even when the
-- default enforce mode is in effect.
local waf_mode = resolve_panel_mode("CFM_PANEL_WAF", panel_bridge_cfg and panel_bridge_cfg.panel_waf_mode)
if waf_mode ~= "off" and uri ~= decision_uri and uri ~= "/__cfm_verify" then
    local waf_enforce = (waf_mode == "enforce")
    local okp, waf_action, waf_reason = pcall(panel_waf_probe, client_ip, normalized_host, uri, ngx.var.args or "", method, ua, panel_scope, waf_enforce)
    if okp and waf_enforce and waf_action == "block" then
        return deny(mode, "panel_waf_block_" .. tostring(waf_reason or "-"))
    end
end

-- 3) Human panel entrypoints.
if is_human_panel_entry(ngx.var.host or "", uri) then
    local clearance_ok, clearance_reason = clearance_cookie_state(client_ip, normalized_host, panel_scope)
    clearance_reason = normalize_validator_reason(clearance_reason)
    local cookie_present = read_clearance_cookie(panel_scope) and "1" or "0"
    local prior = pop_verify_trace(client_ip)

    -- error_log defaults to "warn"; use WARN on validation failures so the
    -- operator can see WHY the cookie was rejected without flipping the
    -- whole error_log level. Successful validations still log at NOTICE.
    local trace_level = (clearance_ok and ngx.NOTICE) or ngx.WARN
    ngx.log(
        trace_level,
        "[cfm_panel_trace] phase=validate_next",
        " corr_id=", tostring(req_id),
        " req_id=", tostring(req_id),
        " prior_verify=", tostring(prior or "-"),
        " host_header=", tostring(ngx.var.host or "-"),
        " host_norm=", tostring(normalized_host or "-"),
        " scope=", tostring(panel_scope or "-"),
        " server_port=", tostring(ngx.var.server_port or "-"),
        " origin=", tostring(origin or "-"),
        " cookie_present=", cookie_present,
        " validator_reason=", tostring(clearance_reason or "validator_error")
    )
    ngx.header["X-CFM-Panel-Scope"] = panel_scope
    ngx.header["X-CFM-Panel-Clearance"] = clearance_reason
    if (ngx.var.http_x_cfm_debug_headers == "1" or os.getenv("CFM_DEBUG_HEADERS") == "1") and clearance_reason == "module_error" then
        ngx.header["X-CFM-Clearance"] = "module_error"
    end

    -- Bridge decision. Mode resolved per request (env → detectors.conf
    -- PANEL_DECISION_MODE → default ENFORCE): `off` skips the bridge consult (and
    -- the ok/touch below) entirely; `logonly` records the would-be verdict only;
    -- `enforce` acts.
    -- ENFORCE acts on the HIGH-CONFIDENCE BLOCK tier ONLY: a bridge `block`
    -- (ip/vhost/rule) → hard deny, applied here BEFORE the clearance short-circuit
    -- so an IP the bridge blocked mid-session is denied even with a valid
    -- clearance cookie (web-edge parity: cfm.lua's block ignores clearance). `deny`
    -- is a plain 403 with no redirect, so it can't loop. The CHALLENGE tier is
    -- deliberately NOT enforced from the verdict — the clearance-aware human-entry
    -- challenge below already challenges un-cleared browsers (and passes
    -- non-browsers through), so deriving a challenge from the verdict would
    -- duplicate it and risk the loop Phase 4a avoided. The probe is pcall'd, so any
    -- bridge error fails OPEN to the normal flow (no deny) — a bridge fault can
    -- never lock the panel even under the default enforce mode; PANEL_DECISION_MODE
    -- = off (or CFM_PANEL_DECISION=0) is the per-node kill switch.
    local dec_mode = resolve_panel_mode("CFM_PANEL_DECISION", panel_bridge_cfg and panel_bridge_cfg.panel_decision_mode)
    if dec_mode ~= "off" then
        local dec_enforce = (dec_mode == "enforce")
        local okdp, dec_block, dec_why = pcall(panel_decision_probe, client_ip, normalized_host, uri, method, ua, panel_scope, dec_enforce)
        if okdp and dec_enforce and dec_block then
            return deny(mode, "panel_decision_block_" .. tostring(dec_why or "-"))
        end
    end

    local validator_degraded = validator_degraded_reason(clearance_reason)
    if validator_degraded then
        ngx.ctx.cfm_validator_guard_reason = clearance_reason
        ngx.header["X-CFM-Action"] = "bypass_validator_degraded"

        if uri == "/__cfm_challenge" or starts_with(uri, "/__cfm_challenge/") or uri == "/__cfm_verify" or starts_with(uri, "/__cfm_verify/") then
            return allow_origin(mode, "validator_degraded_challenge_endpoint_bypass_" .. tostring(clearance_reason), origin, method, ua)
        end

        if loop_marker_present() then
            return allow_origin(mode, "validator_degraded_loop_guard_" .. tostring(clearance_reason), origin, method, ua)
        end
    end

    if clearance_ok then
        local ttl = clearance_cookie_ttl()
        trace_verify_success(req_id, client_ip, normalized_host, panel_scope, ngx.time() + ttl, true)
        local ok_refresh, refresh_err = pcall(refresh_clearance_cookie, client_ip, normalized_host, panel_scope)

        if not ok_refresh then
            ngx.log(ngx.WARN, "CFM_PANEL clearance refresh failed: ", tostring(refresh_err))
        end

        -- Mirror the web ok/touch so the bridge records this IP passed on this
        -- panel scope (a bypass hint for the enforce path; never blocks/challenges).
        -- Skipped when the decision mode is off (no bridge interaction at all).
        -- Best-effort, throttled, must not affect the allow.
        if dec_mode ~= "off" then
            pcall(panel_touch_ok, client_ip, normalized_host, panel_scope, ttl)
        end

        return allow_origin(mode, "challenge_pass_clearance_valid", origin, method, ua)
    end

    if is_browser_like(ua) then
        if validator_degraded then
            set_loop_marker_cookie(20)
            return allow_origin(mode, "validator_degraded_fail_open_" .. tostring(clearance_reason), origin, method, ua)
        end

        -- Un-cleared browser: challenge once, then it rides the per-scope
        -- clearance cookie. The prior_attempts>=3 circuit breaker was removed in
        -- the Phase 3 cookie-net cleanup (docs/edge-unification-plan.md) after the
        -- per-scope cookie scheme proved itself fleet-wide — the loop-breaker was
        -- idle on both burn-in nodes in a window entirely after the enforce flip.
        -- The validator_degraded fail-open above still catches a genuinely broken
        -- validator module (HMAC unavailable), which is a different failure mode.
        return issue_challenge(mode, "human_entry_challenge_" .. tostring(clearance_reason or "invalid"), nil, 0, false)
    end

    return allow_origin(mode, "non_browser_entry_passthrough_" .. tostring(clearance_reason or "invalid"), origin, method, ua)
end

-- 4) Everything else passes to cpsrvd.
return allow_origin(mode, "default_passthrough", origin, method, ua)
end

local ok, err = xpcall(main, debug.traceback)
if not ok then
    local req_id = ngx.var.request_id or "-"
    local client = ngx.var.remote_addr or "-"
    local host = ngx.var.host or "-"
    local uri = ngx.var.request_uri or ngx.var.uri or "-"
    local origin = ngx.var.cfm_panel_origin or ""
    ngx.log(ngx.ERR, "[cfm_panel] request_failure",
        " request_id=", req_id,
        " client=", client,
        " host=", host,
        " uri=", uri,
        " policy=", (PANEL_FAIL_OPEN and "fail_open" or "fail_closed"),
        " stack=", tostring(err))
    if PANEL_FAIL_OPEN then
        ngx.var.cfm_pass = origin
        ngx.var.cfm_upstream = "cfm_panel_passthrough"
        return
    end
    return ngx.exit(ngx.HTTP_INTERNAL_SERVER_ERROR)
end

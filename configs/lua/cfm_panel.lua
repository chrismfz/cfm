-- Panel-specific CFM guard/router for cPanel/WHM/Webmail ports.
--
-- Single simplified policy:
--   1) API / SSO / cPanel internal flows: always pass to cpsrvd.
--   2) Human panel entrypoints: browser challenge.
--   3) Non-browser entrypoint clients: pass to cpsrvd, do not 403.
--   4) Everything else: pass to cpsrvd.
--
-- Important:
--   - Do not run mini-WAF here.
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


local _BRIDGE_TOKEN_FILE = "/var/lib/cfm/lua/cfm_bridge_token.lua"

local function load_token(path, tag)
    local chunk, load_err = loadfile(path)
    if not chunk then
        ngx.log(ngx.ERR, "[cfm_panel] cannot load ", tag, " ", path, ": ", tostring(load_err))
        return nil
    end
    local ok, val = pcall(chunk)
    if not ok or type(val) ~= "string" or #val < 32 then
        ngx.log(ngx.ERR, "[cfm_panel] ", tag, " invalid or too short: ", path)
        return nil
    end
    return val
end

local panel_bridge_token = load_token(_BRIDGE_TOKEN_FILE, "bridge token file")

-- Webdetector → Lua runtime knobs (sibling file to the bridge token).
-- Missing/unparseable file falls back to safe defaults so a daemon-vs-Lua
-- upgrade lag doesn't break the panel request path.
local _BRIDGE_CONFIG_FILE = "/var/lib/cfm/lua/cfm_bridge_config.lua"
local panel_bridge_cfg = { clearance_refresh = true }
do
    local chunk = loadfile(_BRIDGE_CONFIG_FILE)
    if chunk then
        local ok, val = pcall(chunk)
        if ok and type(val) == "table" then
            if val.clearance_refresh ~= nil then
                panel_bridge_cfg.clearance_refresh = (val.clearance_refresh ~= false)
            end
        else
            ngx.log(ngx.WARN, "[cfm_panel] bridge config file did not return a table: ", _BRIDGE_CONFIG_FILE)
        end
    end
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

local function loop_key(ip, host)
    return "panel_loop|" .. tostring(ip or "-") .. "|" .. tostring(host or "-")
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

local function note_challenge_attempt(ip, host, ttl)
    local sh = challenge_state()
    if not sh then return 0 end

    local key = loop_key(ip, host)
    local n = tonumber(sh:get(key) or 0) or 0
    n = n + 1

    sh:set(key, n, ttl or 20)

    return n
end

local function read_challenge_attempts(ip, host)
    local sh = challenge_state()
    if not sh then return 0 end
    return tonumber(sh:get(loop_key(ip, host)) or 0) or 0
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

    local attempts = note_challenge_attempt(ngx.var.remote_addr, ngx.var.host or "", 20)
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
        challenge_resume = tostring(attempts),
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

local function clearance_cookie_state(ip, host, scope)
    local token = safe_cookie_value(ngx.var.cookie_cfm_clearance)
    local secret = os.getenv("CFM_CLEARANCE_HMAC_SECRET")
    if not secret or secret == "" then secret = panel_bridge_token end
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

local function refresh_clearance_cookie(ip, host, scope)
    local ttl = parse_duration_seconds(
        ngx.var.cfm_challenge_cookie_life or ngx.var.CHALLENGE_COOKIE_LIFE or "45m",
        2700
    )

    local attrs = "Path=/; Max-Age=" .. tostring(ttl) .. "; HttpOnly; SameSite=Lax"

    if ngx.var.https == "on" or ngx.var.scheme == "https" then
        attrs = attrs .. "; Secure"
    end

    local refreshed = false

    local cfm_clearance = safe_cookie_value(ngx.var.cookie_cfm_clearance)
    if cfm_clearance then
        local out_val = tostring(cfm_clearance)
        if panel_bridge_cfg.clearance_refresh and ip and host and ok_clearance and clearance_validator and type(clearance_validator.mint) == "function" then
            local secret = os.getenv("CFM_CLEARANCE_HMAC_SECRET")
            if not secret or secret == "" then secret = panel_bridge_token end
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
        append_set_cookie("cfm_clearance=" .. out_val .. "; " .. attrs)
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

local function has_panel_prefix(host)
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
local panel_scope = clearance_validator.panel_scope(ngx.var.http_x_cfm_panel_port, ngx.var.http_x_forwarded_port, origin, ngx.var.server_port)
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

-- 3) Human panel entrypoints.
if is_human_panel_entry(ngx.var.host or "", uri) then
    local clearance_ok, clearance_reason = clearance_cookie_state(client_ip, normalized_host, panel_scope)
    clearance_reason = normalize_validator_reason(clearance_reason)
    local cookie_present = safe_cookie_value(ngx.var.cookie_cfm_clearance) and "1" or "0"
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
        local ttl = parse_duration_seconds(
            ngx.var.cfm_challenge_cookie_life or ngx.var.CHALLENGE_COOKIE_LIFE or "45m",
            2700
        )
        trace_verify_success(req_id, client_ip, normalized_host, panel_scope, ngx.time() + ttl, true)
        local ok_refresh, refresh_err = pcall(refresh_clearance_cookie, client_ip, normalized_host, panel_scope)

        if not ok_refresh then
            ngx.log(ngx.WARN, "CFM_PANEL clearance refresh failed: ", tostring(refresh_err))
        end

        return allow_origin(mode, "challenge_pass_clearance_valid", origin, method, ua)
    end

    if is_browser_like(ua) then
        if validator_degraded then
            set_loop_marker_cookie(20)
            return allow_origin(mode, "validator_degraded_fail_open_" .. tostring(clearance_reason), origin, method, ua)
        end

        -- Circuit breaker: if a browser has already been bounced through the
        -- challenge several times in the last 20s and *still* arrives without
        -- a valid clearance cookie, validation is structurally broken (cookie
        -- not coming back, scope/host/IP mismatch, etc). Fail open with a
        -- loop-guard cookie so the user can actually use the panel; the
        -- WARN log above already records the validator_reason for diagnosis.
        local prior_attempts = read_challenge_attempts(client_ip, ngx.var.host or "")
        if loop_marker_present() or prior_attempts >= 3 then
            ngx.log(
                ngx.WARN,
                "[cfm_panel_loop_break] prior_attempts=", tostring(prior_attempts),
                " loop_marker=", loop_marker_present() and "1" or "0",
                " ip=", tostring(client_ip or "-"),
                " host=", tostring(normalized_host or "-"),
                " scope=", tostring(panel_scope or "-"),
                " validator_reason=", tostring(clearance_reason or "-"),
                " cookie_present=", cookie_present
            )
            set_loop_marker_cookie(20)
            return allow_origin(mode, "challenge_loop_break_" .. tostring(clearance_reason or "invalid"), origin, method, ua)
        end

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

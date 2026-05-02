-- Panel-specific CFM guard/router for cPanel/WHM/Webmail ports.
local function starts_with(s, p) return s and p and s:sub(1, #p) == p end

local function decision_log(level, fields)
    ngx.log(level,
        "CFM_PANEL decision",
        " mode=", fields.mode or "-",
        " host=", fields.host or "-",
        " uri=", fields.uri or "-",
        " method=", fields.method or "-",
        " ip=", fields.ip or "-",
        " decision=", fields.decision or "-",
        " reason=", fields.reason or "-",
        " target=", fields.target or "-")
end

local function deny(mode, reason)
    decision_log(ngx.INFO, { mode = mode, host = ngx.var.host, uri = ngx.var.request_uri, method = ngx.req.get_method(), ip = ngx.var.remote_addr, decision = "deny", reason = reason, target = "-" })
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
    return ua:find("mozilla", 1, true) or ua:find("chrome", 1, true) or ua:find("safari", 1, true) or ua:find("firefox", 1, true) or ua:find("edg", 1, true)
end

local function has_clearance_cookie()
    local cookie = ngx.var.http_cookie or ""
    return cookie:find("cfm_clearance=", 1, true) or cookie:find("cf_clearance=", 1, true) or cookie:find("cp_security_token=", 1, true)
end

local function is_exempt_path(uri)
    return uri == "/healthz" or uri == "/ping" or starts_with(uri, "/.well-known/")
end

local function is_panel_sensitive(uri, method)
    if method == "POST" then return true end
    return uri == "/" or uri == "/login/" or starts_with(uri, "/login") or starts_with(uri, "/cpsess") or starts_with(uri, "/session")
end

local function query_decision_api()
    local res = ngx.location.capture("/__cfm_panel_decide")
    if not res then return nil, "backend_unavailable" end
    if res.status >= 500 then return nil, "backend_unavailable" end
    if res.status == 204 then return "allow", "backend_allow_204" end
    if res.status < 200 or res.status >= 300 then return nil, "backend_non_success" end

    local body = ((res.body or ""):gsub("^%s+", ""):gsub("%s+$", "")):lower()
    if body == "allow" or body == '{"decision":"allow"}' then
        return "allow", "backend_allow"
    end
    if body == "challenge" or body == '{"decision":"challenge"}' then
        return "challenge", "backend_challenge"
    end
    return nil, "backend_invalid_payload"
end

local uri = ngx.var.uri or "/"
local method = ngx.req.get_method()
local auth = ngx.var.http_authorization or ""
local origin = ngx.var.cfm_panel_origin or ""
local mode = ngx.var.cfm_panel_challenge_mode or "guard-only"
local fail_mode = ngx.var.cfm_panel_fail_mode or "fail-closed"

local ok, reason = run_basic_guard(); if not ok then return deny(mode, reason) end
if origin == "" then return deny(mode, "panel_origin_empty") end

local is_api = starts_with(uri, "/json-api/") or starts_with(uri, "/execute/") or uri == "/json-api/cpanel" or starts_with(uri, "/json-api/cpanel/")
local api_auth = auth:match("^whm%s+") or auth:match("^cpanel%s+") or auth:match("^[Bb]asic%s+")
if starts_with(uri, "/cpanelwebcall") or (is_api and api_auth) then
    ngx.var.cfm_pass = origin
    ngx.var.cfm_upstream = "cfm_panel_api"
    decision_log(ngx.DEBUG, { mode = mode, host = ngx.var.host, uri = ngx.var.request_uri, method = method, ip = ngx.var.remote_addr, decision = "allow", reason = "api_authenticated", target = origin })
    return
end

if is_exempt_path(uri) then
    ngx.var.cfm_pass = origin
    ngx.var.cfm_upstream = "cfm_panel_exempt"
    decision_log(ngx.INFO, { mode = mode, host = ngx.var.host, uri = ngx.var.request_uri, method = method, ip = ngx.var.remote_addr, decision = "allow", reason = "path_exempt", target = origin })
    return
end

local needs_challenge = false
if mode == "guard-only" then
    needs_challenge = is_panel_sensitive(uri, method)
elseif mode == "browser" then
    needs_challenge = is_browser_like(ngx.var.http_user_agent) and not has_clearance_cookie()
end

if needs_challenge then
    local decision, backend_reason = query_decision_api()
    if decision == "allow" then
        ngx.var.cfm_pass = origin
        ngx.var.cfm_upstream = "cfm_panel_origin"
        decision_log(ngx.INFO, { mode = mode, host = ngx.var.host, uri = ngx.var.request_uri, method = method, ip = ngx.var.remote_addr, decision = "allow", reason = backend_reason, target = origin })
        return
    end

    if backend_reason == "backend_unavailable" then
        if fail_mode == "fail-open" then
            ngx.var.cfm_pass = origin
            ngx.var.cfm_upstream = "cfm_panel_failopen"
            decision_log(ngx.WARN, { mode = mode, host = ngx.var.host, uri = ngx.var.request_uri, method = method, ip = ngx.var.remote_addr, decision = "allow", reason = "backend_unavailable_fail_open", target = origin })
            return
        end
        return deny(mode, "backend_unavailable_fail_closed")
    end
    return deny(mode, "challenge_required")
end

ngx.var.cfm_pass = origin
ngx.var.cfm_upstream = "cfm_panel_origin"
decision_log(ngx.DEBUG, { mode = mode, host = ngx.var.host, uri = ngx.var.request_uri, method = method, ip = ngx.var.remote_addr, decision = "allow", reason = "mode_skip", target = origin })
return

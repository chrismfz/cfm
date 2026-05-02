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
        " subreq_status=", fields.subreq_status or "-",
        " decision_reason=", fields.decision_reason or "-",
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
    if not res then
        return { outcome = "backend_unavailable", reason = "subrequest_nil", subreq_status = "-" }
    end
    local status = tonumber(res.status) or 0
    if status >= 500 then
        return { outcome = "backend_unavailable", reason = "subrequest_5xx", subreq_status = tostring(status) }
    end
    if status == 204 then
        return { outcome = "allow", reason = "backend_allow_204", subreq_status = tostring(status) }
    end
    if status < 200 or status >= 300 then
        return { outcome = "backend_unavailable", reason = "subrequest_non_2xx", subreq_status = tostring(status) }
    end

    local body = ((res.body or ""):gsub("^%s+", ""):gsub("%s+$", "")):lower()
    if body == "allow" or body == '{"decision":"allow"}' then
        return { outcome = "allow", reason = "backend_allow", subreq_status = tostring(status) }
    end
    if body == "challenge" or body == '{"decision":"challenge"}' then
        return { outcome = "challenge", reason = "backend_challenge", subreq_status = tostring(status) }
    end
    if body == "deny" or body == '{"decision":"deny"}' then
        return { outcome = "deny", reason = "backend_deny", subreq_status = tostring(status) }
    end
    return { outcome = "backend_unavailable", reason = "invalid_payload", subreq_status = tostring(status) }
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
    local decision = query_decision_api()
    if decision.outcome == "allow" then
        ngx.var.cfm_pass = origin
        ngx.var.cfm_upstream = "cfm_panel_origin"
        decision_log(ngx.INFO, { mode = mode, host = ngx.var.host, uri = ngx.var.request_uri, method = method, ip = ngx.var.remote_addr, decision = "allow", reason = "backend_allow", decision_reason = decision.reason, subreq_status = decision.subreq_status, target = origin })
        return
    end

    if decision.outcome == "backend_unavailable" then
        if fail_mode == "fail-open" then
            ngx.var.cfm_pass = origin
            ngx.var.cfm_upstream = "cfm_panel_failopen"
            decision_log(ngx.WARN, { mode = mode, host = ngx.var.host, uri = ngx.var.request_uri, method = method, ip = ngx.var.remote_addr, decision = "allow", reason = "backend_error_fail_open", decision_reason = decision.reason, subreq_status = decision.subreq_status, target = origin })
            return
        end
        decision_log(ngx.WARN, { mode = mode, host = ngx.var.host, uri = ngx.var.request_uri, method = method, ip = ngx.var.remote_addr, decision = "deny", reason = "backend_error_fail_closed", decision_reason = decision.reason, subreq_status = decision.subreq_status, target = "-" })
        return ngx.exit(ngx.HTTP_FORBIDDEN)
    end

    if decision.outcome == "challenge" then
        decision_log(ngx.INFO, { mode = mode, host = ngx.var.host, uri = ngx.var.request_uri, method = method, ip = ngx.var.remote_addr, decision = "deny", reason = "challenge_required", decision_reason = decision.reason, subreq_status = decision.subreq_status, target = "-" })
        return ngx.exit(ngx.HTTP_FORBIDDEN)
    end

    if decision.outcome == "deny" then
        decision_log(ngx.INFO, { mode = mode, host = ngx.var.host, uri = ngx.var.request_uri, method = method, ip = ngx.var.remote_addr, decision = "deny", reason = "backend_deny", decision_reason = decision.reason, subreq_status = decision.subreq_status, target = "-" })
        return ngx.exit(ngx.HTTP_FORBIDDEN)
    end

    decision_log(ngx.WARN, { mode = mode, host = ngx.var.host, uri = ngx.var.request_uri, method = method, ip = ngx.var.remote_addr, decision = "deny", reason = "unknown_decision", decision_reason = decision.reason or "-", subreq_status = decision.subreq_status or "-", target = "-" })
    return ngx.exit(ngx.HTTP_FORBIDDEN)
end

ngx.var.cfm_pass = origin
ngx.var.cfm_upstream = "cfm_panel_origin"
decision_log(ngx.DEBUG, { mode = mode, host = ngx.var.host, uri = ngx.var.request_uri, method = method, ip = ngx.var.remote_addr, decision = "allow", reason = "mode_skip", target = origin })
return

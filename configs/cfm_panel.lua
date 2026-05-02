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
        " subreq_uri=", fields.subreq_uri or "-",
        " subreq_status=", fields.subreq_status or "-",
        " subreq_location=", fields.subreq_location or "-",
        " decision_source=", fields.decision_source or "-",
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
    local subreq_uri = "/__cfm_panel_decide"
    local res = ngx.location.capture(subreq_uri)
    if not res then
        return { outcome = "backend_unavailable", reason = "subrequest_nil", subreq_uri = subreq_uri, subreq_status = "-", decision_source = "transport" }
    end

    local status = tonumber(res.status) or 0
    local status_s = tostring(status)
    local headers = res.header or {}
    local location = headers["Location"] or headers["location"] or "-"

    if status >= 500 then
        return { outcome = "backend_unavailable", reason = "subrequest_5xx", subreq_uri = subreq_uri, subreq_status = status_s, subreq_location = location, decision_source = "http_status" }
    end

    if status >= 300 and status < 400 then
        return { outcome = "redirect", reason = "subrequest_redirect", subreq_uri = subreq_uri, subreq_status = status_s, subreq_location = location, decision_source = "http_status" }
    end

    if status == 204 then
        return { outcome = "allow", reason = "backend_allow_204", subreq_uri = subreq_uri, subreq_status = status_s, subreq_location = location, decision_source = "http_status" }
    end

    if status < 200 or status >= 300 then
        return { outcome = "invalid_response", reason = "subrequest_unexpected_status", subreq_uri = subreq_uri, subreq_status = status_s, subreq_location = location, decision_source = "http_status" }
    end

    local body = ((res.body or ""):gsub("^%s+", ""):gsub("%s+$", "")):lower()
    local parsed = body:match('"decision"%s*:%s*"([a-z_%-]+)"')
    local decision = parsed or body

    if decision == "allow" then
        return { outcome = "allow", reason = "backend_allow", subreq_uri = subreq_uri, subreq_status = status_s, subreq_location = location, decision_source = parsed and "body_json" or "body_plain" }
    end
    if decision == "challenge" then
        return { outcome = "challenge", reason = "backend_challenge", subreq_uri = subreq_uri, subreq_status = status_s, subreq_location = location, decision_source = parsed and "body_json" or "body_plain" }
    end
    if decision == "deny" then
        return { outcome = "deny", reason = "backend_deny", subreq_uri = subreq_uri, subreq_status = status_s, subreq_location = location, decision_source = parsed and "body_json" or "body_plain" }
    end

    return { outcome = "invalid_response", reason = "invalid_payload", subreq_uri = subreq_uri, subreq_status = status_s, subreq_location = location, decision_source = parsed and "body_json" or "body_plain" }
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
        decision_log(ngx.INFO, { mode = mode, host = ngx.var.host, uri = ngx.var.request_uri, method = method, ip = ngx.var.remote_addr, decision = "allow", reason = "backend_allow", decision_reason = decision.reason, subreq_uri = decision.subreq_uri, subreq_status = decision.subreq_status, subreq_location = decision.subreq_location, decision_source = decision.decision_source, target = origin })
        return
    end

    if decision.outcome == "backend_unavailable" then
        if fail_mode == "fail-open" then
            ngx.var.cfm_pass = origin
            ngx.var.cfm_upstream = "cfm_panel_failopen"
            decision_log(ngx.WARN, { mode = mode, host = ngx.var.host, uri = ngx.var.request_uri, method = method, ip = ngx.var.remote_addr, decision = "allow", reason = "backend_error_fail_open", decision_reason = decision.reason, subreq_uri = decision.subreq_uri, subreq_status = decision.subreq_status, subreq_location = decision.subreq_location, decision_source = decision.decision_source, target = origin })
            return
        end
        decision_log(ngx.WARN, { mode = mode, host = ngx.var.host, uri = ngx.var.request_uri, method = method, ip = ngx.var.remote_addr, decision = "deny", reason = "backend_error_fail_closed", decision_reason = decision.reason, subreq_uri = decision.subreq_uri, subreq_status = decision.subreq_status, subreq_location = decision.subreq_location, decision_source = decision.decision_source, target = "-" })
        return ngx.exit(ngx.HTTP_FORBIDDEN)
    end


    if decision.outcome == "redirect" then
        decision_log(ngx.INFO, { mode = mode, host = ngx.var.host, uri = ngx.var.request_uri, method = method, ip = ngx.var.remote_addr, decision = "deny", reason = "subrequest_redirect_not_allowed", decision_reason = decision.reason, subreq_uri = decision.subreq_uri, subreq_status = decision.subreq_status, subreq_location = decision.subreq_location, decision_source = decision.decision_source, target = "-" })
        return ngx.exit(ngx.HTTP_FORBIDDEN)
    end

    if decision.outcome == "invalid_response" then
        decision_log(ngx.WARN, { mode = mode, host = ngx.var.host, uri = ngx.var.request_uri, method = method, ip = ngx.var.remote_addr, decision = "deny", reason = "backend_invalid_response", decision_reason = decision.reason, subreq_uri = decision.subreq_uri, subreq_status = decision.subreq_status, subreq_location = decision.subreq_location, decision_source = decision.decision_source, target = "-" })
        return ngx.exit(ngx.HTTP_FORBIDDEN)
    end
    if decision.outcome == "challenge" then
        decision_log(ngx.INFO, { mode = mode, host = ngx.var.host, uri = ngx.var.request_uri, method = method, ip = ngx.var.remote_addr, decision = "deny", reason = "challenge_required", decision_reason = decision.reason, subreq_uri = decision.subreq_uri, subreq_status = decision.subreq_status, subreq_location = decision.subreq_location, decision_source = decision.decision_source, target = "-" })
        return ngx.exit(ngx.HTTP_FORBIDDEN)
    end

    if decision.outcome == "deny" then
        decision_log(ngx.INFO, { mode = mode, host = ngx.var.host, uri = ngx.var.request_uri, method = method, ip = ngx.var.remote_addr, decision = "deny", reason = "backend_deny", decision_reason = decision.reason, subreq_uri = decision.subreq_uri, subreq_status = decision.subreq_status, subreq_location = decision.subreq_location, decision_source = decision.decision_source, target = "-" })
        return ngx.exit(ngx.HTTP_FORBIDDEN)
    end

    decision_log(ngx.WARN, { mode = mode, host = ngx.var.host, uri = ngx.var.request_uri, method = method, ip = ngx.var.remote_addr, decision = "deny", reason = "unknown_decision", decision_reason = decision.reason or "-", subreq_uri = decision.subreq_uri or "-", subreq_status = decision.subreq_status or "-", subreq_location = decision.subreq_location or "-", decision_source = decision.decision_source or "-", target = "-" })
    return ngx.exit(ngx.HTTP_FORBIDDEN)
end

ngx.var.cfm_pass = origin
ngx.var.cfm_upstream = "cfm_panel_origin"
decision_log(ngx.DEBUG, { mode = mode, host = ngx.var.host, uri = ngx.var.request_uri, method = method, ip = ngx.var.remote_addr, decision = "allow", reason = "mode_skip", target = origin })
return

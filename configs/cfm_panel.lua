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
        " allow_origin=", fields.allow_origin or "0",
        " challenge_issued=", fields.challenge_issued or "0",
        " challenge_entry=", fields.challenge_entry or "0",
        " challenge_solved=", fields.challenge_solved or "0",
        " challenge_resume=", fields.challenge_resume or "0",
        " deny_fail_closed=", fields.deny_fail_closed or "0",
        " target=", fields.target or "-")
end

local function parse_socket_error(err)
    local msg = tostring(err or "")
    local path = msg:match("unix:([^:%s]+)")
    if not path then
        path = msg:match("connect%(%) to ([^%s]+) failed")
    end
    return path or "-", msg
end

local function should_emit_failopen_log()
    local dict = ngx.shared and ngx.shared.cfm_stats
    if not dict then return true end
    local now = ngx.now and ngx.now() or os.time()
    local key = "panel_failopen_log:last"
    local last = tonumber(dict:get(key) or 0) or 0
    if now-last < 30 then return false end
    dict:set(key, now, 60)
    return true
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

local function ttl_key(ip) return "panel_ok|" .. tostring(ip or "-") end
local function cooldown_key(ip) return "panel_cooldown|" .. tostring(ip or "-") end

local function mark_challenge_issued(ip, cooldown_ttl)
    local sh = challenge_state(); if not sh then return end
    sh:set(cooldown_key(ip), 1, cooldown_ttl)
end

local function mark_passed(ip, ok_ttl)
    local sh = challenge_state(); if not sh then return end
    sh:set(ttl_key(ip), 1, ok_ttl)
end

local function has_bypass_ttl(ip)
    local sh = challenge_state(); if not sh then return false end
    return sh:get(ttl_key(ip)) ~= nil
end

local function cooldown_active(ip)
    local sh = challenge_state(); if not sh then return false end
    return sh:get(cooldown_key(ip)) ~= nil
end

local decision_uri = "/__cfm_panel_decide"
local function challenge_redirect_target(decision)
    local req_uri = ngx.var.request_uri or ngx.var.uri or "/"
    local challenge_location = ngx.var.cfm_panel_challenge_location or "/__cfm_challenge"
    if challenge_location == decision_uri then
        challenge_location = "/__cfm_challenge"
    end

    local loc = (decision and decision.subreq_location and decision.subreq_location ~= "-") and decision.subreq_location or challenge_location
    if loc == decision_uri or starts_with(loc, decision_uri .. "?") then
        return challenge_location
    end
    local full_decision = "http://" .. (ngx.var.host or "") .. decision_uri
    local full_decisions = {
        full_decision,
        "https://" .. (ngx.var.host or "") .. decision_uri,
    }
    for _, candidate in ipairs(full_decisions) do
        if starts_with(loc, candidate) then
            return challenge_location
        end
    end
    local sep = loc:find("?", 1, true) and "&" or "?"
    return loc .. sep .. "next=" .. ngx.escape_uri(req_uri)
end

local function issue_challenge(mode, reason, decision, cooldown_ttl)
    local loc = challenge_redirect_target(decision)
    mark_challenge_issued(ngx.var.remote_addr, cooldown_ttl or 0)
    decision_log(ngx.INFO, {
        mode = mode, host = ngx.var.host, uri = ngx.var.request_uri, method = ngx.req.get_method(), ip = ngx.var.remote_addr,
        decision = "challenge", reason = reason, decision_reason = decision and decision.reason or "-",
        subreq_uri = decision and decision.subreq_uri or "-", subreq_status = decision and decision.subreq_status or "-", subreq_location = decision and decision.subreq_location or "-", decision_source = decision and decision.decision_source or "-",
        allow_origin = "0", challenge_issued = "1", challenge_entry = "1", challenge_solved = "0", challenge_resume = "0", deny_fail_closed = "0", target = loc,
    })
    return ngx.redirect(loc, ngx.HTTP_TEMPORARY_REDIRECT)
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
    return cookie:find("cfm_ok=", 1, true) or cookie:find("cfm_clearance=", 1, true) or cookie:find("cf_clearance=", 1, true) or cookie:find("cp_security_token=", 1, true)
end

local function is_exempt_path(uri)
    return uri == "/healthz" or uri == "/ping" or uri == "/__cfm_challenge" or starts_with(uri, "/.well-known/")
end

local function is_panel_sensitive(uri, method)
    if method == "POST" then return true end
    return uri == "/" or uri == "/login/" or starts_with(uri, "/login") or starts_with(uri, "/cpsess") or starts_with(uri, "/session")
end

local function query_decision_api()
    local subreq_uri = decision_uri
    local res, err = ngx.location.capture(subreq_uri)
    if not res then
        local sock, detail = parse_socket_error(err)
        return { outcome = "backend_unavailable", reason = "backend_unavailable", subreq_uri = subreq_uri, subreq_status = "-", subreq_location = "-", subreq_socket = sock, subreq_error = detail, decision_source = "transport" }
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
local fail_mode = ngx.var.cfm_panel_fail_mode or "fail-open"
local challenge_cooldown_ttl = parse_duration_seconds(ngx.var.cfm_challenge_cooldown or ngx.var.CHALLENGE_COOLDOWN or "45m", 2700)
local challenge_cookie_life_ttl = parse_duration_seconds(ngx.var.cfm_challenge_cookie_life or ngx.var.CHALLENGE_COOKIE_LIFE or "45m", 2700)
local openresty_ok_ip_ttl = parse_duration_seconds(ngx.var.cfm_openresty_ok_ip_ttl or ngx.var.OPENRESTY_OK_IP_TTL or "45m", challenge_cookie_life_ttl)

local ok, reason = run_basic_guard(); if not ok then return deny(mode, reason) end
if origin == "" then return deny(mode, "panel_origin_empty") end


if uri == decision_uri then
    local is_internal = ngx.req and ngx.req.is_internal and ngx.req.is_internal()
    if not is_internal then
        return ngx.exit(ngx.HTTP_NOT_FOUND or ngx.HTTP_FORBIDDEN)
    end
end

local is_directadmin_api = starts_with(uri, "/api/")
local is_api = is_directadmin_api or starts_with(uri, "/json-api/") or starts_with(uri, "/execute/") or starts_with(uri, "/cpanelwebcall") or uri == "/json-api/cpanel" or starts_with(uri, "/json-api/cpanel/")
local api_auth = auth:match("^whm%s+") or auth:match("^cpanel%s+") or auth:match("^[Bb]asic%s+")
if is_api and api_auth then
    ngx.var.cfm_pass = origin
    ngx.var.cfm_upstream = "cfm_panel_api"
    local api_reason = is_directadmin_api and "api_authenticated_directadmin" or "api_authenticated"
    decision_log(ngx.DEBUG, { mode = mode, host = ngx.var.host, uri = ngx.var.request_uri, method = method, ip = ngx.var.remote_addr, decision = "allow", reason = api_reason, target = origin })
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
elseif mode == "forced" then
    needs_challenge = true
end

if mode == "forced" then
    if has_clearance_cookie() then
        mark_passed(ngx.var.remote_addr, openresty_ok_ip_ttl)
        ngx.var.cfm_pass = origin
        ngx.var.cfm_upstream = "cfm_panel_origin"
        decision_log(ngx.INFO, { mode = mode, host = ngx.var.host, uri = ngx.var.request_uri, method = method, ip = ngx.var.remote_addr, decision = "allow", reason = "challenge_pass_cookie", allow_origin = "1", challenge_issued = "0", challenge_entry = "0", challenge_solved = "1", challenge_resume = "1", target = origin })
        return
    end
    if has_bypass_ttl(ngx.var.remote_addr) then
        ngx.var.cfm_pass = origin
        ngx.var.cfm_upstream = "cfm_panel_origin"
        decision_log(ngx.INFO, { mode = mode, host = ngx.var.host, uri = ngx.var.request_uri, method = method, ip = ngx.var.remote_addr, decision = "allow", reason = "challenge_bypass_ttl", allow_origin = "1", challenge_issued = "0", challenge_entry = "0", challenge_solved = "0", challenge_resume = "1", target = origin })
        return
    end
    if cooldown_active(ngx.var.remote_addr) then
        return issue_challenge(mode, "challenge_cooldown", nil, challenge_cooldown_ttl)
    end
    return issue_challenge(mode, "forced_no_clearance_cookie", nil, challenge_cooldown_ttl)
end

if needs_challenge then
    local decision = query_decision_api()
    if decision.outcome == "allow" then
        mark_passed(ngx.var.remote_addr, openresty_ok_ip_ttl)
        ngx.var.cfm_pass = origin
        ngx.var.cfm_upstream = "cfm_panel_origin"
        decision_log(ngx.INFO, { mode = mode, host = ngx.var.host, uri = ngx.var.request_uri, method = method, ip = ngx.var.remote_addr, decision = "allow", reason = "backend_allow", decision_reason = decision.reason, subreq_uri = decision.subreq_uri, subreq_status = decision.subreq_status, subreq_location = decision.subreq_location, decision_source = decision.decision_source, allow_origin = "1", challenge_issued = "0", deny_fail_closed = "0", target = origin })
        return
    end

    if decision.outcome == "backend_unavailable" then
        if fail_mode == "fail-open" then
            ngx.var.cfm_pass = origin
            ngx.var.cfm_upstream = "cfm_panel_origin"
            if should_emit_failopen_log() then
                decision_log(ngx.WARN, { mode = mode, host = ngx.var.host, uri = ngx.var.request_uri, method = method, ip = ngx.var.remote_addr, decision = "allow", reason = "backend_unavailable_fail_open", decision_reason = decision.reason, subreq_uri = decision.subreq_uri, subreq_status = decision.subreq_status, subreq_location = (decision.subreq_location or "-") .. " socket=" .. (decision.subreq_socket or "-") .. " error=" .. (decision.subreq_error or "-"), decision_source = decision.decision_source, allow_origin = "1", challenge_issued = "0", deny_fail_closed = "0", target = origin })
            end
            return
        end
        if mode == "guard-only" and is_panel_sensitive(uri, method) then
            return issue_challenge(mode, "backend_error_fail_closed_challenge", decision, challenge_cooldown_ttl)
        end
        decision_log(ngx.WARN, { mode = mode, host = ngx.var.host, uri = ngx.var.request_uri, method = method, ip = ngx.var.remote_addr, decision = "deny", reason = "backend_error_fail_closed", decision_reason = decision.reason, subreq_uri = decision.subreq_uri, subreq_status = decision.subreq_status, subreq_location = decision.subreq_location, decision_source = decision.decision_source, allow_origin = "0", challenge_issued = "0", deny_fail_closed = "1", target = "-" })
        return ngx.exit(ngx.HTTP_FORBIDDEN)
    end


    if decision.outcome == "redirect" then
        return issue_challenge(mode, "challenge_redirect", decision, challenge_cooldown_ttl)
    end

    if decision.outcome == "invalid_response" then
        decision_log(ngx.WARN, { mode = mode, host = ngx.var.host, uri = ngx.var.request_uri, method = method, ip = ngx.var.remote_addr, decision = "deny", reason = "backend_invalid_response", decision_reason = decision.reason, subreq_uri = decision.subreq_uri, subreq_status = decision.subreq_status, subreq_location = decision.subreq_location, decision_source = decision.decision_source, target = "-" })
        return ngx.exit(ngx.HTTP_FORBIDDEN)
    end
    if decision.outcome == "challenge" then
        return issue_challenge(mode, "challenge_required", decision, challenge_cooldown_ttl)
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

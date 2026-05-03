-- Panel-specific CFM guard/router for cPanel/WHM/Webmail ports.
local function starts_with(s, p) return s and p and s:sub(1, #p) == p end

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

local function ttl_key(ip, host) return "panel_ok|" .. tostring(ip or "-") .. "|" .. tostring(host or "-") end
local function cooldown_key(ip, host) return "panel_cooldown|" .. tostring(ip or "-") .. "|" .. tostring(host or "-") end

local function mark_challenge_issued(ip, host, cooldown_ttl)
    local sh = challenge_state(); if not sh then return end
    sh:set(cooldown_key(ip, host), 1, cooldown_ttl)
end

local function mark_passed(ip, host, ok_ttl)
    local sh = challenge_state(); if not sh then return end
    sh:set(ttl_key(ip, host), 1, ok_ttl)
end

local function has_bypass_ttl(ip, host)
    local sh = challenge_state(); if not sh then return false end
    return sh:get(ttl_key(ip, host)) ~= nil
end

local function cooldown_active(ip, host)
    local sh = challenge_state(); if not sh then return false end
    return sh:get(cooldown_key(ip, host)) ~= nil
end

local decision_uri = "/__cfm_panel_decide"

local function is_internal_decision_uri(candidate)
    if type(candidate) ~= "string" then return false end
    local c = candidate:gsub("^%s+", ""):gsub("%s+$", "")
    if c == "" then return false end
    if c == decision_uri or starts_with(c, decision_uri .. "?") then return true end
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
    if is_internal_guard_uri(candidate) or is_internal_decision_uri(candidate) then
        return fallback or "/"
    end
    return candidate or fallback or "/"
end

local function strip_nested_next_chain(raw_next)
    local candidate = sanitize_panel_next_target(raw_next, "/")
    if is_internal_decision_uri(candidate) then return "/" end
    if type(candidate) ~= "string" or candidate == "" then return "/" end
    if not starts_with(candidate, "/") then return candidate end
    local path, query = candidate:match("^([^?]*)%??(.*)$")
    if not query or query == "" then return candidate end
    local cleaned = {}
    for pair in query:gmatch("[^&]+") do
        local key, value = pair:match("^([^=]+)=?(.*)$")
        local dk = ngx.unescape_uri(key or "")
        if dk ~= "next" then
            cleaned[#cleaned+1] = pair
        elseif value and value ~= "" then
            local nested = sanitize_panel_next_target(value, "")
            if nested ~= "" and not is_internal_guard_uri(nested) then
                cleaned[#cleaned+1] = "next=" .. ngx.escape_uri(nested)
            end
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
            local sanitized = strip_nested_next_chain(raw)
            if type(sanitized) == "string" and sanitized ~= "" and not is_internal_guard_uri(sanitized) then
                return sanitized
            end
        end
    end
    return "/"
end

local function challenge_redirect_target(decision)
    local req_uri = ngx.var.request_uri or ngx.var.uri or "/"
    req_uri = strip_nested_next_chain(req_uri)
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
    local safe_next = sanitize_panel_next_target(req_uri, "/")
    if is_internal_guard_uri(safe_next) or is_internal_decision_uri(safe_next) then safe_next = "/" end
    return loc .. sep .. "next=" .. ngx.escape_uri(safe_next)
end

local function issue_challenge(mode, reason, decision, cooldown_ttl)
    local loc = challenge_redirect_target(decision)
    mark_challenge_issued(ngx.var.remote_addr, ngx.var.host or "", cooldown_ttl or 0)
    decision_log(ngx.INFO, {
        mode = mode, host = ngx.var.host, uri = ngx.var.request_uri, method = ngx.req.get_method(), ua = ngx.var.http_user_agent, ip = ngx.var.remote_addr,
        decision = "challenge", reason = reason, decision_reason = decision and decision.reason or "-",
        subreq_uri = decision and decision.subreq_uri or "-", subreq_status = decision and decision.subreq_status or "-", subreq_location = decision and decision.subreq_location or "-", decision_source = decision and decision.decision_source or "-",
        allow_origin = "0", challenge_issued = "1", challenge_entry = "1", challenge_solved = "0", challenge_resume = "0", deny_fail_closed = "0", target = loc,
    })
    return ngx.redirect(loc, ngx.HTTP_TEMPORARY_REDIRECT)
end

local function deny(mode, reason)
    decision_log(ngx.INFO, { mode = mode, host = ngx.var.host, uri = ngx.var.request_uri, method = ngx.req.get_method(), ua = ngx.var.http_user_agent, ip = ngx.var.remote_addr, decision = "deny", reason = reason, target = "-" })
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
    local cookie = "; " .. (ngx.var.http_cookie or "")
    return cookie:find("; cfm_ok=", 1, true) or cookie:find("; cfm_clearance=", 1, true) or cookie:find("; cf_clearance=", 1, true) or cookie:find("; cp_security_token=", 1, true)
end

local function is_exempt_path(uri)
    return uri == "/healthz" or uri == "/ping" or uri == "/__cfm_challenge" or starts_with(uri, "/.well-known/")
end

local function next_points_to_challenge()
    local args = ngx.req.get_uri_args()
    local next_arg = args and args.next
    if type(next_arg) == "table" then
        next_arg = next_arg[1]
    end
    if type(next_arg) ~= "string" or next_arg == "" then
        return false
    end

    local decoded = sanitize_panel_next_target(next_arg, "")
    return is_internal_challenge_uri(decoded)
end

-- /__cfm_verify is handled by exact nginx location blocks before Lua runs here.
local function is_challenge_flow_request(uri)
    return uri == "/__cfm_challenge" or starts_with(uri, "/__cfm_challenge/")
end


local function append_set_cookie(v)
    local h = ngx.header["Set-Cookie"]
    if not h then ngx.header["Set-Cookie"] = v; return end
    if type(h) == "table" then table.insert(h, v); ngx.header["Set-Cookie"] = h; return end
    ngx.header["Set-Cookie"] = { h, v }
end

local function refresh_clearance_cookie()
    local raw = ngx.var.cookie_cfm_ok
    if not raw or raw == "" then return false end
    local ttl = parse_duration_seconds(ngx.var.cfm_challenge_cookie_life or ngx.var.CHALLENGE_COOKIE_LIFE or "45m", 2700)
    local attrs = "Path=/; Max-Age=" .. tostring(ttl) .. "; HttpOnly; SameSite=Lax"
    if ngx.var.https == "on" then attrs = attrs .. "; Secure" end
    append_set_cookie("cfm_ok=" .. tostring(raw) .. "; " .. attrs)
    return true
end
local function is_panel_sensitive(uri, method)
    if method == "POST" then return true end
    return uri == "/" or uri == "/login/" or starts_with(uri, "/login") or starts_with(uri, "/openid_connect/") or starts_with(uri, "/cpsess") or starts_with(uri, "/session")
end

local function has_known_panel_prefix(host)
    local h = (host or ""):lower()
    return starts_with(h, "cpanel.") or starts_with(h, "whm.") or starts_with(h, "webmail.") or starts_with(h, "webdisk.")
end

local function is_configured_panel_host(host)
    local primary = (ngx.var.cfm_panel_primary_domain or ""):lower()
    local h = (host or ""):lower()
    if primary == "" then return true end
    if h == primary then return true end
    local proxies = (ngx.var.cfm_panel_proxy_domains or "")
    for token in proxies:gmatch("[^,%s]+") do
        if h == token:lower() then return true end
    end
    return false
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
local ua = ngx.var.http_user_agent or "-"
if uri == "/__cfm_challenge" or uri == "/__cfm_verify" then
    local args = ngx.req.get_uri_args() or {}
    local normalized_next = normalize_challenge_next_arg(args.next)
    if is_internal_guard_uri(normalized_next) or is_internal_decision_uri(normalized_next) then
        normalized_next = "/"
    end
    args.next = normalized_next
    ngx.req.set_uri_args(args)
end
local auth = ngx.var.http_authorization or ""
local origin = ngx.var.cfm_panel_origin or ""
local mode = ngx.var.cfm_panel_challenge_mode or "guard-only"
local fail_mode = ngx.var.cfm_panel_fail_mode or "fail-open"
local challenge_cooldown_ttl = parse_duration_seconds(ngx.var.CHALLENGE_COOLDOWN or "45m", 2700)
local challenge_cookie_life_ttl = parse_duration_seconds(ngx.var.CHALLENGE_COOKIE_LIFE or "45m", 2700)
local openresty_ok_ip_ttl = parse_duration_seconds(ngx.var.OPENRESTY_OK_IP_TTL or "45m", challenge_cookie_life_ttl)

local ok, reason = run_basic_guard(); if not ok then return deny(mode, reason) end
if origin == "" then return deny(mode, "panel_origin_empty") end

if not is_configured_panel_host(ngx.var.host) then
    return deny(mode, "host_not_configured")
end

local host = ngx.var.host or ""
local host_is_known_panel_prefix = has_known_panel_prefix(host)

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

if is_challenge_flow_request(uri) then
    ngx.var.cfm_pass = origin
    ngx.var.cfm_upstream = "cfm_panel_origin"
    decision_log(ngx.INFO, { mode = mode, host = ngx.var.host, uri = ngx.var.request_uri, method = method, ip = ngx.var.remote_addr, decision = "allow", reason = "challenge_endpoint_exempt", allow_origin = "1", challenge_issued = "0", challenge_entry = "1", challenge_solved = "0", challenge_resume = "0", target = origin })
    return
end

if is_exempt_path(uri) then
    ngx.var.cfm_pass = origin
    ngx.var.cfm_upstream = "cfm_panel_exempt"
    decision_log(ngx.INFO, { mode = mode, host = ngx.var.host, uri = ngx.var.request_uri, method = method, ip = ngx.var.remote_addr, decision = "allow", reason = "path_exempt", target = origin })
    return
end

local needs_challenge = host_is_known_panel_prefix
if mode == "guard-only" then
    needs_challenge = needs_challenge or is_panel_sensitive(uri, method)
elseif mode == "browser" then
    needs_challenge = needs_challenge or (is_browser_like(ngx.var.http_user_agent) and not has_clearance_cookie())
elseif mode == "forced" then
    needs_challenge = true
end

if mode == "forced" then
    if has_clearance_cookie() then
        mark_passed(ngx.var.remote_addr, host, openresty_ok_ip_ttl)
        refresh_clearance_cookie()
        ngx.var.cfm_pass = origin
        ngx.var.cfm_upstream = "cfm_panel_origin"
        decision_log(ngx.INFO, { mode = mode, host = ngx.var.host, uri = ngx.var.request_uri, method = method, ua = ua, ip = ngx.var.remote_addr, decision = "allow", reason = "challenge_pass_cookie", allow_origin = "1", challenge_issued = "0", challenge_entry = "0", challenge_solved = "1", challenge_resume = "1", target = origin })
        return
    end
    if has_bypass_ttl(ngx.var.remote_addr, host) then
        ngx.var.cfm_pass = origin
        ngx.var.cfm_upstream = "cfm_panel_origin"
        decision_log(ngx.INFO, { mode = mode, host = ngx.var.host, uri = ngx.var.request_uri, method = method, ua = ua, ip = ngx.var.remote_addr, decision = "allow", reason = "challenge_bypass_ttl", allow_origin = "1", challenge_issued = "0", challenge_entry = "0", challenge_solved = "0", challenge_resume = "1", target = origin })
        return
    end
    local sensitive = is_panel_sensitive(uri, method)
    if sensitive and cooldown_active(ngx.var.remote_addr, host) then
        if not is_browser_like(ua) then
            return deny(mode, "challenge_loop_protection")
        end
        return issue_challenge(mode, "challenge_loop_protection", nil, challenge_cooldown_ttl)
    end
    if sensitive and not is_browser_like(ua) then
        return deny(mode, "deny_unsolvable_client")
    end
    if sensitive then
        needs_challenge = true
    end
end

if needs_challenge then
    local decision = query_decision_api()
    if decision.outcome == "allow" then
        mark_passed(ngx.var.remote_addr, host, openresty_ok_ip_ttl)
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

-- cfm_clamav.lua
-- Async upload scanner: intercepts multipart POSTs, copies the body to a
-- temp file, and notifies the cfm bridge which enqueues it for ClamAV scanning.
-- All results go to cfm.clam.log via the Go side.
-- cfm.lua calls: require("cfm_clamav").notify(ip, waf_tag)

local _M = {}

-- ─────────────────────────────────────────────────────────────────────────────
-- CONFIG
-- ─────────────────────────────────────────────────────────────────────────────

local CFG = {
    enabled     = true,

    methods     = { POST = true, PUT = true },

    exclude_hosts = {
        -- ["internal.example.gr"] = true,
    },

    exclude_uri_prefixes = {
        -- "/wp-admin/",
    },

    timeout_ms  = 300,
    pending_dir = "/var/lib/cfm/scanner/pending",
    token       = "",   -- overwritten by init()
}

-- ─────────────────────────────────────────────────────────────────────────────
-- INIT  (call once from cfm.lua after CFM_TOKEN is known)
-- ─────────────────────────────────────────────────────────────────────────────

function _M.init(overrides)
    if type(overrides) ~= "table" then return end
    for k, v in pairs(overrides) do
        CFG[k] = v
    end
end

-- ─────────────────────────────────────────────────────────────────────────────
-- INTERNAL HELPERS
-- ─────────────────────────────────────────────────────────────────────────────

local function is_excluded(host, uri)
    if CFG.exclude_hosts[host] then return true end
    for _, prefix in ipairs(CFG.exclude_uri_prefixes) do
        if uri:sub(1, #prefix) == prefix then return true end
    end
    return false
end

local function write_temp(body_data, ip)
    local tmppath = string.format(
        "%s/upload_%d_%s_%s",
        CFG.pending_dir,
        math.floor(ngx.now() * 1000),
        ip:gsub("[^%w]", "_"),
        (ngx.var.request_id or "x"):sub(1, 8)
    )

    local f, err = io.open(tmppath, "wb")
    if not f then
        ngx.log(ngx.WARN, "[cfm_clamav] cannot write temp: ", err)
        return nil
    end
    f:write(body_data)
    f:close()
    return tmppath
end

local function extract_filename()
    if not ngx.ctx.waf_body then return "" end
    local fn = ngx.ctx.waf_body:match('[Ff]ilename%s*=%s*"([^"]+)"')
            or ngx.ctx.waf_body:match("[Ff]ilename%s*=%s*'([^']+)'")
    if fn then return fn:sub(1, 128) end
    return ""
end

local function has_file_part()
    if not ngx.ctx.waf_body or ngx.ctx.waf_body == "" then
        return false
    end
    return ngx.ctx.waf_body:find('[Ff]ilename%s*=') ~= nil
end

local function send_to_bridge(payload, scan_path, already_copied)
    local sock = ngx.socket.tcp()
    sock:settimeout(CFG.timeout_ms)

    local ok, err = sock:connect("unix:" .. CFG.sock_path)
    if not ok then
        ngx.log(ngx.DEBUG, "[cfm_clamav] bridge unavailable: ", err)
        if already_copied then os.remove(scan_path) end
        return
    end

    local req = table.concat({
        "POST /nginx/upload HTTP/1.1\r\n",
        "Host: cfm\r\n",
        "Content-Type: application/json\r\n",
        "X-CFM-Token: " .. CFG.token .. "\r\n",
        "Content-Length: " .. #payload .. "\r\n",
        "Connection: close\r\n\r\n",
        payload,
    })

    local _, send_err = sock:send(req)
    if send_err then
        if already_copied then os.remove(scan_path) end
        sock:close()
        return
    end

    -- Block until bridge responds so nginx spool stays alive long enough
    -- for the bridge to copy it, and Lua-written temps are confirmed received.
    local line = sock:receive("*l")
    sock:close()

    if already_copied and line and not line:find("200") then
        os.remove(scan_path)
    end
end

-- ─────────────────────────────────────────────────────────────────────────────
-- PUBLIC API
-- ─────────────────────────────────────────────────────────────────────────────

function _M.notify(ip, waf_tag)
    local ok, err = pcall(function()

        if not CFG.enabled then return end

        local method = ngx.req.get_method()
        if not CFG.methods[method] then return end

        local host = (ngx.var.host or ""):lower()
        local uri  = ngx.var.request_uri or ""
        if is_excluded(host, uri) then return end

        local ct = (ngx.var.content_type or ""):lower()
        if not ct:find("multipart/form-data", 1, true) then return end

        if not ngx.ctx.waf_body then
            ngx.req.read_body()
        end

        -- ClamAV lane: only real multipart file uploads.
        -- Generic FormData/admin-ajax requests without filename= stay in WAF lane only.
        if not has_file_part() then
            return
        end

        local scan_path, already_copied

        local body_file = ngx.req.get_body_file()
        if body_file and body_file ~= "" then
            scan_path      = body_file
            already_copied = false
        else
            local body_data = ngx.req.get_body_data()
            if not body_data or body_data == "" then return end
            scan_path = write_temp(body_data, ip)
            if not scan_path then return end
            already_copied = true
        end

        local ok_json, cjson = pcall(require, "cjson")
        if not ok_json then
            if already_copied then os.remove(scan_path) end
            return
        end

        local payload = cjson.encode({
            ip             = ip,
            host           = host,
            uri            = uri,
            method         = method,
            filename       = extract_filename(),
            body_file      = scan_path,
            reason         = waf_tag or "",
            already_copied = already_copied,
        })

        send_to_bridge(payload, scan_path, already_copied)
    end)

    if not ok then
        ngx.log(ngx.ERR, "[cfm_clamav] unexpected error: ", err)
    end
end

return _M

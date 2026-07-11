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

-- Content-Disposition parameter names are case-insensitive (RFC 2183), and
-- PHP/most origins parse `FILENAME=`/`FileName=` as a file part — so match the
-- whole word case-insensitively, not just the first letter, or a small in-memory
-- upload could dodge the file-part check with an odd-cased name.
local FN_CLASS = "[Ff][Ii][Ll][Ee][Nn][Aa][Mm][Ee]"

-- Best-effort filename for the scan label only (the scan itself uses the full
-- body_file). Reads the WAF's inspected view, so it returns "" when the file
-- part sits beyond the cap (the wants_scan fallback case) — the scan still runs.
local function extract_filename()
    if not ngx.ctx.waf_body then return "" end
    local fn = ngx.ctx.waf_body:match(FN_CLASS .. '%s*=%s*"([^"]+)"')
            or ngx.ctx.waf_body:match(FN_CLASS .. "%s*=%s*'([^']+)'")
    if fn then return fn:sub(1, 128) end
    return ""
end

-- Decide whether this multipart request carries a file worth scanning.
--
-- ngx.ctx.waf_body is only the WAF's first waf_body_max_len bytes (32KB today),
-- and it is absent (nil) whenever the WAF skipped the body read (e.g. a body
-- over the WAF's Content-Length gate). A filename= check on that view ALONE is
-- blind to a file part pushed past the cap by leading padding, or to a body the
-- WAF never inspected — so an attacker could evade the AV scan by prepending a
-- large non-file field before the file field (audit F17).
--
-- Fail safe: when the inspected view shows no file part but the real request
-- body has bytes we did NOT inspect (nginx spooled it to disk because it
-- exceeded the in-memory buffer), scan anyway rather than trust a truncated or
-- absent view. A genuinely small, fully-inspected multipart with no filename=
-- stays in the WAF lane only (no wasted scan), preserving the "scan only real
-- uploads" resource posture for the common admin-ajax/FormData case. The scan
-- itself always covers the full spooled body, so a file part beyond the cap is
-- still scanned once we decide to send it.
local function wants_scan(body_file)
    local waf_body = ngx.ctx.waf_body or ""
    if waf_body:find(FN_CLASS .. "%s*=") then
        return true            -- fast path: file part visible in the inspected view
    end
    if body_file and body_file ~= "" then
        return true            -- spooled tail beyond our view → can't rule out a file part
    end
    -- Whole body is in memory (small enough not to spool): this view is complete
    -- and authoritative, even when the WAF never populated ngx.ctx.waf_body. With
    -- the shipped client_body_buffer_size (1m), bodies up to ~1MB whose filename=
    -- sits past the 32KB WAF cap land here, so this branch is load-bearing.
    local data = ngx.req.get_body_data() or ""
    return data:find(FN_CLASS .. "%s*=") ~= nil
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

        -- ClamAV lane: only real multipart file uploads (or a body large enough
        -- that a file part could hide beyond the WAF's inspected view — see
        -- wants_scan). Generic small FormData/admin-ajax without filename= stays
        -- in the WAF lane only.
        local body_file = ngx.req.get_body_file()
        if not wants_scan(body_file) then
            return
        end

        local scan_path, already_copied

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

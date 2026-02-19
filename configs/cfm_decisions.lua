-- cfm_decisions.lua
-- Queries the cfm nginx_bridge unix socket for IP/vhost decisions.
-- Results are cached in a shared dict to avoid a socket call on every request.
--
-- Required nginx.conf:
--   lua_shared_dict cfm_decisions 10m;
--
-- Usage (from cfm_access.lua):
--   local decisions = require "cfm_decisions"
--   local d = decisions.get(ip, host)
--   -- d.ip_action:    "allow" | "challenge" | "block"
--   -- d.vhost_action: "allow" | "challenge"

local _M = {}

-- ── Config ────────────────────────────────────────────────────────────────────

local SOCK_PATH  = "/var/run/cfm/cfm_nginx.sock"
local TOKEN      = os.getenv("CFM_NGINX_TOKEN") or "cfm"
local CACHE_TTL  = 5   -- seconds to cache a positive decision
local ALLOW_TTL  = 2   -- seconds to cache an "allow" (shorter, so bans propagate fast)
local TIMEOUT_MS = 150 -- socket connect+read timeout (ms)

-- ── Shared dict cache ─────────────────────────────────────────────────────────

local cache = ngx.shared.cfm_decisions

local function cache_key(ip, host)
    return "d:" .. ip .. "|" .. (host or "")
end

-- ── HTTP/1.0 request over unix socket ─────────────────────────────────────────
-- We use ngx.socket.tcp() which supports unix: addresses in OpenResty.

local function query_bridge(ip, host)
    local sock = ngx.socket.tcp()
    sock:settimeout(TIMEOUT_MS)

    local ok, err = sock:connect("unix:" .. SOCK_PATH)
    if not ok then
        ngx.log(ngx.WARN, "[cfm] bridge connect failed: ", err)
        return nil
    end

    local path = "/nginx/decision?ip=" .. ngx.escape_uri(ip)
    if host and host ~= "" then
        path = path .. "&host=" .. ngx.escape_uri(host)
    end

    local req = table.concat({
        "GET " .. path .. " HTTP/1.0\r\n",
        "Host: cfm\r\n",
        "X-CFM-Token: " .. TOKEN .. "\r\n",
        "Connection: close\r\n",
        "\r\n",
    })

    local bytes, werr = sock:send(req)
    if not bytes then
        ngx.log(ngx.WARN, "[cfm] bridge send failed: ", werr)
        sock:close()
        return nil
    end

    -- Read status line
    local status_line, rerr = sock:receive("*l")
    if not status_line then
        ngx.log(ngx.WARN, "[cfm] bridge read status failed: ", rerr)
        sock:close()
        return nil
    end

    -- Expect "HTTP/1.0 200 OK"
    if not status_line:find("200") then
        ngx.log(ngx.WARN, "[cfm] bridge non-200: ", status_line)
        sock:close()
        return nil
    end

    -- Skip headers (read until blank line)
    while true do
        local line, lerr = sock:receive("*l")
        if not line or line == "" or lerr then break end
    end

    -- Read body
    local body, berr = sock:receive("*a")
    sock:close()

    if not body or body == "" then
        ngx.log(ngx.WARN, "[cfm] bridge empty body: ", berr)
        return nil
    end

    -- Parse JSON ({"ip_action":"...","vhost_action":"..."})
    -- Avoid cjson dependency: simple pattern match is safe for this fixed schema.
    local ip_action    = body:match('"ip_action"%s*:%s*"([^"]+)"')
    local vhost_action = body:match('"vhost_action"%s*:%s*"([^"]+)"')

    return {
        ip_action    = ip_action    or "allow",
        vhost_action = vhost_action or "allow",
    }
end

-- ── Public API ────────────────────────────────────────────────────────────────

-- get returns the decision for (ip, host), using the shared dict cache.
-- On socket error it fails open (returns "allow") to avoid blocking legit traffic.
function _M.get(ip, host)
    if not ip or ip == "" then
        return { ip_action = "allow", vhost_action = "allow" }
    end

    local key = cache_key(ip, host)

    -- Cache hit
    if cache then
        local cached = cache:get(key)
        if cached then
            local ia = cached:match("ip:([^|]+)")
            local va = cached:match("vh:([^|]+)")
            return {
                ip_action    = ia or "allow",
                vhost_action = va or "allow",
            }
        end
    end

    -- Cache miss → query bridge
    local d = query_bridge(ip, host)
    if not d then
        -- fail open
        return { ip_action = "allow", vhost_action = "allow" }
    end

    -- Cache result
    if cache then
        local is_allow = (d.ip_action == "allow" and d.vhost_action == "allow")
        local ttl = is_allow and ALLOW_TTL or CACHE_TTL
        cache:set(key, "ip:" .. d.ip_action .. "|vh:" .. d.vhost_action, ttl)
    end

    return d
end

-- invalidate removes a cached decision (call after PoW solve so next request re-queries)
function _M.invalidate(ip, host)
    if cache then
        cache:delete(cache_key(ip, host))
    end
end

return _M

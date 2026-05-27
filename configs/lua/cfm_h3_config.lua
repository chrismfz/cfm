-- configs/lua/cfm_h3_config.lua
--
-- HTTP/3 per-vhost opt-in for the Alt-Svc response header.
--
-- WHAT THIS DOES
-- --------------
-- For each request that reaches a successful allow, decide whether to
-- emit `Alt-Svc: h3=":443"; ma=300` in the response. The decision is
-- per-vhost and driven by an opt-in list maintained by the cfm daemon.
--
-- The list lives in JSON on disk (managed by Go side via CLI/apiserver
-- and cfm-admin's "Per-vhost controls" UI). Workers fetch it lazily via
-- the cfm_nginx.sock bridge at GET /nginx/h3/config every REFRESH_SEC
-- seconds. Each worker keeps its own in-memory cache; no shared dict is
-- needed because the data set is small (typically <100 hosts).
--
-- WHY OPT-IN (default OFF)
-- ------------------------
-- HTTP/3 over UDP/443 has been observed to fail silently on flaky mobile
-- and CGNAT paths: nginx logs status=200 rt=0.003 while the client
-- browser hangs for minutes on small assets. Until that path becomes
-- reliable for every traffic profile, the safe default is "don't
-- advertise H3 at all". A vhost owner who wants H3 opts in explicitly.
--
-- COST PER REQUEST
-- ----------------
-- * One ngx.now() vs cached timestamp comparison (~50 ns).
-- * Possibly one shdict access (REFRESH_SEC interval, ~1 µs).
-- * One Lua table hash lookup on the host (~0.5 µs).
-- * Wildcard fallback (linear over the small list of "*.example" entries).
-- Total: ~1-3 µs per response. Negligible vs the rest of the request.
--
-- OPERATIONAL NOTES
-- -----------------
-- * Toggle changes propagate within REFRESH_SEC (default 60s).
--   No nginx reload required.
-- * Tunable via env: CFM_H3_REFRESH_SEC.
-- * If the bridge is unreachable, the worker keeps the LAST KNOWN list
--   indefinitely and retries every REFRESH_SEC. Failure stays in the
--   "do not advertise" direction (fail-safe).
-- * Refresh is serialized across workers via a 1s lock entry in the
--   ngx.shared.cfm_decisions dict — at most one worker hits the bridge
--   per refresh window. Other workers reuse their last cached list.

local cjson = require "cjson.safe"

local _M = {}

-- ---------------------------------------------------------------------------
-- Per-worker cache state. Module-level locals persist across requests inside
-- the same worker process.

local _cache = {
    hosts_exact = {},  -- map[host] -> true
    hosts_wild  = {},  -- array of "*.example.com" patterns
    has_any     = false,
}
local _last_refresh_at = 0
local _refresh_sec     = tonumber(os.getenv("CFM_H3_REFRESH_SEC") or "60") or 60
if _refresh_sec < 1 then _refresh_sec = 1 end

-- ---------------------------------------------------------------------------
-- Helpers

local function lower(s)
    if not s then return "" end
    return string.lower(s)
end

-- normalize_host: lowercase, strip trailing dot, strip optional port.
-- Mirrors the Go-side normalizeControlHost so the two ends agree on keys.
local function normalize_host(raw)
    local h = lower(tostring(raw or ""))
    if h == "" then return "" end
    -- strip trailing dot
    if h:sub(-1) == "." then h = h:sub(1, -2) end
    -- strip ":port" (we don't need it for matching)
    local colon = h:find(":", 1, true)
    if colon then h = h:sub(1, colon - 1) end
    return h
end

-- glob_match: very small subset of shell glob for trailing "*" segments
-- and "*.example.com" forms. The Go side uses path/filepath.Match which
-- supports more, but in practice the only useful patterns for vhosts
-- are "*.suffix" and exact hosts. Keep it cheap.
local function glob_match(pattern, host)
    if pattern == host then return true end
    -- "*.example.com" => match anything ending with ".example.com"
    if pattern:sub(1, 2) == "*." then
        local suffix = pattern:sub(2)  -- ".example.com"
        if #host >= #suffix and host:sub(-#suffix) == suffix then
            return true
        end
    end
    return false
end

-- ---------------------------------------------------------------------------
-- Bridge fetch. Uses a private cosocket so it does not depend on cfm.lua's
-- internal http_unix function. Mirrors the same wire format (HTTP/1.1 over
-- unix socket with X-CFM-Token header).

local SOCK_PATH      = "/var/run/cfm/cfm_nginx.sock"
local BRIDGE_PATH    = "/nginx/h3/config"
local TOKEN_HEADER   = "X-CFM-Token"
local IO_TIMEOUT_MS  = 1000

-- _bridge_token is loaded lazily on first refresh attempt. We cannot do it
-- at module init because the cfm daemon may not have written the token
-- file yet at worker boot.
local _bridge_token        = nil
local _BRIDGE_TOKEN_FILE   = "/var/lib/cfm/lua/cfm_bridge_token.lua"

local function load_bridge_token()
    if _bridge_token then return _bridge_token end
    local chunk = loadfile(_BRIDGE_TOKEN_FILE)
    if not chunk then return nil end
    local ok, val = pcall(chunk)
    if not ok or type(val) ~= "string" or #val < 32 then return nil end
    _bridge_token = val
    return _bridge_token
end

local function bridge_fetch()
    local token = load_bridge_token()
    if not token then return nil, "no bridge token yet" end

    local s, err = ngx.socket.tcp()
    if not s then return nil, "socket.tcp: " .. (err or "?") end
    s:settimeouts(IO_TIMEOUT_MS, IO_TIMEOUT_MS, IO_TIMEOUT_MS)
    local ok, cerr = s:connect("unix:" .. SOCK_PATH)
    if not ok then s:close(); return nil, "connect: " .. (cerr or "?") end

    local req = "GET " .. BRIDGE_PATH .. " HTTP/1.1\r\n" ..
                "Host: localhost\r\n" ..
                "Connection: close\r\n" ..
                TOKEN_HEADER .. ": " .. token .. "\r\n\r\n"
    local _, werr = s:send(req)
    if werr then s:close(); return nil, "send: " .. (werr or "?") end

    local status_line, rerr = s:receive("*l")
    if not status_line then s:close(); return nil, "recv status: " .. (rerr or "?") end
    local code = tonumber(status_line:match("%s(%d%d%d)%s"))
    if code ~= 200 then s:close(); return nil, "http " .. tostring(code) end

    -- drain headers
    while true do
        local line, _ = s:receive("*l")
        if not line or line == "" then break end
    end
    local body = s:receive("*a") or ""
    s:close()
    return body, nil
end

-- ---------------------------------------------------------------------------
-- Refresh logic. Called at most once per REFRESH_SEC per worker, with a
-- shared-dict lock to deduplicate across workers (best-effort; if the
-- lock fails another worker is already fetching).

local function rebuild_cache(hosts)
    local exact, wild = {}, {}
    local n = 0
    for _, h in ipairs(hosts or {}) do
        local norm = normalize_host(h)
        if norm ~= "" then
            n = n + 1
            if norm:find("*", 1, true) or norm:find("?", 1, true) then
                wild[#wild + 1] = norm
            else
                exact[norm] = true
            end
        end
    end
    _cache.hosts_exact = exact
    _cache.hosts_wild  = wild
    _cache.has_any     = n > 0
end

local function refresh_if_needed()
    local now = ngx.now()
    if (now - _last_refresh_at) < _refresh_sec then
        return
    end

    -- Cross-worker dedupe via shdict lock. cfm_decisions is created in the
    -- nginx http {} block (lua_shared_dict cfm_decisions ...). The lock
    -- entry is short-lived (1s) so a crashed worker doesn't block the
    -- next refresh for long.
    local SH = ngx.shared.cfm_decisions
    if SH then
        local locked = SH:add("h3cfg_lock", "1", 1)
        if not locked then
            -- Another worker is fetching right now. Reset our timer so we
            -- don't keep retrying inside this same second.
            _last_refresh_at = now
            return
        end
    end

    local body, err = bridge_fetch()
    _last_refresh_at = now  -- always advance even on error (fail-safe)
    if SH then SH:delete("h3cfg_lock") end

    if not body then
        ngx.log(ngx.WARN, "[cfm_h3] refresh failed: ", tostring(err),
                " (keeping last cached list)")
        return
    end
    local decoded = cjson.decode(body)
    if type(decoded) ~= "table" then
        ngx.log(ngx.WARN, "[cfm_h3] bad bridge response (not JSON)")
        return
    end
    rebuild_cache(decoded.hosts)
end

-- ---------------------------------------------------------------------------
-- Public API

-- enabled_for: returns true if the given host should get Alt-Svc.
-- Cheap path when no vhosts are opted-in: short-circuits to false.
function _M.enabled_for(host)
    refresh_if_needed()
    if not _cache.has_any then return false end
    local h = normalize_host(host)
    if h == "" then return false end
    if _cache.hosts_exact[h] then return true end
    for _, pattern in ipairs(_cache.hosts_wild) do
        if glob_match(pattern, h) then return true end
    end
    return false
end

-- maybe_set_alt_svc: convenience helper for callers that want the full
-- behavior in one line. Sets ngx.header["Alt-Svc"] if the current request's
-- host is opted in. Safe to call from any phase where ngx.header is
-- writable (rewrite, access, header_filter, content).
function _M.maybe_set_alt_svc()
    local host = ngx.var.host
    if _M.enabled_for(host) then
        ngx.header["Alt-Svc"] = 'h3=":443"; ma=300'
    end
end

return _M

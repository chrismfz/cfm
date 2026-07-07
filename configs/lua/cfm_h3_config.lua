-- configs/lua/cfm_h3_config.lua
--
-- HTTP/3 (QUIC) per-vhost opt-in for the Alt-Svc response header.
--
-- WHAT THIS DOES
-- --------------
-- For each response, decide whether to emit `Alt-Svc: h3=":443"; ma=300`.
-- Per-vhost, driven by an opt-in list maintained by the cfm daemon. The
-- module is consumed from a server-level `header_filter_by_lua_block` (see
-- angie.conf / openresty.conf) so EVERY served response is covered,
-- regardless of which cfm.lua Step decided to allow the request — that
-- includes the clearance-cookie fast-path which is the bulk of real
-- production traffic.
--
-- The list lives in JSON on disk (managed by Go side via CLI/apiserver
-- and cfm-admin's "Per-vhost controls" UI). Workers fetch it lazily via
-- the cfm_nginx.sock bridge at GET /nginx/h3/config every REFRESH_SEC
-- seconds. Each worker keeps its own in-memory cache.
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
-- * has_any short-circuit (~10 ns) — common case when no opt-ins exist.
-- * Otherwise: one normalize_host + one table hash lookup (~0.5-2 µs).
-- * Wildcard fallback: linear over hosts_wild (typically <10 entries).
-- Total p99: <5 µs per response. Negligible.
--
-- REFRESH MODEL
-- -------------
-- Each request that finds the cache stale schedules an ASYNC refresh via
-- ngx.timer.at(0, ...) and continues serving with whatever cache it has
-- (even if empty). The actual bridge fetch never blocks the request
-- path. A per-worker boolean prevents stacking multiple in-flight
-- refreshes from the same worker.
--
-- We deliberately do NOT serialize refreshes across workers via
-- ngx.shared dicts. The previous attempt had a starvation bug: workers
-- that lost the lock advanced their own _last_refresh_at and never
-- updated their cache, so after enabling H3 only ~1/N of responses got
-- Alt-Svc for the entire REFRESH_SEC window. N workers polling once per
-- 60s over a localhost unix socket is trivial (~1ms each, ~8 calls/min
-- per nginx for an 8-worker box).
--
-- OPERATIONAL NOTES
-- -----------------
-- * Toggle changes propagate within REFRESH_SEC (default 60s).
-- * No nginx reload required.
-- * Tunable via env: CFM_H3_REFRESH_SEC.
-- * If the bridge is unreachable, the worker keeps the LAST KNOWN list
--   and retries on the next interval. Failure stays in the
--   "do not advertise" direction (fail-safe).

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
local _last_refresh_at  = 0
local _refresh_in_progress = false
local _refresh_sec      = tonumber(os.getenv("CFM_H3_REFRESH_SEC") or "60") or 60
if _refresh_sec < 1 then _refresh_sec = 1 end

-- ---------------------------------------------------------------------------
-- Helpers

-- normalize_host: lowercase, strip trailing dot, strip optional port. Mirrors
-- the Go-side normalizeControlHost so the two ends agree on keys.
-- IPv6-aware: `[::1]:443` and `[2001:db8::1]` keep their brackets and inner
-- colons; only a trailing `:port` outside the brackets is stripped.
local function normalize_host(raw)
    local h = string.lower(tostring(raw or ""))
    if h == "" then return "" end
    if h:sub(-1) == "." then h = h:sub(1, -2) end
    if h:sub(1, 1) == "[" then
        -- IPv6 literal. Keep everything up to the closing bracket; strip a
        -- trailing ":port" after it if present.
        local close = h:find("]", 1, true)
        if close then
            return h:sub(1, close)
        end
        return h
    end
    -- IPv4 / hostname. Strip ":port" if present.
    local colon = h:find(":", 1, true)
    if colon then h = h:sub(1, colon - 1) end
    return h
end

-- glob_match: minimal subset of shell glob covering the only patterns the
-- UI/CLI actually let an operator add for vhosts: exact host and
-- "*.suffix.tld". The Go store accepts richer patterns via filepath.Match
-- (`?`, `[abc]`, mid-pattern `*`), so rebuild_cache below tags any unknown
-- wildcard as "unsupported" and logs a one-shot warning rather than
-- silently routing it where glob_match cannot find it.
local function glob_match(pattern, host)
    if pattern == host then return true end
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
-- unix socket with X-CFM-Token header). Runs in a timer context — never
-- blocks the request path.

local SOCK_PATH      = "/var/run/cfm/cfm_nginx.sock"
local BRIDGE_PATH    = "/nginx/h3/config"
local TOKEN_HEADER   = "X-CFM-Token"
local IO_TIMEOUT_MS  = 200  -- localhost unix socket; 200ms is 200x headroom.

-- Bridge token via the shared cached accessor (cfm_bridge_cfg →
-- cfm_filecache, 10s TTL). The old private copy here cached the token
-- FOREVER per worker, so a daemon-side rotation left this module 403-ing
-- against the bridge until an nginx reload; now it converges within 10s
-- like every other consumer. pcall guards an upgrade lag where the module
-- set is older than this file.
local function load_bridge_token()
    local ok, bc = pcall(require, "cfm_bridge_cfg")
    if ok and type(bc) == "table" and bc.token then
        return (bc.token())
    end
    return nil
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

    while true do
        local line, _ = s:receive("*l")
        if not line or line == "" then break end
    end
    local body = s:receive("*a") or ""
    s:close()
    return body, nil
end

-- ---------------------------------------------------------------------------
-- Cache rebuild.
--
-- Hosts that contain glob characters the local matcher does not handle
-- (`?`, `[`, mid-pattern `*`) would silently never match if we routed them
-- into hosts_wild — that was a real bug. We now drop them and log a
-- one-shot warning per pattern so the operator knows. The Go store will
-- still hold them, the API will still list them, and a future shared
-- glob_to_lua_pattern helper (cfm.lua already has one) can lift this
-- restriction without re-introducing the silent-drop bug.

local _warned_unsupported = {}

local function is_supported_pattern(p)
    if not p:find("*", 1, true) and not p:find("?", 1, true) and not p:find("[", 1, true) then
        return true  -- exact host
    end
    if p:sub(1, 2) == "*." and not p:sub(3):find("*", 1, true)
       and not p:find("?", 1, true) and not p:find("[", 1, true) then
        return true  -- "*.suffix" only
    end
    return false
end

local function rebuild_cache(hosts)
    local exact, wild = {}, {}
    local n = 0
    for _, h in ipairs(hosts or {}) do
        local norm = normalize_host(h)
        if norm ~= "" then
            if is_supported_pattern(norm) then
                n = n + 1
                if norm:sub(1, 2) == "*." then
                    wild[#wild + 1] = norm
                else
                    exact[norm] = true
                end
            elseif not _warned_unsupported[norm] then
                _warned_unsupported[norm] = true
                ngx.log(ngx.WARN,
                    "[cfm_h3] dropping unsupported pattern (only exact and '*.suffix' are supported by the Lua matcher): ",
                    norm)
            end
        end
    end
    _cache.hosts_exact = exact
    _cache.hosts_wild  = wild
    _cache.has_any     = n > 0
end

-- ---------------------------------------------------------------------------
-- Async refresh. Each request that finds the cache stale schedules a timer
-- and returns immediately. The timer runs out-of-band, updates the cache,
-- and clears the in-progress flag. Concurrent requests within the same
-- worker do not stack timers (the _refresh_in_progress flag dedupes).

local function async_refresh_handler(premature)
    -- The flag MUST be cleared even if anything below raises, otherwise
    -- the worker never schedules another refresh until restart. Wrap the
    -- body in pcall and clear the flag in a finally-style block.
    local ok, err = pcall(function()
        if premature then return end
        local body, ferr = bridge_fetch()
        _last_refresh_at = ngx.now()
        if body then
            local decoded = cjson.decode(body)
            if type(decoded) == "table" then
                rebuild_cache(decoded.hosts)
            else
                ngx.log(ngx.WARN, "[cfm_h3] bad bridge response (not JSON)")
            end
        else
            ngx.log(ngx.WARN, "[cfm_h3] refresh failed: ", tostring(ferr),
                    " (keeping last cached list)")
        end
    end)
    _refresh_in_progress = false
    if not ok then
        ngx.log(ngx.ERR, "[cfm_h3] refresh handler raised: ", tostring(err))
    end
end

local function schedule_refresh_if_needed()
    if _refresh_in_progress then return end
    local now = ngx.now()
    if (now - _last_refresh_at) < _refresh_sec then return end
    _refresh_in_progress = true
    local ok, err = ngx.timer.at(0, async_refresh_handler)
    if not ok then
        _refresh_in_progress = false
        ngx.log(ngx.WARN, "[cfm_h3] could not schedule refresh timer: ", tostring(err))
    end
end

-- ---------------------------------------------------------------------------
-- Public API

-- enabled_for: returns true if the given host should get Alt-Svc.
-- Cheap path when no vhosts are opted-in: short-circuits to false BEFORE
-- doing any string work or scheduling work.
function _M.enabled_for(host)
    if not _cache.has_any then
        -- Still schedule the periodic refresh so a fresh opt-in eventually
        -- arrives even on a quiet worker. Refresh is bounded by REFRESH_SEC
        -- and runs out-of-band.
        schedule_refresh_if_needed()
        return false
    end
    schedule_refresh_if_needed()
    local h = normalize_host(host)
    if h == "" then return false end
    if _cache.hosts_exact[h] then return true end
    for _, pattern in ipairs(_cache.hosts_wild) do
        if glob_match(pattern, h) then return true end
    end
    return false
end

-- maybe_set_alt_svc: convenience helper. Sets ngx.header["Alt-Svc"] if the
-- current request's host is opted in. Safe to call from any phase where
-- ngx.header is writable (header_filter is the recommended phase — see the
-- nginx config blocks in angie.conf / openresty.conf).
function _M.maybe_set_alt_svc()
    if not _cache.has_any then
        schedule_refresh_if_needed()
        return
    end
    if _M.enabled_for(ngx.var.host) then
        ngx.header["Alt-Svc"] = 'h3=":443"; ma=300'
    end
end

return _M

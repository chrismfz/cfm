-- configs/lua/cfm_cache.lua
--
-- Site Cache — per-vhost edge caching policy, EDGE SIDE.
-- Design / plan of record: docs/site-cache-design.md.
--
-- PHASE 2 — OBSERVE ONLY
-- ----------------------
-- This module pulls the per-vhost cache policy the cfm daemon serves on
-- /nginx/cache/config and, from a server-level `header_filter_by_lua_block`
-- (see openresty.conf / angie.conf, next to the H3 Alt-Svc block), stamps an
-- `X-CFM-Cache` header on responses for vhosts that have a policy. It does
-- NOT cache anything — there is no `proxy_cache` wired yet. The point of this
-- phase is to validate the whole feed→edge→per-request-lookup pipeline and
-- measure its cost on real traffic BEFORE any body is cached. Later phases add
-- the safety rails and turn on caching (docs §14 Phase 3/4).
--
-- Structure mirrors cfm_h3_config.lua on purpose (same proven per-worker
-- async-refresh model, same fail-safe posture): a load error or an unreachable
-- bridge degrades silently to "no policy" — it can never affect the request.
--
-- COST PER REQUEST
-- ----------------
-- * Normal traffic (no X-CFM-Cache-Debug header): one schedule-refresh check
--   (a flag + one time compare, ~10 ns when a poll is not due — the same
--   per-response cost cfm_h3_config already pays) + one ngx.var read, then
--   return. No policy lookup on the ordinary path.
-- * An operator debug request additionally does one normalize_host + one table
--   hash lookup (~0.5-2 µs) plus a linear scan of the (tiny) wildcard list.
--
-- REFRESH MODEL
-- -------------
-- Each request that finds the cache stale schedules an ASYNC refresh via
-- ngx.timer.at(0, ...) and serves with whatever cache it has. The bridge fetch
-- never blocks the request path; a per-worker flag dedupes in-flight refreshes.
-- Fixed 60s poll (no env, no knob — CFM is config-file driven, not env-driven).
-- No nginx reload needed. Bridge unreachable → keep the LAST KNOWN policy
-- (fail-safe: no header rather than a wrong one).

local cjson = require "cjson.safe"

local _M = {}

-- ---------------------------------------------------------------------------
-- Per-worker cache state (module-level locals persist across requests in the
-- same worker process). `policies` maps an exact host to its policy table;
-- `wild` is an array of { pattern = "*.suffix", policy = {...} }.

local _cache = {
    policies = {},    -- map[host] -> policy table
    wild     = {},    -- array of { pattern, policy }
    has_any  = false,
}
local _last_refresh_at     = 0
local _refresh_in_progress = false
-- Fixed feed-poll interval. 60s matches the H3 sibling and needs no tuning for
-- an observe-only phase. CFM is config-file driven, not env-driven, so there is
-- deliberately nothing to override here (an earlier os.getenv gate was wrong:
-- nginx strips undeclared worker env, so it never fired on a real box).
local _refresh_sec = 60

-- The X-CFM-Cache observe header is a PER-REQUEST operator opt-in: it is stamped
-- ONLY when the request carries `X-CFM-Cache-Debug` (any non-empty value), so
-- internal cache policy (recipe / TTL bucket / purge generation) is never
-- disclosed to an ordinary client. Design §11.3 ("behind a debug flag"). No env
-- var and no config plumbing — an operator just runs
--   curl -H 'X-CFM-Cache-Debug: 1' -I https://site/
-- The persistent fleet on/off gate is the Phase-3 SITE_CACHE config knob (via
-- cfm_bridge_cfg), not this observe header.
local OBSERVE_HEADER_VAR = "http_x_cfm_cache_debug"

-- ---------------------------------------------------------------------------
-- Host helpers: shared with cfm_h3_config.lua via cfm_hostmatch (one matcher,
-- no drift — CLAUDE.md §5). Aliased to locals so the call sites below read the
-- same as before.
local hm = require "cfm_hostmatch"
local normalize_host      = hm.normalize_host
local glob_match          = hm.glob_match
local is_supported_pattern = hm.is_supported_pattern

-- ---------------------------------------------------------------------------
-- Bridge fetch (identical wire format to cfm_h3_config.lua: HTTP/1.1 over the
-- cfm_nginx.sock unix socket with the X-CFM-Token header, run in a timer so it
-- never blocks the request path).

local SOCK_PATH     = "/var/run/cfm/cfm_nginx.sock"
local BRIDGE_PATH   = "/nginx/cache/config"
local TOKEN_HEADER  = "X-CFM-Token"
local IO_TIMEOUT_MS = 200

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
-- Cache rebuild. Only exact hosts and "*.suffix" wildcards are honored (same
-- rule as the Go store); anything else is dropped with a one-shot warning so a
-- pattern the Lua matcher cannot find never silently disappears.

local _warned_unsupported = {}

local function rebuild_cache(entries)
    local policies, wild = {}, {}
    local n = 0
    for _, e in ipairs(entries or {}) do
        if type(e) == "table" and type(e.host) == "string" then
            local norm = normalize_host(e.host)
            if norm ~= "" and is_supported_pattern(norm) then
                local pol = {
                    gen            = tonumber(e.gen) or 0,
                    static         = (type(e.static) == "table") and e.static or nil,
                    micro          = (type(e.micro) == "table") and e.micro or nil,
                    strict_cookies = e.strict_cookies and true or false,
                    auth_cookies   = (type(e.auth_cookies) == "table") and e.auth_cookies or nil,
                }
                n = n + 1
                if norm:sub(1, 2) == "*." then
                    wild[#wild + 1] = { pattern = norm, policy = pol }
                else
                    policies[norm] = pol
                end
            elseif norm ~= "" and not _warned_unsupported[norm] then
                _warned_unsupported[norm] = true
                ngx.log(ngx.WARN,
                    "[cfm_cache] dropping unsupported host pattern (only exact and '*.suffix' supported): ",
                    norm)
            end
        end
    end
    _cache.policies = policies
    _cache.wild     = wild
    _cache.has_any  = n > 0
end

-- ---------------------------------------------------------------------------
-- Async refresh (identical model to cfm_h3_config.lua).

local function async_refresh_handler(premature)
    local ok, err = pcall(function()
        if premature then return end
        local body, ferr = bridge_fetch()
        _last_refresh_at = ngx.now()
        if body then
            local decoded = cjson.decode(body)
            if type(decoded) == "table" then
                rebuild_cache(decoded.entries)
            else
                ngx.log(ngx.WARN, "[cfm_cache] bad bridge response (not JSON)")
            end
        else
            ngx.log(ngx.WARN, "[cfm_cache] refresh failed: ", tostring(ferr),
                    " (keeping last cached policy)")
        end
    end)
    _refresh_in_progress = false
    if not ok then
        ngx.log(ngx.ERR, "[cfm_cache] refresh handler raised: ", tostring(err))
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
        ngx.log(ngx.WARN, "[cfm_cache] could not schedule refresh timer: ", tostring(err))
    end
end

-- ---------------------------------------------------------------------------
-- Public API

-- policy_for: returns the policy table for the given host, or nil. Cheap path
-- when nothing is armed: short-circuits BEFORE any string work.
function _M.policy_for(host)
    if not _cache.has_any then
        schedule_refresh_if_needed()
        return nil
    end
    schedule_refresh_if_needed()
    local h = normalize_host(host)
    if h == "" then return nil end
    local p = _cache.policies[h]
    if p then return p end
    for _, w in ipairs(_cache.wild) do
        if glob_match(w.pattern, h) then return w.policy end
    end
    return nil
end

-- label_for renders a compact, greppable summary of what WOULD apply.
local function label_for(p)
    local parts = {}
    if type(p.static) == "table" and p.static.on then
        local s = "static=" .. tostring(p.static.recipe or "on")
        if p.static.ttl then s = s .. "/" .. tostring(p.static.ttl) end
        parts[#parts + 1] = s
    end
    if type(p.micro) == "table" and p.micro.on then
        local m = "micro=" .. tostring(p.micro.recipe or "on")
        if p.micro.ttl then m = m .. "/" .. tostring(p.micro.ttl) end
        parts[#parts + 1] = m
    end
    parts[#parts + 1] = "gen=" .. tostring(p.gen or 0)
    return table.concat(parts, " ")
end

-- observe: PHASE 2 header-filter hook. Stamps X-CFM-Cache on responses for a
-- vhost that has a policy, so an operator can watch (curl -I) which vhosts are
-- armed and what would apply — without any caching taking place. Safe to call
-- from any phase where ngx.header is writable (header_filter is recommended).
function _M.observe()
    -- Keep the per-worker cache warm from ALL traffic (like cfm_h3_config's
    -- enabled_for), so a debug request reports CURRENT policy rather than the
    -- state as of the previous debug request. Cheap: a flag + one time compare
    -- when a refresh is not due; it never blocks the request.
    schedule_refresh_if_needed()
    -- Stamp only for an operator's opt-in debug request, so ordinary clients see
    -- nothing. NOTE (Phase 3): before real cache HIT/MISS/keys are exposed here,
    -- gate this on a shared secret or a trusted source, not just the presence of
    -- a guessable header name.
    local dbg = ngx.var[OBSERVE_HEADER_VAR]
    if not dbg or dbg == "" then return end
    local p = _M.policy_for(ngx.var.host)
    if p then
        ngx.header["X-CFM-Cache"] = "observe " .. label_for(p)
    end
end

-- Exposed for unit tests (scripts/tests/cfm_cache_test.lua): drive the cache
-- without a live bridge/ngx, then assert lookups.
_M._rebuild_cache   = rebuild_cache
_M._label_for       = label_for
_M._normalize_host  = normalize_host
_M._has_any         = function() return _cache.has_any end

return _M

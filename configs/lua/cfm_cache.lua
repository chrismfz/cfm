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
-- * SITE_CACHE off (the operator kill switch): one cached-config bool read,
--   then return — a full no-op, nothing else runs.
-- * Normal traffic (SITE_CACHE on, no X-CFM-Cache-Debug header): that same
--   cached-config read + one schedule-refresh check (a flag + one time compare,
--   ~10 ns when a poll is not due — the per-response cost cfm_h3_config already
--   pays) + one ngx.var read, then return. No policy lookup on the ordinary
--   path. The config read is a cfm_filecache 10s-TTL hit (a table lookup),
--   which cfm.lua already does per request.
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
local bcfg  = require "cfm_bridge_cfg"   -- master SITE_CACHE gate (~10s TTL)

local _M = {}

-- site_cache_enabled reads the daemon-published master KILL SWITCH
-- ([webdetector] SITE_CACHE, via cfm_bridge_cfg's ~10s-TTL cache). Default ON:
-- only an EXPLICIT false disarms the module (absent field / missing file → on),
-- matching how fp_policy et al. are consumed. This is a kill switch, not an
-- opt-in — the per-vhost policy feed (empty by default) still governs whether
-- any vhost is armed, so nothing caches until one is (docs §0).
local function site_cache_enabled()
    return bcfg.get().site_cache ~= false
end

-- micro_enforce_enabled reads the daemon-published Tier B ENFORCE gate
-- ([webdetector] MICRO_CACHE_ENFORCE, via the same ~10s-TTL bridge cache).
-- OPT-IN: default FALSE (absent field / older daemon → dry-run). Only an
-- explicit true lets micro_gate() ngx.exec to a cache location — HTML
-- micro-caching never turns itself on (mirror image of site_cache_enabled).
local function micro_enforce_enabled()
    return bcfg.get().micro_cache_enforce == true
end

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

-- Stats push (3c): the reverse direction of the config pull — the edge POSTs a
-- per-vhost cache-verdict snapshot to the daemon every _stats_sec. Same fixed
-- interval, config-driven ethos (no env). A node-wide cross-worker lock in the
-- cfm_cache_stats dict ensures only ONE worker pushes per window.
local _last_stats_flush_at   = 0
local _stats_flush_in_progress = false
local _stats_sec = 60

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

-- bridge_send: the shared client both directions use. Connects to the bridge
-- unix socket, sends one request (GET when body is nil; POST with a JSON body +
-- explicit Content-Length otherwise — the daemon's minimal reader wants a
-- non-chunked body), reads the status line, and returns the STILL-OPEN socket +
-- HTTP code so the caller can read (or discard) the response. On any pre-status
-- failure the socket is closed and (nil, nil, err) is returned. One copy of the
-- token/connect/send/status plumbing — no drift between fetch and push.
local function bridge_send(method, path, body)
    local token = load_bridge_token()
    if not token then return nil, nil, "no bridge token yet" end

    local s, err = ngx.socket.tcp()
    if not s then return nil, nil, "socket.tcp: " .. (err or "?") end
    s:settimeouts(IO_TIMEOUT_MS, IO_TIMEOUT_MS, IO_TIMEOUT_MS)
    local ok, cerr = s:connect("unix:" .. SOCK_PATH)
    if not ok then s:close(); return nil, nil, "connect: " .. (cerr or "?") end

    local req = method .. " " .. path .. " HTTP/1.1\r\n" ..
                "Host: localhost\r\n" ..
                "Connection: close\r\n" ..
                TOKEN_HEADER .. ": " .. token .. "\r\n"
    if body then
        req = req .. "Content-Type: application/json\r\n" ..
                     "Content-Length: " .. #body .. "\r\n\r\n" .. body
    else
        req = req .. "\r\n"
    end
    local _, werr = s:send(req)
    if werr then s:close(); return nil, nil, "send: " .. (werr or "?") end

    local status_line, rerr = s:receive("*l")
    if not status_line then s:close(); return nil, nil, "recv status: " .. (rerr or "?") end
    return s, tonumber(status_line:match("%s(%d%d%d)%s")), nil
end

local function bridge_fetch()
    local s, code, err = bridge_send("GET", BRIDGE_PATH, nil)
    if err then return nil, err end
    if code ~= 200 then s:close(); return nil, "http " .. tostring(code) end
    while true do                          -- discard the response headers
        local line = s:receive("*l")
        if not line or line == "" then break end
    end
    local body = s:receive("*a") or ""
    s:close()
    return body, nil
end

-- bridge_push: POST a JSON body to a bridge path (the reverse of bridge_fetch);
-- only the status matters. Returns true on HTTP 200, else nil+err. Timer-only.
local STATS_PATH = "/nginx/cache/stats"

local function bridge_push(path, body)
    local s, code, err = bridge_send("POST", path, body)
    if err then return nil, err end
    s:close()
    if code ~= 200 then return nil, "http " .. tostring(code) end
    return true, nil
end

-- ---------------------------------------------------------------------------
-- Cache rebuild. Only exact hosts and "*.suffix" wildcards are honored (same
-- rule as the Go store); anything else is dropped with a one-shot warning so a
-- pattern the Lua matcher cannot find never silently disappears.

local _warned_unsupported = {}

local function rebuild_cache(entries)
    local policies, wild = {}, {}
    local n, micro_n = 0, 0
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
                if type(pol.micro) == "table" and pol.micro.on then micro_n = micro_n + 1 end
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
    _cache.policies  = policies
    _cache.wild      = wild
    _cache.has_any   = n > 0
    -- has_micro: meta flag = "some vhost has its micro tier armed". B2's observe()
    -- is already debug-gated and per-vhost (p.micro.on), so it does not read this
    -- yet; the flag is the cheap fleet-wide early-out that B3's ACCESS-phase micro
    -- gate will short-circuit on (mirroring has_any) so a static-only/uncached
    -- fleet pays nothing on the hot path (design §5.6 Invariant 2). Exercised now
    -- by the unit tests; consumed for real in B3.
    _cache.has_micro = micro_n > 0
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
-- Stats push: snapshot the per-vhost cache-verdict counters (cfm_cache_log)
-- and POST them to the daemon. Absolute counts; the daemon UPSERTs per vhost.

local STATS_LOCK_KEY = "cache:stats:flush_lock"

local function stats_flush_handler(premature)
    local ok, err = pcall(function()
        if premature then return end
        local ok2, cl = pcall(require, "cfm_cache_log")
        if not (ok2 and cl and cl.snapshot_vhosts) then return end
        local vhosts = cl.snapshot_vhosts()
        local rows = {}
        for host, counts in pairs(vhosts) do
            rows[#rows + 1] = { host = host, counts = counts }
        end
        if #rows == 0 then return end   -- nothing armed / no traffic yet
        local _, perr = bridge_push(STATS_PATH, cjson.encode({ rows = rows }))
        if perr then
            ngx.log(ngx.WARN, "[cfm_cache] stats push failed: ", tostring(perr))
        end
    end)
    _stats_flush_in_progress = false
    if not ok then
        ngx.log(ngx.ERR, "[cfm_cache] stats flush handler raised: ", tostring(err))
    end
end

-- schedule_stats_flush_if_needed: per-worker throttle + a node-wide cross-worker
-- lock (dict:add with TTL) so exactly one worker pushes per window. Fail-safe:
-- any hiccup just skips this window; the counters keep accumulating.
--
-- INVARIANT: the per-worker throttle interval and the cross-worker lock TTL are
-- BOTH _stats_sec, deliberately. A worker that loses the add() race has already
-- advanced _last_stats_flush_at, so its own throttle and the lock free up at the
-- same time and exactly one push lands per window. Keep them equal if you touch
-- either.
local function schedule_stats_flush_if_needed()
    if _stats_flush_in_progress then return end
    local now = ngx.now()
    if (now - _last_stats_flush_at) < _stats_sec then return end
    _last_stats_flush_at = now
    -- The lock lives in cfm_decisions (a large, long-lived dict), NOT
    -- cfm_cache_stats — so it can never be LRU-evicted by counter-key growth in
    -- the stats dict (which would silently halt every push).
    local sh = ngx.shared
    local d = sh and sh.cfm_decisions
    if d then
        -- add() succeeds only for the worker that wins the window; the TTL
        -- releases it after _stats_sec so the next window has a fresh race.
        local won = d:add(STATS_LOCK_KEY, 1, _stats_sec)
        if not won then return end
    end
    _stats_flush_in_progress = true
    local ok, err = ngx.timer.at(0, stats_flush_handler)
    if not ok then
        _stats_flush_in_progress = false
        ngx.log(ngx.WARN, "[cfm_cache] could not schedule stats flush: ", tostring(err))
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

-- policy_key_for: like policy_for, but returns the CANONICAL policy KEY that
-- matched — the exact host, or the "*.suffix" pattern for a wildcard match — or
-- nil when nothing is armed for `host`. Stats are keyed on THIS, never on the
-- raw request Host: under an armed wildcard (`*.example.com`) a client can send
-- unbounded distinct sub-hosts, so keying per request-host would blow the
-- cfm_cache_stats dict; keying per policy bounds cardinality to the number of
-- armed policies. Read-only (no refresh scheduling) — the log phase must not
-- drive I/O; observe() keeps the cache warm.
function _M.policy_key_for(host)
    if not _cache.has_any then return nil end
    local h = normalize_host(host)
    if h == "" then return nil end
    if _cache.policies[h] then return h end
    for _, w in ipairs(_cache.wild) do
        if glob_match(w.pattern, h) then return w.pattern end
    end
    return nil
end

-- maybe_flush_stats: public tick for the stats push, called from the HTTP-level
-- log_by_lua so it fires for ALL traffic (both the :9080 and :9043 servers) —
-- observe() runs only in the HTTPS header_filter, which would leave an HTTP-only
-- box's armed vhosts counted but never pushed. Master-gated + internally
-- throttled/locked, so calling it per request is a cheap time compare.
function _M.maybe_flush_stats()
    if not site_cache_enabled() then return end
    schedule_stats_flush_if_needed()
end

-- ---------------------------------------------------------------------------
-- Tier B micro-cache — TTL-bucket snapping (Phase B1, pure helper).
--
-- proxy_cache_valid is a per-LOCATION directive and is NOT variablizable
-- (verified against nginx: `proxy_cache $var` selects only the storage zone; a
-- single location's proxy_cache_valid applies to every zone it caches into). So
-- a per-vhost micro TTL is served by one internal location per bucket
-- (`@cfm_micro_<n>s`), each pinning `proxy_cache cfm_micro_<n>s;` +
-- `proxy_cache_valid 200 <n>s;`. B3 will read a vhost's armed micro policy and
-- ngx.exec to the bucket location; this helper is the mapping it uses. A stored
-- TTL (recipe preset or operator custom) SNAPS to the nearest bucket — for herd
-- protection the gap between 7s and 8s is operationally meaningless
-- (design §5.4), so the snapped menu behaves as effectively continuous.
local MICRO_BUCKETS = { 1, 2, 5, 10, 30, 60 } -- seconds; mirrors the declared cfm_micro_<n>s zones

-- micro_bucket_seconds: snap a stored TTL to the nearest bucket. Accepts a
-- number of seconds or a string ("5", "5s", "30 s"); nil/empty/unparseable or
-- <=0 snaps to the smallest bucket (the safest, shortest TTL — closest to not
-- caching). Ties snap DOWN (the shorter, safer TTL) because the buckets ascend
-- and the comparison keeps the first minimum.
local function micro_bucket_seconds(ttl)
    local n
    if type(ttl) == "number" then
        n = ttl
    elseif type(ttl) == "string" then
        n = tonumber(ttl:match("%d+"))
    end
    if not n or n <= 0 then return MICRO_BUCKETS[1] end
    local best, bestd = MICRO_BUCKETS[1], math.huge
    for _, b in ipairs(MICRO_BUCKETS) do
        local d = b - n; if d < 0 then d = -d end
        if d < bestd then best, bestd = b, d end
    end
    return best
end

-- micro_zone_name: the storage zone / internal-location suffix for a stored TTL,
-- e.g. 5 or "7s" → "cfm_micro_5s". The single source of truth for the bucket
-- name so the conf zones, the daemon dirs and B3's ngx.exec target can't drift.
local function micro_zone_name(ttl)
    return "cfm_micro_" .. micro_bucket_seconds(ttl) .. "s"
end

-- ---------------------------------------------------------------------------
-- Tier B micro-cache — request classification (Phase B2, OBSERVE-ONLY).
--
-- Decides whether an ALLOWED request WOULD be micro-cacheable and to which TTL
-- bucket. NOTHING caches in B2: observe() records the verdict on the debug-gated
-- X-CFM-Cache header only, so the cookie allowlist + anonymity rails burn in on
-- real traffic (curl -H "X-CFM-Cache-Debug: 1") before B3 activates proxy_cache.
-- The RESPONSE-side rails (a Set-Cookie, or a Cache-Control: private/no-store/
-- no-cache response, is never stored) are nginx-native and enforced at store
-- time in B3 — this Lua covers only the REQUEST-side rails (armed, method,
-- path, cookies).
--
-- Cookie model (design §4.1): the bypass is NOT "the request has a Cookie
-- header". It is a positive AUTH allowlist (a named app-session cookie → bypass,
-- possibly a logged-in user) plus, for the opt-in strict_cookies vhost, an
-- IGNORE-list of cookies treated as anonymous (CFM's own cfm_* cookies — incl.
-- cfm_clearance — and common analytics/consent cookies). A cleared but
-- app-anonymous visitor (only cfm_clearance) IS cacheable: that post-challenge
-- burst is exactly what micro-cache exists to absorb.

-- Exact lowercase auth-cookie names + name PREFIX / SUFFIX families. A request
-- carrying any of these bypasses micro-cache (never stored), on every vhost.
-- Bias toward OVER-inclusion: a false bypass only costs a cache miss, while a
-- missed session cookie would (in B3) serve one user's page to another. The set
-- is PHP/cPanel-primary (the fleet) plus the mainstream non-PHP session cookies;
-- a stack with an unlisted session-cookie name still relies on the response-side
-- rails (Set-Cookie / Cache-Control: private) and the opt-in strict_cookies.
local MICRO_AUTH_EXACT = {
    -- PHP / cPanel ecosystem
    ["phpsessid"] = true, ["cpsession"] = true, ["whmsession"] = true,
    ["roundcube_sessid"] = true, ["roundcube_sessauth"] = true,
    ["laravel_session"] = true, ["ci_session"] = true, ["xsrf-token"] = true,
    ["horde"] = true,
    -- mainstream non-PHP stacks
    ["jsessionid"] = true,        -- Java / Tomcat / JSP
    ["asp.net_sessionid"] = true, -- classic ASP.NET
    ["connect.sid"] = true,       -- Express / Node
    ["sessionid"] = true,         -- Django
}
local MICRO_AUTH_PREFIX = {
    "wordpress_logged_in_", "wordpress_sec_", "wp-postpass_", "comment_author_",
    "woocommerce_", "wp_woocommerce_session_", "prestashop-", "horde_",
    ".aspnetcore.",               -- ASP.NET Core session/antiforgery/auth
}
-- SUFFIX families: the `*_session` convention (Rails `_<app>_session`, and the
-- generic framework pattern). Redundant-but-harmless with the exact _session
-- names above.
local MICRO_AUTH_SUFFIX = { "_session" }
-- Ignore-list (consulted ONLY under strict_cookies): a strict vhost bypasses on
-- ANY cookie not matched here. cfm_ covers cfm_clearance + every CFM-set cookie;
-- the rest are common non-session analytics/consent cookies.
local MICRO_IGNORE_EXACT = {
    ["_ga"] = true, ["_gid"] = true, ["_fbp"] = true, ["_gat"] = true,
    ["euconsent"] = true, ["euconsent-v2"] = true,
}
local MICRO_IGNORE_PREFIX = {
    "cfm_", "_ga_", "_gat", "_gcl_", "_gac_", "_dc_gtm_",
    "cookielawinfo-", "__cmp", "_hj",
}

local function name_matches(lname, exact, prefixes, suffixes)
    if exact[lname] then return true end
    for _, p in ipairs(prefixes) do
        if lname:sub(1, #p) == p then return true end
    end
    if suffixes then
        for _, s in ipairs(suffixes) do
            if #lname >= #s and lname:sub(-#s) == s then return true end
        end
    end
    return false
end

-- micro_cookie_verdict: classify a request's Cookie header. Returns
-- (anonymous:bool, reason:string|nil). Anonymous (cacheable) when no auth cookie
-- is present and — under strict — every cookie name is ignore-listed. Cookies
-- are split on ';' FIRST, then the name taken before the first '=', so a value
-- that itself contains '=' (base64/JWT) can never fabricate a phantom name.
-- extra_auth is an optional {lowername=true} set of per-vhost auth cookies.
local function micro_cookie_verdict(cookie_header, strict, extra_auth)
    if not cookie_header or cookie_header == "" then return true, nil end
    for pair in cookie_header:gmatch("[^;]+") do
        local name = pair:match("^%s*([^=%s]+)")
        if name then
            local lname = name:lower()
            if name_matches(lname, MICRO_AUTH_EXACT, MICRO_AUTH_PREFIX, MICRO_AUTH_SUFFIX)
               or (extra_auth and extra_auth[lname]) then
                return false, "auth:" .. name
            end
            if strict and not name_matches(lname, MICRO_IGNORE_EXACT, MICRO_IGNORE_PREFIX) then
                return false, "strict:" .. name
            end
        end
    end
    return true, nil
end

-- Request paths never micro-cached even for an anonymous client. /.well-known/
-- is already routed to origin at cfm.lua Step 0a1 (never reaches an allow-
-- return), so it is not re-checked here; /acctxfer* (cPanel account transfer)
-- does reach an allow and must not be cached.
local function micro_path_blocked(uri)
    return type(uri) == "string" and uri:sub(1, 9) == "/acctxfer"
end

-- micro_decision: PURE. Given the vhost policy + request facets, return
-- (cacheable:bool, bucket:int|nil, reason:string). reason is a compact,
-- greppable token for the observe header and a future stat key.
local function micro_decision(pol, method, uri, cookie_header)
    if type(pol) ~= "table" or type(pol.micro) ~= "table" or not pol.micro.on then
        return false, nil, "unarmed"
    end
    if method ~= "GET" and method ~= "HEAD" then
        return false, nil, "method"
    end
    if micro_path_blocked(uri) then
        return false, nil, "path"
    end
    local extra
    if type(pol.auth_cookies) == "table" then
        extra = {}
        for _, nm in ipairs(pol.auth_cookies) do
            if type(nm) == "string" then extra[nm:lower()] = true end
        end
    end
    local anon, why = micro_cookie_verdict(cookie_header, pol.strict_cookies, extra)
    if not anon then
        return false, nil, why
    end
    return true, micro_bucket_seconds(pol.micro.ttl), "ok"
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
    -- Master kill switch first: when SITE_CACHE is off, the module is a full
    -- no-op — no feed poll, no lookup, no header. (Default on; the per-vhost
    -- feed, empty by default, is what actually arms a vhost.)
    if not site_cache_enabled() then return end
    -- Keep the per-worker cache warm from ALL traffic (like cfm_h3_config's
    -- enabled_for), so a debug request reports CURRENT policy rather than the
    -- state as of the previous debug request. Cheap: a flag + one time compare
    -- when a refresh is not due; it never blocks the request.
    schedule_refresh_if_needed()
    -- (The stats push is triggered from the HTTP-level log_by_lua via
    -- maybe_flush_stats(), so it fires for both the :9080 and :9043 servers —
    -- observe() runs only in the HTTPS header_filter.)
    -- Stamp only for an operator's opt-in debug request, so ordinary clients see
    -- nothing. NOTE (Phase 3): before real cache HIT/MISS/keys are exposed here,
    -- gate this on a shared secret or a trusted source, not just the presence of
    -- a guessable header name.
    local dbg = ngx.var[OBSERVE_HEADER_VAR]
    if not dbg or dbg == "" then return end
    local p = _M.policy_for(ngx.var.host)
    if p then
        local lbl = "observe " .. label_for(p)
        -- Now that Tier A caches, surface the actual verdict too (HIT / MISS /
        -- BYPASS / EXPIRED / …) — debug-gated, so ordinary clients never see it.
        local st = ngx.var.upstream_cache_status
        if st and st ~= "" then lbl = lbl .. " status=" .. st end
        -- Tier B (Phase B2, OBSERVE-ONLY): for a micro-armed vhost, surface the
        -- would-cache verdict of the request-side rails (armed / method / path /
        -- cookie allowlist). Nothing is cached — this is the DRY-RUN burn-in
        -- surface so the cookie logic can be validated on real requests before
        -- B3 activates proxy_cache. debug-gated like the rest of this stamp.
        if type(p.micro) == "table" and p.micro.on then
            local okc, bkt, why = micro_decision(p, ngx.var.request_method,
                                                 ngx.var.uri, ngx.var.http_cookie)
            if okc then
                lbl = lbl .. " microcache=would/" .. tostring(bkt) .. "s"
            else
                lbl = lbl .. " microcache=bypass:" .. tostring(why)
            end
        end
        ngx.header["X-CFM-Cache"] = lbl
    end
end

-- static_gate: PHASE 3b ACCESS-phase hook for the static-asset location (the
-- ONLY Lua on that hot path). Bypass-by-default — it flips $cfm_cache_skip to
-- "0" (cache this asset) ONLY when the master switch is on AND this vhost has
-- its static tier armed, and carries the purge generation into $cfm_cache_gen.
-- Otherwise it leaves the pre-set vars untouched ($cfm_cache_skip = "1" → no
-- caching). Never raises (the conf pcall's it too); the fail-safe direction is
-- "do not cache".
--
-- SCOPE (Tier A / 3b): this gate does NOT consult the request-cookie allowlist
-- (design §4.1) — the policy carries strict_cookies/auth_cookies but Tier A does
-- not read them yet. Static assets are public, and per-user safety here rests on
-- the response-side rails nginx already enforces (a Set-Cookie or a
-- Cache-Control: private/no-store/no-cache response is never stored). The full
-- request-cookie allowlist (built-in names + ignore-list + strict mode) lands
-- with Tier B micro-cache, where per-user HTML makes it essential. Residual:
-- a static-extension URL an origin renders per-user with NEITHER Set-Cookie NOR
-- a private Cache-Control would be cached — narrow, documented in
-- docs/site-cache-design.md §14.
function _M.static_gate()
    if not site_cache_enabled() then return end
    local p = _M.policy_for(ngx.var.host)
    if not p then return end
    local s = p.static
    if type(s) ~= "table" or not s.on then return end
    ngx.var.cfm_cache_skip = "0"
    ngx.var.cfm_cache_gen  = tostring(p.gen or 0)
end

-- micro_gate: PHASE B3b ACCESS-phase hook for Tier B (micro-cache of anonymous
-- HTML). Called from cfm.lua at the Step 4 plain-allow return, AFTER $cfm_pass is
-- set. (The Step 2b clearance fast-path is deferred until the §5.5.1 clearance-
-- cookie-across-ngx.exec ordering is verified on a live edge — see cfm.lua.)
-- RETURNS the internal location
-- to serve from ("@cfm_micro_<n>s") when this request should be micro-cached, or
-- nil to proceed normally. The caller ngx.exec()s the returned target OUTSIDE
-- its pcall (ngx.exec never returns, so it must not be swallowed).
--
-- Bypass-safe: returns nil (no caching) on every miss, and specifically —
--   * master SITE_CACHE off, or no micro-armed vhost (cheap fleet-wide early-out)
--   * MICRO_CACHE_ENFORCE off → DRY-RUN: never exec (the observe header still
--     shows the would-cache verdict via observe(), so burn-in is unaffected)
--   * scheme != https: the @cfm_micro_<n>s locations live only in the HTTPS
--     server (B3a). Executing to a missing named location would 500, so a
--     cleartext request is never routed — it just proceeds uncached.
--   * the §4 request-side rails (armed micro tier, GET/HEAD, not /acctxfer*,
--     anonymous per the cookie allowlist) via micro_decision().
-- On a cache decision it sets the same two vars static_gate does ($cfm_cache_skip
-- =0 to open the bypass gate, $cfm_cache_gen for the purge-generation key) and
-- returns the bucket location; the only-200 rail + response-side rails (Set-Cookie
-- / Cache-Control: private never stored) are enforced natively in that location.
function _M.micro_gate()
    if not site_cache_enabled() then return nil end
    if not _cache.has_micro then return nil end
    if not micro_enforce_enabled() then return nil end
    if ngx.var.scheme ~= "https" then return nil end
    local p = _M.policy_for(ngx.var.host)
    if not p then return nil end
    local ok, bucket = micro_decision(p, ngx.var.request_method, ngx.var.uri, ngx.var.http_cookie)
    if not ok then return nil end
    ngx.var.cfm_cache_skip = "0"
    ngx.var.cfm_cache_gen  = tostring(p.gen or 0)
    return "@cfm_micro_" .. bucket .. "s"
end

-- Exposed for unit tests (scripts/tests/cfm_cache_test.lua): drive the cache
-- without a live bridge/ngx, then assert lookups.
_M._rebuild_cache      = rebuild_cache
_M._label_for          = label_for
_M._normalize_host     = normalize_host
_M._has_any            = function() return _cache.has_any end
_M._micro_bucket       = micro_bucket_seconds
_M._micro_zone_name    = micro_zone_name
_M._micro_cookie       = micro_cookie_verdict
_M._micro_decision     = micro_decision
_M._has_micro          = function() return _cache.has_micro end
_M._micro_enforce      = micro_enforce_enabled

return _M

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

-- nginx >= 1.23 joins repeated response headers in $upstream_http_<name>; older
-- cores expose only the first line (see micro_gate). Angie is 1.23+-based and
-- defines nginx_version like any build lua-nginx-module compiles against.
local NGX_JOINS_HEADERS = type(ngx.config) == "table"
    and (tonumber(ngx.config.nginx_version) or 0) >= 1023000

-- ---------------------------------------------------------------------------
-- Per-worker cache state (module-level locals persist across requests in the
-- same worker process). `policies` maps an exact host to its policy table;
-- `wild` is an array of { pattern = "*.suffix", policy = {...} }, MOST SPECIFIC
-- (longest) pattern first — the lookups take the first match. A policy with no
-- armed tier is an OPT-OUT row (the daemon emits one for an all-off exact host
-- or narrower wildcard under a broader armed wildcard): being the more
-- specific match it wins, and it caches nothing.

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
-- ONLY when the request carries `X-CFM-Cache-Debug` (any non-empty value) AND
-- comes from a trusted source (debug_source_trusted: the box, its own IPs,
-- IGNORE_IPS / IGNORE_NETS), so internal cache policy (recipe / TTL bucket /
-- purge generation / HIT-MISS) is never disclosed to an ordinary client. Design
-- §11.3 ("behind a debug flag"). No env var and no config plumbing — an
-- operator runs, on the box, against the edge's HTTPS listener (:9043; :443 on
-- loopback reaches the origin, not the edge):
--   curl -sk -I -H 'X-CFM-Cache-Debug: 1' --resolve site:9043:<site-ip> https://site:9043/
-- (a self-origin request bypasses cfm.lua at Step 0a, so it never takes the
-- micro path itself: the micro token is the would-cache verdict; the served
-- verdict of real traffic is the access log's ucache= / up= fields and the
-- stats — docs/site-cache-design.md §5.7).
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

-- Panel / webmail rail (BOTH tiers): a cPanel / WHM / webmail / webdisk / mail
-- host is never cached, even under an armed wildcard — those front per-user
-- sessions (a login page, a /cpsess<token>/ URL), which are not things to
-- replay to another client. The prefix list is the canonical one cfm.lua and
-- cfm_panel.lua share (cfm_panel_hosts.lua — one list, no drift). A missing or
-- broken module FAILS CLOSED: neither tier caches anything (there is no second
-- copy of the list to fall back on).
local ok_ph, panel_hosts = pcall(require, "cfm_panel_hosts")
if not ok_ph or type(panel_hosts) ~= "table" or type(panel_hosts.has_panel_prefix) ~= "function" then
    ngx.log(ngx.WARN, "[cfm_cache] cfm_panel_hosts unavailable — Site Cache caches nothing: ", tostring(panel_hosts))
    panel_hosts = nil
end
-- Cache-only additions: cPanel service subdomains that are not panels (so they
-- are not in the shared list, which also drives the challenge policy) but
-- answer per account: mail autodiscover/autoconfig, CalDAV / CardDAV.
local CACHE_SERVICE_PREFIXES = {
    autodiscover = true, autoconfig = true, cpcalendars = true, cpcontacts = true,
}

-- panel_host: true when `host` must never be cached (see above).
local function panel_host(host)
    if not panel_hosts then return true end
    local h = normalize_host(host)
    if panel_hosts.has_panel_prefix(h) then return true end
    local label = h:match("^([^%.]+)%.")
    return label ~= nil and CACHE_SERVICE_PREFIXES[label] == true
end

-- The debug stamp (observe) is served only to a trusted source: loopback /
-- link-local, the box's own IPs, or IGNORE_IPS / IGNORE_NETS — the same
-- predicate the self-origin bypass uses (cfm_selfip.lua). A missing module
-- stamps nothing.
local ok_si, selfip = pcall(require, "cfm_selfip")
if not ok_si or type(selfip) ~= "table" or type(selfip.is_self_origin) ~= "function" then
    ngx.log(ngx.WARN, "[cfm_cache] cfm_selfip unavailable — no X-CFM-Cache debug stamp: ", tostring(selfip))
    selfip = nil
end

local function debug_source_trusted()
    if not selfip then return false end
    local ok, trusted = pcall(selfip.is_self_origin, ngx.var.remote_addr)
    return ok and trusted == true
end

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
    -- Most specific wildcard first: with *.example.com AND *.shop.example.com
    -- armed, x.shop.example.com must get the narrower policy. The daemon sends
    -- this order already; sorting here keeps the edge right on its own (and
    -- the alphabetical tie-break keeps it deterministic).
    table.sort(wild, function(a, b)
        if #a.pattern ~= #b.pattern then return #a.pattern > #b.pattern end
        return a.pattern < b.pattern
    end)
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

-- policy_armed: true when at least one tier of the policy is on (false for an
-- opt-out row).
local function policy_armed(p)
    if type(p.static) == "table" and p.static.on then return true end
    if type(p.micro) == "table" and p.micro.on then return true end
    return false
end

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
-- nil when nothing is armed for `host` (an opt-out row included — exact or
-- wildcard: it caches nothing, so it has nothing to count). Stats are keyed on THIS, never on the
-- raw request Host: under an armed wildcard (`*.example.com`) a client can send
-- unbounded distinct sub-hosts, so keying per request-host would blow the
-- cfm_cache_stats dict; keying per policy bounds cardinality to the number of
-- armed policies. Read-only (no refresh scheduling) — the log phase must not
-- drive I/O; observe() keeps the cache warm.
function _M.policy_key_for(host)
    if not _cache.has_any then return nil end
    local h = normalize_host(host)
    if h == "" then return nil end
    local p = _cache.policies[h]
    if p then
        if policy_armed(p) then return h end
        return nil
    end
    for _, w in ipairs(_cache.wild) do
        if glob_match(w.pattern, h) then
            -- the most specific match decides, like policy_for: an opt-out
            -- wildcard (a narrower one turned off under a broader armed one)
            -- counts nothing
            if policy_armed(w.policy) then return w.pattern end
            return nil
        end
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
-- number of seconds or a string "[+]<n><unit>" with unit s/m/h/d, as the
-- daemon's parseCacheTTL stores it ("5s", "+5s", "1m", "2h"; a bare number or
-- inner spaces, which the daemon rejects, are read as seconds); nil/empty/
-- unparseable or <=0 snaps to the smallest bucket (the safest, shortest TTL —
-- closest to not caching), anything above 60s clamps to 60s. Ties snap DOWN
-- (the shorter, safer TTL) because the buckets ascend and the comparison keeps
-- the first minimum. (It used to read only the digits, so "1m" became 1s.)
local TTL_UNIT_SECONDS = { [""] = 1, s = 1, m = 60, h = 3600, d = 86400 }
local function micro_bucket_seconds(ttl)
    local n
    if type(ttl) == "number" then
        n = ttl
    elseif type(ttl) == "string" then
        local q, unit = ttl:lower():match("^%s*%+?(%d+)%s*([a-z]?)%s*$")
        if q and TTL_UNIT_SECONDS[unit] then n = tonumber(q) * TTL_UNIT_SECONDS[unit] end
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
-- Tier B micro-cache — request classification.
--
-- Decides whether an ALLOWED request may be micro-cached and to which TTL
-- bucket: the REQUEST-side rails (armed, method, credentials, Range /
-- event-stream, path, panel host, cookies). micro_gate() routes on the verdict
-- under MICRO_CACHE_ENFORCE=1; observe() shows it on the debug-gated
-- X-CFM-Cache header (the dry-run burn-in surface). The RESPONSE-side rails
-- (only a 200; Set-Cookie; Cache-Control private / no-store / no-cache /
-- s-maxage=0; X-Accel-Expires 0 or @…) are enforced by the micro locations
-- at store time, and micro_mark_ttl() below mirrors them.
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
    ["ocsessid"] = true,          -- OpenCart
    ["frontend"] = true,          -- Magento 1
    ["private_content_version"] = true, -- Magento 2 (per-customer blocks)
    ["moodlesession"] = true,     -- Moodle
    ["edd_items_in_cart"] = true, -- Easy Digital Downloads
    ["sid"] = true, ["token"] = true, ["auth"] = true,
    -- a page that varies on a language / currency cookie without Vary
    ["wp-wpml_current_language"] = true, ["_icl_current_language"] = true,
    ["wmc_current_currency"] = true, ["woocs_current_currency"] = true,
    ["aelia_cs_selected_currency"] = true,
    -- mainstream non-PHP stacks
    ["jsessionid"] = true,        -- Java / Tomcat / JSP
    ["asp.net_sessionid"] = true, -- classic ASP.NET
    ["connect.sid"] = true,       -- Express / Node
    ["sessionid"] = true,         -- Django
}
local MICRO_AUTH_PREFIX = {
    "wordpress_logged_in_", "wordpress_sec_", "wp-postpass_", "comment_author_",
    "woocommerce_", "wp_woocommerce_session_", "wp_edd_session_", "prestashop-",
    "horde_", "mage-",
    "sess", "ssess",              -- Drupal SESS<hash> / SSESS<hash>, and any sess*
    ".aspnetcore.",               -- ASP.NET Core session/antiforgery/auth
}
-- SUFFIX families: the `*_session` convention (Rails `_<app>_session`, and the
-- generic framework pattern) and `*_sid`. Redundant-but-harmless with the exact
-- _session names above.
local MICRO_AUTH_SUFFIX = { "_session", "_sid" }
-- The __Host- / __Secure- cookie prefixes (RFC 6265bis) are stripped before
-- matching, so __Host-PHPSESSID is PHPSESSID.
local COOKIE_NAME_PREFIXES = { "__host-", "__secure-" }
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

-- cookie_key: a cookie name as the app sees it, so a session cookie cannot be
-- smuggled past the lists in a form the app still reads: PHP (and Rack)
-- percent-decode a name, PHP reads "a[b]" as the array a, and turns " ", "."
-- and a lone "[" into "_" when it builds $_COOKIE (wordpress.logged.in_x is
-- wordpress_logged_in_x to WordPress); lowercased; a __Host- / __Secure-
-- prefix stripped. The lists are normalised the same way at load
-- (connect.sid and .aspnetcore. still match).
local function cookie_key(name)
    local n = name:gsub("%%(%x%x)", function(h) return string.char(tonumber(h, 16)) end)
    local b = n:find("[", 1, true)
    if b and n:find("]", b, true) then n = n:sub(1, b - 1) end
    n = n:lower():gsub("[ %.%[]", "_")
    for _, cp in ipairs(COOKIE_NAME_PREFIXES) do
        if n:sub(1, #cp) == cp then return n:sub(#cp + 1) end
    end
    return n
end
local function norm_set(t)
    local out = {}
    for k, v in pairs(t) do out[cookie_key(k)] = v end
    return out
end
local function norm_list(t)
    local out = {}
    for i, v in ipairs(t) do out[i] = cookie_key(v) end
    return out
end
MICRO_AUTH_EXACT    = norm_set(MICRO_AUTH_EXACT)
MICRO_AUTH_PREFIX   = norm_list(MICRO_AUTH_PREFIX)
MICRO_AUTH_SUFFIX   = norm_list(MICRO_AUTH_SUFFIX)
MICRO_IGNORE_EXACT  = norm_set(MICRO_IGNORE_EXACT)
MICRO_IGNORE_PREFIX = norm_list(MICRO_IGNORE_PREFIX)

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
-- are split on ';' FIRST, then the name taken before the first '=' (inner
-- spaces included, outer ones trimmed), so a value that itself contains '='
-- (base64/JWT) can never fabricate a phantom name; the name is then compared
-- as cookie_key() sees it. extra_auth is an optional {cookie_key=true} set of
-- per-vhost auth cookies.
local function micro_cookie_verdict(cookie_header, strict, extra_auth)
    if not cookie_header or cookie_header == "" then return true, nil end
    for pair in cookie_header:gmatch("[^;]+") do
        local name = pair:match("^%s*([^=]-)%s*=") or pair:match("^%s*(.-)%s*$")
        if name and name ~= "" then
            local lname = cookie_key(name)
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
-- does reach an allow and must not be cached. The admin / login / *.php paths
-- go to the no-buffer passthrough location, which never routes to micro (only
-- `location /` sets $cfm_micro_conf to "1"); they are listed again so the rail
-- does not rest on the conf's location regex alone, and the rail also covers
-- what that regex misses (other script extensions, PATH_INFO URLs). Matched on
-- the decoded, lowercased path (nginx matches that location case-insensitively).
local MICRO_PATH_PREFIX = {
    "/acctxfer", "/wp-admin", "/administrator/", "/admin/", "/sysadmin/",
    "/___proxy_subdomain_",       -- cPanel's proxy-subdomain paths (panel services)
}
-- A path segment that names a PHP script: the script extensions the static-asset
-- location excludes (php, php<digit>, phtml, pht, phar), at the end of the path
-- or followed by "/" (PATH_INFO: /index.php/checkout/cart, /wp-login.php/).
local function script_ext(ext)
    return ext == "php" or ext == "phtml" or ext == "pht" or ext == "phar"
        or ext:match("^php%d$") ~= nil
end
local function micro_path_blocked(uri)
    if type(uri) ~= "string" then return false end
    local u = uri:lower()
    for _, pfx in ipairs(MICRO_PATH_PREFIX) do
        if u:sub(1, #pfx) == pfx then return true end
    end
    -- wp-login.php, xmlrpc.php, wp-cron.php and every other script
    for ext in u:gmatch("%.([a-z0-9]+)/") do
        if script_ext(ext) then return true end
    end
    local last = u:match("%.([a-z0-9]+)$")
    return last ~= nil and script_ext(last)
end

-- micro_args_blocked: a WordPress cron spawn (ALTERNATE_WP_CRON sends the
-- visitor through ?doing_wp_cron=<ts>) runs the cron in that request.
local function micro_args_blocked(args)
    return type(args) == "string" and args:lower():find("doing_wp_cron", 1, true) ~= nil
end

-- micro_decision: PURE. Given the vhost policy + request facets, return
-- (cacheable:bool, bucket:int|nil, reason:string). reason is a compact,
-- greppable token for the observe header and a future stat key.
--
-- r is a table of request facets: method, uri (the path), args, host, cookie,
-- auth (Authorization), range (Range), accept (Accept), fragment (the first
-- partial-page request header present). Besides the rails
-- below, it bypasses:
--   * a Range request — nginx strips Range upstream when caching and fetches
--     the whole page; micro is for plain page loads;
--   * Accept: text/event-stream — a micro location buffers the response, so a
--     Server-Sent-Events stream would be held back until it ends;
--   * a partial-page request (r.fragment: X-Requested-With, X-PJAX, HX-Request,
--     Turbo-Frame or X-Inertia present) — apps answer those with a fragment,
--     usually without Vary, and a stored fragment would be every visitor's
--     page for the bucket TTL;
--   * a panel / webmail / service host (panel_host).
--
-- auth_header is the request's Authorization value. Any non-empty value means
-- the origin may answer per-credential (HTTP basic auth — cPanel Directory
-- Privacy — or a bearer token), and nginx does NOT treat Authorization as a
-- cache bypass on its own: a stored 200 would be replayed to anonymous
-- visitors. So a credentialed request is never routed to micro-cache. The
-- cache locations also carry $cfm_req_auth (a map on $http_authorization:
-- any non-empty value, "0" included) on proxy_cache_bypass + proxy_no_cache
-- (the conf-side rail that covers Tier A too); this is the request-side half,
-- so a credentialed request does not even take the buffered micro path.
local function micro_decision(pol, r)
    if type(pol) ~= "table" or type(pol.micro) ~= "table" or not pol.micro.on then
        return false, nil, "unarmed"
    end
    if type(r) ~= "table" then r = {} end
    if r.method ~= "GET" and r.method ~= "HEAD" then
        return false, nil, "method"
    end
    if type(r.auth) == "string" and r.auth ~= "" then
        return false, nil, "authorization"
    end
    if type(r.range) == "string" and r.range ~= "" then
        return false, nil, "range"
    end
    if type(r.accept) == "string" and r.accept:lower():find("text/event-stream", 1, true) then
        return false, nil, "event-stream"
    end
    if type(r.fragment) == "string" and r.fragment ~= "" then
        return false, nil, "fragment"
    end
    if micro_path_blocked(r.uri) or micro_args_blocked(r.args) then
        return false, nil, "path"
    end
    if panel_host(r.host) then
        return false, nil, "panel"
    end
    local extra
    if type(pol.auth_cookies) == "table" then
        extra = {}
        for _, nm in ipairs(pol.auth_cookies) do
            if type(nm) == "string" then extra[cookie_key(nm)] = true end
        end
    end
    local anon, why = micro_cookie_verdict(r.cookie, pol.strict_cookies, extra)
    if not anon then
        return false, nil, why
    end
    return true, micro_bucket_seconds(pol.micro.ttl), "ok"
end

-- ---------------------------------------------------------------------------
-- Tier B remember-uncacheable (nginx has no hit-for-pass).
--
-- A micro key whose response cannot be stored (non-200, Set-Cookie, Cache-
-- Control private/no-store/no-cache/s-maxage=0, X-Accel-Expires 0 or @…,
-- Vary: *) is never
-- cached, yet every request for it still takes the cache lock: concurrent
-- requests queue behind the one in flight (in 500ms steps, up to the 5s
-- lock_timeout), so arming micro on a vhost whose pages set a cookie for every
-- visitor would serialise its traffic. micro_note() (log phase, micro requests
-- only) remembers such a key for MICRO_UNCACHEABLE_TTL in the
-- cfm_cache_uncacheable dict, and micro_verdict() skips micro for it until the
-- mark expires — the request is served uncached, exactly as without micro.
-- When the mark expires the next request probes again. An edge conf without
-- the dict just does not remember (the queue returns, nothing else changes).
-- The mark key is the cache key without the purge generation (a purge does not
-- change what the origin sends); hashed, so the dict holds fixed-size keys. The
-- dict evicts least-recently-used marks when full, which only costs a re-probe.
--
-- Which answers mark (micro_mark_ttl):
--   * a 5xx or a request-level 4xx (400, 405, 406, 408, 411, 412, 413, 414,
--     415, 416, 417, 421, 429, 431) is origin trouble or about the request,
--     not the page. On an EXPIRED key it never marks: the stale copy absorbs
--     it (use_stale updating plus http_500..504 serve it, the fetching request
--     included; any other 5xx, e.g. CloudLinux's 508, reaches only the request
--     that refreshes), and a mark would send the whole load to the failing
--     origin — any client could also provoke one (an oversized header, an
--     origin rate limit or WAF rule answering 406) to switch micro off. On a
--     MISS (no copy) it marks for MICRO_UNCACHEABLE_SHORT_TTL, the lock
--     timeout: the lock does not spare the origin (every waiter reaches it,
--     as the next filler or when its wait times out), it only delays each
--     visitor up to 5s, so the key is served direct for a few seconds, then
--     probed again, and caches again as soon as the origin recovers. A 401 /
--     403 / 404 / 410 is the page (gone or protected now) and marks normally.
--     (An origin WAF that answers 403 to a request is the residual below.)
--   * a MISS that could not be stored: MICRO_UNCACHEABLE_TTL.
--   * an EXPIRED refresh that could not be stored — the page changed (sets a
--     cookie, went private, redirects, 404): MICRO_UNCACHEABLE_STALE_TTL,
--     longer than the largest micro zone's `inactive` (180s), so the stale copy
--     is evicted before the next probe. Otherwise every probe would serve it
--     to the requests arriving during its fetch, for as long as they kept it
--     warm. check_site_cache_config.sh pins inactive + 30s <= this value.
-- Residual (like Varnish hit-for-miss): one client's non-storable answer skips
-- micro for that URL for everyone until the mark expires — a client that can
-- make the origin answer differently (a UA/language redirect, a cookie, an
-- origin WAF 403) can keep micro off for one URL with a request per mark. That
-- URL is then served as it would be without micro; nothing wrong is stored.
local UNCACHEABLE_DICT            = "cfm_cache_uncacheable"
local MICRO_UNCACHEABLE_TTL       = 60
local MICRO_UNCACHEABLE_STALE_TTL = 240
local MICRO_UNCACHEABLE_SHORT_TTL = 5    -- the micro proxy_cache_lock_timeout
local NGX_CACHE_VARY_LEN          = 128  -- nginx does not store a longer Vary
local REQUEST_INDUCED_4XX = {
    [400] = true, [405] = true, [406] = true, [408] = true, [411] = true, [412] = true,
    [413] = true, [414] = true, [415] = true, [416] = true, [417] = true, [421] = true,
    [429] = true, [431] = true,
}

local function micro_mark_key()
    local v = ngx.var
    return ngx.md5((v.server_addr or "") .. "|" .. (v.scheme or "") .. "|" ..
        (v.cf_xfp or "") .. "://" .. (v.host or "") .. (v.request_uri or ""))
end

-- micro_storable: PURE. Would nginx store this fetched response in a micro
-- location? Mirrors the location's rails: proxy_no_cache $cfm_cache_non200
-- (only a 200), $cfm_cc_nostore and $cfm_xae_nocache (the maps on the origin's
-- Cache-Control / X-Accel-Expires), plus nginx's own Set-Cookie and Vary rules
-- (neither header is ignored), and X-Accel-Buffering: no (not ignored either:
-- nginx then streams the response and stores nothing). A "*" anywhere in Vary
-- counts, which is slightly broader than nginx (only a bare "*"): the cost is
-- a skipped micro, never a stored response. (A response carrying
-- X-Accel-Redirect is served by an internal redirect and never reaches
-- micro_note with a fetch status — it is neither stored nor remembered.)
local function micro_storable(status, set_cookie, cc_nostore, xae_nocache, vary, x_accel_buffering)
    if status ~= "200" then return false end
    if type(set_cookie) == "string" and set_cookie ~= "" then return false end
    if type(x_accel_buffering) == "string" and x_accel_buffering:lower() == "no" then return false end
    if cc_nostore == "1" or xae_nocache == "1" then return false end
    if type(vary) == "string" and (vary:find("*", 1, true) or #vary > NGX_CACHE_VARY_LEN) then
        return false
    end
    return true
end

-- micro_mark_ttl: PURE. How long to remember this fetch's key as uncacheable,
-- or nil to not mark it (see the rules above). cache_status is
-- $upstream_cache_status; status is $upstream_status, whose LAST entry is the
-- answer (a retried fetch lists every attempt).
local function micro_mark_ttl(cache_status, status, set_cookie, cc_nostore, xae_nocache, vary, x_accel_buffering)
    if cache_status ~= "MISS" and cache_status ~= "EXPIRED" then return nil end
    local code = tonumber(type(status) == "string" and status:match("(%d+)%s*$") or nil)
    if not code then return nil end
    if code >= 500 or REQUEST_INDUCED_4XX[code] then
        if cache_status == "MISS" then return MICRO_UNCACHEABLE_SHORT_TTL end
        return nil
    end
    if micro_storable(status, set_cookie, cc_nostore, xae_nocache, vary, x_accel_buffering) then return nil end
    if cache_status == "EXPIRED" then return MICRO_UNCACHEABLE_STALE_TTL end
    return MICRO_UNCACHEABLE_TTL
end

local function uncacheable_marked()
    local dict = ngx.shared and ngx.shared[UNCACHEABLE_DICT]
    if not dict then return false end
    return dict:get(micro_mark_key()) ~= nil
end

-- micro_note: log-phase hook (the conf's http-level log_by_lua_block, for a
-- request an @cfm_micro_<n>s location served). Marks the key uncacheable when
-- this request FETCHED from the origin (MISS / EXPIRED) and the answer was one
-- nginx could not store and micro_mark_ttl says to remember. A fetch that
-- looked storable but was not stored (a waiter whose lock wait timed out) is
-- never marked. Never raises into the caller (the conf pcall's it too).
function _M.micro_note()
    local v = ngx.var
    local st = v.upstream_cache_status
    if st ~= "MISS" and st ~= "EXPIRED" then return end
    if v.cfm_upstream ~= "cfm_apache_micro" then return end
    local dict = ngx.shared and ngx.shared[UNCACHEABLE_DICT]
    if not dict then return end
    local ttl = micro_mark_ttl(st, v.upstream_status, v.upstream_http_set_cookie,
                               v.cfm_cc_nostore, v.cfm_xae_nocache, v.upstream_http_vary,
                               v.upstream_http_x_accel_buffering)
    if ttl then dict:set(micro_mark_key(), true, ttl) end
end

-- micro_verdict: the request-side decision for THIS request (impure: reads
-- ngx.var): micro_decision over the request facets, then the remembered-
-- uncacheable skip. Shared by observe (would-cache) and micro_gate (routing).
local function micro_verdict(p)
    local v = ngx.var
    local ok, bucket, why = micro_decision(p, {
        method = v.request_method, uri = v.uri, args = v.args, host = v.host,
        cookie = v.http_cookie, auth = v.http_authorization,
        range = v.http_range, accept = v.http_accept,
        fragment = v.http_x_requested_with or v.http_x_pjax or v.http_hx_request
            or v.http_turbo_frame or v.http_x_inertia,
    })
    if ok and uncacheable_marked() then return false, nil, "uncacheable" end
    return ok, bucket, why
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

-- observe: header-filter hook. For a debug request (X-CFM-Cache-Debug), stamps
-- X-CFM-Cache on responses for a vhost that has a policy, so an operator can
-- watch (curl -I) what applies: the tiers, the generation, the cache verdict
-- ($upstream_cache_status) and the micro would-cache verdict — or "opt-out".
-- Observing only: the caching itself is done by static_gate / micro_gate and
-- the proxy_cache locations. Safe to call from any phase where ngx.header is
-- writable (header_filter is recommended).
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
    -- Stamp only for an operator's opt-in debug request from a trusted source
    -- (the header name alone is guessable), so ordinary clients see nothing.
    local dbg = ngx.var[OBSERVE_HEADER_VAR]
    if not dbg or dbg == "" then return end
    if not debug_source_trusted() then return end
    local p = _M.policy_for(ngx.var.host)
    if p then
        -- An opt-out row (no armed tier) is labelled as such, not left as a
        -- bare "gen=N" that reads like a malformed policy.
        local lbl = "observe " .. (policy_armed(p) and "" or "opt-out ") .. label_for(p)
        -- Now that Tier A caches, surface the actual verdict too (HIT / MISS /
        -- BYPASS / EXPIRED / …) — debug-gated, so ordinary clients never see it.
        local st = ngx.var.upstream_cache_status
        if st and st ~= "" then lbl = lbl .. " status=" .. st end
        -- Tier B: for a micro-armed vhost, surface the would-cache verdict of
        -- the request-side rails (micro_verdict: armed / method / credentials /
        -- range / path / panel / cookie allowlist / remembered-uncacheable) —
        -- the DRY-RUN burn-in surface under MICRO_CACHE_ENFORCE=0. debug-gated
        -- like the rest of this stamp.
        if type(p.micro) == "table" and p.micro.on then
            local okc, bkt, why = micro_verdict(p)
            -- what micro_gate would also refuse here: a location other than
            -- `location /` (no sentinel), an internal redirect (a response a
            -- micro location served is itself internal: not that), an nginx
            -- core older than 1.23
            if okc then
                if ngx.var.cfm_micro_conf ~= "1"
                   or (ngx.var.cfm_upstream ~= "cfm_apache_micro" and ngx.req.is_internal()) then
                    okc, why = false, "location"
                elseif not NGX_JOINS_HEADERS then
                    okc, why = false, "nginx-version"
                end
            end
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
-- docs/site-cache-design.md §14. A panel / webmail host (panel_host) is never
-- cached, even under an armed wildcard.
function _M.static_gate()
    if not site_cache_enabled() then return end
    local p = _M.policy_for(ngx.var.host)
    if not p then return end
    local s = p.static
    if type(s) ~= "table" or not s.on then return end
    if panel_host(ngx.var.host) then return end
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
--   * $cfm_micro_conf != "1": the conf sentinel, "1" only in the HTTPS
--     server's `location /` ("" by default at server level). It pins micro to
--     that location (never the no-buffer PHP/admin or streaming passthroughs,
--     whose unbuffered proxying a micro location would replace), and an older
--     live conf — one without the origin Cache-Control / X-Accel-Expires rails
--     and with background updates on — lacks it, so newer Lua never routes
--     into its locations.
--   * an internal redirect: a redirect to a named location (error_page … =
--     @x, ngx.exec("@x")) keeps the sentinel variable in the target location.
--     (A redirect to a URI re-runs the server-level "" default; `rewrite …
--     last` in `location /` and ngx.req.set_uri(…, true) keep it without making
--     the request internal — check_site_cache_config.sh forbids rewrite in
--     `location /` and rewrite_by_lua* in it and at server / http level.)
--   * nginx core older than 1.23: it exposes only the FIRST of several
--     Cache-Control headers in $upstream_http_cache_control, so a `private` on
--     a second line would not reach $cfm_cc_nostore.
--   * the request-side rails (micro_verdict: armed micro tier, GET/HEAD, no
--     Authorization / Range / event-stream, not an admin / script / transfer
--     path, not a panel host, anonymous per the cookie allowlist, not
--     remembered as uncacheable).
-- On a cache decision it sets the same two vars static_gate does ($cfm_cache_skip
-- =0 to open the bypass gate, $cfm_cache_gen for the purge-generation key) and
-- returns the bucket location; the only-200 rail + response-side rails (Set-Cookie,
-- Cache-Control private/no-store/no-cache/s-maxage=0, X-Accel-Expires 0 or @…
-- never stored) are enforced natively in that location.
function _M.micro_gate()
    if not site_cache_enabled() then return nil end
    if not _cache.has_micro then return nil end
    if not NGX_JOINS_HEADERS then return nil end
    if not micro_enforce_enabled() then return nil end
    if ngx.var.scheme ~= "https" then return nil end
    local p = _M.policy_for(ngx.var.host)
    if not p then return nil end
    if ngx.var.cfm_micro_conf ~= "1" then return nil end
    if ngx.req.is_internal() then return nil end
    local ok, bucket = micro_verdict(p)
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
_M._cookie_key         = cookie_key
_M._micro_decision     = micro_decision
_M._micro_storable     = micro_storable
_M._micro_mark_ttl     = micro_mark_ttl
_M._panel_host         = panel_host
_M._has_micro          = function() return _cache.has_micro end
_M._micro_enforce      = micro_enforce_enabled

return _M

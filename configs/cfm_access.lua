-- cfm_access.lua
-- OpenResty access phase handler for cfm WAF integration.
--
-- Install in nginx.conf:
--   lua_shared_dict cfm_decisions 10m;
--   lua_package_path "/opt/openresty/nginx/lua/?.lua;;";
--
-- In each server block (or http block for global):
--   access_by_lua_file /opt/openresty/nginx/lua/cfm_access.lua;
--
-- For the verify endpoint, add a dedicated location:
--   location = /cfm_verify {
--       content_by_lua_file /opt/openresty/nginx/lua/cfm_access.lua;
--   }
--
-- Env vars (set via env directive in nginx.conf):
--   env CFM_CHALLENGE_SECRET;
--   env CFM_NGINX_TOKEN;
--   env CFM_NGINX_SOCK;      (optional, default /var/run/cfm/cfm_nginx.sock)
--   env CFM_CF_DOMAINS;      (optional, comma-separated CF domains, e.g. "example.com,foo.net")
--
-- Flow:
--   1. Extract real IP  (CF-Connecting-IP for Cloudflare domains, else $remote_addr)
--   2. POST /cfm_verify → hand off to cfm_pow.handle_verify
--   3. Check cfm_ok solved cookie → allow immediately (no socket query)
--   4. Query cfm bridge for decision (cached in shared dict)
--   5. allow       → pass through
--      block        → 403
--      challenge    → serve PoW HTML inline at current URL

local decisions = require "cfm_decisions"
local pow       = require "cfm_pow"

-- ── Real IP extraction ────────────────────────────────────────────────────────
-- For Cloudflare domains, trust CF-Connecting-IP.
-- For direct traffic, use $remote_addr.
-- We identify CF domains by checking the Host against a configured list.

local CF_DOMAINS_RAW = os.getenv("CFM_CF_DOMAINS") or ""

local cf_domains = {}
for d in CF_DOMAINS_RAW:gmatch("[^,]+") do
    d = d:match("^%s*(.-)%s*$"):lower()
    if d ~= "" then
        cf_domains[d] = true
    end
end

local function is_cf_domain(host)
    if not host then return false end
    host = host:lower()
    -- strip port
    host = host:match("^([^:]+)") or host
    if cf_domains[host] then return true end
    -- check suffix: "*.example.com" style
    for d, _ in pairs(cf_domains) do
        if host:sub(-(#d + 1)) == "." .. d then return true end
    end
    return false
end

-- Cloudflare sends a real IPv4 in CF-Connecting-IP even for IPv6 connections.
-- For non-CF traffic, $remote_addr is authoritative.
local function get_real_ip()
    local host = ngx.var.host or ""
    if is_cf_domain(host) then
        local cf_ip = ngx.req.get_headers()["CF-Connecting-IP"]
        if cf_ip and cf_ip ~= "" then
            -- strip whitespace
            cf_ip = cf_ip:match("^%s*(.-)%s*$")
            if cf_ip ~= "" then return cf_ip end
        end
    end
    return ngx.var.remote_addr
end

-- ── Skip rules ────────────────────────────────────────────────────────────────
-- Don't challenge certain paths that would break things or cause loops.

local SKIP_PATHS = {
    "^/cfm_verify",         -- our own verify endpoint
    "^/favicon%.ico$",
    "^/robots%.txt$",
    "^/%.well%-known/",
    "^/apple%-touch%-icon",
}

local function should_skip(uri)
    if not uri then return true end
    for _, pat in ipairs(SKIP_PATHS) do
        if uri:match(pat) then return true end
    end
    return false
end

-- ── Main entry point ──────────────────────────────────────────────────────────

local uri = ngx.var.uri or "/"
local host = ngx.var.host or ""
local ua   = ngx.req.get_headers()["User-Agent"] or ""
local ip   = get_real_ip()

-- 1. Verify endpoint: JS posts here after solving PoW
if uri == "/cfm_verify" or uri:match("^/cfm_verify%?") then
    return pow.handle_verify(ip, ua)
end

-- 2. Skip static/well-known paths
if should_skip(uri) then
    return  -- pass through
end

-- 3. Check solved cookie (fast path — no socket query)
if pow.is_solved(ip) then
    return  -- pass through
end

-- 4. Query bridge decision (cached)
local d = decisions.get(ip, host)

-- 5. Route based on decision
if d.ip_action == "block" then
    ngx.status = 403
    ngx.header["Content-Type"] = "text/plain"
    ngx.header["Cache-Control"] = "no-store"
    ngx.say("Access denied.")
    return ngx.exit(403)
end

if d.ip_action == "challenge" or d.vhost_action == "challenge" then
    -- Serve PoW inline at the current URL.
    -- The next= parameter encodes where to redirect after solving.
    local next_url = ngx.var.request_uri or "/"
    return pow.serve_challenge(ip, ua, host, next_url)
end

-- d.ip_action == "allow" and d.vhost_action == "allow" → fall through to proxy

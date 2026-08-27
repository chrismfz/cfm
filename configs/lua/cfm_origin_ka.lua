-- /var/lib/cfm/lua/cfm_origin_ka.lua
--
-- balancer_by_lua helper for the OPT-IN origin keepalive pools
-- (upstream cfm_origin_http / cfm_origin_https in openresty.conf and
-- angie.conf). See docs/proxy-performance.md for the full rationale,
-- enablement recipe and safety discussion.
--
-- WHAT THIS BUYS
--
-- The default CFM routing is `proxy_pass http(s)://$server_addr:{80,443}`.
-- With a variable proxy_pass and no upstream block there is NO connection
-- reuse: every proxied request opens a fresh TCP connection to Apache and,
-- on the 443 path, pays a full upstream TLS handshake. That handshake is
-- the single largest avoidable per-request cost of the in-path edge
-- (typically several ms of pure CPU per request on loopback).
--
-- When the operator enables it — detectors.conf [webdetector]
-- ORIGIN_KEEPALIVE = 1, published via cfm_bridge_config.lua — cfm.lua's
-- origin_pass_for() routes through the cfm_origin_* upstream blocks
-- instead (guarded by the $cfm_origin_ka_conf sentinel so an older live
-- proxy conf without the upstreams safely stays on direct proxying), and
-- this module sets the real peer per request ($server_addr keeps
-- dedicated-IP routing intact):
--
--   * port 80  — POOLED (the ONLY pooled port). HTTP/1.1 keepalive +
--     Host-header vhost routing is standard; Apache serves different vhosts
--     over ONE connection natively, so reusing a pooled HTTP connection across
--     vhosts is always correct. The Lua balancer owns this pool.
--   * everything else (443 today, any port added later) — NEVER POOLED, at
--     any layer. Each request gets its own upstream connection; on 443 the SNI
--     comes from `proxy_ssl_name $host`. This is the fail-safe DEFAULT branch,
--     not a `port==443` special case, so a new port can never silently pool a
--     TLS origin.
--
-- WHY HTTPS(443) IS NEVER POOLED  (the 421 incident — 2026-08)
--
-- An HTTPS origin keepalive pool is only safe if a connection handshaked with
-- SNI=hostA is NEVER reused for a request to hostB: the SNI is baked into the
-- established TLS connection at handshake time, so a cross-vhost reuse makes
-- Apache answer `AH02032 ... 421 Misdirected Request` on shared-IP vhosts.
-- Production evidence on OpenResty 1.31.1.1 → Apache: thousands of 421s across
-- dozens of vhosts sharing one origin IP, on warm (uct=0.000) connections
-- carrying the wrong SNI, all through the shared `cfm_origin_https` upstream.
--
-- There are THREE independent connection/TLS reuse layers, and ALL THREE must
-- be off on 443 or the invariant is unproven:
--   1. nginx-core NATIVE upstream keepalive. As of nginx 1.29.7 (this
--      OpenResty ships nginx 1.31.1) it is ON BY DEFAULT (`keepalive 32
--      local`) and SNI-BLIND — it reuses by peer IP:port and ignores SNI
--      (lua-resty-core: native reuse "only considers the IP and port ... fails
--      to consider the SNI extension"). `local` separates only by *location*,
--      not by $host, so every vhost through one origin location shares the
--      pool. This is the most likely layer behind the incident — and the one a
--      `keepalive`-directive audit misses, because it is a *default*, not a
--      directive. Engine-specific: OpenResty disables it explicitly with
--      `keepalive 0` on both cfm_origin_* upstreams; Angie keeps native
--      upstream keepalive OFF by engine default and REJECTS `keepalive 0`
--      (`angie -t` -> invalid value "0"), so it carries no such directive.
--   2. The Lua balancer keepalive (`balancer.enable_keepalive`) — simply never
--      called for 443 here.
--   3. TLS session reuse (`proxy_ssl_session_reuse`, default on). The upstream
--      SSL session cache is peer-keyed, not SNI-keyed, so a resumed session can
--      carry hostA's TLS identity into a hostB request. Disabled with
--      `proxy_ssl_session_reuse off` on every 443 origin location.
-- With 1+2+3 off, 443 is "fresh TCP + fresh TLS/SNI per request" — provably
-- SNI-safe. (An earlier version of this module relied ONLY on not calling
-- enable_keepalive, which left the default-on native pool active and did NOT
-- actually prevent 443 reuse — the lesson that a runtime *default* is as
-- dangerous as an explicit directive.)
--
-- Scope of the retained port-80 pool: cfm.lua's origin_pass_for() routes by the
-- CLIENT scheme, so HTTPS clients go to cfm_origin_https:443 (per-request) and
-- HTTP clients to cfm_origin_http:80 (pooled). On a TLS-everywhere panel most
-- traffic is HTTPS, so the port-80 pool mainly benefits plain-HTTP origin
-- requests (redirects, ACME/.well-known DCV, plain-HTTP sites); the bulk 443
-- handshake saving is given up until a proven SNI-keyed 443 pool lands
-- (docs/proxy-performance.md — which must be gated by a two-vhost same-IP
-- integration test on the deployed engine, not a stubbed unit test).
--
-- FAIL-SAFETY
--
-- Capability gaps degrade, they don't error: enable_keepalive missing or
-- its FFI shim absent from the engine's lua module build (possible on some
-- Angie angie-module-lua versions) → port 80 also falls back to per-request
-- connections with one WARN per worker. A hard failure to even set the peer
-- surfaces as a 502 on the affected request — same blast radius as any
-- upstream connect failure — and is logged. The knob defaults to OFF;
-- nothing in this file runs unless the operator opts in.

local ok_bal, balancer = pcall(require, "ngx.balancer")

local _M = {}

-- Pool tuning: detectors.conf [webdetector] ORIGIN_KEEPALIVE_IDLE_SEC /
-- ORIGIN_KEEPALIVE_MAX_REQS via the bridge config; built-in defaults when
-- the fields are absent (older daemon). The idle timeout MUST stay below
-- Apache's KeepAliveTimeout (EA4/cPanel default: 5s) so nginx retires
-- pooled connections before Apache closes them under us. These apply to the
-- port-80 pool (443 is never pooled).
--
-- bridge_cfg.get() returns the SAME cached table between bridge-config
-- reloads (cfm_filecache), so knob resolution is memoised on table
-- identity — the steady-state cost is one call + one pointer compare.
local bridge_cfg = require "cfm_bridge_cfg"
local DEFAULT_IDLE_SEC = 3
local DEFAULT_MAX_REQS = 1000
local last_cfg, cur_idle, cur_reqs

local function pool_knobs()
  local cfg = bridge_cfg.get()
  if cfg ~= last_cfg then
    last_cfg = cfg
    cur_idle = cfg.origin_ka_idle_sec or DEFAULT_IDLE_SEC
    cur_reqs = cfg.origin_ka_max_reqs or DEFAULT_MAX_REQS
    if cur_idle <= 0 then cur_idle = DEFAULT_IDLE_SEC end
    if cur_reqs <= 0 then cur_reqs = DEFAULT_MAX_REQS end
  end
  return cur_idle, cur_reqs
end

-- Set when enable_keepalive is absent or throws (missing FFI shim). One WARN,
-- then the worker permanently degrades to per-request connections on port 80
-- instead of re-checking (and re-warning) every request.
local keepalive_broken = false
local pool80_announced = false
local ka_fail_warned = false
local more_tries_warned = false
local retry_unavailable_warned = false

-- Arm exactly ONE keepalive-race retry on the FIRST attempt of a request that
-- is actually being POOLED. balancer_by_lua disables nginx's default upstream
-- retries, so without this a pooled connection Apache closed in the idle
-- window turns into a client-facing 502; one retry re-runs the balancer on a
-- fresh connection. get_last_failure() is nil only on the initial attempt, so
-- retries never stack. Called ONLY from enable_pool()'s success path, so it
-- never arms on an unpooled request (443, keepalive_broken, or a transient
-- enable_keepalive failure) — a retry with no pool to race against would just
-- double connect load against an already-failing origin during an outage. The
-- (rare) set_more_tries failure is throttled to once/worker like the other
-- degradation WARNs, so it can't flood error.log at request rate.
local function arm_keepalive_retry()
  if type(balancer.get_last_failure) ~= "function"
     or type(balancer.set_more_tries) ~= "function" then
    -- Pooled, but this engine cannot arm a keepalive-race retry: a pooled
    -- connection Apache closed in the idle window will surface as a 502 with no
    -- retry. Surface this middle tier (pooled, no retry) with its own
    -- once-per-worker WARN so it does not hide behind "pooling active".
    if not retry_unavailable_warned then
      retry_unavailable_warned = true
      ngx.log(ngx.WARN, "[cfm_origin_ka] HTTP(80) pooling active but the ",
              "keepalive-race retry is unavailable (engine lacks ",
              "get_last_failure/set_more_tries) — a stale pooled connection may ",
              "surface as a 502 for this worker")
    end
    return
  end
  if balancer.get_last_failure() ~= nil then return end   -- retry attempt: never stack
  local ok, err = balancer.set_more_tries(1)
  if not ok and not more_tries_warned then
    more_tries_warned = true
    ngx.log(ngx.WARN, "[cfm_origin_ka] set_more_tries failed: ", tostring(err),
            " (warned once/worker)")
  end
end

local function enable_pool()
  if keepalive_broken then return end
  if type(balancer.enable_keepalive) ~= "function" then
    -- No balancer keepalive at all in this engine's lua module build
    -- (possible on some Angie angie-module-lua versions). Latch + one WARN so
    -- the degraded state is VISIBLE: a silent return would run port 80
    -- per-request while the logs claim nothing — the log blind spot this
    -- change exists to close.
    keepalive_broken = true
    ngx.log(ngx.WARN, "[cfm_origin_ka] engine lacks balancer.enable_keepalive; ",
            "HTTP(80) origin degraded to per-request connections for this worker")
    return
  end
  local idle, reqs = pool_knobs()
  local pok, ok, err = pcall(balancer.enable_keepalive, idle, reqs)
  if not pok then
    keepalive_broken = true
    ngx.log(ngx.WARN, "[cfm_origin_ka] enable_keepalive raised (", tostring(ok),
            ") — engine lacks balancer keepalive support; ",
            "degrading to per-request connections for this worker")
    return
  end
  if not ok then
    -- A NON-raising failure return (e.g. a transient "no memory", or an
    -- engine that reports an error code instead of raising). Do NOT latch —
    -- the next request may pool fine — but throttle the WARN to once per
    -- worker so a deterministic failure can't flood error.log at request rate.
    if not ka_fail_warned then
      ka_fail_warned = true
      ngx.log(ngx.WARN, "[cfm_origin_ka] enable_keepalive failed: ", tostring(err),
              " (warned once/worker; port 80 stays unpooled while this recurs)")
    end
    return
  end
  -- Success: this request IS pooled. Arm the keepalive-race retry now (only
  -- here, so no unpooled path ever arms it), and report the pooled state once
  -- per worker at WARN — visible at the default `error_log warn` level, the
  -- signal operators grep for. We log that pooling is active, not the live
  -- idle/max_reqs values: those follow ORIGIN_KEEPALIVE_* in detectors.conf
  -- and update within ~10s, so a once-per-worker line would go stale.
  arm_keepalive_retry()
  if not pool80_announced then
    pool80_announced = true
    ngx.log(ngx.WARN, "[cfm_origin_ka] HTTP(80) origin pooling active")
  end
end

-- Always the plain 2-arg form. SNI for HTTPS comes from proxy_ssl_name $host at
-- the location level. We deliberately do NOT use set_current_peer's host arg
-- (the SNI-aware Lua pooling path) here, because HTTPS pooling is disabled by
-- policy — see the header comment. (lua-resty-core also advises against setting
-- both the host arg and proxy_ssl_name at once.)
local function set_peer(addr, port)
  local ok, err = balancer.set_current_peer(addr, port)
  if not ok then
    ngx.log(ngx.ERR, "[cfm_origin_ka] set_current_peer(", addr, ":", port,
            ") failed: ", tostring(err))
    return false
  end
  return true
end

-- Per-worker visibility. error_log runs at `warn` in both openresty.conf and
-- angie.conf, so an informational NOTICE would never be written — operators
-- had no way to confirm from logs what this module was actually doing, the
-- blind spot that hid the 421 root cause for a week. Each path reports its
-- TRUE effective state exactly once per worker at WARN: port 80 from
-- enable_pool() above (pooled, or degraded), the unpooled ports (443 and any
-- other) from the default branch below (always per-request by design). We
-- deliberately never pre-announce a policy before it is established, so the log
-- can never claim "pooled" on an engine that turned out unable to pool.
-- Keyed by port so each unpooled port a worker serves announces once (a worker
-- that saw 8443 first still announces 443 when it appears).
local announced_unpooled = {}

-- balance(port) — entry point called from the balancer_by_lua_block of
-- the cfm_origin_http (80) / cfm_origin_https (443) upstreams.
function _M.balance(port)
  if not ok_bal or type(balancer.set_current_peer) ~= "function" then
    ngx.log(ngx.ERR, "[cfm_origin_ka] ngx.balancer unavailable: ", tostring(balancer))
    return ngx.exit(ngx.ERROR)
  end

  local addr = ngx.var.server_addr
  if not addr or addr == "" then addr = "127.0.0.1" end

  -- Fail-safe dispatch: port 80 is the ONLY port we pool. HTTP/1.1 keepalive +
  -- Host-header vhost routing is safe to reuse across vhosts on one connection,
  -- so pooling it is a pure optimisation. enable_pool() arms the keepalive-race
  -- retry itself, only on the request it actually pools.
  if port == 80 then
    if not set_peer(addr, 80) then
      return ngx.exit(ngx.ERROR)
    end
    enable_pool()
    return
  end

  -- EVERYTHING ELSE (443 today, and any port added later) is correctness-first:
  -- a per-request connection, never pooled. This is deliberately the default
  -- branch, not a `port == 443` special case, so a future balance(<newport>)
  -- can never silently pool a TLS origin. SNI for 443 comes from
  -- proxy_ssl_name $host at the location level; nginx-core's native pool is
  -- disabled on these upstreams (keepalive 0) and proxy_ssl_session_reuse is
  -- off, so no layer can reuse a 443 connection or TLS session across vhosts.
  if not announced_unpooled[port] then
    announced_unpooled[port] = true
    ngx.log(ngx.WARN, "[cfm_origin_ka] origin port ", port, ": per-request ",
            "connection, never pooled (SNI-safe by design). Pooling a TLS ",
            "origin across vhosts on a shared IP risks Apache 421 Misdirected ",
            "Request. See docs/proxy-performance.md.")
  end
  if not set_peer(addr, port) then
    return ngx.exit(ngx.ERROR)
  end
end

return _M

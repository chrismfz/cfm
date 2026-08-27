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
--   * port 80  — POOLED. HTTP/1.1 keepalive + Host-header vhost routing is
--     standard; Apache serves different vhosts over ONE connection
--     natively, so reusing a pooled HTTP connection across vhosts is always
--     correct.
--   * port 443 — NEVER POOLED. Each request gets its own upstream TLS
--     connection; the SNI comes from `proxy_ssl_name $host` at the location
--     level. Functionally identical to the pre-keepalive 443 behaviour.
--
-- WHY 443 IS NOT POOLED  (the 421 incident — 2026-08)
--
-- An HTTPS origin keepalive pool is only safe if a connection handshaked
-- with SNI=hostA is NEVER reused for a request to hostB: the SNI is baked
-- into the established TLS connection at handshake time and cannot change,
-- so a cross-vhost reuse makes Apache answer `AH02032 ... 421 Misdirected
-- Request` (SNI/Host mismatch) on shared-IP vhosts.
--
-- lua-resty-core's `balancer.enable_keepalive` keys its connection pool by
-- the PEER ADDRESS only: the default pool name is "<peer_addr>:<port>"
-- (e.g. "203.0.113.7:443"), which does NOT include the SNI. The third
-- `host` argument to `set_current_peer` sets the SNI for the *handshake*
-- but does NOT alter the pool name — and lua-resty-core explicitly forbids
-- combining that `host` arg with `proxy_ssl_name` anyway. This module
-- previously (wrongly) assumed the 3-arg form keyed the pool by host;
-- production evidence on OpenResty 1.31.1.1 proved it does not — thousands
-- of 421s across dozens of vhosts sharing one Apache origin IP, warm
-- (uct=0.000) connections carrying the wrong SNI.
--
-- Rather than depend on an unverified, version-specific pool-naming API to
-- fold the SNI into the pool key, HTTPS origin connections are simply not
-- pooled. The upstream TLS handshake cost returns on 443, but HTTP (80)
-- pooling — the HTML document path on panels that terminate TLS at the edge
-- — is retained, and the entire cross-SNI 421 class is gone. The knob stays
-- safe to run fleet-wide. docs/proxy-performance.md records the (future)
-- path to safe host-scoped 443 pooling (a per-host `pool` name proven by an
-- integration test against the deployed engine).
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
    ngx.log(ngx.WARN, "[cfm_origin_ka] enable_keepalive failed: ", tostring(err))
    return
  end
  -- Success: report the TRUE pooled state once per worker (WARN, so it shows
  -- at the default `error_log warn` level) — the signal operators grep for.
  if not pool80_announced then
    pool80_announced = true
    ngx.log(ngx.WARN, "[cfm_origin_ka] HTTP(80) origin pooling active ",
            "(idle=", idle, "s max_reqs=", reqs, ")")
  end
end

-- Always the plain 2-arg form: the SNI for 443 comes from proxy_ssl_name
-- $host at the location level, never from set_current_peer's `host` arg
-- (lua-resty-core forbids setting both, and the arg would not key the pool
-- anyway — see the header comment).
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
-- enable_pool() above (pooled, or degraded), port 443 from the 443 branch
-- below (always per-request by design). We deliberately never pre-announce a
-- policy before it is established, so the log can never claim "pooled" on an
-- engine that turned out unable to pool.
local announced_443 = false

-- Arm exactly ONE keepalive-race retry on the FIRST attempt of a POOLED
-- (port 80) request. balancer_by_lua disables nginx's default upstream
-- retries, so without this a pooled connection Apache closed in the idle
-- window turns into a client-facing 502; one retry re-runs the balancer on a
-- fresh connection. get_last_failure() is nil only on the initial attempt, so
-- retries never stack. NOT armed on the unpooled 443 path: there is no
-- stale-pool race there, and a blanket retry would just double connect load
-- against an already-failing origin during an outage.
local function arm_keepalive_retry()
  if type(balancer.get_last_failure) == "function"
     and type(balancer.set_more_tries) == "function"
     and balancer.get_last_failure() == nil then
    local ok, err = balancer.set_more_tries(1)
    if not ok then
      ngx.log(ngx.WARN, "[cfm_origin_ka] set_more_tries failed: ", tostring(err))
    end
  end
end

-- balance(port) — entry point called from the balancer_by_lua_block of
-- the cfm_origin_http (80) / cfm_origin_https (443) upstreams.
function _M.balance(port)
  if not ok_bal or type(balancer.set_current_peer) ~= "function" then
    ngx.log(ngx.ERR, "[cfm_origin_ka] ngx.balancer unavailable: ", tostring(balancer))
    return ngx.exit(ngx.ERROR)
  end

  local addr = ngx.var.server_addr
  if not addr or addr == "" then addr = "127.0.0.1" end

  if port == 443 then
    -- SNI-safe per-request connection: set the peer but do NOT pool. Each
    -- 443 request gets its own connection whose SNI is proxy_ssl_name $host
    -- — no cross-vhost reuse is possible, so Apache never sees an SNI/Host
    -- mismatch. Identical to the pre-keepalive behaviour.
    if not announced_443 then
      announced_443 = true
      ngx.log(ngx.WARN, "[cfm_origin_ka] HTTPS(443) origin: per-request TLS by ",
              "design (SNI from proxy_ssl_name $host; not pooled — backend ",
              "keepalive pools key on peer addr:port, not SNI, so pooling 443 ",
              "would risk Apache 421 Misdirected Request). ",
              "See docs/proxy-performance.md.")
    end
    if not set_peer(addr, 443) then
      return ngx.exit(ngx.ERROR)
    end
    return
  end

  -- Plain-HTTP origin (port 80): Host-header vhost routing, always safe to
  -- pool per (addr, port).
  arm_keepalive_retry()
  if not set_peer(addr, port) then
    return ngx.exit(ngx.ERROR)
  end
  enable_pool()
end

return _M

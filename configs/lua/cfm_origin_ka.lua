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
-- this module pools backend connections:
--
--   * port 80  — always pooled. HTTP/1.1 keepalive + Host-header vhost
--     routing is standard; Apache serves different vhosts on one
--     connection natively.
--   * port 443 — pooled ONLY when lua-resty-core's
--     balancer.set_current_peer accepts the third `host` argument
--     (OpenResty 1.27.1.1+), which sets the upstream SNI AND keys the
--     connection pool by it. Without host-keyed pools, a connection
--     handshaked with SNI=hostA could be reused for a request to hostB on
--     the same IP — Apache answers those with 421 Misdirected Request /
--     400 SNI-Host mismatch on shared-vhost servers. In that case this
--     module falls back to per-request connections (identical behaviour
--     to the knob being off) rather than risking cross-SNI reuse.
--
-- FAIL-SAFETY
--
-- Capability gaps degrade, they don't error: no SNI-keyed pools → HTTPS
-- stays per-request (one NOTICE per worker); enable_keepalive missing or
-- its FFI shim absent from the engine's lua module build (possible on
-- some Angie angie-module-lua versions) → per-request connections with
-- one WARN per worker. A hard failure to even set the peer surfaces as a
-- 502 on the affected request — same blast radius as any upstream connect
-- failure — and is logged. The knob defaults to OFF; nothing in this file
-- runs unless the operator opts in.

local ok_bal, balancer = pcall(require, "ngx.balancer")

local _M = {}

-- Capability probe, once per worker: does set_current_peer take a third
-- `host` argument? Older lua-resty-core silently IGNORES extra arguments
-- (plain Lua varargs), so a pcall probe cannot detect support — inspect
-- the function's declared parameter count instead. A vararg
-- implementation reads as nparams=0 and is treated as unsupported (safe).
-- Also demoted at runtime (with one WARN) if the 3-arg call ever fails —
-- e.g. a future core that expects an opts table instead of a string.
local sni_pool_ok = false
if ok_bal and type(balancer.set_current_peer) == "function" then
  local ok_info, info = pcall(debug.getinfo, balancer.set_current_peer, "u")
  if ok_info and type(info) == "table" and (info.nparams or 0) >= 3 then
    sni_pool_ok = true
  end
end

-- Pool tuning: detectors.conf [webdetector] ORIGIN_KEEPALIVE_IDLE_SEC /
-- ORIGIN_KEEPALIVE_MAX_REQS via the bridge config; built-in defaults when
-- the fields are absent (older daemon). The idle timeout MUST stay below
-- Apache's KeepAliveTimeout (EA4/cPanel default: 5s) so nginx retires
-- pooled connections before Apache closes them under us.
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

local warned_no_sni_pool = false

-- Set when enable_keepalive throws (missing FFI shim). One WARN, then the
-- worker permanently degrades to per-request connections instead of
-- erroring every request.
local keepalive_broken = false

local function enable_pool()
  if keepalive_broken then return end
  if type(balancer.enable_keepalive) ~= "function" then return end
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
  end
end

local function set_peer(addr, port)
  local ok, err = balancer.set_current_peer(addr, port)
  if not ok then
    ngx.log(ngx.ERR, "[cfm_origin_ka] set_current_peer(", addr, ":", port,
            ") failed: ", tostring(err))
    return false
  end
  return true
end

-- balance(port) — entry point called from the balancer_by_lua_block of
-- the cfm_origin_http (80) / cfm_origin_https (443) upstreams.
function _M.balance(port)
  if not ok_bal or type(balancer.set_current_peer) ~= "function" then
    ngx.log(ngx.ERR, "[cfm_origin_ka] ngx.balancer unavailable: ", tostring(balancer))
    return ngx.exit(ngx.ERROR)
  end

  -- Keepalive-race retry. balancer_by_lua disables nginx's default
  -- upstream retries — without set_more_tries a pooled connection that
  -- Apache closed in the idle window turns into a client-facing 502.
  -- Allow exactly ONE retry (a fresh connection) on the first failure;
  -- get_last_failure() is nil only on the initial attempt, so retries
  -- never stack more tries.
  if type(balancer.get_last_failure) == "function"
     and type(balancer.set_more_tries) == "function"
     and balancer.get_last_failure() == nil then
    local ok, err = balancer.set_more_tries(1)
    if not ok then
      ngx.log(ngx.WARN, "[cfm_origin_ka] set_more_tries failed: ", tostring(err))
    end
  end

  local addr = ngx.var.server_addr
  if not addr or addr == "" then addr = "127.0.0.1" end

  if port == 443 then
    local host = ngx.var.host or ""
    if sni_pool_ok and host ~= "" then
      -- 3-arg form: host sets the upstream SNI and is part of the
      -- keepalive pool key, so pooled connections never cross vhosts.
      local pok, ok, err = pcall(balancer.set_current_peer, addr, port, host)
      if pok and ok then
        enable_pool()
        return
      end
      -- Latch off: the failure is deterministic for this core build
      -- (argument shape / peer handling), so retrying — and re-warning —
      -- per request would spam error.log at request rate under load.
      sni_pool_ok = false
      ngx.log(ngx.WARN, "[cfm_origin_ka] SNI-keyed set_current_peer failed (",
              tostring(pok and err or ok),
              ") — disabling HTTPS pooling for this worker, ",
              "falling back to per-request connections")
      -- fall through to the unpooled 2-arg path below
    elseif not warned_no_sni_pool then
      warned_no_sni_pool = true
      ngx.log(ngx.NOTICE, "[cfm_origin_ka] lua-resty-core lacks SNI-keyed ",
              "connection pools (needs OpenResty 1.27.1.1+); HTTPS origin ",
              "connections stay per-request. HTTP (port 80) pooling is active.")
    end
    -- No SNI-keyed pooling available: set the peer but do NOT pool.
    -- SNI still comes from proxy_ssl_name $host at the location level,
    -- and each request gets its own connection — identical to the
    -- pre-keepalive behaviour.
    if not set_peer(addr, port) then
      return ngx.exit(ngx.ERROR)
    end
    return
  end

  -- Plain-HTTP origin (port 80): Host-header vhost routing, always safe
  -- to pool per (addr, port).
  if not set_peer(addr, port) then
    return ngx.exit(ngx.ERROR)
  end
  enable_pool()
end

-- Exposed for the host-side smoke test (scripts/tests/cfm_origin_ka_test.lua)
-- and ad-hoc debugging.
function _M.sni_pool_supported()
  return sni_pool_ok
end

return _M

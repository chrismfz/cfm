-- Tests for cfm_cfg.lua — the request-INVARIANT slice of cfm.lua's CFG that is
-- built ONCE per worker, plus the metatable layering cfm.lua uses to keep the
-- four bridge-derived fields per-request.
--
-- The hoist's whole safety claim is "byte-identical to the old per-request
-- literal": the static fields resolve to the same defaults, the dynamic fields
-- come from the live bridge config, and cfm_decision's in-place `cfg.token =
-- fresh` mutation must land on the per-request top table, never the shared
-- module (which would corrupt every later request on that worker).

package.path = "configs/lua/?.lua;" .. package.path

local fails = 0
local function check(cond, msg)
  if cond then return end
  fails = fails + 1
  io.stderr:write("FAIL: " .. tostring(msg) .. "\n")
end

local static = require("cfm_cfg")

-- Rebuild CFG exactly as cfm.lua does: dynamic fields on top, static via __index.
local function build_cfg(bridge_cfg, bridge_token)
  return setmetatable({
    token             = bridge_token,
    ok_ttl_sec        = static.resolve_ok_ttl(bridge_cfg.cookie_life_sec),
    clearance_refresh = bridge_cfg.clearance_refresh,
    origin_keepalive  = (bridge_cfg.origin_keepalive == true),
  }, { __index = static })
end

-- ── Static defaults resolve via __index, matching the old inline literal ──────
-- (No CFM_* env var is ever set — the systemd units export none and nginx
-- strips vars not declared with `env` — so os.getenv always returns nil here and
-- the defaults win. This test therefore also documents the effective values.)
do
  local CFG = build_cfg({ cookie_life_sec = 7200, clearance_refresh = false, origin_keepalive = true }, "TOK")
  local want = {
    sock_path = "/var/run/cfm/cfm_nginx.sock",
    token_header = "X-CFM-Token",
    decision_timeout_ms = 300,
    decision_cache_ttl_ms = 90000,
    waf_excl_cache_ttl_ms = 6000,
    waf_excl_meta_ttl_sec = 15,
    waf_excl_refresh_sec = 10,
    block_code = 403,
    fail_open = true,
    debug = false,
    debug_headers = false,
    log_allows = false,
    ok_touch_every_sec = 120,
    keepalive_idle_ms = 60000,
    keepalive_pool = 512,
    waf_body_max_len = 32768,
    waf_body_read_max_cl = 1048576,
    post_resume_enable = true,
    post_resume_max_len = 65536,
    post_resume_ttl_sec = 90,
    waf_after_clearance_challenge = "logonly",
    waf_after_clearance_high_risk = "block",
    waf_stats_enable = true,
    waf_stats_flush_sec = 60,
  }
  for k, v in pairs(want) do
    check(CFG[k] == v, "static field " .. k .. " = " .. tostring(CFG[k]) .. " want " .. tostring(v))
  end
end

-- ── Dynamic bridge-derived fields live in the top table (per request) ─────────
do
  local CFG = build_cfg({ cookie_life_sec = 7200, clearance_refresh = false, origin_keepalive = true }, "TOK")
  check(rawget(CFG, "token") == "TOK", "token is a top-table (dynamic) field")
  check(rawget(CFG, "origin_keepalive") == true, "origin_keepalive is a top-table field")
  check(rawget(CFG, "clearance_refresh") == false, "clearance_refresh is a top-table field")
  check(rawget(CFG, "sock_path") == nil, "static field is NOT copied into the top table (resolves via __index)")

  -- Different bridge config on the next request → different dynamic values,
  -- while the shared static module is untouched.
  local CFG2 = build_cfg({ cookie_life_sec = nil, clearance_refresh = true, origin_keepalive = false }, "TOK2")
  check(CFG2.token == "TOK2" and CFG2.clearance_refresh == true and CFG2.origin_keepalive == false,
    "a fresh per-request build reflects the live bridge config")
  check(CFG.origin_keepalive == true, "the earlier request's CFG is unaffected by a later build")
end

-- ── resolve_ok_ttl priority: env override > bridge cookie life (>0) > 3600 ─────
-- CFM_OK_TTL_SEC is unset in the test env, so the env branch is nil and we fall
-- through to the bridge value / default (the production reality per the note).
do
  check(static.resolve_ok_ttl(7200) == 7200,   "cookie_life 7200 honoured")
  check(static.resolve_ok_ttl("1800") == 1800, "numeric-string cookie_life parsed")
  check(static.resolve_ok_ttl(0) == 3600,      "cookie_life 0 is not >0 → 3600 fallback")
  check(static.resolve_ok_ttl(nil) == 3600,    "absent cookie_life → 3600 fallback")
  check(static.resolve_ok_ttl("") == 3600,     "empty cookie_life → 3600 fallback")
end

-- ── cfm_decision's in-place token mutation stays isolated to the top table ────
-- cfm_decision does `cfg.token = fresh` on a 403 token rotation. Because `token`
-- already exists in the top table, that assignment rawsets the top table and
-- NEVER writes through to the shared static module (which would leak a stale
-- token into every later request on the worker).
do
  local CFG = build_cfg({ cookie_life_sec = 7200 }, "OLD")
  CFG.token = "ROTATED"
  check(CFG.token == "ROTATED", "token mutation visible on this request")
  check(rawget(static, "token") == nil, "token mutation did NOT write through to the shared static module")
  -- A brand-new per-request build still starts from the real bridge token.
  local CFG2 = build_cfg({ cookie_life_sec = 7200 }, "FRESH")
  check(CFG2.token == "FRESH", "next request's token is independent of the prior mutation")
end

if fails > 0 then
  io.stderr:write("\n" .. fails .. " test(s) failed in cfm_cfg_test.lua\n")
  os.exit(1)
end
io.stdout:write("ok: cfm_cfg per-worker static CFG + metatable dynamic layering (hoist parity)\n")

-- Tests for cfm_cache.lua — edge-local per-vhost Site Cache policy (PHASE 2,
-- observe-only). Pure luajit: ngx is mocked (now/timer/log + var/header for
-- observe), cjson.safe is stubbed (only needed so `require` succeeds — the
-- async bridge fetch is never driven here). We drive the per-worker cache
-- directly via the exposed _rebuild_cache and assert policy_for / label_for /
-- observe.

package.path = "configs/lua/?.lua;" .. package.path

package.loaded["cjson.safe"] = { decode = function() return nil end }

-- Master SITE_CACHE gate stub (cfm_bridge_cfg). Default ON so the lookup/observe
-- assertions below exercise the real path; flipped to false for the gate test.
local _site_cache_on = true
package.loaded["cfm_bridge_cfg"] = { get = function() return { site_cache = _site_cache_on } end }

local _header = {}
local _now = 0            -- mutable clock (0 keeps schedule_refresh a no-op)
local _timer_calls = 0   -- counts async-refresh schedules
_G.ngx = {
  now       = function() return _now end,
  timer     = { at = function() _timer_calls = _timer_calls + 1; return true end },
  log       = function() end,
  WARN      = 1,
  ERR       = 2,
  var       = { host = "" },
  header    = _header,
}

local cache = require("cfm_cache")

local fails = 0
local function check(c, m)
  if c then return end
  fails = fails + 1
  io.stderr:write("FAIL: " .. m .. "\n")
end

-- ── normalize_host parity with the Go store / cfm_h3_config ───────────────────
check(cache._normalize_host("MyIP.gr.") == "myip.gr", "normalize lowercases + strips trailing dot")
check(cache._normalize_host("example.com:443") == "example.com", "normalize strips :port")
check(cache._normalize_host("") == "", "normalize empty stays empty")

-- ── empty cache: nothing armed ────────────────────────────────────────────────
check(cache._has_any() == false, "fresh cache has_any=false")
check(cache.policy_for("myip.gr") == nil, "no policy when cache empty")

-- ── rebuild + lookup (exact, wildcard, miss, unsupported drop) ────────────────
cache._rebuild_cache({
  { host = "myip.gr", gen = 3,
    static = { on = true, recipe = "static_aggressive", ttl = "7d" },
    micro  = { on = true, recipe = "micro_safe", ttl = "1s" } },
  { host = "www.myip.gr", gen = 0,
    micro = { on = true, recipe = "micro_aggressive", ttl = "30s" } },
  { host = "*.cdn.example.com", gen = 1,
    static = { on = true, recipe = "static_lean", ttl = "1h" } },
  { host = "cdn.*.bad.com", gen = 0,           -- unsupported pattern → dropped
    static = { on = true, recipe = "static_lean" } },
})

check(cache._has_any() == true, "has_any true after rebuild")

local p = cache.policy_for("MyIP.gr")           -- case-insensitive via normalize
check(p ~= nil and p.gen == 3, "exact host resolves (case-insensitive)")
check(p and p.static and p.static.on and p.static.ttl == "7d", "static tier carried")
check(p and p.micro and p.micro.ttl == "1s", "micro tier carried")

check(cache.policy_for("www.myip.gr") ~= nil, "exact-host www is its OWN entry (not *.myip.gr)")
check(cache.policy_for("sub.myip.gr") == nil, "no implicit wildcard for myip.gr")

local w = cache.policy_for("assets.cdn.example.com")
check(w ~= nil and w.static and w.static.recipe == "static_lean", "*.suffix wildcard matches")
check(cache.policy_for("cdn.example.com") == nil, "wildcard does not match the bare suffix host")

check(cache.policy_for("other.com") == nil, "unarmed host → nil")
check(cache.policy_for("anything.bad.com") == nil, "unsupported pattern was dropped, never matches")

-- ── label_for: compact, greppable, tiers omitted when off ─────────────────────
check(cache._label_for({ gen = 3,
        static = { on = true, recipe = "static_aggressive", ttl = "7d" },
        micro  = { on = true, recipe = "micro_safe", ttl = "1s" } })
      == "static=static_aggressive/7d micro=micro_safe/1s gen=3", "full label")
check(cache._label_for({ gen = 0, micro = { on = true, recipe = "micro_safe" } })
      == "micro=micro_safe gen=0", "micro-only label, no ttl")
check(cache._label_for({ gen = 2 }) == "gen=2", "no tiers → just gen")

-- ── master gate: SITE_CACHE off → full no-op even with the debug header ───────
_site_cache_on = false
_now = 1000000
_timer_calls = 0
for k in pairs(_header) do _header[k] = nil end
ngx.var.http_x_cfm_cache_debug = "1"
ngx.var.host = "myip.gr"
cache.observe()
check(_header["X-CFM-Cache"] == nil, "SITE_CACHE off → observe stamps nothing even with the debug header")
check(_timer_calls == 0, "SITE_CACHE off → observe schedules no refresh (full no-op)")
_site_cache_on = true    -- restore for the remaining assertions

-- ── observe warms the cache from ALL traffic, not only debug requests ─────────
-- (regression guard: gating the refresh behind the debug header made every
-- debug report reflect the PREVIOUS debug request's state.)
_now = 1000000            -- make a refresh "due"
_timer_calls = 0
ngx.var.http_x_cfm_cache_debug = nil
ngx.var.host = "on.com"
cache.observe()
check(_timer_calls >= 1, "observe schedules a refresh even WITHOUT the debug header (cache stays warm)")

-- ── observe: only stamps when the request carries X-CFM-Cache-Debug ───────────
-- Without the debug header, observe() is a no-op (header-wise) even for an armed
-- vhost (no disclosure to ordinary clients).
for k in pairs(_header) do _header[k] = nil end
ngx.var.host = "myip.gr"
ngx.var.http_x_cfm_cache_debug = nil
cache.observe()
check(_header["X-CFM-Cache"] == nil, "observe stamps nothing without the debug header")

-- With the debug header present: stamps for an armed vhost, nothing for unarmed.
ngx.var.http_x_cfm_cache_debug = "1"
for k in pairs(_header) do _header[k] = nil end
ngx.var.host = "myip.gr"
cache.observe()
check(_header["X-CFM-Cache"] ~= nil and _header["X-CFM-Cache"]:find("static=", 1, true),
      "observe stamps X-CFM-Cache for an armed vhost when the debug header is present")

for k in pairs(_header) do _header[k] = nil end
ngx.var.host = "unarmed.com"
cache.observe()
check(_header["X-CFM-Cache"] == nil, "observe stamps nothing for an unarmed vhost")

-- ── master gate defaults ON when the field is absent (older daemon / no file) ─
-- Kill switch, not opt-in: only an explicit false disarms it.
_site_cache_on = nil     -- {site_cache = nil} → absent field
for k in pairs(_header) do _header[k] = nil end
ngx.var.http_x_cfm_cache_debug = "1"
ngx.var.host = "myip.gr"
cache.observe()
check(_header["X-CFM-Cache"] ~= nil, "absent SITE_CACHE field defaults ON (kill switch, not opt-in)")
_site_cache_on = true

-- ── static_gate: PHASE 3b access-phase hook — the bypass-by-default flip ───────
-- The conf pre-sets $cfm_cache_skip="1" / $cfm_cache_gen="0"; static_gate() flips
-- skip→"0" and stamps the purge generation ONLY for a vhost whose STATIC tier is
-- armed AND while the master switch is on. Every other path leaves the vars
-- untouched — the fail-safe direction is "do not cache".
local function reset_cache_vars()
  ngx.var.cfm_cache_skip = "1"   -- conf default (bypass)
  ngx.var.cfm_cache_gen  = "0"
end

-- armed static vhost → arm cache + carry generation
reset_cache_vars()
ngx.var.host = "myip.gr"
cache.static_gate()
check(ngx.var.cfm_cache_skip == "0", "static_gate arms cache ($cfm_cache_skip=0) for a static-armed vhost")
check(ngx.var.cfm_cache_gen == "3", "static_gate carries the purge generation into $cfm_cache_gen")

-- wildcard static match → same behaviour, its own generation
reset_cache_vars()
ngx.var.host = "assets.cdn.example.com"
cache.static_gate()
check(ngx.var.cfm_cache_skip == "0", "static_gate arms cache for a *.suffix static-armed vhost")
check(ngx.var.cfm_cache_gen == "1", "static_gate stamps the wildcard entry's generation")

-- MICRO-ONLY vhost → static_gate must NOT touch the static cache (skip stays 1)
reset_cache_vars()
ngx.var.host = "www.myip.gr"
cache.static_gate()
check(ngx.var.cfm_cache_skip == "1", "static_gate leaves a micro-ONLY vhost uncached at the static tier (bypass stays)")

-- unarmed host → untouched
reset_cache_vars()
ngx.var.host = "other.com"
cache.static_gate()
check(ngx.var.cfm_cache_skip == "1", "static_gate leaves an unarmed host uncached (bypass stays)")

-- master switch OFF → full no-op even for an armed vhost
_site_cache_on = false
reset_cache_vars()
ngx.var.host = "myip.gr"
cache.static_gate()
check(ngx.var.cfm_cache_skip == "1", "SITE_CACHE off → static_gate is a full no-op (bypass stays)")
_site_cache_on = true

if fails > 0 then
  io.stderr:write(fails .. " failure(s)\n")
  os.exit(1)
end
print("OK cfm_cache_test")

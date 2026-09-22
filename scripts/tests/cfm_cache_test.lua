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

-- ── policy_key_for: stats key by CANONICAL policy, never the raw request host ──
-- (bounds cfm_cache_stats cardinality: an armed *.suffix must not let a client
-- explode the dict with distinct sub-hosts — all fold onto the pattern key.)
check(cache.policy_key_for("MyIP.gr") == "myip.gr", "exact match → the exact host key")
check(cache.policy_key_for("www.myip.gr") == "www.myip.gr", "the www exact entry keys on itself")
check(cache.policy_key_for("assets.cdn.example.com") == "*.cdn.example.com", "wildcard match → the PATTERN key, not the sub-host")
check(cache.policy_key_for("images.cdn.example.com") == "*.cdn.example.com", "a different sub-host folds onto the SAME pattern key")
check(cache.policy_key_for("other.com") == nil, "unarmed host → nil key (uncounted)")
check(cache.policy_key_for("cdn.example.com") == nil, "wildcard bare-suffix does not match → nil")

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

-- ── Tier B micro-cache: TTL-bucket snapping (Phase B1, pure helper) ────────────
-- proxy_cache_valid is per-location + not variablizable, so a stored micro TTL
-- snaps to one of the six declared cfm_micro_<n>s zones. Exact buckets pass
-- through; between-bucket values snap to the nearest; ties snap DOWN (shorter,
-- safer); junk/<=0/absent → the smallest bucket (closest to not caching).
for _, b in ipairs({ 1, 2, 5, 10, 30, 60 }) do
  check(cache._micro_bucket(b) == b, "micro bucket exact " .. b .. "s passes through")
  check(cache._micro_bucket(b .. "s") == b, "micro bucket string \"" .. b .. "s\" parses")
end
check(cache._micro_bucket(3) == 2,  "3s snaps down to 2s (|3-2|<|3-5|)")
check(cache._micro_bucket(4) == 5,  "4s snaps up to 5s (|4-5|<|4-2|)")
check(cache._micro_bucket(8) == 10, "8s snaps to 10s")
check(cache._micro_bucket(45) == 30, "45s snaps down to 30s (tie 30/60 → smaller)")
check(cache._micro_bucket(1000) == 60, "huge TTL clamps to the largest bucket")
check(cache._micro_bucket(0) == 1,  "0 → smallest bucket (no caching-adjacent)")
check(cache._micro_bucket(-5) == 1, "negative → smallest bucket")
check(cache._micro_bucket(nil) == 1, "nil → smallest bucket")
check(cache._micro_bucket("") == 1, "empty string → smallest bucket")
check(cache._micro_bucket("junk") == 1, "unparseable → smallest bucket")
check(cache._micro_bucket("30 s") == 30, "TTL with spaces parses")
check(cache._micro_zone_name(1) == "cfm_micro_1s", "zone name for 1s")
check(cache._micro_zone_name("7s") == "cfm_micro_5s", "zone name snaps 7s → 5s bucket")
check(cache._micro_zone_name(60) == "cfm_micro_60s", "zone name for 60s")

-- ── Tier B micro-cache: cookie verdict (Phase B2, observe-only) ────────────────
-- (anonymous:bool, reason). Non-strict: bypass ONLY on a named app-session
-- cookie; unknown/analytics/cfm_* cookies stay anonymous. Strict: bypass on any
-- cookie not on the ignore-list.
local function anon(c, strict, extra) local a = cache._micro_cookie(c, strict, extra); return a end
local function why(c, strict, extra) local _, r = cache._micro_cookie(c, strict, extra); return r end
check(anon(nil) == true, "no cookie header → anonymous")
check(anon("") == true, "empty cookie header → anonymous")
check(anon("cfm_clearance=abc123") == true, "cfm_clearance only → anonymous (cleared visitor is cacheable)")
check(anon("_ga=GA1.2.3; _fbp=fb.1; _gid=x") == true, "analytics-only cookies → anonymous (non-strict)")
check(anon("PHPSESSID=deadbeef") == false, "PHPSESSID → bypass (app session)")
check(why("phpsessid=x") == "auth:phpsessid", "auth match is case-insensitive")
check(anon("wordpress_logged_in_9a8b=v") == false, "wordpress_logged_in_* prefix → bypass")
check(anon("woocommerce_cart_hash=1; _ga=2") == false, "woocommerce_* prefix → bypass even mixed with analytics")
check(anon("cpsession=1") == false and anon("roundcube_sessauth=1") == false, "cpanel/roundcube sessions → bypass")
check(anon("Horde=abc") == false, "Horde session cookie (exact, case-insensitive) → bypass")
check(anon("horde_secret_key=1") == false, "horde_* prefix → bypass")
-- mainstream non-PHP stacks (over-inclusion is the safe direction)
check(anon("JSESSIONID=0x1") == false, "Java JSESSIONID → bypass")
check(anon("ASP.NET_SessionId=x") == false, "classic ASP.NET session → bypass")
check(anon(".AspNetCore.Session=x") == false, ".AspNetCore.* prefix → bypass")
check(anon("connect.sid=s%3Aabc") == false, "Express connect.sid → bypass")
check(anon("sessionid=django") == false, "Django sessionid → bypass")
check(anon("_myapp_session=rails") == false, "*_session suffix (Rails) → bypass")
check(anon("_ga=1; _gat_gtag_UA_123=1", true) == true, "strict: _gat* analytics is ignore-listed → anonymous")
check(anon("_dc_gtm_UA-1=1", true) == true, "strict: _dc_gtm_* (GTM) is ignore-listed → anonymous")
-- value that itself contains '=' must not fabricate a phantom auth name
check(anon("token=aGVsbG8=d29ybGQ=") == true, "cookie value with '=' does not create a phantom name → anonymous")
check(anon("a=1; PHPSESSID=x; b=2") == false, "auth cookie detected mid-list")
-- strict mode
check(anon("_ga=1", true) == true, "strict: ignore-listed analytics cookie stays anonymous")
check(anon("cfm_clearance=x", true) == true, "strict: cfm_ cookies are ignore-listed → anonymous")
check(anon("randomapp=1", true) == false, "strict: any non-ignored cookie → bypass")
check(why("randomapp=1", true) == "strict:randomapp", "strict bypass names the offending cookie")
check(anon("randomapp=1", false) == true, "non-strict: an unknown cookie stays anonymous")
-- per-vhost extra auth cookie names
check(anon("myapp_sess=1", false, { ["myapp_sess"] = true }) == false, "per-vhost auth_cookies → bypass")

-- ── Tier B micro-cache: full request decision ─────────────────────────────────
local function armed(ttl) return { micro = { on = true, ttl = ttl }, strict_cookies = false } end
local function dec(pol, m, u, c) return cache._micro_decision(pol, m, u, c) end
do
  local ok1, bkt1, r1 = dec(armed("5s"), "GET", "/", nil)
  check(ok1 == true and bkt1 == 5 and r1 == "ok", "armed GET, no cookie → would-cache at 5s bucket")
  local ok2, _, r2 = dec(armed("5s"), "POST", "/", nil)
  check(ok2 == false and r2 == "method", "POST → bypass:method")
  local ok3, _, r3 = dec(armed("5s"), "GET", "/acctxfer/xfer.tar", nil)
  check(ok3 == false and r3 == "path", "/acctxfer* → bypass:path")
  local ok4, _, r4 = dec(armed("5s"), "GET", "/", "PHPSESSID=x")
  check(ok4 == false and r4 == "auth:PHPSESSID", "armed GET with app session → bypass:cookie")
  local ok5, _, r5 = dec({ micro = { on = false } }, "GET", "/", nil)
  check(ok5 == false and r5 == "unarmed", "micro tier off → unarmed")
  local ok6, _, r6 = dec({ static = { on = true } }, "GET", "/", nil)
  check(ok6 == false and r6 == "unarmed", "static-only vhost → micro unarmed")
  local ok7, bkt7 = dec(armed("30s"), "HEAD", "/x", "_ga=1")
  check(ok7 == true and bkt7 == 30, "HEAD + analytics cookie + 30s ttl → would-cache at 30s")
end

check(cache._has_micro() == true, "has_micro true (fixture arms micro on myip.gr / www.myip.gr)")

-- ── observe() surfaces the micro verdict (debug-gated, OBSERVE-ONLY) ───────────
_site_cache_on = true
ngx.var.http_x_cfm_cache_debug = "1"
ngx.var.request_method = "GET"; ngx.var.uri = "/"; ngx.var.http_cookie = nil
for k in pairs(_header) do _header[k] = nil end
ngx.var.host = "myip.gr"
cache.observe()
check(_header["X-CFM-Cache"] and _header["X-CFM-Cache"]:find("microcache=would/1s", 1, true),
      "observe stamps microcache=would/1s for an anonymous request to a micro-armed vhost")
for k in pairs(_header) do _header[k] = nil end
ngx.var.http_cookie = "PHPSESSID=abc"
cache.observe()
check(_header["X-CFM-Cache"] and _header["X-CFM-Cache"]:find("microcache=bypass:auth:PHPSESSID", 1, true),
      "observe stamps microcache=bypass for a request carrying an app session cookie")
for k in pairs(_header) do _header[k] = nil end
ngx.var.host = "assets.cdn.example.com"; ngx.var.http_cookie = nil
cache.observe()
check(_header["X-CFM-Cache"] and not _header["X-CFM-Cache"]:find("microcache=", 1, true),
      "observe omits the microcache token for a static-only vhost")
ngx.var.request_method = nil; ngx.var.uri = nil; ngx.var.http_cookie = nil

if fails > 0 then
  io.stderr:write(fails .. " failure(s)\n")
  os.exit(1)
end
print("OK cfm_cache_test")

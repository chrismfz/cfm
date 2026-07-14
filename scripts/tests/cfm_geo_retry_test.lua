-- Tests for cfm_geo transient-failure retry-with-cooldown (audit F46).
--
-- Previously a single init/open failure on the first lookup set
-- _geo_api_mode = "disabled" permanently for the worker's life: country()
-- returned "" for every later request with no retry, so a worker whose
-- once-per-worker init landed during a MaxMind DB atomic-rename lost geo
-- forever (fail-OPEN for blocklists, fail-CLOSED for allowlists). Fix: keep
-- the mode and retry after GEO_INIT_RETRY_SEC so a later good DB self-heals,
-- while never re-initing after a success (mmap-leak protection intact).

local _now = 1000
_G.ngx = {
  now  = function() return _now end,
  log  = function() end,
  WARN = 1, ERR = 2, INFO = 3,
}

local fails = 0
local function check(cond, msg)
  if cond then return end
  fails = fails + 1
  io.stderr:write("FAIL: " .. msg .. "\n")
end

package.path = "configs/lua/?.lua;" .. package.path

-- Read GEO_INIT_RETRY_SEC out of the source so the cooldown step tracks the
-- real constant rather than a hard-coded copy.
local COOLDOWN
do
  local f = assert(io.open("configs/lua/cfm_geo.lua", "r"))
  local src = f:read("*a"); f:close()
  COOLDOWN = tonumber(src:match("GEO_INIT_RETRY_SEC%s*=%s*(%d+)"))
  assert(COOLDOWN and COOLDOWN > 0, "could not read GEO_INIT_RETRY_SEC from cfm_geo.lua")
end

-- ── Scenario A: init_lookup backend, init fails then recovers ────────────────
local a_init_count, a_fail = 0, true
package.loaded["resty.maxminddb"] = {
  init   = function(_) a_init_count = a_init_count + 1; if a_fail then return nil, "open failed (transient)" end return true end,
  lookup = function(ip) if ip == "0.0.0.0" then return {} end return { country = { iso_code = "US" } } end,
}
package.loaded["cfm_geo"] = nil
local geo = require("cfm_geo")
check(geo.mode() == "init_lookup", "backend detected as init_lookup")

-- First lookup: init fails transiently.
local cc_a1, res_a1 = geo.country("1.2.3.4")
check(cc_a1 == "" and res_a1 == false, "F25 pt2: init failure returns ('', resolved=false) — must not be cached")
check(a_init_count == 1, "first call attempted init once")
check(geo.mode() == "init_lookup", "F46: mode NOT permanently disabled after a transient failure")
check(geo.initialised() == false, "not initialised after failure")

-- Within the cooldown: no re-init (don't re-mmap on every request).
geo.country("1.2.3.4")
check(a_init_count == 1, "F46: within cooldown, init is not re-attempted")

-- Past the cooldown but STILL failing: retries once, fails, re-arms the
-- cooldown. This is the "genuinely broken lib fails fast every window" path.
_now = _now + COOLDOWN + 1
check(geo.country("1.2.3.4") == "", "F46: past cooldown, a still-failing DB retries and returns ''")
check(a_init_count == 2, "F46: past cooldown a still-failing init retries once")
check(geo.mode() == "init_lookup", "F46: a repeated failure still does not permanently disable")
geo.country("1.2.3.4")
check(a_init_count == 2, "F46: the failed retry re-armed the cooldown (no re-attempt within it)")

-- After the next cooldown, DB now healthy: retry succeeds and geo self-heals.
_now = _now + COOLDOWN + 1
a_fail = false
local cc_a2, res_a2 = geo.country("1.2.3.4")
check(cc_a2 == "US" and res_a2 == true, "F25 pt2: a healthy lookup returns (code, resolved=true) — cacheable")
check(a_init_count == 3, "F46: init retried once more after cooldown -> success")
check(geo.initialised() == true, "initialised after successful retry")

-- After success: never re-init (mmap-leak protection preserved).
check(geo.country("5.6.7.8") == "US", "post-success lookup works")

-- A successful lookup with NO country resolves to ("", true): a definitive
-- answer, so it IS cacheable — distinct from a failure's ("", false). This is
-- the exact distinction F25 pt2 relies on to avoid caching transient failures.
local cc_nc, res_nc = geo.country("0.0.0.0")
check(cc_nc == "" and res_nc == true, "F25 pt2: successful lookup with no country → ('', resolved=true)")
_now = _now + COOLDOWN + 1
geo.country("9.9.9.9")
check(a_init_count == 3, "F46: init never called again after a success (no mmap re-map)")

-- ── Scenario B: new_object backend, open fails then recovers ─────────────────
local b_new_count, b_fail = 0, true
local fake_db = { lookup = function(_, _) return { country = { iso_code = "GB" } } end }
package.loaded["resty.maxminddb"] = {
  new = function(_) b_new_count = b_new_count + 1; if b_fail then return nil, "open failed" end return fake_db end,
}
package.loaded["cfm_geo"] = nil
_now = 1000
local geo2 = require("cfm_geo")
check(geo2.mode() == "new_object", "backend detected as new_object")
local cc_b1, res_b1 = geo2.country("1.2.3.4")
check(cc_b1 == "" and res_b1 == false, "new_object: open failure returns ('', resolved=false)")
check(geo2.mode() == "new_object", "F46: new_object mode not permanently disabled")
geo2.country("1.2.3.4")
check(b_new_count == 1, "F46: new_object within cooldown, no re-open")
_now = _now + COOLDOWN + 1
b_fail = false
local cc_b2, res_b2 = geo2.country("1.2.3.4")
check(cc_b2 == "GB" and res_b2 == true, "F46: new_object self-heals after cooldown (resolved=true)")
check(b_new_count == 2, "F46: new_object retried once after cooldown")

if fails > 0 then
  io.stderr:write("\n" .. fails .. " test(s) failed in cfm_geo_retry_test.lua\n")
  os.exit(1)
end
io.stdout:write("ok: cfm_geo transient-failure retry-with-cooldown + self-heal (F46)\n")

-- Tests for the Gravity SMTP unauth sensitive-info exposure detector
-- (rule 10013, WAF_CVE). Production tier: block. CVE-2026-4020.
--
-- The REST route /gravitysmtp/v1/tests/mock-data has permission_callback=true
-- and dumps the full System Report to unauthenticated callers. Keyed on the
-- plugin-unique route in EITHER permalink form (pretty /wp-json/... or plain
-- ?rest_route=/...) + UNAUTH gate: the only legit caller is the plugin's own
-- wp-admin settings screen, which carries the WP logged-in cookie.

_G.ngx = {
  now           = function() return 1000 end,
  decode_base64 = function(_) return nil end,
  log           = function(_, _) end,
  ERR           = 0, WARN = 1, INFO = 2,
}

package.path = "configs/lua/?.lua;" .. package.path
local waf = require("cfm_waf")

local fails = 0
local function check(cond, msg)
  if cond then return end
  fails = fails + 1
  io.stderr:write("FAIL: " .. msg .. "\n")
end

local function set_only(map)
  local snap = waf.get_config()
  for k, _ in pairs(snap) do
    if k:sub(1, 5) == "rule_" then waf.set_rule(k, "disabled") end
  end
  for k, m in pairs(map) do waf.set_rule(k, m) end
end

local function req(method, uri, args, cookie)
  return { uri = uri or "/", args = args or "", method = method or "GET", ip = "203.0.113.72",
           headers = { ["User-Agent"] = "Mozilla/5.0" },
           body = "", cookie = cookie or "" }
end

local function fires(c, label, want_reason)
  local hit, reason = waf.check(c)
  check(hit == true, label .. " — hit=true (got " .. tostring(hit) .. ")")
  check(reason == want_reason, label .. " — reason=" .. want_reason .. " (got " .. tostring(reason) .. ")")
end
local function clean(c, label)
  local hit = waf.check(c)
  check(hit ~= true, label .. " — must NOT fire (got hit=" .. tostring(hit) .. ")")
end

set_only({ rule_cve_gravity_smtp = "block" })

local R = "WAF_CVE:CVE_2026_4020:GRAVITY_SMTP:MOCK_DATA"

-- ── Positives ───────────────────────────────────────────────────────────────
fires(req("GET", "/wp-json/gravitysmtp/v1/tests/mock-data", "page=gravitysmtp-settings", ""),
      "pretty-permalink route, unauth, with the settings-page marker", R)
fires(req("GET", "/wp-json/gravitysmtp/v1/tests/mock-data", "", ""),
      "route alone, unauth (endpoint leaks with or without page=)", R)
fires(req("GET", "/", "rest_route=/gravitysmtp/v1/tests/mock-data", ""),
      "plain-permalink ?rest_route= form (route rides in args)", R)
fires(req("GET", "/", "rest_route=%2fgravitysmtp%2fv1%2ftests%2fmock-data", ""),
      "?rest_route= with url-encoded slashes (normalize defeats the evasion)", R)

-- ── Negatives ───────────────────────────────────────────────────────────────
clean(req("GET", "/wp-json/gravitysmtp/v1/tests/mock-data", "page=gravitysmtp-settings",
          "wordpress_logged_in_abc=deadbeef"),
      "authenticated admin (logged-in cookie) — legit settings-screen call")
clean(req("GET", "/wp-json/gravitysmtp/v1/settings", "", ""),
      "different gravitysmtp REST route (not the mock-data leak)")
clean(req("GET", "/wp-json/wp/v2/posts", "", ""),
      "unrelated REST endpoint")

if fails > 0 then
  io.stderr:write(("cfm_waf Gravity SMTP CVE tests: %d FAILED\n"):format(fails))
  os.exit(1)
end
print("ok: cfm_waf Gravity SMTP sensitive-info exposure (rule 10013, CVE-2026-4020)")

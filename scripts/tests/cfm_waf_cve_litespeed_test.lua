-- Tests for the LiteSpeed Cache (< 6.4) unauth privilege-escalation detector
-- (rule 10004, WAF_CVE; CVE-2024-28000). Production tier: block.
--
-- The plugin's crawler role-simulation validates a weak 6-char hash (~1M values)
-- from the `litespeed_hash` cookie; brute-forcing it -> simulated as admin. The
-- attack sends up to ~1M requests, each carrying a guessed `litespeed_hash`
-- cookie (plus `litespeed_role`). Those cookies are an internal mechanism a real
-- visitor never sets, so presence of the cookie NAME is a near-zero-FP marker.
-- Cookie-based + all-methods (the brute-force is a GET to the REST API).

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

-- Minimal ctx; the detector only reads ctx.cookie (+ method is irrelevant).
local function req(method, uri, cookie)
  return { uri = uri or "/", args = "", method = method or "GET",
           ip = "203.0.113.95", headers = {}, body = "", cookie = cookie or "" }
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

set_only({ rule_cve_litespeed_hash_privesc = "block" })

local HASH = "WAF_CVE:CVE_2024_28000:LITESPEED_CACHE:HASH_COOKIE"
local ROLE = "WAF_CVE:CVE_2024_28000:LITESPEED_CACHE:ROLE_COOKIE"

-- ── Positives ───────────────────────────────────────────────────────────────
fires(req("GET", "/wp-json/wp/v2/users", "litespeed_hash=abcd12"),
      "GET brute-force with litespeed_hash cookie", HASH)
fires(req("GET", "/", "litespeed_role=1"),
      "litespeed_role cookie", ROLE)
fires(req("GET", "/", "wordpress_test_cookie=WP; litespeed_hash=deadbe"),
      "litespeed_hash after another cookie", HASH)
fires(req("POST", "/wp-admin/admin-ajax.php", "litespeed_hash=abcd12"),
      "cookie marker on POST too (all-methods)", HASH)
fires(req("GET", "/", "LiteSpeed_Hash=ABCD12"),
      "case-insensitive cookie name (caller lowercases)", HASH)

-- ── Negatives: legit LiteSpeed + normal traffic must NOT fire ────────────────
clean(req("GET", "/", ""),
      "no cookie")
clean(req("GET", "/", "_lscache_vary=guest; PHPSESSID=x"),
      "legit LiteSpeed _lscache_vary cookie (real visitor)")
clean(req("GET", "/", "wordpress_logged_in_abc=admin%7C123; wp-settings-1=x"),
      "normal WP session cookies")
clean(req("GET", "/", "foo=litespeed_hash=notaname"),
      "litespeed_hash appears only inside another cookie's VALUE (not a name)")

if fails > 0 then
  io.stderr:write(("cfm_waf LiteSpeed CVE tests: %d FAILED\n"):format(fails))
  os.exit(1)
end
print("ok: cfm_waf LiteSpeed Cache privesc (rule 10004, CVE-2024-28000)")

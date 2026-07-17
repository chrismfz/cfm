-- Tests for the Kirki unauth account-takeover detector
-- (rule 10009, WAF_CVE; CVE-2026-8206). Production tier: block.
--
-- Kirki <= 6.0.6 exposes an unauth REST endpoint
--   POST /wp-json/KirkiComponentLibrary/v1/kirki-forgot-password
-- whose handle_forgot_password() accepts a `username` and an `email`
-- independently (no cross-check), so an attacker resets any admin's password to
-- their own email. Keyed on the endpoint + both params (both are required for
-- the exploit; a single-field legit reset is let through).

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

local EP = "/wp-json/KirkiComponentLibrary/v1/kirki-forgot-password"
local function post(uri, body, ct)
  return { uri = uri, args = "", method = "POST", ip = "203.0.113.201",
           headers = { ["Content-Type"] = ct or "application/json" },
           body = body, cookie = "" }
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

set_only({ rule_cve_kirki_forgot_password = "block" })

local HIT = "WAF_CVE:CVE_2026_8206:KIRKI:FORGOT_PASSWORD"

-- ── Positives ───────────────────────────────────────────────────────────────
fires(post(EP, '{"username":"admin","email":"attacker@evil.com","emailBody":"..."}'),
      "PoC: JSON body username+email to the endpoint", HIT)
fires(post(EP, "username=admin&email=attacker%40evil.com"),
      "urlencoded username+email", HIT)

-- ── Negatives ───────────────────────────────────────────────────────────────
clean(post(EP, '{"email":"me@example.com"}'),
      "single-field reset (email only) — legit-shaped, let through")
clean(post(EP, '{"username":"admin"}'),
      "single-field (username only) — let through")
clean(post("/wp-json/wp/v2/users", '{"username":"admin","email":"x@y.com"}'),
      "username+email but NOT the kirki endpoint")
clean({ uri = EP, args = "username=admin&email=x%40y.com", method = "GET",
        headers = {}, body = "", cookie = "" },
      "GET (the reset is a POST)")
clean(post("/wp-login.php?action=lostpassword", "user_login=admin"),
      "native WP lost-password (unrelated endpoint)")

if fails > 0 then
  io.stderr:write(("cfm_waf Kirki CVE tests: %d FAILED\n"):format(fails))
  os.exit(1)
end
print("ok: cfm_waf Kirki unauth account takeover (rule 10009, CVE-2026-8206)")

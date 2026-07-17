-- Tests for the Post SMTP unauth email-log disclosure detector
-- (rule 10007, WAF_CVE; CVE-2025-11833 + CVE-2023-6875). Production tier: block.
--
-- Unauth access to the plugin's REST namespace (/wp-json/post-smtp/ —
-- v1/get-log(s), v1/connect-app) or the postman_email_log admin page exposes
-- logged emails incl. password-reset links -> account takeover. UNAUTH-gated:
-- a logged-in admin (or the plugin's own admin-UI AJAX) carries the WP
-- logged-in cookie and is exempt.

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
  return { uri = uri, args = args or "", method = method or "GET", ip = "203.0.113.98",
           headers = {}, body = "", cookie = cookie or "" }
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

set_only({ rule_cve_post_smtp = "block" })

local REST = "WAF_CVE:CVE_2025_11833:POST_SMTP:REST"
local LOG  = "WAF_CVE:CVE_2025_11833:POST_SMTP:EMAIL_LOG"
local WP_ADMIN_COOKIE = "wordpress_logged_in_deadbeef0000=admin%7C1700000000%7Cabc"

-- ── Positives (unauth) ──────────────────────────────────────────────────────
fires(req("GET", "/wp-json/post-smtp/v1/get-logs", ""),
      "unauth REST get-logs", REST)
fires(req("POST", "/wp-json/post-smtp/v1/connect-app", ""),
      "unauth REST connect-app (POST)", REST)
fires(req("GET", "/wp-admin/admin.php", "page=postman_email_log"),
      "unauth admin email-log page", LOG)

-- ── Negatives ───────────────────────────────────────────────────────────────
clean(req("GET", "/wp-json/post-smtp/v1/get-logs", "", WP_ADMIN_COOKIE),
      "logged-in admin viewing logs (cookie present) — exempt")
clean(req("GET", "/wp-admin/admin.php", "page=postman_email_log", WP_ADMIN_COOKIE),
      "logged-in admin on the log page — exempt")
clean(req("GET", "/wp-json/wp/v2/posts", ""),
      "unauth to a different (legit public) REST namespace")
clean(req("GET", "/wp-json/contact-form-7/v1/contact-forms", ""),
      "unauth to an unrelated plugin REST namespace")
clean(req("GET", "/wp-admin/admin.php", "page=dashboard"),
      "unauth to a non-postman admin page")

if fails > 0 then
  io.stderr:write(("cfm_waf Post SMTP CVE tests: %d FAILED\n"):format(fails))
  os.exit(1)
end
print("ok: cfm_waf Post SMTP unauth email-log disclosure (rule 10007, CVE-2025-11833)")

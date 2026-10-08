-- Tests for the TranslatePress unauthenticated account-takeover detectors
-- (CVE-2026-19632; translatepress-multilingual <= 3.3.1, fixed in 3.3.2):
--
--   rule 10018  rule_cve_translatepress_reset_preview  (WAF_CVE, block, armed)
--     `trp-edit-translation` on a password-reset request: wp-login.php's
--     lostpassword/retrievepassword action, or a POST carrying user_login.
--     force_language_in_preview() then translates the reset mail and automatic
--     string saving stores it, reset key included.
--
--   rule 10019  rule_cve_translatepress_id_lookup      (WAF_CVE, block, autoblock held)
--     action=trp_get_translations_regular with a non-empty string_ids and no
--     WordPress login cookie — the nopriv lookup that reads the stored strings
--     back by id. Only trp-editor.js (logged-in translators) sends string_ids.
--
-- The request shapes follow the titan capture (villadimitramykonos.com,
-- 2026-10-08) and the 3.3.1 sources (trp-editor.js, trp-translate-dom-changes.js).

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

local cfg = waf.get_config()
check(cfg.rule_cve_translatepress_reset_preview == "block",
      "rule_cve_translatepress_reset_preview ships at block (got " .. tostring(cfg.rule_cve_translatepress_reset_preview) .. ")")
check(cfg.rule_cve_translatepress_reset_preview_authed == "block",
      "rule_cve_translatepress_reset_preview_authed ships at block")
check(cfg.rule_cve_translatepress_id_lookup == "block",
      "rule_cve_translatepress_id_lookup ships at block (got " .. tostring(cfg.rule_cve_translatepress_id_lookup) .. ")")

local function set_only(map)
  local snap = waf.get_config()
  for k, _ in pairs(snap) do
    if k:sub(1, 5) == "rule_" then waf.set_rule(k, "disabled") end
  end
  for k, m in pairs(map) do waf.set_rule(k, m) end
end

local UE = "application/x-www-form-urlencoded"
local function get(path, args, cookie)
  return { uri = path, raw_uri = path .. (args ~= "" and ("?" .. args) or ""), args = args,
           method = "GET", ip = "203.0.113.91", headers = {}, body = "", cookie = cookie }
end
local function post(path, args, body, ct, cookie)
  return { uri = path, raw_uri = path .. (args ~= "" and ("?" .. args) or ""), args = args,
           method = "POST", ip = "203.0.113.92", headers = { ["Content-Type"] = ct or UE },
           body = body, cookie = cookie }
end
local function multipart(fields)
  local b = {}
  for _, f in ipairs(fields) do
    b[#b + 1] = "------WebKitFormBoundaryX\r\nContent-Disposition: form-data; name=\"" .. f[1] .. "\"\r\n\r\n" .. f[2] .. "\r\n"
  end
  b[#b + 1] = "------WebKitFormBoundaryX--\r\n"
  return table.concat(b), "multipart/form-data; boundary=----WebKitFormBoundaryX"
end

local function fires(c, label, want, want_id)
  local hit, reason, _, action, _, id = waf.check(c)
  check(hit == true and action == "block", label .. " — blocks (got hit=" .. tostring(hit) .. " action=" .. tostring(action) .. ")")
  check(reason == want, label .. " — reason=" .. want .. " (got " .. tostring(reason) .. ")")
  if want_id then
    check(id == want_id, label .. " — rule id " .. want_id .. " (got " .. tostring(id) .. ")")
  end
end
local function clean(c, label)
  local hit, reason = waf.check(c)
  check(hit ~= true, label .. " — must NOT fire (got " .. tostring(reason) .. ")")
end

-- ═══ Rule 10018 — reset request in translation preview ══════════════════════
set_only({ rule_cve_translatepress_reset_preview = "block", rule_cve_translatepress_reset_preview_authed = "block" })
local LOST = "WAF_CVE:CVE_2026_19632:TRANSLATEPRESS:LOSTPASSWORD"
local FORM = "WAF_CVE:CVE_2026_19632:TRANSLATEPRESS:WC_LOSTPASSWORD"
local LOGIN_COOKIE = "wordpress_logged_in_0123abcd=editor%7C1791%7Cx"

fires(post("/wp-login.php", "action=lostpassword&trp-edit-translation=preview",
           "user_login=admin&redirect_to=&wp-submit=Get+New+Password"),
      "the titan request (POST lostpassword, preview in the query)", LOST, 10018)
fires(post("/wp-login.php", "action=lostpassword&trp-edit-translation=preview",
           "user_login=admin&wp-submit=Get+New+Password", UE, LOGIN_COOKIE),
      "a logged-in translator submitting the form in preview — filed under 10020 (ban held)", LOST, 10020)
-- PHP's variable-name rewriting (php_register_variable_ex): NUL ends the name.
fires(post("/wp-login.php", "action=lostpassword&trp-edit-translation%00x=preview", "user_login=admin"),
      "NUL-cut parameter name", LOST)
fires(post("/wp-login.php", "trp-edit-translation=preview", "action%00x=lostpassword&user_login=admin"),
      "NUL-cut action name", LOST)
fires(get("/wp-login.php", "action=lostpassword&trp-edit-translation=preview"),
      "GET of the lost-password form in preview", LOST)
fires(post("/wp-login.php", "action=retrievepassword&trp-edit-translation=true", "user_login=admin"),
      "retrievepassword alias, editor value", LOST)
fires(post("/wp-login.php", "trp-edit-translation=preview", "action=lostpassword&user_login=admin"),
      "action in the body ($_REQUEST)", LOST)
fires(post("/wp-login.php", "", "trp-edit-translation=preview&action=lostpassword&user_login=admin"),
      "both in the body", LOST)
fires(post("/wp-login.php", "action=lostpassword&trp%2Dedit%2Dtranslation=preview", "user_login=admin"),
      "percent-encoded parameter name", LOST)
fires(post("/wp-login.php", "action=lostpassword&trp-edit-translation", "user_login=admin"),
      "bare parameter without `=` (PHP registers it as an empty string)", LOST)
fires(post("/wp-login.php", "action=lostpassword&trp-edit-translation%5B%5D=preview", "user_login=admin"),
      "array form of the parameter (PHP keys it on the name before the bracket)", LOST)
fires(post("/secret-login/", "action=lostpassword&trp-edit-translation=preview", "user_login=admin"),
      "renamed login URL (WPS Hide Login) — keyed on the parameters, not the path", LOST)
do
  local b, ct = multipart({ { "user_login", "admin" }, { "trp-edit-translation", "preview" } })
  fires(post("/wp-login.php", "action=lostpassword", b, ct), "multipart body", LOST)
end
fires(post("/my-account/lost-password/", "trp-edit-translation=preview",
           "user_login=admin&wc_reset_password=true&woocommerce-lost-password-nonce=abc"),
      "WooCommerce lost-password form in preview", FORM)
fires(post("/my-account/lost-password/", "trp-edit-translation=preview",
           "user.login=admin&wc_reset_password=true"),
      "WooCommerce form with user.login (PHP: user_login)", FORM)

clean(get("/wp-login.php", "action=lostpassword"), "plain lost-password form")
clean(post("/wp-login.php", "action=lostpassword", "user_login=admin&wp-submit=Get+New+Password"),
      "plain reset request")
clean(get("/about/", "trp-edit-translation=preview"), "editor preview of a content page")
clean(get("/", "trp-edit-translation=true"), "translation editor home")
clean(get("/wp-login.php", "action=logout&trp-edit-translation=preview"), "logout in preview (not a reset)")
clean(post("/contact/", "trp-edit-translation=preview", "your-name=A&your-email=a%40b.gr"),
      "a contact form submitted inside the preview")
clean(post("/wp-login.php", "action=register&trp-edit-translation=preview", "user_login=new&user_email=n%40x.gr", UE, LOGIN_COOKIE),
      "core registration form submitted in the editor preview")
clean(post("/my-account/edit-account/", "", "trp-edit-translation=preview&user_login=admin&account_email=a%40b.gr"),
      "a profile form with user_login (not a reset)")
clean(post("/wp-login.php", "action=lostpassword", "user_login=admin&note=trp-edit-translation"),
      "the word as a value, not a parameter")

-- ═══ Rule 10019 — unauthenticated lookup by string id ═══════════════════════
set_only({ rule_cve_translatepress_id_lookup = "block" })
local IDS = "WAF_CVE:CVE_2026_19632:TRANSLATEPRESS:STRING_IDS"
local AJAX = "/wp-admin/admin-ajax.php"

fires(post(AJAX, "", "action=trp_get_translations_regular&security=abc&language=en_US&string_ids=%5B680%2C681%5D"),
      "urlencoded id walk", IDS)
fires(post(AJAX, "action=trp_get_translations_regular", "language=en_US&string_ids=[681]"),
      "action in the query string", IDS)
do
  local b, ct = multipart({ { "action", "trp_get_translations_regular" }, { "all_languages", "true" },
                            { "security", "abc" }, { "language", "en_US" }, { "string_ids", "[1,2,3]" } })
  fires(post(AJAX, "", b, ct), "multipart, the editor's own FormData shape, without a login", IDS)
  clean(post(AJAX, "", b, ct, "wordpress_logged_in_0123abcd=admin%7C1791%7Cx; wp-settings-1=a"),
        "the same request from a logged-in translator")
end
fires(post(AJAX, "", "action=trp_get_translations_regular&string_ids=[5]", UE, "wp-settings-time-1=1791"),
      "other WordPress cookies are not a login", IDS)
-- PHP's variable-name rewriting: `.`/space/unmatched `[` become `_`, NUL ends it.
fires(post(AJAX, "", "action=trp_get_translations_regular&string.ids=%5B680%5D"), "string.ids", IDS)
fires(post(AJAX, "", "action=trp_get_translations_regular&string+ids=%5B680%5D"), "string ids", IDS)
fires(post(AJAX, "", "action=trp_get_translations_regular&string%5Bids=%5B680%5D"), "string[ids", IDS)
fires(post(AJAX, "", "action=trp_get_translations_regular&string_ids%00x=%5B680%5D"), "string_ids NUL-cut", IDS)
fires(post(AJAX, "", "action%00x=trp_get_translations_regular&string_ids=%5B680%5D"), "action NUL-cut", IDS)

clean(post(AJAX, "", "action=trp_get_translations_regular&all_languages=false&security=abc&language=en_US"
           .. "&original_language=el&originals=%5B%22Hello%22%5D&skip_machine_translation=%5B%5D&dynamic_strings=true"),
      "<= 3.3.1 front-end DOM-changes request (originals, no string_ids)")
clean(post(AJAX, "", "action=trp_get_translations_regular&string_ids=%5B%5D"), "empty id list")
clean(post(AJAX, "", "action=trp_get_translations_domchanges&string_ids=[1]"), "3.3.2 front-end action")
clean(post("/wp-content/plugins/translatepress-multilingual/includes/trp-ajax.php", "",
           "action=trp_get_translations_regular&language=en_US&original_language=el&originals=%5B%22Hello%22%5D"),
      "trp-ajax.php fast endpoint (looks up by original only)")
clean(post(AJAX, "", "action=heartbeat&data=string_ids"), "unrelated admin-ajax action")

-- ═══ Both armed, shipped defaults ════════════════════════════════════════════
for k, v in pairs(cfg) do
  if k:sub(1, 5) == "rule_" then waf.set_rule(k, v) end
end
local hit, reason = waf.check(post("/wp-login.php", "action=lostpassword&trp-edit-translation=preview",
                                   "user_login=admin&redirect_to=&wp-submit=Get+New+Password"))
check(hit == true and reason == LOST, "defaults: the titan reset request is attributed to 10018 (got " .. tostring(reason) .. ")")
hit, reason = waf.check(post(AJAX, "", "action=trp_get_translations_regular&security=abc&language=en_US&string_ids=%5B680%5D"))
check(hit == true and reason == IDS, "defaults: the id walk is attributed to 10019 (got " .. tostring(reason) .. ")")

if fails > 0 then
  io.stderr:write(("cfm_waf CVE-2026-19632 tests: %d FAILED\n"):format(fails))
  os.exit(1)
end
print("ok: cfm_waf TranslatePress account takeover (rules 10018/10019, CVE-2026-19632)")

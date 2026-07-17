-- Tests for the Avada / Fusion Builder detector (rule 10008, WAF_CVE).
-- Production tier: block. Two unauth admin-ajax legs:
--
-- Leg A — RCE, CVE-2026-6279 (<=3.15.2): action=fusion_get_widget_markup with a
--   base64 render_logics that decodes to
--   {"type":"wp_conditional_tags","value":{"function":"system","args":"id"}} —
--   the function value reaches call_user_func().
-- Leg B — arbitrary file delete, CVE-2026-8713 (<=3.15.3): action=
--   fusion_form_submit_ajax + privacy_expiration_action (server-only field).

-- render_logics base64 payloads (see the CVE-2026-6279 PoC).
local B64_MALICIOUS = "eyJ0eXBlIjoid3BfY29uZGl0aW9uYWxfdGFncyIsInZhbHVlIjp7ImZ1bmN0aW9uIjoic3lzdGVtIiwiYXJncyI6ImlkIn19"
local B64_LEGIT     = "eyJ0eXBlIjoid3BfY29uZGl0aW9uYWxfdGFncyIsInZhbHVlIjp7ImZ1bmN0aW9uIjoiaXNfZnJvbnRfcGFnZSIsImFyZ3MiOiIifX0="
local DECODE = {
  [B64_MALICIOUS] = '{"type":"wp_conditional_tags","value":{"function":"system","args":"id"}}',
  [B64_LEGIT]     = '{"type":"wp_conditional_tags","value":{"function":"is_front_page","args":""}}',
}

_G.ngx = {
  now           = function() return 1000 end,
  decode_base64 = function(c) return DECODE[c] end,
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

local AJAX = "/wp-admin/admin-ajax.php"
local function post(body)
  return { uri = AJAX, args = "", method = "POST", ip = "203.0.113.99",
           headers = { ["Content-Type"] = "application/x-www-form-urlencoded" },
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

set_only({ rule_cve_fusion_builder = "block" })

local RCE = "WAF_CVE:CVE_2026_6279:FUSION_BUILDER:RCE"
local DEL = "WAF_CVE:CVE_2026_8713:FUSION_BUILDER:FILE_DELETE"

-- ── Leg A — RCE ─────────────────────────────────────────────────────────────
fires(post("action=fusion_get_widget_markup&fusion_load_nonce=abc&render_logics=" ..
           B64_MALICIOUS .. "&widget_type=WP_Widget_Recent_Posts"),
      "RCE: render_logics decodes to function=system", RCE)

-- ── Leg B — file delete ─────────────────────────────────────────────────────
fires(post("action=fusion_form_submit_ajax&formData=x&privacy_expiration_action=delete&file=../../wp-config.php"),
      "FILE_DELETE: privacy_expiration_action present", DEL)

-- ── Negatives ───────────────────────────────────────────────────────────────
clean(post("action=fusion_get_widget_markup&render_logics=" .. B64_LEGIT ..
           "&widget_type=WP_Widget_Recent_Posts"),
      "legit render_logics (function=is_front_page)")
clean(post("action=fusion_form_submit_ajax&formData=name%3DBob%26message%3DHello"),
      "legit Avada form submission (no privacy_expiration_action)")
clean(post("action=fusion_get_widget_markup&widget_type=WP_Widget_Recent_Posts"),
      "fusion_get_widget_markup with no render_logics")
clean(post("action=heartbeat&data=1"),
      "unrelated admin-ajax action")
clean({ uri = AJAX, args = "action=fusion_form_submit_ajax&privacy_expiration_action=delete",
        method = "GET", headers = {}, body = "", cookie = "" },
      "GET (fusion legs are POST body)")

if fails > 0 then
  io.stderr:write(("cfm_waf Fusion Builder CVE tests: %d FAILED\n"):format(fails))
  os.exit(1)
end
print("ok: cfm_waf Avada/Fusion Builder (rule 10008, CVE-2026-6279 + CVE-2026-8713)")

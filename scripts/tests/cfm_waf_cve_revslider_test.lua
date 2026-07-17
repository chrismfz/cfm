-- Tests for the Slider Revolution (revslider) virtual-patch detector
-- (rule 10005, WAF_CVE). Production tier: block. Behavioural (shape-based),
-- protects all versions — not a single-CVE version match.
--
-- Leg A — LFI, CVE-2015-1579 (exploit-db 36554):
--   admin-ajax.php?action=revslider_show_image&img=../wp-config.php
-- Leg B — arbitrary plugin/zip upload -> RCE (Metasploit
--   wp_revslider_upload_execute):
--   POST admin-ajax.php action=revslider_ajax_action&client_action=update_plugin
--   (UNAUTH only — update_plugin is a real admin action).

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

local AJAX = "/wp-admin/admin-ajax.php"

local function get(args)
  return { uri = AJAX, args = args, method = "GET", ip = "203.0.113.96",
           headers = {}, body = "", cookie = "" }
end
local function post(body, ct, cookie)
  return { uri = AJAX, args = "", method = "POST", ip = "203.0.113.96",
           headers = { ["Content-Type"] = ct or "application/x-www-form-urlencoded" },
           body = body, cookie = cookie or "" }
end

-- Multipart upload body carrying the two field values + a zip file part.
local function upload_body(action, client_action)
  return
    "------X\r\n" .. 'Content-Disposition: form-data; name="action"\r\n\r\n' .. action .. "\r\n" ..
    "------X\r\n" .. 'Content-Disposition: form-data; name="client_action"\r\n\r\n' .. client_action .. "\r\n" ..
    "------X\r\n" .. 'Content-Disposition: form-data; name="update_file"; filename="x.zip"\r\n' ..
    "Content-Type: application/zip\r\n\r\nPK\3\4shell.php<?php\r\n" ..
    "------X--\r\n"
end
local MP = "multipart/form-data; boundary=----X"

local function fires(c, label, want_reason)
  local hit, reason = waf.check(c)
  check(hit == true, label .. " — hit=true (got " .. tostring(hit) .. ")")
  check(reason == want_reason, label .. " — reason=" .. want_reason .. " (got " .. tostring(reason) .. ")")
end
local function clean(c, label)
  local hit = waf.check(c)
  check(hit ~= true, label .. " — must NOT fire (got hit=" .. tostring(hit) .. ")")
end

set_only({ rule_cve_revslider = "block" })

local LFI    = "WAF_CVE:CVE_2015_1579:REVSLIDER:LFI"
local UPLOAD = "WAF_CVE:REVSLIDER:PLUGIN_UPLOAD"

-- ── Leg A — LFI ─────────────────────────────────────────────────────────────
fires(get("action=revslider_show_image&img=../../wp-config.php"),
      "LFI: revslider_show_image + ../ traversal", LFI)
fires(get("action=revslider_show_image&img=..%2f..%2fwp-config.php"),
      "LFI: url-encoded traversal", LFI)

-- ── Leg B — plugin/zip upload RCE (unauth) ──────────────────────────────────
fires(post(upload_body("revslider_ajax_action", "update_plugin"), MP),
      "RCE: multipart update_plugin, unauth", UPLOAD)
fires(post("action=revslider_ajax_action&client_action=update_plugin", nil),
      "RCE: urlencoded update_plugin, unauth", UPLOAD)

-- ── Negatives ───────────────────────────────────────────────────────────────
clean(get("action=revslider_show_image&img=slider-1.jpg"),
      "legit revslider_show_image, no traversal")
clean(post("action=revslider_ajax_action&client_action=get_slider_html", nil),
      "legit front-end slider render (get_slider_html)")
clean(post("action=revslider_ajax_action&client_action=update_plugin", nil, "wordpress_logged_in_deadbeef=admin%7C123"),
      "update_plugin by a LOGGED-IN admin (unauth gate excludes)")
clean(get("action=heartbeat&data=1"),
      "unrelated admin-ajax action")
clean(get(""),
      "no query at all")

if fails > 0 then
  io.stderr:write(("cfm_waf revslider CVE tests: %d FAILED\n"):format(fails))
  os.exit(1)
end
print("ok: cfm_waf Slider Revolution virtual-patch (rule 10005, CVE-2015-1579 + upload RCE)")

-- Tests for the unauthenticated PHP object-injection detector (rule 329,
-- WAF_RCE:PHP_OBJECT_INJECTION). Production tier: block (WAF_RCE is armed).
--
-- A PHP serialized OBJECT marker (O:N:"…" / C:N:"…") in an UNAUTHENTICATED
-- request is deserialization -> RCE (kirki/jet-engine/woodmart/…). Legit
-- serialized blobs (WooCommerce/Elementor) ride AUTHENTICATED admin-ajax with
-- the WP logged-in cookie, so the unauth gate keeps FP near-zero. Scans args AND
-- body incl. base64; leaves the authenticated case to rule 306 (challenge).

local B64_OBJECT = "Tzo0OiJFdmlsIjowOnt9"              -- base64 of O:4:"Evil":0:{}
local B64_ARRAY  = "YToxOntpOjA7czoyOiJoaSI7fQ=="      -- base64 of a:1:{...} (array)
local DECODE = {
  [B64_OBJECT] = 'O:4:"Evil":0:{}',
  [B64_ARRAY]  = 'a:1:{i:0;s:2:"hi";}',
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

local WP_COOKIE = "wordpress_logged_in_deadbeef0000=admin%7C1700000000%7Cabc"
local function post(body, cookie)
  return { uri = "/wp-admin/admin-ajax.php", args = "", method = "POST", ip = "203.0.113.210",
           headers = { ["Content-Type"] = "application/x-www-form-urlencoded" },
           body = body, cookie = cookie or "" }
end
local function get(qs, cookie)
  return { uri = "/", args = qs, method = "GET", ip = "203.0.113.210",
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

set_only({ rule_php_object_injection = "block" })

local PLAIN  = "WAF_RCE:PHP_OBJECT_INJECTION:PLAIN"
local BASE64 = "WAF_RCE:PHP_OBJECT_INJECTION:BASE64"

-- ── Positives (unauth) ──────────────────────────────────────────────────────
fires(post('payload=O:8:"Evil_Gadget":1:{s:3:"cmd";s:2:"id";}'),
      "unauth object marker in BODY (rule 306 is args-only)", PLAIN)
fires(get('data=O:4:"Evil":0:{}'),
      "unauth object marker in ARGS", PLAIN)
fires(post('c=C:16:"SplObjectStorage":0:{}'),
      "unauth custom-object (C:) marker", PLAIN)
fires(post("blob=" .. B64_OBJECT),
      "unauth base64'd object (closes 304 logonly gap)", BASE64)

-- ── Negatives ───────────────────────────────────────────────────────────────
clean(post('payload=O:8:"Evil_Gadget":1:{s:3:"cmd";s:2:"id";}', WP_COOKIE),
      "AUTHENTICATED object marker — left to rule 306 (challenge), not this rule")
clean(post('data=a:2:{i:0;s:1:"x";i:1;s:1:"y";}'),
      "serialized ARRAY (a:N:) is common/benign — not matched")
clean(post("blob=" .. B64_ARRAY),
      "base64'd ARRAY — not an object")
clean(post("message=Hello, please email me at o:3 tomorrow"),
      "benign text resembling o:N but no :\" object shape")
clean(get("q=how to unserialize in php"),
      "benign prose")

if fails > 0 then
  io.stderr:write(("cfm_waf PHP object-injection tests: %d FAILED\n"):format(fails))
  os.exit(1)
end
print("ok: cfm_waf unauth PHP object injection (rule 329, WAF_RCE)")

-- Regression: rule 329 (WAF_RCE:PHP_OBJECT_INJECTION) must NOT fire on Akeeba
-- Restore endpoints. FP 2026-07-17 (vioygeia.com): a legit Joomla admin running
-- `option=com_joomlaupdate&task=update.install` was blocked+ban-listed on every
-- extract.php step. Akeeba Restore (which drives Joomla core updates and Akeeba
-- Backup restores) round-trips its engine state as a base64-encoded PHP-serialized
-- object in the `factory` POST field on EVERY step — a genuine O:N:"…" object,
-- indistinguishable by shape from an attack. The detector must exclude these
-- endpoints by context.

-- decode_base64 stub that returns the object marker for the Akeeba factory blob.
local DECODE = {
  -- base64("O:24:\"Akeeba\\Engine\\Factory\":0:{}") -> pretend blob token
  ["TzoyNDoiQWtlZWJhXEVuZ2luZVxGYWN0b3J5IjowOnt9"] = 'O:24:"Akeeba\\Engine\\Factory":0:{}',
  -- a real attack payload token (top-level object) used for the positive control
  ["TzoxMjoiRXZpbENsYXNzWCI6MDp7fQ"] = 'O:12:"EvilClassX":0:{}',
}

_G.ngx = {
  now           = function() return 1000 end,
  decode_base64 = function(c) return DECODE[c] end,
  log           = function(_, _) end,
  ERR = 0, WARN = 1, INFO = 2,
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

-- The Akeeba factory blob rides in a multipart POST body, unauth (no WP cookie).
local FACTORY = "TzoyNDoiQWtlZWJhXEVuZ2luZVxGYWN0b3J5IjowOnt9"
local ATTACK  = "TzoxMjoiRXZpbENsYXNzWCI6MDp7fQ"

local function post(uri, body)
  return { uri = uri, args = "", method = "POST", ip = "203.0.113.9",
           headers = { ["Content-Type"] = "multipart/form-data; boundary=----X" },
           body = 'name="factory"\r\n\r\n' .. body, cookie = "" }
end

local function fires(c, label, want)
  local hit, reason = waf.check(c)
  check(hit == true, label .. " — hit=true (got " .. tostring(hit) .. ")")
  check(reason == want, label .. " — reason=" .. want .. " (got " .. tostring(reason) .. ")")
end
local function clean(c, label)
  local hit = waf.check(c)
  check(hit ~= true, label .. " — must NOT fire (got hit=" .. tostring(hit) .. ")")
end

set_only({ rule_php_object_injection = "block" })

local HIT = "WAF_RCE:PHP_OBJECT_INJECTION:BASE64"

-- ── The FP: legit Joomla update / Akeeba restore endpoints stay clean ────────
clean(post("/administrator/components/com_joomlaupdate/extract.php", FACTORY),
      "Joomla core update: com_joomlaupdate/extract.php factory blob")
clean(post("/administrator/components/com_joomlaupdate/restore.php", FACTORY),
      "Joomla core update: com_joomlaupdate/restore.php factory blob")
clean(post("/administrator/components/com_joomlaupdate/finalisation.php", FACTORY),
      "Joomla core update: com_joomlaupdate/finalisation.php")
clean(post("/administrator/components/com_akeebabackup/restore.php", FACTORY),
      "Akeeba Backup restore: com_akeebabackup/restore.php factory blob")
-- An actual attack object shipped to the SAME excluded endpoint is also not
-- blocked here — that is the accepted trade-off; the endpoint is Joomla core and
-- the generic serialize rule (306) still applies to args.
clean(post("/administrator/components/com_joomlaupdate/extract.php", ATTACK),
      "excluded endpoint accepts the trade-off (no 329 here)")

-- ── Positive control: same base64 object on ANY OTHER endpoint still blocks ───
fires(post("/wp-content/plugins/whatever/ajax.php", ATTACK),
      "object-injection payload on a normal endpoint still fires", HIT)
fires(post("/index.php", FACTORY),
      "factory-shaped object on a non-Akeeba endpoint still fires", HIT)

if fails > 0 then
  io.stderr:write(("cfm_waf object-injection Akeeba FP tests: %d FAILED\n"):format(fails))
  os.exit(1)
end
print("ok: cfm_waf object-injection Akeeba Restore carve-out (rule 329)")

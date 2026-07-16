-- Tests for the Joomla JCE (< 2.9.99.5) unauth PHP-upload -> RCE detector
-- (rule 10002, WAF_CVE; CVE-2026-48907). Production tier: block.
--
-- Exploit (public PoC 0xgh057r3c0n/CVE-2026-48907):
--   POST /index.php?option=com_jce   (multipart/form-data)
--     task = profiles.import                (a multipart FIELD part, not key=value)
--     profile_file = <file>  filename "cve-....xml.php" (double-ext -> .php)
--
-- The detector keys on component (com_jce) + action value (profiles.import) +
-- a php-executable multipart upload filename. Because the PoC sends both files
-- and data, requests encodes EVERYTHING as multipart, so `task` is a field part
-- (name="task"\r\n\r\nprofiles.import) — the detector matches the VALUE
-- substrings, which survive either encoding. Near-zero FP: a legit JCE profile
-- import ships an .xml/.zip profile, never a php file.

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

local JCE_CT = "multipart/form-data; boundary=----X"

-- Realistic multipart body: a `task` field part + a `profile_file` upload part.
local function jce_body(task, filename)
  return
    "------X\r\n" ..
    'Content-Disposition: form-data; name="task"\r\n\r\n' ..
    task .. "\r\n" ..
    "------X\r\n" ..
    'Content-Disposition: form-data; name="profile_file"; filename="' .. filename .. '"\r\n' ..
    "Content-Type: application/xml\r\n\r\n" ..
    '<?xml version="1.0"?><root/>\r\n' ..
    "------X--\r\n"
end

local function ctx(method, uri, args, body, ct)
  return {
    uri = uri, args = args or "", method = method, ip = "203.0.113.92",
    headers = { ["Content-Type"] = ct or "application/x-www-form-urlencoded" },
    body = body or "",
  }
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

set_only({ rule_cve_joomla_jce_profile_import = "block" })

local HIT = "WAF_CVE:CVE_2026_48907:JOOMLA_JCE:PROFILE_IMPORT"

-- ── Positive: the exploit shape ─────────────────────────────────────────────
fires(ctx("POST", "/index.php?option=com_jce", "", jce_body("profiles.import", "cve-2026-48907-4821.xml.php"), JCE_CT),
      "PoC: com_jce + profiles.import + .xml.php upload", HIT)
fires(ctx("POST", "/index.php?option=com_jce", "", jce_body("profiles.import", "x.phtml"), JCE_CT),
      "variant: rename target .phtml", HIT)
fires(ctx("POST", "/index.php?option=com_jce", "", jce_body("profiles.import", "SHELL.PHP"), JCE_CT),
      "variant: uppercase .PHP filename", HIT)
-- option can arrive via the parsed args surface too.
fires(ctx("POST", "/index.php", "option=com_jce", jce_body("profiles.import", "a.xml.php"), JCE_CT),
      "option=com_jce via args surface", HIT)

-- ── Negatives: legit / near-miss must NOT fire ──────────────────────────────
clean(ctx("GET", "/index.php?option=com_jce", "task=profiles.import", "", nil),
      "GET (not the exploit method)")
clean(ctx("POST", "/index.php?option=com_jce", "", jce_body("profiles.import", "profile.xml"), JCE_CT),
      "legit profile import: .xml upload (no php)")
clean(ctx("POST", "/index.php?option=com_jce", "", jce_body("profiles.import", "backup.zip"), JCE_CT),
      "legit profile import: .zip upload (no php)")
clean(ctx("POST", "/index.php?option=com_jce", "", jce_body("editor.save", "note.xml.php"), JCE_CT),
      "com_jce + php upload but NOT profiles.import action")
clean(ctx("POST", "/index.php?option=com_content", "", jce_body("profiles.import", "x.xml.php"), JCE_CT),
      "profiles.import + php upload but NOT com_jce component")
clean(ctx("POST", "/index.php?option=com_jce", "", jce_body("profiles.import", "photo.png"), JCE_CT),
      "com_jce + profiles.import but benign .png upload")

if fails > 0 then
  io.stderr:write(("cfm_waf Joomla JCE CVE tests: %d FAILED\n"):format(fails))
  os.exit(1)
end
print("ok: cfm_waf Joomla JCE profile-import RCE (rule 10002, CVE-2026-48907)")

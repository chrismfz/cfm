-- Tests for the Simple File List (WordPress) unauth upload->rename RCE detector
-- (rule 10001, WAF_CVE; CVE-2025-34085 / CVE-2020-36847). Production tier: block.
--
-- Two vulnerable endpoints under /wp-content/plugins/simple-file-list/:
--   ee-upload-engine.php — upload PHP disguised as .png (exploit body carries <?php)
--   ee-file-engine.php    — rename the uploaded file to .php/.phtml/.php5 = RCE
--
-- Public PoCs use different rename param names (oldFile/newFile vs
-- eeFileOld/eeFileAction/eeListFolder), so the detector keys on endpoint +
-- exec-extension / php-tag marker, not on the volatile param names. These tests
-- assert both PoC shapes fire and that near-miss legitimate traffic does not.

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

local SFL = "/wp-content/plugins/simple-file-list/"

local function post(uri, body, ct)
  return {
    uri = uri, args = "", method = "POST", ip = "203.0.113.90",
    headers = { ["Content-Type"] = ct or "application/x-www-form-urlencoded" },
    body = body,
  }
end
local function get(uri, args)
  return { uri = uri, args = args or "", method = "GET", ip = "203.0.113.91", headers = {}, body = "" }
end

-- A realistic multipart file part (browser-style) with an optional trailing body.
local function multipart(filename, ctype, payload)
  return
    "------WebKitFormBoundaryZ\r\n" ..
    'Content-Disposition: form-data; name="file"; filename="' .. filename .. '"\r\n' ..
    "Content-Type: " .. ctype .. "\r\n\r\n" ..
    payload .. "\r\n------WebKitFormBoundaryZ--\r\n"
end
local MULTIPART_CT = "multipart/form-data; boundary=----WebKitFormBoundaryZ"

local function fires(ctx, label, want_reason)
  local hit, reason = waf.check(ctx)
  check(hit == true, label .. " — hit=true (got " .. tostring(hit) .. ")")
  check(reason == want_reason, label .. " — reason=" .. want_reason .. " (got " .. tostring(reason) .. ")")
end
local function clean(ctx, label)
  local hit = waf.check(ctx)
  check(hit ~= true, label .. " — must NOT fire (got hit=" .. tostring(hit) .. ")")
end

set_only({ rule_cve_simple_file_list_upload = "block" })

local RENAME = "WAF_CVE:CVE_2025_34085:SIMPLE_FILE_LIST:RENAME_TO_PHP"
local UPLOAD = "WAF_CVE:CVE_2025_34085:SIMPLE_FILE_LIST:UPLOAD_PHP"

-- ── Rename leg (the RCE trigger) ─────────────────────────────────────────────
fires(post(SFL .. "ee-file-engine.php", "oldFile=shell_x.png&newFile=shell_x.php"),
      "PoC-2020 rename png->php (oldFile/newFile)", RENAME)
fires(post(SFL .. "ee-file-engine.php", "eeSFL_ID=1&eeListFolder=%2F&eeFileOld=a.png&eeFileAction=a.phtml"),
      "PoC-2025 rename ->phtml (eeFile* params)", RENAME)
fires(post(SFL .. "ee-file-engine.php", "newFile=x.php5"),
      "rename ->php5", RENAME)
fires(post(SFL .. "ee-file-engine.php", "newFile=X.PHP"),
      "rename ->PHP uppercase", RENAME)

-- ── Upload leg (PHP content disguised as image) ──────────────────────────────
fires(post(SFL .. "ee-upload-engine.php", multipart("pwn.png", "image/png", "<?php echo 'x'; ?>"), MULTIPART_CT),
      "upload php-as-png (<?php tag)", UPLOAD)
fires(post(SFL .. "ee-upload-engine.php", multipart("pwn.png", "image/png", "<?= system($_GET[c]) ?>"), MULTIPART_CT),
      "upload short-echo tag", UPLOAD)

-- ── Negatives: legit / near-miss must NOT fire ───────────────────────────────
clean(get(SFL .. "ee-file-engine.php", "newFile=x.php"),
      "GET (not the exploit method)")
clean(post(SFL .. "ee-file-engine.php", "oldFile=photo.png&newFile=photo.jpg"),
      "legit rename png->jpg")
clean(post(SFL .. "ee-file-engine.php", "newFile=report.phpx"),
      "near-miss extension .phpx (not php-executable)")
clean(post("/wp-admin/admin-ajax.php", "action=rename&newFile=x.php"),
      "php ext but NOT the vulnerable endpoint")
clean(post(SFL .. "ee-upload-engine.php", multipart("cat.png", "image/png", "\137PNG\r\n\026\nIDATrealimagebytes"), MULTIPART_CT),
      "legit image upload (no php tag)")

if fails > 0 then
  io.stderr:write(("cfm_waf Simple File List CVE tests: %d FAILED\n"):format(fails))
  os.exit(1)
end
print("ok: cfm_waf Simple File List upload->rename RCE (rule 10001, CVE-2025-34085/CVE-2020-36847)")

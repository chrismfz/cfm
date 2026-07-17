-- Tests for the Ninja Forms "File Uploads" add-on unauth arbitrary-file-upload
-- + path-traversal RCE detector (rule 10003, WAF_CVE; CVE-2026-0740).
-- Production tier: block.
--
-- Exploit (public PoC 0xgh057r3c0n/CVE-2026-0740):
--   POST /wp-admin/admin-ajax.php   (multipart/form-data)
--     action    = nf_fu_upload                 (a multipart FIELD, not key=value)
--     image_jpg = ../../../                     (path-traversal dest path)
--     files-<id> = <file>                        (arbitrary upload; RCE if .php)
--
-- Keyed on the SPECIFIC action nf_fu_upload (a bare admin-ajax.php match is NOT
-- enough — form submissions are common) plus an exploit marker: a php-exec
-- upload filename OR image_jpg traversal.

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
local NF_CT = "multipart/form-data; boundary=----X"

-- Multipart body: `action` + optional `image_jpg` fields + a `files-<id>` upload.
local function nf_body(action, image_jpg, filename)
  local parts = {
    "------X\r\n" ..
    'Content-Disposition: form-data; name="action"\r\n\r\n' .. action .. "\r\n",
  }
  if image_jpg then
    parts[#parts + 1] =
      "------X\r\n" ..
      'Content-Disposition: form-data; name="image_jpg"\r\n\r\n' .. image_jpg .. "\r\n"
  end
  if filename then
    parts[#parts + 1] =
      "------X\r\n" ..
      'Content-Disposition: form-data; name="files-1234"; filename="' .. filename .. '"\r\n' ..
      "Content-Type: application/octet-stream\r\n\r\nBINARYDATA\r\n"
  end
  parts[#parts + 1] = "------X--\r\n"
  return table.concat(parts)
end

local function post(body, ct)
  return {
    uri = AJAX, args = "", method = "POST", ip = "203.0.113.93",
    headers = { ["Content-Type"] = ct or NF_CT }, body = body,
  }
end
local function get(uri, args)
  return { uri = uri, args = args or "", method = "GET", ip = "203.0.113.94", headers = {}, body = "" }
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

set_only({ rule_cve_ninja_forms_fu_upload = "block" })

local UPLOAD = "WAF_CVE:CVE_2026_0740:NINJA_FORMS:UPLOAD_PHP"
local TRAV   = "WAF_CVE:CVE_2026_0740:NINJA_FORMS:TRAVERSAL"

-- ── Positives ───────────────────────────────────────────────────────────────
fires(post(nf_body("nf_fu_upload", "../../../", "shell.php")),
      "PoC: nf_fu_upload + traversal + .php upload", UPLOAD)  -- php filename leg wins (checked first)
fires(post(nf_body("nf_fu_upload", nil, "backdoor.phtml")),
      "nf_fu_upload + .phtml upload (no traversal)", UPLOAD)
fires(post(nf_body("nf_fu_upload", "../../../", "notes.txt")),
      "nf_fu_upload + traversal, non-php file", TRAV)
fires(post(nf_body("nf_fu_upload", "..%2f..%2f", "notes.txt")),
      "nf_fu_upload + url-encoded traversal", TRAV)

-- ── Negatives: bare admin-ajax and legit form uploads must NOT fire ──────────
clean(get(AJAX, "action=nf_fu_get_new_nonce"),
      "GET nonce request (not the exploit method)")
clean(post(nf_body("some_other_action", nil, "shell.php")),
      "php upload but NOT the nf_fu_upload action")
clean(post(nf_body("nf_fu_upload", "photo.jpg", "photo.jpg")),
      "legit nf_fu_upload: image, normal dest, no traversal, no php")
clean(post(nf_body("nf_fu_upload", nil, "resume.pdf")),
      "legit nf_fu_upload: pdf upload, no traversal")
-- Regression: a legit upload of a code/config file whose CONTENT contains ../
-- (e.g. require('../../lib')) with a NORMAL image_jpg must NOT trip TRAVERSAL —
-- the traversal check is scoped to the image_jpg value, not the whole buffer.
clean(post(
        "------X\r\n" ..
        'Content-Disposition: form-data; name="action"\r\n\r\nnf_fu_upload\r\n' ..
        "------X\r\n" ..
        'Content-Disposition: form-data; name="image_jpg"\r\n\r\nphoto.jpg\r\n' ..
        "------X\r\n" ..
        'Content-Disposition: form-data; name="files-1234"; filename="config.js"\r\n' ..
        "Content-Type: application/octet-stream\r\n\r\n" ..
        "var p = require('../../lib/util');\r\n" ..
        "------X--\r\n"),
      "legit code-file upload: ../ in file CONTENT, normal image_jpg")
clean({ uri = AJAX, args = "action=heartbeat", method = "POST",
        headers = { ["Content-Type"] = "application/x-www-form-urlencoded" },
        body = "action=heartbeat&data=1" },
      "unrelated admin-ajax POST (heartbeat)")

if fails > 0 then
  io.stderr:write(("cfm_waf Ninja Forms CVE tests: %d FAILED\n"):format(fails))
  os.exit(1)
end
print("ok: cfm_waf Ninja Forms File Uploads RCE (rule 10003, CVE-2026-0740)")

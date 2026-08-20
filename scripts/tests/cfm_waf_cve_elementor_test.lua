-- Tests for the Elementor Pro Forms unauth arbitrary-file-upload RCE detector
-- (rule 10016, WAF_CVE; CVE-2026-32475). Production tier: block.
--
-- Exploit (Patchstack advisory / write-up):
--   POST /wp-admin/admin-ajax.php   (multipart/form-data)
--     action = elementor_pro_forms_send_form            (nopriv form handler)
--     form_fields[<id>][] = <empty part; filename="">   (UPLOAD_ERR_NO_FILE)
--     form_fields[<id>][] = <file; filename="x.php"; PHP payload>
--   The empty first part makes validation() return before it type-checks the
--   .php part, while process_field() still moves it into the public
--   wp-content/uploads/elementor/forms/ directory.
--
-- Keyed on the SPECIFIC action elementor_pro_forms_send_form (a bare
-- admin-ajax.php match is NOT enough) plus an exploit marker: a php-exec upload
-- filename OR raw php webshell content in the upload bytes.

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
local CT   = "multipart/form-data; boundary=----X"

-- An empty (UPLOAD_ERR_NO_FILE) upload part: filename="" and no bytes.
local EMPTY_PART =
  "------X\r\n" ..
  'Content-Disposition: form-data; name="form_fields[abc123][]"; filename=""\r\n' ..
  "Content-Type: application/octet-stream\r\n\r\n\r\n"

-- Multipart body: `action` field, an optional leading empty part (the CVE
-- decoy), then a `form_fields[<id>][]` file upload with the given filename and
-- content bytes.
local function el_body(action, opts)
  opts = opts or {}
  local parts = {
    "------X\r\n" ..
    'Content-Disposition: form-data; name="action"\r\n\r\n' .. action .. "\r\n",
    "------X\r\n" ..
    'Content-Disposition: form-data; name="post_id"\r\n\r\n17\r\n',
  }
  if opts.empty_first then parts[#parts + 1] = EMPTY_PART end
  if opts.filename then
    parts[#parts + 1] =
      "------X\r\n" ..
      'Content-Disposition: form-data; name="form_fields[abc123][]"; filename="' ..
        opts.filename .. '"\r\n' ..
      "Content-Type: application/octet-stream\r\n\r\n" ..
        (opts.content or "BINARYDATA") .. "\r\n"
  end
  parts[#parts + 1] = "------X--\r\n"
  return table.concat(parts)
end

local function post(body, ct, args)
  return {
    uri = AJAX, args = args or "", method = "POST", ip = "203.0.113.71",
    headers = { ["Content-Type"] = ct or CT }, body = body,
  }
end
local function get(uri, args)
  return { uri = uri, args = args or "", method = "GET", ip = "203.0.113.72", headers = {}, body = "" }
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

set_only({ rule_cve_elementor_pro_form_upload = "block" })

local UPLOAD = "WAF_CVE:CVE_2026_32475:ELEMENTOR_PRO:UPLOAD_PHP"

-- ── Positives ───────────────────────────────────────────────────────────────
-- The canonical CVE shape: empty decoy part then a .php payload part.
fires(post(el_body("elementor_pro_forms_send_form",
                   { empty_first = true, filename = "shell.php", content = "<?php system($_GET['c']); ?>" })),
      "PoC: empty part + .php payload part", UPLOAD)
-- Single .php part (no decoy) — filename leg still fires.
fires(post(el_body("elementor_pro_forms_send_form", { filename = "backdoor.php" })),
      "elementor action + .php upload", UPLOAD)
-- Alt PHP handler extension.
fires(post(el_body("elementor_pro_forms_send_form", { empty_first = true, filename = "x.phtml" })),
      "elementor action + .phtml upload", UPLOAD)
-- MultiPHP numeric handler extension.
fires(post(el_body("elementor_pro_forms_send_form", { filename = "a.php7" })),
      "elementor action + .php7 upload", UPLOAD)
-- action delivered as a query param instead of a body field (admin-ajax reads
-- $_REQUEST['action'], so both are valid).
fires(post(el_body("noop", { filename = "shell.php" }), CT,
           "action=elementor_pro_forms_send_form"),
      "elementor action in query string + .php upload", UPLOAD)

-- ── Negatives: legit Elementor form submissions and near-misses ──────────────
-- The vuln is extension-based: an image-named part carrying php CONTENT is NOT
-- this CVE's shape (the stored name keeps the .jpg extension). This rule stands
-- down for it; raw php content is covered fleet-wide by the armed generic rule
-- 402 (WAF_UPLOAD_CONTENT), disabled here by set_only so this stays clean.
clean(post(el_body("elementor_pro_forms_send_form",
                   { filename = "avatar.jpg", content = "<?php echo shell_exec($_POST['x']); ?>" })),
      "elementor action + php content in image-named part (rule 402's job, not this CVE)")
clean(get(AJAX, "action=elementor_pro_forms_send_form"),
      "GET (not the exploit method / no body)")
clean(post(el_body("some_other_action", { filename = "shell.php" })),
      "php upload but NOT the elementor action")
clean(post(el_body("elementor_pro_forms_send_form", { filename = "resume.pdf" })),
      "legit Elementor form: pdf upload")
clean(post(el_body("elementor_pro_forms_send_form", { empty_first = true, filename = "photo.png",
                                                      content = "\137PNG\r\n\26\n binary image bytes" })),
      "legit Elementor form: empty optional field + png upload")
clean(post(el_body("elementor_pro_forms_send_form", {})),
      "legit Elementor form: no file field at all (text-only submission)")
clean(post(el_body("elementor_pro_forms_send_form", { empty_first = true })),
      "legit Elementor form: empty optional upload field, no payload")
clean({ uri = AJAX, args = "action=heartbeat", method = "POST",
        headers = { ["Content-Type"] = "application/x-www-form-urlencoded" },
        body = "action=heartbeat&data=1" },
      "unrelated admin-ajax POST (heartbeat)")

if fails > 0 then
  io.stderr:write(("cfm_waf Elementor Pro CVE tests: %d FAILED\n"):format(fails))
  os.exit(1)
end
print("ok: cfm_waf Elementor Pro Forms upload RCE (rule 10016, CVE-2026-32475)")

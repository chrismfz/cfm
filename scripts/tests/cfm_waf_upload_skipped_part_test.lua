-- A file part PHP does not read — an empty filename (UPLOAD_ERR_NO_FILE), a
-- name with unbalanced brackets, or a file past max_file_uploads (20 by
-- default) — sends rfc1867's find_boundary on line by line from the end of
-- its headers, so a boundary line right there opens the next part. The
-- PHP-faithful multipart reader (each_multipart_field) used to jump to the
-- next "\n--<boundary>" after every part and so missed that part: a
-- `shell.php` whose name is split over a colon-less continuation line (only
-- the reader joins it; the raw scan cannot see it), right after an empty file
-- part, passed rule 401 and Elementor's 10016. Checked against PHP 8.3.6:
-- PHP stores shell.php in each shape below.

_G.ngx = {
  now           = function() return 1000 end,
  decode_base64 = function(_) return nil end,
  log           = function(_, _) end,
  ERR           = 0, WARN = 1, INFO = 2,
}
package.path = "configs/lua/?.lua;" .. package.path
local waf = require("cfm_waf")
local det = require("cfm_waf_detectors")

local fails = 0
local function check(cond, msg)
  if cond then return end
  fails = fails + 1
  io.stderr:write("FAIL: " .. msg .. "\n")
end

local CT = "multipart/form-data; boundary=XB"
local H = { ["Content-Type"] = CT }
-- The split name: PHP joins a colon-less continuation line to the header.
local SPLIT = '--XB\r\nContent-Disposition: form-data; name="up"; filename="shell.p\r\nhp"\r\n\r\n<?php x ?>\r\n'
local EMPTY = '--XB\r\nContent-Disposition: form-data; name="e"; filename=""\r\n\r\n'
local END = "--XB--\r\n"

local function f401(b) return det.detect_upload_filename(b, H) end

check(f401(SPLIT .. END), "split name alone")
check(f401(EMPTY .. SPLIT .. END), "split name right after an empty file part")
check(f401(EMPTY .. EMPTY .. EMPTY .. SPLIT .. END), "split name after three empty file parts")
check(f401('--XB\r\nContent-Disposition: form-data; name="a[b"; filename="x.txt"\r\n\r\n' .. SPLIT .. END),
      "split name right after a file part PHP refuses (unbalanced brackets)")
do
  local t = {}
  for i = 1, 20 do
    t[#t + 1] = '--XB\r\nContent-Disposition: form-data; name="f' .. i .. '"; filename="a' .. i .. '.txt"\r\n\r\nz\r\n'
  end
  t[#t + 1] = '--XB\r\nContent-Disposition: form-data; name="over"; filename="b.txt"\r\n\r\n'
  check(f401(table.concat(t) .. SPLIT .. END), "split name right after a file past max_file_uploads")
end
-- A kept file's bytes are not parts: a `--XB` line inside them ends the file
-- (PHP reads to the next "\n--XB"), so a clean upload stays clean.
check(not f401('--XB\r\nContent-Disposition: form-data; name="doc"; filename="notes.txt"\r\n\r\n' ..
               'line\r\n--XBnot-a-boundary\r\nX: y\r\n\r\nmore text\r\n' .. END),
      "a boundary-prefix line inside a kept file is not a part")
check(not f401(EMPTY .. '--XB\r\nContent-Disposition: form-data; name="photo"; filename="cat.jpg"\r\n\r\nJPEG\r\n' .. END),
      "an empty file part then a clean image")

-- Through the engine: rule 401 and the Elementor 10016 shape (empty first part).
local function set_only(map)
  for k, _ in pairs(waf.get_config()) do
    if k:sub(1, 5) == "rule_" then waf.set_rule(k, "disabled") end
  end
  for k, m in pairs(map) do waf.set_rule(k, m) end
end
local function post(uri, b, args)
  return { uri = uri, args = args or "", method = "POST", ip = "203.0.113.81", headers = H, body = b }
end
set_only({ rule_upload_filename = "block" })
local hit, reason = waf.check(post("/wp-admin/async-upload.php", EMPTY .. SPLIT .. END))
check(hit == true and tostring(reason):find("WAF_UPLOAD_FNAME", 1, true), "rule 401 via waf.check: " .. tostring(reason))
set_only({ rule_cve_elementor_pro_form_upload = "block" })
hit, reason = waf.check(post("/wp-admin/admin-ajax.php",
  '--XB\r\nContent-Disposition: form-data; name="action"\r\n\r\nelementor_pro_forms_send_form\r\n' ..
  '--XB\r\nContent-Disposition: form-data; name="form_fields[abc][]"; filename=""\r\n\r\n' ..
  '--XB\r\nContent-Disposition: form-data; name="form_fields[abc][]"; filename="shell.p\r\nhp"\r\n\r\n<?php x ?>\r\n' .. END))
check(hit == true and tostring(reason):find("CVE_2026_32475", 1, true), "rule 10016 via waf.check: " .. tostring(reason))

if fails > 0 then
  io.stderr:write(fails .. " failure(s)\n")
  os.exit(1)
end
print("ok: upload filename after a part PHP does not read (rules 401, 10016)")

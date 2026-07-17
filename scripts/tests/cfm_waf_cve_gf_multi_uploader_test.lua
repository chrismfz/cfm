-- Tests for the Multi Uploader for Gravity Forms detector
-- (rule 10010, WAF_CVE; CVE-2025-23921). Production tier: block.
--
-- Unauth arbitrary file upload -> RCE: a multipart POST to gf_page=upload whose
-- gform_unique_id field (a UUID normally) is set to a path-traversal destination
-- ending in .phtml/.php (webshell). The php-exec extension rides in the FIELD
-- VALUE, not the multipart filename=, so rule 401 misses it. Keyed on
-- gf_page=upload + gform_unique_id value with traversal + php-exec ext.

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

local MP = "multipart/form-data; boundary=----X"
-- Multipart body: a gform_unique_id field + a file part.
local function body(unique_id, filename, content)
  return
    "------X\r\n" .. 'Content-Disposition: form-data; name="gform_unique_id"\r\n\r\n' .. unique_id .. "\r\n" ..
    "------X\r\n" .. 'Content-Disposition: form-data; name="file"; filename="' .. (filename or "photo.jpg") .. '"\r\n' ..
    "Content-Type: application/octet-stream\r\n\r\n" .. (content or "BINARY") .. "\r\n" ..
    "------X--\r\n"
end
local function post(uri, args, b)
  return { uri = uri, args = args or "", method = "POST", ip = "203.0.113.220",
           headers = { ["Content-Type"] = MP }, body = b, cookie = "" }
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

set_only({ rule_cve_gf_multi_uploader = "block" })

local HIT = "WAF_CVE:CVE_2025_23921:GF_MULTI_UPLOADER:TRAVERSAL_PHTML"

-- ── Positives ───────────────────────────────────────────────────────────────
fires(post("/", "gf_page=upload", body("../../../wp-content/uploads/shell.phtml", "photo.jpg")),
      "gf_page=upload + gform_unique_id traversal to .phtml", HIT)
fires(post("/?gf_page=upload", "", body("../../../x/evil.php", "img.png")),
      "traversal to .php in gform_unique_id (gf_page in uri)", HIT)

-- ── Negatives ───────────────────────────────────────────────────────────────
clean(post("/", "gf_page=upload", body("6f3a1b2c-1234-4abc-9def-0123456789ab", "photo.jpg")),
      "legit upload: gform_unique_id is a UUID, no traversal/phtml")
clean(post("/", "gf_page=upload", body("../../../notes/readme.txt", "readme.txt")),
      "traversal in gform_unique_id but NOT a php-exec extension")
clean(post("/", "gf_page=upload", body("legit-uuid",
      "config.php")),
      -- a .php in the multipart filename= is rule 401's job; this rule keys on
      -- the gform_unique_id value, which here is a clean UUID -> clean here.
      "php filename= but clean gform_unique_id (this rule stays scoped)")
clean(post("/", "gf_page=upload", body("legit-uuid", "notes.txt",
      "see ../../../etc/shell.phtml in this uploaded log")),
      "traversal + .phtml in FILE CONTENT, not gform_unique_id (no FP)")
clean(post("/", "action=heartbeat", body("../../../x/shell.phtml", "photo.jpg")),
      "traversal+phtml but NOT the gf_page=upload endpoint")

if fails > 0 then
  io.stderr:write(("cfm_waf GF Multi Uploader CVE tests: %d FAILED\n"):format(fails))
  os.exit(1)
end
print("ok: cfm_waf Multi Uploader for Gravity Forms (rule 10010, CVE-2025-23921)")

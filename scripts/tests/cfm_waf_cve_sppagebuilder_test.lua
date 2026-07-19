-- Tests for the SP Page Builder unauth arbitrary-upload detector
-- (rule 10014, WAF_CVE; CVE-2026-48908, the "ANTONKILL" vector). Production tier:
-- block. Joomla com_sppagebuilder asset.upload* (uploadCustomIcon/uploadImage/
-- uploadFont) has no auth check and no file-type restriction, so an anon POST can
-- drop a webshell. Confirmed in the wild dropping payload.zip (php-in-zip). Keyed
-- on component+task + a php-executable payload; near-zero FP (a real icon/image/
-- font upload never carries PHP).

_G.ngx = {
  now           = function() return 1000 end,
  decode_base64 = function(_) return nil end,
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

local MP = "multipart/form-data; boundary=----X"
-- A minimal multipart file part with a chosen filename + body content.
local function upload(filename, content)
  return
    "------X\r\n" ..
    'Content-Disposition: form-data; name="file"; filename="' .. filename .. '"\r\n' ..
    "Content-Type: application/octet-stream\r\n\r\n" ..
    (content or "GIF89a binary") .. "\r\n" ..
    "------X--\r\n"
end
-- A ZIP local-file-header carrying `entry` as its filename (php-in-zip vector).
local function zip_with(entry, payload)
  payload = payload or "PK-content"
  local nlen = #entry
  local hdr = "PK\3\4" .. ("\0"):rep(22) .. string.char(nlen % 256, math.floor(nlen / 256))
             .. ("\0\0") .. entry .. payload
  return
    "------X\r\n" ..
    'Content-Disposition: form-data; name="file"; filename="pack.zip"\r\n' ..
    "Content-Type: application/zip\r\n\r\n" .. hdr .. "\r\n" ..
    "------X--\r\n"
end

local function post(uri, body)
  return { uri = uri, args = "", method = "POST",
           headers = { ["Content-Type"] = MP }, body = body, cookie = "", ip = "203.0.113.7" }
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

set_only({ rule_cve_sppagebuilder_upload = "block" })

local EP = "/index.php?option=com_sppagebuilder&task=asset.uploadCustomIcon"

-- ── Positives ───────────────────────────────────────────────────────────────
fires(post(EP, upload("shell.php", "<?php system($_GET['c']); ?>")),
      "direct php filename upload", "WAF_CVE:CVE_2026_48908:SPPAGEBUILDER:PHP_FILENAME")
fires(post(EP, zip_with("payload.php", "<?php eval($_POST[0]); ?>")),
      "php-in-zip icon-pack (the wild payload.zip vector)", "WAF_CVE:CVE_2026_48908:SPPAGEBUILDER:PHP_IN_ZIP")
-- The EXACT captured 2026-07 drop: an icon-pack zip whose webshell hides as a
-- MULTI-DIGIT MultiPHP handler extension (fonts/kamley.php56), GIF-magic + <?php,
-- deflate-compressed so only the entry NAME is scannable in-path.
fires(post("/index.php?option=com_sppagebuilder&task=asset.uploadCustomIcon",
      zip_with("fonts/kamley.php56", "GIF89a;<?php system($_GET[0]);?>")),
      "php-in-zip with a .php56 (MultiPHP) entry — the captured payload", "WAF_CVE:CVE_2026_48908:SPPAGEBUILDER:PHP_IN_ZIP")
fires(post(EP, upload("icon.gif", "<?php echo shell_exec($_REQUEST['x']); ?>")),
      "php webshell CONTENT under an image filename", "WAF_CVE:CVE_2026_48908:SPPAGEBUILDER:PHP_CONTENT")
-- uploadImage/uploadFont share the same vulnerable task family.
fires(post("/index.php?option=com_sppagebuilder&task=asset.uploadImage", upload("x.phtml", "<?php ?>")),
      "asset.uploadImage + .phtml is the same vector", "WAF_CVE:CVE_2026_48908:SPPAGEBUILDER:PHP_FILENAME")

-- ── Negatives (near-zero FP: legit icon/image/font uploads) ──────────────────
clean(post(EP, upload("logo.svg", "<svg xmlns='http://www.w3.org/2000/svg'><path d='M0 0'/></svg>")),
      "legit custom icon: an SVG with no php")
clean(post(EP, upload("photo.png", "\137PNG\r\n\26\n binary image data")),
      "legit image upload: a PNG")
clean(post(EP, zip_with("icons/menu.svg", "<svg/>")),
      "legit icon-pack zip: only svg entries, no php")
-- Same php payload but NOT the sppagebuilder endpoint -> this rule stays scoped
-- (generic rules 401/414 cover other endpoints).
clean(post("/index.php?option=com_content&task=article.save", upload("shell.php", "<?php ?>")),
      "php upload to a different component is out of scope here")

if fails > 0 then
  io.stderr:write(("cfm_waf SP Page Builder CVE tests: %d FAILED\n"):format(fails))
  os.exit(1)
end
print("ok: cfm_waf SP Page Builder unauth upload (rule 10014, CVE-2026-48908)")

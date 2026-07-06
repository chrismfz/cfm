-- Tests for rule 414 (detect_upload_archive_php): a PHP webshell compressed
-- inside an uploaded .zip. Vector: 2026-07 Joomla mass-defacement (ANTONKILL)
-- via com_sppagebuilder asset.uploadCustomIcon uploading ico*.zip. The existing
-- filename (401) and content (402) rules miss it (outer name is .zip; the <?php
-- bytes are compressed). This rule reads the ZIP directory, where entry names
-- are cleartext, so it is obfuscation-proof. Covers both the local file header
-- (PK\3\4) and the central directory (PK\1\2 — the name ZipArchive extracts).

package.path = "configs/lua/?.lua;" .. package.path
local det = require("cfm_waf_detectors")

det.init({}, {
  has   = function(h, n) return h and n and h:find(n, 1, true) ~= nil end,
  lower = string.lower,
})

local fails = 0
local function check(cond, msg)
  if cond then return end
  fails = fails + 1
  io.stderr:write("FAIL: " .. msg .. "\n")
end

local CT = "multipart/form-data; boundary=X"

-- Minimal ZIP local file header (PK\3\4): 26 fixed bytes, then a 2-byte LE
-- filename length, 2-byte extra length, then the cleartext filename.
local function zip_local(name)
  local n = #name
  return "PK\3\4"
      .. "\20\0" .. "\0\0" .. "\0\0" .. "\0\0" .. "\0\0"       -- ver/flags/method/time/date
      .. "\0\0\0\0" .. "\0\0\0\0" .. "\0\0\0\0"                 -- crc/comp/uncomp
      .. string.char(n % 256, math.floor(n / 256)) .. "\0\0"   -- fnamelen LE + extralen
      .. name .. "XXXXcompresseddataXXXX"
end

-- Central directory header (PK\1\2): 28 fixed bytes, 2-byte LE filename length,
-- then extra/comment/disk/attrs/offset (16 bytes), then filename at offset 46.
local function zip_central(name)
  local n = #name
  return "PK\1\2"
      .. string.rep("\0", 24)                                  -- through uncompsize
      .. string.char(n % 256, math.floor(n / 256))             -- fnamelen LE @28
      .. "\0\0" .. "\0\0" .. "\0\0" .. "\0\0" .. "\0\0\0\0" .. "\0\0\0\0"
      .. name
end

local function body_of(zip)
  return '--X\r\nContent-Disposition: form-data; name="file"; filename="icon.zip"\r\n'
      .. 'Content-Type: application/zip\r\n\r\n' .. zip .. '\r\n--X--\r\n'
end

local function hit_local(name)
  return det.detect_upload_archive_php(body_of(zip_local(name)), { ["content-type"] = CT })
end
local function hit_central(name)
  return det.detect_upload_archive_php(body_of(zip_central(name)), { ["content-type"] = CT })
end

-- Positives — PHP-executable / handler-override entries hidden in the zip.
check(hit_local("shell.php"),          "php entry must be flagged")
check(hit_local("wp/x.php5"),          ".php5 entry must be flagged")
check(hit_local("a/b/cmd.phtml"),      ".phtml entry must be flagged")
check(hit_local("evil.pht"),           ".pht entry must be flagged")
check(hit_local("x.phar"),             ".phar entry must be flagged")
check(hit_local("evil.php.png"),       "double-extension .php.png must be flagged")
check(hit_local(".htaccess"),          ".htaccess entry must be flagged")
check(hit_local("assets/.user.ini"),   ".user.ini entry must be flagged")

-- Central-directory name is what PHP's ZipArchive extracts: a benign local name
-- with a malicious central name must still be caught.
check(hit_central("innocent/../shell.php"), "central-dir php name must be flagged")

-- Negatives — a real custom-icon / font / media zip must NOT trip.
check(not hit_local("icon.svg"),            "svg entry must NOT be flagged")
check(not hit_local("fonts/icomoon.woff2"), "woff2 entry must NOT be flagged")
check(not hit_local("images/logo.png"),     "png entry must NOT be flagged")
check(not hit_local("readme.txt"),          "txt entry must NOT be flagged")
check(not hit_local("style.css"),           "css entry must NOT be flagged")
check(not hit_local("app.phpstorm"),        ".phpstorm must NOT overmatch as .php")

-- Non-zip multipart (no PK header) must be a no-op.
local png = '--X\r\nContent-Disposition: form-data; name="f"; filename="a.png"\r\n\r\n'
        .. '\137PNG\r\n\26\n binary junk \r\n--X--\r\n'
check(not det.detect_upload_archive_php(png, { ["content-type"] = CT }), "non-zip upload must be a no-op")

-- Non-multipart must be a no-op.
check(not det.detect_upload_archive_php(zip_local("shell.php"), { ["content-type"] = "application/json" }),
  "non-multipart must be a no-op")

if fails > 0 then
  io.stderr:write(("cfm_waf_upload_archive_test.lua: %d FAILED\n"):format(fails))
  os.exit(1)
end
print("ok: cfm_waf upload-archive (php-in-zip) tests (rule 414)")

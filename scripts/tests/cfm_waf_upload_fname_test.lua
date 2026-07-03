-- Tests for rule 401 (WAF_UPLOAD_FNAME) dangerous-extension matching in
-- detect_upload_filename. Focus: the .pht/.phtm/.shtml/.shtm alt-handler
-- extensions added 2026-07 (they previously slipped past the .php[%d] matcher
-- and reached origin), plus regression coverage that benign uploads — and the
-- deliberately-excluded .phps source-viewer extension — do NOT trip this
-- block-tier rule.

package.path = "configs/lua/?.lua;" .. package.path
local det = require("cfm_waf_detectors")

-- detect_upload_filename only needs `lower` and `has` from the util table.
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

local function upload_body(fname)
  return '--X\r\nContent-Disposition: form-data; name="file"; filename="'
      .. fname .. '"\r\nContent-Type: application/octet-stream\r\n\r\n'
      .. 'data\r\n--X--\r\n'
end

local function hit(fname)
  return det.detect_upload_filename(upload_body(fname), { ["content-type"] = CT })
end

-- Positives: newly-covered PHP alt-handlers + SSI pages.
check(hit("shell.pht"),    ".pht must be flagged")
check(hit("shell.phtm"),   ".phtm must be flagged")
check(hit("shell.phtml"),  ".phtml must be flagged")
check(hit("evil.pht.jpg"), ".pht double-extension must be flagged")

-- Positives: pre-existing coverage must still fire.
check(hit("c99.php"),  ".php must be flagged")
check(hit("c99.php5"), ".php5 must be flagged")
check(hit("x.phar"),   ".phar must be flagged")

-- Negatives: benign uploads pass, and .phps (source viewer, lower execution
-- risk) is deliberately kept OUT of the block-tier set to limit FP surface.
check(not hit("photo.jpg"),   ".jpg must pass")
check(not hit("archive.zip"), ".zip must pass")
check(not hit("notes.txt"),   ".txt must pass")
check(not hit("readme.phps"), ".phps is deliberately excluded (source viewer)")
-- SSI pages are a legit static file type on cPanel and are deliberately NOT
-- blocked (see bad_fname note) — blocking would FP + autoblock a customer's IP.
check(not hit("home.shtml"),  ".shtml is legit static SSI — must pass")
check(not hit("frag.shtm"),   ".shtm is legit static SSI — must pass")
-- The 'pht' substring mid-word (no preceding literal dot) must NOT match:
-- the matcher requires '%.pht' (dot + pht), so these benign names pass.
check(not hit("graphite.zip"), "'graphite' must not false-match .pht")
check(not hit("alphtest.doc"), "'alphtest' must not false-match .pht")
check(not hit("naphtha.txt"),  "'naphtha' must not false-match .pht")
check(not hit("report.phtx"),  ".phtx is not a handler and must pass")

if fails > 0 then
  io.stderr:write(("cfm_waf upload-fname tests: %d failure(s)\n"):format(fails))
  os.exit(1)
end
print("ok: cfm_waf upload-fname extension tests (rule 401: .pht/.phtm block; .shtml/.shtm allowed)")

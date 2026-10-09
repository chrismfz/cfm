-- Tests for rule 401 (WAF_UPLOAD_FNAME) dangerous-extension matching in
-- detect_upload_filename. Focus: the .pht/.phtm PHP alt-handlers added 2026-07
-- (they previously slipped past the .php[%d] matcher and reached origin), plus
-- regression coverage that benign uploads — the deliberately-excluded .phps
-- source-viewer extension, the legit SSI static types .shtml/.shtm, and the
-- .phtm-overmatch guard (x.phtmz) — do NOT trip this block-tier rule.

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

-- Flexible builder: pass a raw Content-Disposition parameter tail so tests can
-- exercise the parameter-name casing and the RFC 5987 `filename*=` form.
local function hit_cd(cd_tail)
  local body = '--X\r\nContent-Disposition: form-data; ' .. cd_tail
      .. '\r\nContent-Type: application/octet-stream\r\n\r\ndata\r\n--X--\r\n'
  return det.detect_upload_filename(body, { ["content-type"] = CT })
end

-- Positives: newly-covered PHP alt-handlers + SSI pages.
check(hit("shell.pht"),    ".pht must be flagged")
check(hit("shell.phtm"),   ".phtm must be flagged")
check(hit("shell.phtml"),  ".phtml must be flagged")
check(hit("evil.pht.jpg"), ".pht double-extension must be flagged")

-- Positives: pre-existing coverage must still fire.
check(hit("c99.php"),  ".php must be flagged")
check(hit("c99.php5"), ".php5 must be flagged")
check(hit("c99.php56"), ".php56 multi-digit MultiPHP handler must be flagged")
check(hit("c99.php74.jpg"), ".php74 double-extension must be flagged")
check(hit("x.phar"),   ".phar must be flagged")

-- Positives: the server-side-handler extensions must still fire when they are a
-- real trailing extension OR a double-extension (Apache/IIS/LiteSpeed can map
-- `shell.asp.jpg` to the engine), now that they are anchored like .php.
check(hit("shell.phar"),      ".phar (final) must be flagged")
check(hit("shell.phar.jpg"),  ".phar double-extension must be flagged")
check(hit("webshell.asp"),    ".asp must be flagged")
check(hit("webshell.aspx"),   ".aspx must be flagged")
check(hit("x.asp.png"),       ".asp double-extension must be flagged")
check(hit("global.asax"),     ".asax must be flagged")
check(hit("shell.jsp"),       ".jsp must be flagged")
check(hit("shell.jspx"),      ".jspx must be flagged")
check(hit("x.jsp.gif"),       ".jsp double-extension must be flagged")
check(hit("svc.asmx"),        ".asmx must be flagged")
check(hit("ctl.ascx"),        ".ascx must be flagged")
check(hit("shell.cer"),       ".cer must be flagged")
check(hit("x.cer.jpg"),       ".cer double-extension must be flagged")
check(hit("data.cdx"),        ".cdx must be flagged")

-- Negatives: benign names that merely CONTAIN a handler extension as a mid-word
-- substring must NOT trip rule 401 (block + 6h autoblock ban). These are the
-- unanchored-match FPs this change fixes.
check(not hit("company.pharma.pdf"),   "'pharma' must not false-match .phar")
check(not hit("trip.aspen.jpg"),       "'aspen' must not false-match .asp")
check(not hit("team.asana.csv"),       "'asana' must not false-match .asa")
check(not hit("vendor.jspdf.min.js"),  "'jspdf' must not false-match .jsp")
check(not hit("vase.ceramic.jpg"),     "'ceramic' must not false-match .cer")
check(not hit("my.cert.pem"),          ".cert (certificate) must not match .cer")
check(not hit("aspect-ratio.png"),     "'aspect' must not false-match .asp")
check(not hit("jasper-report.pdf"),    "'jasper' has no dot before jsp — must pass")

-- Evasion robustness: the `[^%w]` boundary catches a dangerous extension
-- followed by any non-word char the OS/handler strips or ignores — trailing
-- space/dot, Windows ADS (`::$DATA`), an embedded NUL, a tab — and lower()
-- handles case. None of these should slip past rule 401.
check(hit("shell.asp "),        "trailing space after .asp must be flagged")
check(hit("shell.asp."),        "trailing dot after .asp must be flagged")
check(hit("shell.asp::$DATA"),  "Windows ADS ::$DATA after .asp must be flagged")
check(hit("SHELL.ASP"),         "uppercase .ASP must be flagged (lowercased)")
check(hit("shell.asp\0.jpg"),   "embedded NUL after .asp must be flagged")
check(hit("shell.phar\t"),      "trailing tab after .phar must be flagged")

-- Filename EXTRACTION robustness: the Content-Disposition parameter name is
-- case-insensitive (PHP rfc1867 strcasecmp), so a capitalised `FileName`/
-- `FILENAME` must not skip extraction and let a webshell through.
check(hit_cd('name="f"; FileName="shell.php"'),  "capital-N FileName must be extracted + flagged")
check(hit_cd('name="f"; FILENAME="shell.php"'),  "all-caps FILENAME must be extracted + flagged")
check(hit_cd('name="f"; fileName="c99.phtml"'),  "mixed-case fileName must be extracted + flagged")
-- RFC 5987 / 6266 extended parameter `filename*=charset'lang'pct-value`
-- (honoured by ASP.NET/IIS) must be extracted, percent-decoded, and checked.
check(hit_cd("name=\"f\"; filename*=UTF-8''shell.aspx"),       "filename*= (.aspx) must be flagged")
check(hit_cd("name=\"f\"; filename*=UTF-8''shell%2Easpx"),     "filename*= with %2E-encoded dot must be flagged")
check(hit_cd("name=\"f\"; filename*=utf-8''webshell%2Ephar"),  "filename*= (.phar, pct-encoded) must be flagged")
check(hit_cd("name=\"f\"; filename*=shell.jsp"),               "filename*= without charset prefix must be flagged")
-- PHP's rfc1867 (php_ap_getword_conf) honours a `\"` escaped quote and an
-- UNTERMINATED opening quote, so these deliver a real `.php`/handler file that
-- the precise quote patterns under-read; the end-of-line backstop must catch
-- them.
check(hit_cd('name="f"; filename="shell\\".php"'),  "escaped-quote filename must be flagged")
check(hit_cd('name="f"; filename="shell.php'),      "unterminated double-quote filename must be flagged")
check(hit_cd("name=\"f\"; filename='shell.php"),    "unterminated single-quote filename must be flagged")
check(hit_cd('name="f"; filename=shell.pht.jpg'),   "unquoted double-extension must be flagged")

-- Extraction FPs: a field literally named "filename", a benign RFC 5987 upload,
-- and benign names that the greedy end-of-line backstop must NOT over-match.
check(not hit_cd('name="filename"'),                           "a field NAMED filename (no ext value) must pass")
check(not hit_cd("name=\"f\"; filename*=UTF-8''holiday%20photo.jpg"), "benign filename*= (.jpg) must pass")
check(not hit_cd('name="f"; filename="company.pharma.pdf"'),   "backstop must not over-match 'pharma' as .phar")
check(not hit_cd('name="f"; filename="vendor.jspdf.min.js"'),  "backstop must not over-match 'jspdf' as .jsp")

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
check(not hit("x.phtmz"),      ".phtm matcher must be anchored — x.phtmz must pass")
check(not hit("bibliophtml.doc"), "'phtml' mid-word (no dot) must pass")

if fails > 0 then
  io.stderr:write(("cfm_waf upload-fname tests: %d failure(s)\n"):format(fails))
  os.exit(1)
end
print("ok: cfm_waf upload-fname extension tests (rule 401: .pht/.phtm block; .shtml/.shtm allowed)")

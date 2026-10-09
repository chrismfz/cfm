-- Upload-family gaps (edge Lua sweep 2026-10-09, PR 5). Each let a webshell
-- upload through an armed block rule:
--   * 401 read `filename=` one line at a time, but PHP's multipart reader
--     appends a header line with no `:` to the line before it:
--     `filename="shell.p` CRLF `hp"` and `file` CRLF `name="shell.php"` both
--     register shell.php (checked against php -S). 401 now also checks every
--     filename PHP registers (each_multipart_field, the oracle-checked reader).
--   * 414 stopped after 512 `PK\3\4` headers: 512 decoys in a field before the
--     real zip hid its entries (the ANTONKILL SP Page Builder vector).
--   * 402's short-echo matcher missed `<?=\f(`, `<?=/**/f(`, `<?=#x` LF `f(`,
--     `<?=print`…``, `<?= new X(`, and the `<? echo` short open tag.
--   * 402 reads the body's first 2 KB only: a webshell after 2 KB of image
--     data went unseen. New rule 415 reads the uploaded files to the multipart
--     budget for the openers, logonly (burn-in).

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

local UA = "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 " ..
           "(KHTML, like Gecko) Chrome/131.0.0.0 Safari/537.36"
local MP = "multipart/form-data; boundary=XB"
local H = { ["content-type"] = MP }
local function part(cd, content, ctype)
  return "--XB\r\nContent-Disposition: form-data; " .. cd .. "\r\n" ..
         (ctype and ("Content-Type: " .. ctype .. "\r\n") or "") .. "\r\n" .. content .. "\r\n"
end
local function body(...) return table.concat({ ... }) .. "--XB--\r\n" end
local function run(b, t)
  t = t or {}
  local hit, reason, _, action, hits = waf.check({
    uri = t.uri or "/upload.php", args = t.args or "", method = "POST", ip = "203.0.113.9", body = b,
    headers = { ["content-type"] = MP, ["user-agent"] = UA, accept = "text/html" },
  })
  local ids = {}
  for _, h in ipairs(hits or {}) do ids[#ids + 1] = tostring(h.waf_rule_id) .. "=" .. tostring(h.action) end
  return { hit = hit, reason = tostring(reason), action = action, ids = "," .. table.concat(ids, ",") .. "," }
end
local function show(r) return r.reason .. "/" .. tostring(r.action) .. " " .. r.ids end

-- ── 401: filenames as PHP reads them ───────────────────────────────────────
do
  for _, cd in ipairs({
    'name="f"; filename="shell.p\r\nhp"',          -- continuation without whitespace: shell.php
    'name="f"; file\r\nname="shell.php"',           -- a split parameter name
  }) do
    local r = run(body(part(cd, "GIF89a", "image/gif")))
    check(r.ids:find(",401=block,", 1, true), "401 reads the folded filename (" .. cd:gsub("\r\n", "<CRLF>") .. "): " .. show(r))
  end
  -- A continuation with leading whitespace keeps it: PHP registers `shell.p hp`.
  local r = run(body(part('name="f"; filename="shell.p\r\n hp"', "GIF89a", "image/gif")))
  check(not r.ids:find(",401=", 1, true), "`shell.p hp` is not a php file: " .. show(r))
  r = run(body(part('name="f"; filename="photo.jpg"', "GIF89a", "image/gif")))
  check(not r.hit, "a plain photo upload stays clean: " .. show(r))
end

-- ── 414: every zip header is read ──────────────────────────────────────────
do
  local function le16(n) return string.char(n % 256, math.floor(n / 256)) end
  local function zip_entry(name)  -- a local file header + its name (no data needed)
    return "PK\3\4" .. ("\0"):rep(22) .. le16(#name) .. le16(0) .. name
  end
  local zip = zip_entry("icons/a.svg") .. zip_entry("fonts/kamley.php56")
  for _, n in ipairs({ 0, 600 }) do
    local b = body(part('name="pad"', ("PK\3\4"):rep(n)), part('name="file"; filename="icons.zip"', zip, "application/zip"))
    check(det.detect_upload_archive_php(b, H) ~= nil, n .. " decoy headers before the zip: the php entry is still found")
    local r = run(b, { uri = "/index.php", args = "option=com_sppagebuilder&task=asset.uploadCustomIcon" })
    -- 10014 (the SP Page Builder CVE rule) reads the same zip scanner and runs first.
    check(r.action == "block" and (r.ids:find(",414=block,", 1, true) or r.ids:find(",10014=block,", 1, true)),
          n .. " decoys: the SP Page Builder zip is blocked: " .. show(r))
  end
end

-- ── 402: short-echo variants ───────────────────────────────────────────────
do
  for _, php in ipairs({
    '<?=\\strtoupper("ok1")?>', '<?=/**/strtoupper("ok2")?>', '<? echo strtoupper("ok3");?>',
    '<?=#x\nstrtoupper("ok4")?>', '<?=print`echo ok5`?>', '<?=\tnew ArrayObject([1])?>',
    '<?=system/**/("id")?>', '<?=@$_GET[0]?>',
    "<?=!system('id')?>", "<?=-system('id')?>", "<?=~system('id')?>", "<?=0?system('id'):1?>",
    "<?=system//x\n('id')?>", "<?=system#x\n('id')?>",
  }) do
    local r = run(body(part('name="f"; filename="x.jpg"', php, "image/jpeg")))
    check(r.ids:find(",402=block,", 1, true), "402 catches " .. php:gsub("\n", "<LF>") .. ": " .. show(r))
  end
  -- Binary-safe: a stray `<?=` / `<?` in non-PHP content.
  -- \v and \f are not PHP whitespace after an opener (the tokenizer reads
  -- space, tab, CR, LF only).
  for _, s in ipairs({ "<?xml version=\"1.0\"?>", "a<?=b", "x <? y", "<?=9", "data<?\0=",
                       "<?\v$x", "<?=\f$x", "<?\fecho $x" }) do
    local r = run(body(part('name="f"; filename="x.svg"', s, "image/svg+xml")))
    check(not r.ids:find(",402=", 1, true), "no 402 on " .. s:gsub("%z", "\\0") .. ": " .. show(r))
  end
end

-- ── 415: the openers in uploaded files past 402's 2 KB ────────────────────
do
  local img = "\255\216\255\224" .. ("\1\2\3\4\5\6\7\8"):rep(400)   -- ~3.2 KB of "JPEG"
  local r = run(body(part('name="f"; filename="photo.jpg"', img .. "<?php system($_GET['c']); ?>", "image/jpeg")))
  check(r.ids:find(",415=logonly,", 1, true) and r.reason:find("UPLOAD_PHP_TAG_DEEP", 1, true),
        "a webshell after 3 KB of image data → 415 logonly: " .. show(r))
  check(not r.ids:find(",402=", 1, true), "…which 402 (2 KB) does not see: " .. show(r))
  r = run(body(part('name="a"', ("x"):rep(3000)), part('name="f"; filename="b.png"', "<?=`id`?>", "image/png")))
  check(r.ids:find(",415=logonly,", 1, true), "a second file past 2 KB → 415: " .. show(r))
  -- Text FIELDS (no filename) and superglobal words are not 415's.
  r = run(body(part('name="msg"', ("x"):rep(3000) .. " <?php echo 1; ?> $_POST is empty")))
  check(not r.ids:find(",415=", 1, true), "a text field quoting PHP past 2 KB: not 415: " .. show(r))
  r = run(body(part('name="f"; filename="notes.txt"', ("y"):rep(3000) .. " $_POST and $_GET are empty", "text/plain")))
  check(not r.ids:find(",415=", 1, true), "superglobal words in a file past 2 KB: not 415: " .. show(r))
  r = run(body(part('name="f"; filename="photo.jpg"', img, "image/jpeg")))
  check(not r.hit, "a clean 3 KB image stays clean: " .. show(r))
  -- An opener inside 402's 2 KB with its code padded past the edge: 402 sees
  -- `<?=` and blanks, so 415 reads the part from its start.
  r = run(body(part('name="f"; filename="a.gif"',
    "GIF89a" .. ("\1"):rep(1850) .. "<?=" .. (" "):rep(300) .. "system($_GET[0]);?>", "image/gif")))
  check(r.ids:find(",415=logonly,", 1, true), "an opener straddling 402's edge → 415: " .. show(r))
end

-- ── Cost: the short-echo parser stays linear on runs of openers ─────────────
do
  local src = io.open("configs/lua/cfm_waf_detectors.lua"):read("*a")
  local fsrc = src:match("(local SHORT_ECHO_WORDS.-\nlocal function has_php_short_echo%(s%).-\nend\n)")
  check(fsrc ~= nil, "has_php_short_echo found")
  if fsrc then
    local se = assert(loadstring(fsrc .. "\nreturn has_php_short_echo"))()
    for _, s in ipairs({ ("<?=/*"):rep(13000), ("<?=#"):rep(16000), ("<? "):rep(20000), ("<?=system"):rep(7000) }) do
      local t0 = os.clock(); se(s)
      local ms = (os.clock() - t0) * 1000
      check(ms < 250, ("short-echo parser on 64 KB of %q… took %.1f ms"):format(s:sub(1, 8), ms))
    end
  end
end

if fails > 0 then
  io.stderr:write(("cfm_waf upload-hardening tests: %d FAILED\n"):format(fails))
  os.exit(1)
end
print("ok: cfm_waf upload hardening (401 folding, 414 decoys, 402 short echo, 415 deep)")

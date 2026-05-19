-- Tests for the WAF_BACKDOOR detector family (rules 430-433, Tier 1).
-- Source workload: captured 2026-05-19 PHP webshell deployed as
-- /home/<user>/public_html/wp-content/themes/bridge/includes/radio.php —
-- char-pool obfuscator output with %PDF- polyglot prefix and a 5KB
-- gzdeflate'd-then-base64'd payload eval'd via variable-fed call chain.

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

local function disable_all_rules()
  local snap = waf.get_config()
  for k, _ in pairs(snap) do
    if k:sub(1, 5) == "rule_" then
      waf.set_rule(k, "disabled")
    end
  end
end

local function ctx(body, ct)
  return {
    uri     = "/wp-admin/theme-editor.php",
    args    = "",
    method  = "POST",
    ip      = "203.0.113.7",
    headers = { ["Content-Type"] = ct or "application/x-www-form-urlencoded" },
    body    = body,
  }
end

-- A long base64-shaped string for the eval-loader test — 256 chars of
-- alphanumerics with a few '+' / '/' so it parses as base64.
local function long_b64(n)
  n = n or 256
  local alphabet = "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/"
  local out = {}
  for i = 1, n do
    local idx = ((i * 7 + 3) % #alphabet) + 1
    out[i] = alphabet:sub(idx, idx)
  end
  return table.concat(out)
end

-- ─────────────────────────────────────────────────────────────────────────────
-- 430 — .htaccess / .user.ini poisoning
-- ─────────────────────────────────────────────────────────────────────────────

do
  disable_all_rules()
  waf.set_rule("rule_htaccess_poisoning", "block")

  local hit, reason, _ttl, action = waf.check(ctx(
    "AddType application/x-httpd-php .jpg .gif .png"))
  check(hit == true,                                "430 AddType — hit=true")
  check(reason == "WAF_BACKDOOR:HTACCESS_ADDTYPE_PHP", "430 AddType — reason")
  check(action == "block",                          "430 AddType — action=block")
end

do
  disable_all_rules()
  waf.set_rule("rule_htaccess_poisoning", "challenge")

  local hit, reason = waf.check(ctx("SetHandler application/x-httpd-php\n"))
  check(hit == true,                                  "430 SetHandler — hit=true")
  check(reason == "WAF_BACKDOOR:HTACCESS_SETHANDLER_PHP", "430 SetHandler — reason")
end

do
  disable_all_rules()
  waf.set_rule("rule_htaccess_poisoning", "challenge")

  local hit, reason = waf.check(ctx("php_value auto_prepend_file /tmp/shell.php"))
  check(hit == true,                                "430 auto_prepend — hit=true")
  check(reason == "WAF_BACKDOOR:HTACCESS_AUTO_PREPEND", "430 auto_prepend — reason")
end

do
  disable_all_rules()
  waf.set_rule("rule_htaccess_poisoning", "challenge")

  -- .user.ini shape — no Apache wrapper
  local hit, reason = waf.check(ctx("auto_prepend_file = /tmp/.cache/shell.php"))
  check(hit == true,                              "430 user.ini — hit=true")
  check(reason == "WAF_BACKDOOR:USER_INI_AUTO_PREPEND", "430 user.ini — reason")
end

do
  disable_all_rules()
  waf.set_rule("rule_htaccess_poisoning", "block")

  local hit, reason = waf.check(ctx("Options +ExecCGI"))
  check(hit == true,                             "430 ExecCGI — hit=true")
  check(reason == "WAF_BACKDOOR:HTACCESS_EXEC_CGI", "430 ExecCGI — reason")
end

-- Negative: legit .htaccess with rewrite rules + cache headers (WP / WP-Rocket)
do
  disable_all_rules()
  waf.set_rule("rule_htaccess_poisoning", "block")

  local hit = waf.check(ctx([[
RewriteEngine On
RewriteBase /
RewriteRule ^index\.php$ - [L]
RewriteCond %{REQUEST_FILENAME} !-f
RewriteCond %{REQUEST_FILENAME} !-d
RewriteRule . /index.php [L]

<IfModule mod_expires.c>
  ExpiresActive On
  ExpiresByType image/jpeg "access plus 1 year"
  AddType image/svg+xml svg
</IfModule>
]]))
  check(hit ~= true, "430 negative — legit WP .htaccess does not fire")
end

-- Negative: legit AddType for fonts (no x-httpd-php)
do
  disable_all_rules()
  waf.set_rule("rule_htaccess_poisoning", "block")

  local hit = waf.check(ctx("AddType application/font-woff .woff\n"))
  check(hit ~= true, "430 negative — AddType for fonts does not fire")
end

-- ─────────────────────────────────────────────────────────────────────────────
-- 431 — character-pool function-name builder (the captured sample's signature)
-- ─────────────────────────────────────────────────────────────────────────────

do
  disable_all_rules()
  waf.set_rule("rule_php_char_pool_obfuscation", "block")

  -- Verbatim shape from the captured wp-themes/bridge/includes/radio.php
  local body = [[
<?php
$t_Ohw = "8Njlp26zFZ1PYvUsnckDOX5JdhCwMSRafLi0bqeQo4WxtBrTAu3IEm7VHG_K9gy";
$IDC3B = $t_Ohw[61].$t_Ohw[7].$t_Ohw[34].$t_Ohw[16].$t_Ohw[32].$t_Ohw[3].$t_Ohw[31].$t_Ohw[44].$t_Ohw[38];
]]
  local hit, reason, _ttl, action = waf.check(ctx(body))
  check(hit == true,                              "431 captured-sample — hit=true")
  check(reason == "WAF_BACKDOOR:CHAR_POOL_BUILDER", "431 captured-sample — reason")
  check(action == "block",                        "431 captured-sample — action=block")
end

-- Whitespace-padded variant — obfuscators sometimes pretty-print to evade
do
  disable_all_rules()
  waf.set_rule("rule_php_char_pool_obfuscation", "challenge")

  local body = [[<?php $a = "AAAA"; $f = $a[0] . $a[1] . $a[2] . $a[3];]]
  local hit, reason = waf.check(ctx(body))
  check(hit == true,                              "431 spaced — hit=true")
  check(reason == "WAF_BACKDOOR:CHAR_POOL_BUILDER", "431 spaced — reason")
end

-- Negative: two accesses (not three) — under the threshold for malware shape
do
  disable_all_rules()
  waf.set_rule("rule_php_char_pool_obfuscation", "challenge")

  local hit = waf.check(ctx([[<?php $first_two = $x[0].$x[1];]]))
  check(hit ~= true, "431 negative — two indexed accesses does not fire")
end

-- Negative: three accesses but DIFFERENT variables (legit "merge first chars")
do
  disable_all_rules()
  waf.set_rule("rule_php_char_pool_obfuscation", "challenge")

  local hit = waf.check(ctx([[<?php $merged = $a[0].$b[0].$c[0];]]))
  check(hit ~= true, "431 negative — different-variable accesses do not fire")
end

-- ─────────────────────────────────────────────────────────────────────────────
-- 432 — full-body polyglot (magic-byte prefix + PHP opener anywhere)
-- ─────────────────────────────────────────────────────────────────────────────

do
  disable_all_rules()
  waf.set_rule("rule_php_polyglot_full_body", "block")

  -- Verbatim head from the captured radio.php
  local body = "%PDF-\n%PDF-\n<?php\n$x = 1;\n"
  local hit, reason, _ttl, action = waf.check(ctx(body, "application/pdf"))
  check(hit == true,                          "432 PDF polyglot — hit=true")
  check(reason == "WAF_BACKDOOR:POLYGLOT_DEEP_PDF", "432 PDF polyglot — reason")
  check(action == "block",                    "432 PDF polyglot — action=block")
end

-- JPEG polyglot — magic bytes + <?php at offset > 64
do
  disable_all_rules()
  waf.set_rule("rule_php_polyglot_full_body", "challenge")

  local padding = string.rep("A", 100) -- push <?php past the 64-byte window
  local body = "\xff\xd8\xff\xe0" .. padding .. "<?php system($_GET['c']); ?>"
  local hit, reason = waf.check(ctx(body, "image/jpeg"))
  check(hit == true,                          "432 JPEG deep — hit=true")
  check(reason == "WAF_BACKDOOR:POLYGLOT_DEEP_JPEG", "432 JPEG deep — reason")
end

-- PNG polyglot
do
  disable_all_rules()
  waf.set_rule("rule_php_polyglot_full_body", "challenge")

  local body = "\x89PNG\r\n\x1a\n" .. string.rep("\x00", 50) .. "<?=`id`;?>"
  local hit, reason = waf.check(ctx(body, "image/png"))
  check(hit == true,                          "432 PNG short-tag — hit=true")
  check(reason == "WAF_BACKDOOR:POLYGLOT_DEEP_PNG", "432 PNG short-tag — reason")
end

-- ZIP/JAR polyglot
do
  disable_all_rules()
  waf.set_rule("rule_php_polyglot_full_body", "challenge")

  local body = "PK\x03\x04" .. string.rep("z", 80) .. "<?php eval($_POST['c']); ?>"
  local hit, reason = waf.check(ctx(body, "application/zip"))
  check(hit == true,                          "432 ZIP polyglot — hit=true")
  check(reason == "WAF_BACKDOOR:POLYGLOT_DEEP_ZIP", "432 ZIP polyglot — reason")
end

-- Negative: PHP in body but NO magic byte prefix
do
  disable_all_rules()
  waf.set_rule("rule_php_polyglot_full_body", "challenge")

  local hit = waf.check(ctx("<?php echo 'hi'; ?>"))
  check(hit ~= true, "432 negative — PHP with no magic prefix does not fire")
end

-- Negative: legit JPEG without PHP
do
  disable_all_rules()
  waf.set_rule("rule_php_polyglot_full_body", "challenge")

  local hit = waf.check(ctx("\xff\xd8\xff\xe0" .. string.rep("\x00", 200), "image/jpeg"))
  check(hit ~= true, "432 negative — clean JPEG does not fire")
end

-- ─────────────────────────────────────────────────────────────────────────────
-- 433 — variable-fed eval-loader with >=200-char base64 literal
-- ─────────────────────────────────────────────────────────────────────────────

do
  disable_all_rules()
  waf.set_rule("rule_php_eval_loader_b64", "block")

  -- Shape from the captured sample (reduced)
  local payload = long_b64(300)
  local body = [[<?php $K = "]] .. payload .. [["; eval($A($B($K)));]]
  local hit, reason, _ttl, action = waf.check(ctx(body))
  check(hit == true,                          "433 captured-shape — hit=true")
  check(reason == "WAF_BACKDOOR:EVAL_LOADER_B64", "433 captured-shape — reason")
  check(action == "block",                    "433 captured-shape — action=block")
end

-- assert() variant — `assert($f($payload))` is the modern eval-evader
do
  disable_all_rules()
  waf.set_rule("rule_php_eval_loader_b64", "challenge")

  local body = [[<?php assert($d("]] .. long_b64(220) .. [[")); ]]
  -- assert($d( — argument starts with $varname-call → matches
  local hit, reason = waf.check(ctx(body))
  check(hit == true,                          "433 assert+var — hit=true")
  check(reason == "WAF_BACKDOOR:EVAL_LOADER_B64", "433 assert+var — reason")
end

-- call_user_func variant
do
  disable_all_rules()
  waf.set_rule("rule_php_eval_loader_b64", "challenge")

  local body = [[<?php $p = "]] .. long_b64(220) .. [["; call_user_func($f, $p);]]
  local hit, reason = waf.check(ctx(body))
  check(hit == true,                          "433 call_user_func — hit=true")
  check(reason == "WAF_BACKDOOR:EVAL_LOADER_B64", "433 call_user_func — reason")
end

-- Negative: eval() with LITERAL function name (not variable)
do
  disable_all_rules()
  waf.set_rule("rule_php_eval_loader_b64", "challenge")

  -- eval(base64_decode("...")) — literal function name, not variable
  local body = [[<?php eval(base64_decode("]] .. long_b64(220) .. [[")); ]]
  local hit = waf.check(ctx(body))
  check(hit ~= true, "433 negative — eval with literal funcname does not fire (rule targets variable-fed shape)")
end

-- Negative: variable-call eval but no large base64 literal
do
  disable_all_rules()
  waf.set_rule("rule_php_eval_loader_b64", "challenge")

  local body = [[<?php eval($a($b("hello"))); ]]
  local hit = waf.check(ctx(body))
  check(hit ~= true, "433 negative — short literal does not fire")
end

-- Negative: large base64 string by itself (no eval / assert / cuf)
do
  disable_all_rules()
  waf.set_rule("rule_php_eval_loader_b64", "challenge")

  local body = [[<?php $token = "]] .. long_b64(300) .. [["; echo $token;]]
  local hit = waf.check(ctx(body))
  check(hit ~= true, "433 negative — base64 token without eval-loader does not fire")
end

-- ─────────────────────────────────────────────────────────────────────────────
-- Integration: the captured radio.php sample triggers all three of 431, 432, 433.
-- Severity aggregation picks the strongest action; multiple rule_ids in `hits`.
-- ─────────────────────────────────────────────────────────────────────────────

do
  disable_all_rules()
  waf.set_rule("rule_php_char_pool_obfuscation", "challenge")
  waf.set_rule("rule_php_polyglot_full_body",    "challenge")
  waf.set_rule("rule_php_eval_loader_b64",       "block")

  -- Reduced verbatim from the captured radio.php (PDF magic + char-pool + eval-loader).
  local payload = long_b64(400)
  local body = "%PDF-\n%PDF-\n<?php\n" ..
    [[$t_Ohw = "8Njlp26zFZ1PYvUsnckDOX5JdhCwMSRafLi0bqeQo4WxtBrTAu3IEm7VHG_K9gy";]] .. "\n" ..
    [[$IDC3B = $t_Ohw[61].$t_Ohw[7].$t_Ohw[34].$t_Ohw[16].$t_Ohw[32];]] .. "\n" ..
    [[$K1YIr = "]] .. payload .. [[";]] .. "\n" ..
    [[eval($IDC3B($CVOor($K1YIr)));]]
  local hit, _reason, _ttl, action, hits = waf.check(ctx(body, "application/pdf"))
  check(hit == true,                                        "integration — captured sample hits")
  check(action == "block",                                  "integration — block wins severity aggregation")
  check(type(hits) == "table" and #hits >= 3,               "integration — at least three rules recorded (got " .. (type(hits) == "table" and #hits or "?") .. ")")
end

if fails > 0 then
  io.stderr:write(string.format("FAILED %d tests\n", fails))
  os.exit(1)
end
print("ok: cfm_waf backdoor tier-1 tests (430-433)")

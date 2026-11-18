-- Tests for the SQLi / PHP-probe gaps closed on 2026-11-18 (docs/waf.md
-- "SQLi gaps, 2026-11-18"): shapes the fleet's scanners sent that passed the
-- WAF, measured over 8 nodes x 8 days with no legitimate request matching.
--   * a `--` (or `/*`) in one parameter hid every LATER parameter from the
--     SQLi rules: `?x=--&id=1'+union+select…` read as clean;
--   * `/*!NNNNN…*/` content (run by MySQL) was deleted with the comment;
--   * `' order by 3--`, `procedure analyse(`, `') and ('x'='x`, `1 and 1=1`,
--     `utl_inaddr.get_host_address(` (rule 301);
--   * `${@var_dump(md5(31337))}` (rule 332).

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

-- args are given decoded-looking but raw, the way the edge passes $args.
local function get(qs)
  return { uri = "/index.php", args = qs, method = "GET",
           ip = "203.0.113.52", headers = {}, body = "" }
end

local function fires(qs, label)
  local hit, reason = waf.check(get(qs))
  check(hit == true and reason == "WAF_SQLI",
    label .. " — want WAF_SQLI, got " .. tostring(hit) .. " " .. tostring(reason))
end

local function clean(qs, label)
  local hit, reason = waf.check(get(qs))
  check(hit ~= true, label .. " — must NOT fire (got " .. tostring(reason) .. ")")
end

set_only({ rule_sqli = "block" })

-- ── A comment never hides a later parameter ─────────────────────────────────
fires("id=1%27+union+select+1,2,3",                 "baseline union select")
fires("x=--&id=1%27+union+select+1,2,3",            "`--` in an earlier parameter")
fires("x=--&id=1%27+or+%271%27%3D%271",             "`--` before a quoted tautology")
fires("x=a--b&id=1;waitfor+delay+%270:0:5%27",      "`--` mid-value before waitfor")
fires("x=/*&id=1%27+union+select+1&y=*/",           "`/*` and `*/` around a parameter")
fires("x=%2D%2D&id=1%27+union+select+1,2,3",        "encoded `--`")
do -- a `--` in the path (PATH_INFO)
  local hit, reason = waf.check({ uri = "/index.php/--", args = "id=1%27+union+select+1,2",
    method = "GET", ip = "203.0.113.52", headers = {}, body = "" })
  check(hit == true and reason == "WAF_SQLI", "`--` in the path — got " .. tostring(reason))
end

-- ── The body keeps the old strip and gets none of the new shapes ────────────
-- (measured on queries only; a JSON / minified-code body is one line, and
-- its first `--` hid the rest of it before this change too)
local function post(body, ct)
  return { uri = "/wp-json/wp/v2/posts/1", args = "", method = "POST", ip = "203.0.113.53",
           headers = { ["Content-Type"] = ct or "application/json" }, body = body }
end
do
  local hit = waf.check(post('{"content":"<p style=\\"color:var(--wp--preset--color--x)\\">Never write \' or \'1\'=\'1 in a login form</p>"}'))
  check(hit ~= true, "Gutenberg save: text after `--` stays out of the body scan")
  hit = waf.check(post("q=select+*+from+t+where+id%3D1+order+by+2+--+x", "application/x-www-form-urlencoded"))
  check(hit ~= true, "a SQL console body: `order by 2 --` is a query-only shape")
  hit = waf.check(post('{"a":"\\" and \\"a\\"=\\"a"}'))
  check(hit ~= true, "a code snippet body: the tautology is a query-only shape")
  -- the old rules still read the body as before
  hit = waf.check(post("subject=1%27+union+select+1,2", "application/x-www-form-urlencoded"))
  check(hit == true, "body: 301 still blocks union select")
end
-- ...and splitting on a DECODED `&` does not open a hole of its own
fires("id=1%27--%0Aunion+select+1,2",               "comment, newline, union")
fires("id=1%27/*%26*/union+select+1,2",             "encoded `&` inside a block comment")
fires("id=1%27--%26%0Aunion+select+1,2",            "encoded `&` inside a line comment")

-- ── Executable comments are read as SQL ─────────────────────────────────────
fires("catid=0%27%20/*!11110procedure*/%20/*!11110analyse*/%20(/*!11110extractvalue*/(0x30,/*!11110concat*/(0x27,DATABASE())),0x30)",
      "versioned procedure analyse")
fires("id=1/*!50000union*//*!50000select*/1,2",     "versioned union select")

-- content between keywords, and an empty one inside a call (adversarial review)
do
  local function hit(qs) local h = waf.check(get(qs)); return h == true end
  set_only({ rule_sqli_union_variant = "challenge_v2" })
  check(hit("id=1%27union/*!all*/select+1,2"),      "319: union/*!all*/select")
  check(hit("id=1%27union/*!50000all*/select+1,2"), "319: union/*!50000all*/select")
  set_only({ rule_sqli_blind_lexical = "block" })
  check(hit("id=1+and+extractvalue/*!*/(1,1)"),     "309: extractvalue/*!*/(")
  check(hit("id=1+or+sleep/*!*/(5)"),               "309: or sleep/*!*/(")
  set_only({ rule_sqli = "block" })
end

-- ── New 301 shapes ──────────────────────────────────────────────────────────
fires("q=wahl%27%20ORDER%20BY%201--%20-",           "' order by 1-- -")
fires("view=article%27%20ORDER%20BY%2012%23",       "' order by 12#")
fires("id=5)+order+by+3--",                         ") order by 3--")
fires("q=%27)%20AND%20(%27dluhmo%27%3D%27dluhmo",   "') and ('x'='x")
fires("option=com_content%20%22%20AND%20%22a%22%3D%22a", "\" and \"a\"=\"a")
fires("q=1%27+or+%27abc%27%3D%27abc%27",            "' or 'abc'='abc'")
fires("language=en%27%20and%201%3Dutl_inaddr.get_host_address((chr(126)))", "utl_inaddr")
fires("q=75%20AND%201%3D1",                         "75 and 1=1")
fires("id=1%27+and+1%3D1--",                        "' and 1=1--")
fires("q=x%27+procedure+analyse(extractvalue(1,1),1)", "' procedure analyse(")

-- ── Legitimate shapes that must stay clean ──────────────────────────────────
clean("x=--&q=hello+world",                         "a lone `--` value")
clean("title=foo--bar&page=2",                      "`--` inside a slug")
clean("sort=price&order=asc",                       "a sort parameter")
clean("q=sort+2+order+by+3+days",                   "order by without a comment")
clean("q=terms+and+conditions",                     "plain `and`")
clean("q=1+and+1%3D10",                             "1=10 is not 1=1")
clean("q=size+2+and+1%3D1px",                       "1=1 followed by a word")
clean("msg=1%20and%201=1%20is%20a%20very%20basic%20mathematical%20operation", "1 and 1=1 in prose")
fires("q=1+and+1%3D1&page=2",                       "1 and 1=1 ending its parameter")
-- Known residual: followed by more words it reads like the prose above.
clean("s=%27nv%27+and+1%3D1+or+x",                  "residual: ' and 1=1 or …")
clean("q=brand+%27a%27%3D%27a%27",                  "`brand` is not `and`")
clean("q=a+and+%27b%27%3D%27c%27",                  "different words")
clean("q=x+and+%27ab%27%3D%27abc%27",               "a prefix is not the same word")
clean("q=procedure+analysis",                       "prose: procedure analysis")
clean("q=x+and+(%27a%27%3D%27a%27)",                "tautology with no value break before `and`")
clean("q=mysql+procedure+analyse(+)+syntax",        "prose: procedure analyse( with no value break")
clean("q=/*+a+comment+*/hello",                     "a plain block comment")

-- ── Rule 332: the var_dump(md5(N)) probe ────────────────────────────────────
check(det.detect_php_code_args("language=%24%7B%40var_dump(md5(631881373))%7D%3B") == "VAR_DUMP_MD5",
      "332: ${@var_dump(md5(N))};")
check(det.detect_php_code_args("x=var_dump+(+md5(+31337+)+)") == "VAR_DUMP_MD5", "332: spaced")
check(det.detect_php_code_args("q=var_dump+tutorial") == nil, "332: the word var_dump")
check(det.detect_php_code_args("q=var_dump(md5(%24x))") == nil, "332: md5 of a variable is not the probe")
check(det.detect_php_code_args("q=md5(123)") == nil, "332: md5 alone")
check(det.detect_php_code_args("q=php+var_dump(md5(123))") == nil, "332: a forum search with a small number")

if fails > 0 then
  io.stderr:write("\n" .. fails .. " check(s) failed in cfm_waf_sqli_gaps_test.lua\n")
  os.exit(1)
end
io.stdout:write("ok: SQLi / PHP-probe gaps (2026-11-18)\n")

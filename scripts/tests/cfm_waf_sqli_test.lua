-- Tests for the WAF SQLi detectors: the sqlmap-class time-based / boolean /
-- error-based blind family, the POST-body inspection that lets it see
-- form-field SQLi, and the two-tier split:
--   * rule 301 (WAF_SQLI, challenge)         — DBMS-unique blind primitives
--   * rule 309 (WAF_SQLI_LEXICAL, logonly)   — word/method-colliding tokens
--     (extractvalue(/updatexml(/benchmark(/floor(rand(/randomblob(/…sleep()
--     kept observe-only so a legit XML parser / updater / custom script
--     can't be broken (split decided 2026-06-26; see docs/waf.md FP review).
--
-- Source workload: captured 2026-06-26 sqlmap scan of the WHMCS ticket form
-- (myip.gr support) — every captured payload carries a DBMS-unique token, so
-- the scan stays fully covered at `challenge` after the split.

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

-- Disable every rule, then enable the given { name = mode } set.
local function set_only(map)
  local snap = waf.get_config()
  for k, _ in pairs(snap) do
    if k:sub(1, 5) == "rule_" then waf.set_rule(k, "disabled") end
  end
  for k, m in pairs(map) do waf.set_rule(k, m) end
end

-- WHMCS-style ticket submission: payload in the urlencoded POST body.
local function post(body)
  return {
    uri     = "/submitticket.php",
    args    = "",
    method  = "POST",
    ip      = "203.0.113.50",
    headers = { ["Content-Type"] = "application/x-www-form-urlencoded" },
    body    = body,
  }
end

local function get(qs)
  return {
    uri = "/index.php", args = qs, method = "GET",
    ip = "203.0.113.51", headers = {}, body = "",
  }
end

local function fires(ctx, label, want_reason)
  want_reason = want_reason or "WAF_SQLI"
  local hit, reason = waf.check(ctx)
  check(hit == true,             label .. " — hit=true")
  check(reason == want_reason,   label .. " — reason=" .. want_reason .. " (got " .. tostring(reason) .. ")")
end

local function clean(ctx, label)
  local hit = waf.check(ctx)
  check(hit ~= true, label .. " — must NOT fire")
end

-- ─────────────────────────────────────────────────────────────────────────────
-- Tier 1 (rule 301, WAF_SQLI, challenge): DBMS-unique blind primitives + the
-- pre-existing cheap signatures. Every captured WHMCS payload lives here.
-- ─────────────────────────────────────────────────────────────────────────────
set_only({ rule_sqli = "challenge" })

-- Verbatim captured WHMCS payloads (body-borne).
fires(post("subject=-1 OR 2+77-77-1=0+0+0+1"),                         "boolean 2+77-77-1=0+0+0+1")
fires(post("subject=-1' OR 2+481-481-1=0+0+0+1 -- "),                  "boolean with -- comment tail")
fires(post("subject=-1\" OR 2+38-38-1=0+0+0+1 -- "),                   "boolean double-quote variant")
fires(post("subject=-1' OR 2+204-204-1=0+0+0+1 or 'yZP0Qyxe'='"),      "boolean trailing or-string")
fires(post("message=1*if(now()=sysdate(),sleep(15),0)"),              "MySQL now()=sysdate() time-based")
fires(post("subject=10'XOR(1*if(now()=sysdate(),sleep(15),0))XOR'Z"), "MySQL XOR sysdate time-based")
fires(post("subject=(select(0)from(select(sleep(15)))v)/**/"),        "MySQL stacked select(sleep())")
fires(post("subject=1-1; waitfor delay '0:0:15'"),                    "MSSQL waitfor delay (stacked)")
fires(post("subject=1-1 waitfor delay '0:0:15' -- "),                 "MSSQL waitfor delay (inline)")
fires(post("subject=1-1 OR 947=(SELECT 947 FROM PG_SLEEP(15))"),      "PostgreSQL PG_SLEEP")
fires(post("subject=1*DBMS_PIPE.RECEIVE_MESSAGE(CHR(99)||CHR(99)||CHR(99),15)"), "Oracle DBMS_PIPE")
fires(post("subject=1'||DBMS_PIPE.RECEIVE_MESSAGE(CHR(98)||CHR(98)||CHR(98),15)||'"), "Oracle DBMS_PIPE concat")

-- Other DBMS-unique family members.
fires(post("q=1 AND 1=DBMS_LOCK.SLEEP(5)"),       "Oracle DBMS_LOCK.SLEEP")
fires(post("q=1 RLIKE SLEEP(5)"),                 "MySQL rlike sleep")
fires(post("q=1;SELECT SLEEP(5)"),                "MySQL SELECT SLEEP")
fires(post("q=1 AND exp(~(select user()))"),      "MySQL error-based exp(~")

-- Pre-existing cheap signatures (regression guard).
fires(get("id=1 UNION SELECT username,password FROM users"), "classic UNION SELECT")
fires(get("id=1' OR '1'='1"),                                "classic ' OR '1'='1")
fires(post("filter=1 AND 1=1 UNION SELECT * FROM information_schema.tables"), "information_schema")

-- form-urlencoded space as '+' / '%2B' still matches.
fires(post("subject=1;waitfor+delay+'0:0:15'"),      "waitfor delay with '+' as space")
fires(post("subject=-1+OR+2%2B9-9-1=0%2B0%2B0%2B1"), "boolean tail with %2B-encoded plus")

-- '+'-encoded spaces must NOT evade the TAUTOLOGY signatures (union select /
-- or 1=1 / ' or '1'='1). A browser/form sends a space as '+', and PHP decodes
-- '+'->space before the SQL runs, so `1+union+select` reaches the DB as
-- `1 union select`. These checks previously ran against `sc` ('+' preserved),
-- so the '+' form was a first-try block-tier bypass while the space/%20 form
-- was caught (audit 2026-07; now matched against the '+/space'-collapsed scw).
fires(get("id=1+union+select+username,password+from+users"), "'+'-encoded UNION SELECT")
fires(get("id=1+or+1=1"),                                     "'+'-encoded OR 1=1")
fires(get("id=1'+or+'1'='1"),                                 "'+'-encoded ' OR '1'='1")
-- Double separators collapse too (a single-space substring test on sc missed
-- these even without '+').
fires(get("id=1+union++select+1,2,3"),                        "double '+' between UNION/SELECT")
fires(get("id=1%20union%20%20select%201"),                    "double '%20' between UNION/SELECT")

-- Body-only detection (the regression the body-scan wiring fixes): payload in
-- the body, query string clean.
fires(post("name=John&email=a@b.com&message=1 OR 1=1 UNION SELECT 1,2,3"),
      "body-only UNION SELECT (the WHMCS-form fix)")

-- The lexical (word-colliding) tokens must NOT fire rule 301.
clean(post("q=1) OR BENCHMARK(5000000,MD5(0x41))-- -"),  "lexical benchmark( not on rule 301")
clean(post("q=1 AND extractvalue(1,concat(0x7e,version()))"), "lexical extractvalue( not on rule 301")
clean(get("id=1 AND SLEEP(5)"),                          "lexical 'and sleep(' not on rule 301")

-- ─────────────────────────────────────────────────────────────────────────────
-- Tier 2 (rule 309, WAF_SQLI_LEXICAL): word/method-colliding tokens. Tested at
-- `block` for crisp assertions; ships at `logonly` (observe-only) in prod.
-- ─────────────────────────────────────────────────────────────────────────────
set_only({ rule_sqli_blind_lexical = "block" })

fires(post("q=1) OR BENCHMARK(5000000,MD5(0x41))-- -"),       "BENCHMARK", "WAF_SQLI_LEXICAL")
fires(post("q=1 AND extractvalue(1,concat(0x7e,version()))"), "extractvalue", "WAF_SQLI_LEXICAL")
fires(post("q=1 AND updatexml(1,concat(0x7e,user()),1)"),     "updatexml", "WAF_SQLI_LEXICAL")
fires(post("q=1 OR 1=randomblob(1000000000)"),                "randomblob", "WAF_SQLI_LEXICAL")
fires(post("q=1 AND (SELECT 1 FROM(SELECT COUNT(*),concat(version(),floor(rand(0)*2))x FROM t GROUP BY x)a)"),
      "floor(rand", "WAF_SQLI_LEXICAL")
fires(get("id=1+AND+SLEEP(5)"),                               "and sleep( with '+'", "WAF_SQLI_LEXICAL")
fires(post("q=1 OR SLEEP(5)"),                                "or sleep(", "WAF_SQLI_LEXICAL")

-- DBMS-unique tokens must NOT fire rule 309.
clean(post("subject=1-1; waitfor delay '0:0:15'"),           "DBMS-unique waitfor not on rule 309")
clean(post("subject=1-1 OR 947=(SELECT 947 FROM PG_SLEEP(15))"), "DBMS-unique pg_sleep not on rule 309")
clean(post("subject=-1 OR 2+77-77-1=0+0+0+1"),               "DBMS-unique boolean tail not on rule 309")

-- ─────────────────────────────────────────────────────────────────────────────
-- Tier 3 (rule 319, WAF_SQLI_UNION_VARIANT): obfuscated UNION that rule 301's
-- ADJACENT `union select` signature misses — keyword (union all/distinct
-- select), paren (union(select), comment (union/**/select → unionselect).
-- Ships at `logonly` (burn-in); tested at `block` for crisp assertions.
-- ─────────────────────────────────────────────────────────────────────────────
set_only({ rule_sqli_union_variant = "block" })

fires(get("id=1+union+all+select+1,2,3"),                    "union all select", "WAF_SQLI_UNION_VARIANT")
fires(get("id=-1'+union+all+select+null,version()"),         "union all select (quote)", "WAF_SQLI_UNION_VARIANT")
fires(get("id=1+union+distinct+select+1"),                   "union distinct select", "WAF_SQLI_UNION_VARIANT")
fires(get("id=1+union(select+1,2)"),                         "union(select (paren)", "WAF_SQLI_UNION_VARIANT")
fires(get("id=1)union(select+1"),                            "union(select (paren terminator)", "WAF_SQLI_UNION_VARIANT")
fires(get("id=1/**/union/**/select+1,2,3"),                  "union/**/select (comment-collapsed)", "WAF_SQLI_UNION_VARIANT")
fires(get("id=1/**/union/**/all/**/select+1,2,3"),           "union/**/all/**/select → unionallselect", "WAF_SQLI_UNION_VARIANT")
fires(get("id=1/**/union/**/distinct/**/select+1"),          "union/**/distinct/**/select → uniondistinctselect", "WAF_SQLI_UNION_VARIANT")
fires(post("subject=null+union+all+select+card_no+from+cards"), "null operand union all select", "WAF_SQLI_UNION_VARIANT")

-- FP: "union" as a noun with the obfuscation words must NOT fire (same
-- value-terminator guard as rule 301: a WORD before "union" excludes it).
clean(get("q=credit+union+all+selected+members"),            "FP: 'credit union all selected'")
clean(get("q=trade+union+distinct+selection"),               "FP: 'trade union distinct selection'")
clean(get("q=european+union+all+select+committee"),          "FP: 'european union all select committee'")
clean(get("q=reunion+selected+tracks"),                      "FP: 'reunion selected'")

-- Literal-prefilter fast path: digit/paren-heavy args with NO `union` literal
-- take the early `return false` (no pattern scans) and must stay clean — the
-- prefilter is a necessary-substring gate, not a behaviour change.
clean(get("id=12345&cat=(shoes)&sort=price_asc&page=3&ref=(home)"), "prefilter: no 'union' literal → clean")

-- Rule 319 must NOT double-fire on a plain adjacent `union select` (that is
-- rule 301's job); and rule 301 must NOT fire on the obfuscated variants.
clean(get("id=1+union+select+1,2,3"),                        "319 does not claim plain 'union select'")
set_only({ rule_sqli = "block" })
clean(get("id=1+union+all+select+1"),                        "301 does not catch 'union all select'")
clean(get("id=1+union(select+1"),                            "301 does not catch 'union(select'")
clean(get("id=1/**/union/**/select+1"),                      "301 does not catch 'union/**/select'")

-- ─────────────────────────────────────────────────────────────────────────────
-- Production-like (301 challenge + 309 logonly) — the captured scan still
-- gets challenged via its DBMS-unique tokens, and ordinary traffic is clean.
-- ─────────────────────────────────────────────────────────────────────────────
set_only({ rule_sqli = "challenge", rule_sqli_blind_lexical = "logonly" })

fires(post("subject=1-1 OR 947=(SELECT 947 FROM PG_SLEEP(15))"), "prod: captured pg_sleep still challenged")

clean(post("subject=Cannot login&message=I get a 500 error when I open my website, please help."),
      "FP: ordinary ticket prose")
clean(post("subject=Slow query&message=My report page runs SELECT * FROM orders and times out."),
      "FP: legit SELECT mention (no blind primitive)")
clean(post("subject=Cron&message=My backup script calls sleep(5) between rsync runs in bash."),
      "FP: bash sleep(5) (no SQL-anchored token)")
clean(post("subject=Power&message=My monitor sleep mode and disk sleep settings won't stick."),
      "FP: 'monitor sleep' prose — 'or sleep' without a '(' anchor stays clean")
clean(post("subject=Invoice math&message=The total is 2+2=4 but the panel shows 5."),
      "FP: arithmetic in prose")
clean(post("subject=Greek&message=Δεν μπορώ να συνδεθώ στο email μου, βοήθεια."),
      "FP: normal Greek prose")
clean(get("page=products&category=laptops&sort=price"),
      "FP: ordinary GET browsing")

-- "union" as an English NOUN followed by "select…" must NOT hit rule 301.
-- Browsers send a space as '+', so after the '+'->space fix these collapse to
-- "… union select …" — a bare substring test would 403 them at block tier.
-- The value-terminator guard keeps them clean while still catching `1 union`,
-- `' union`, `)union`, `=union` injections.
clean(get("q=credit+union+select+account"),      "FP: 'credit union select account'")
clean(get("q=trade+union+selection"),            "FP: 'trade union selection'")
clean(get("q=student+union+selected+works"),     "FP: 'student union selected works'")
clean(get("q=reunion+selected+tracks"),          "FP: 'reunion selected' (union mid-word)")
clean(get("q=european+union+select+committee"),  "FP: 'european union select committee'")
clean(post("subject=Membership&message=Our credit union selected a new bank last month."),
      "FP: 'credit union selected' in ticket prose")
-- '/' and ',' are excluded from the value-terminator class so legit paths and
-- CSV-ish values with a noun "union" next to "select…" stay clean.
clean(get("next=/union+selected+news"),          "FP: path '/union selected news' (slash before union)")
clean(get("tags=jazz,union+select,rock"),        "FP: CSV 'jazz,union select,rock' (comma before union)")
-- "union" as a noun starting a VALUE ("Union Select Board" / "Union Selectmen"
-- municipal searches) must NOT block: '=' is deliberately not a terminator, so
-- the bare-value `?id=union+select+1,2` injection is given up rather than 403
-- these. The common `?id=1+union+select` form is still caught via its DIGIT
-- terminator (the '1' of the value), below.
clean(get("q=union+select+board"),               "FP: 'Union Select Board' (municipal, value starts 'union')")
clean(get("q=union+selectmen"),                  "FP: 'Union Selectmen'")
-- The real value-terminators (digit / paren / quote) still catch injection:
fires(get("id=1)union+select+1,2"),              "')union select' (paren terminator)")
fires(get("name='+union+select+password+from+users"), "quote terminator ' union select")
-- SQL keyword-literal operands (null/true/false) also break out of an unquoted
-- value with no digit/quote/paren — they end in a letter, so they need explicit
-- matching (the pre-fix substring check caught them; missing them would regress).
fires(get("id=null+union+select+username,password+from+users"), "null operand union select")
fires(get("id=1+is+null+union+select+1,2,3"),    "'is null' boolean-expr union select")
fires(get("enabled=true+union+select+card_no,cvv+from+cards"),  "true operand union select")
fires(get("id=false+union+select+1"),            "false operand union select")
-- …but the keyword must be adjacent: 'annul' (one 'l') and non-adjacent 'true …
-- union' are not operand-breaks, so they stay clean.
clean(get("q=annul+union+selection"),            "FP: 'annul union selection' (not 'null')")
clean(get("q=is+that+true+for+the+union+selection"), "FP: 'true' not adjacent to 'union select'")

if fails > 0 then
  io.stderr:write(string.format("FAILED %d tests\n", fails))
  os.exit(1)
end
print("ok: cfm_waf SQLi blind-family split + body-scan tests (rules 301/309)")

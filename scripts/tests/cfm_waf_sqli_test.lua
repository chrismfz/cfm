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

if fails > 0 then
  io.stderr:write(string.format("FAILED %d tests\n", fails))
  os.exit(1)
end
print("ok: cfm_waf SQLi blind-family split + body-scan tests (rules 301/309)")

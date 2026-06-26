-- Tests for the WAF_SQLI detector (rule 301): the sqlmap-class time-based /
-- boolean / error-based blind family, plus the POST-body inspection that lets
-- it see form-field SQLi.
--
-- Source workload: captured 2026-06-26 sqlmap scan against the WHMCS ticket
-- submission form (myip.gr support). Hundreds of tickets, one per payload —
-- time-based (SLEEP / PG_SLEEP / WAITFOR DELAY / DBMS_PIPE.RECEIVE_MESSAGE /
-- now()=sysdate()) and boolean (2+N-N-1=0+0+0+1) blind injections submitted in
-- the body (application/x-www-form-urlencoded), which the old uri+args-only
-- SQLi scan never inspected.

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

local function only_sqli(mode)
  local snap = waf.get_config()
  for k, _ in pairs(snap) do
    if k:sub(1, 5) == "rule_" then waf.set_rule(k, "disabled") end
  end
  waf.set_rule("rule_sqli", mode or "challenge")
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

-- Payload in the query string (GET).
local function get(qs)
  return {
    uri     = "/index.php",
    args    = qs,
    method  = "GET",
    ip      = "203.0.113.51",
    headers = {},
    body    = "",
  }
end

local function fires(ctx, label)
  local hit, reason = waf.check(ctx)
  check(hit == true,            label .. " — hit=true")
  check(reason == "WAF_SQLI",   label .. " — reason=WAF_SQLI (got " .. tostring(reason) .. ")")
end

local function clean(ctx, label)
  local hit = waf.check(ctx)
  check(hit ~= true, label .. " — must NOT fire")
end

-- ─────────────────────────────────────────────────────────────────────────────
-- Verbatim payloads from the captured WHMCS scan (body-borne).
-- ─────────────────────────────────────────────────────────────────────────────
only_sqli("challenge")

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

-- ─────────────────────────────────────────────────────────────────────────────
-- Wider family coverage (other DBMS / techniques sqlmap rotates through).
-- ─────────────────────────────────────────────────────────────────────────────
fires(post("q=1 AND SLEEP(5)"),                          "MySQL bare AND SLEEP")
fires(post("q=1 OR SLEEP(5)"),                           "MySQL bare OR SLEEP")
fires(post("q=1) OR BENCHMARK(5000000,MD5(0x41))-- -"),  "MySQL BENCHMARK CPU time")
fires(post("q=1 AND 1=DBMS_LOCK.SLEEP(5)"),              "Oracle DBMS_LOCK.SLEEP")
fires(post("q=1 OR 1=randomblob(1000000000)"),           "SQLite randomblob")
fires(post("q=1 AND extractvalue(1,concat(0x7e,version()))"), "MySQL error-based extractvalue")
fires(post("q=1 AND updatexml(1,concat(0x7e,user()),1)"),     "MySQL error-based updatexml")
fires(post("q=1 AND (SELECT 1 FROM(SELECT COUNT(*),concat(version(),floor(rand(0)*2))x FROM information_schema.tables GROUP BY x)a)"), "MySQL floor(rand()) error-based")

-- ─────────────────────────────────────────────────────────────────────────────
-- form-urlencoded reality: a space may arrive as '+' or '%20'; the detector
-- collapses both so spaced tokens still match.
-- ─────────────────────────────────────────────────────────────────────────────
fires(post("subject=1;waitfor+delay+'0:0:15'"),          "waitfor delay with '+' as space")
fires(post("subject=-1+OR+2%2B9-9-1=0%2B0%2B0%2B1"),     "boolean tail with %2B-encoded plus")
fires(get("id=1+AND+SLEEP(5)"),                          "GET query-arg AND SLEEP with '+'")

-- ─────────────────────────────────────────────────────────────────────────────
-- The pre-existing cheap signatures still fire (regression guard).
-- ─────────────────────────────────────────────────────────────────────────────
fires(get("id=1 UNION SELECT username,password FROM users"), "classic UNION SELECT")
fires(get("id=1' OR '1'='1"),                                "classic ' OR '1'='1")
fires(post("filter=1 AND 1=1 UNION SELECT * FROM information_schema.tables"), "information_schema")

-- ─────────────────────────────────────────────────────────────────────────────
-- Body-aware wiring: the exact same payload must be caught in the BODY (the
-- regression this change fixes), not only in the query string.
-- ─────────────────────────────────────────────────────────────────────────────
do
  only_sqli("challenge")
  -- query string clean, payload only in the POST body
  local ctx = post("name=John&email=a@b.com&message=1 OR 1=1 UNION SELECT 1,2,3")
  fires(ctx, "body-only UNION SELECT (the WHMCS-form fix)")
end

-- ─────────────────────────────────────────────────────────────────────────────
-- False-positive guards: ordinary support-ticket traffic must stay clean.
-- ─────────────────────────────────────────────────────────────────────────────
only_sqli("challenge")

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
print("ok: cfm_waf SQLi blind-family + body-scan tests (rule 301)")

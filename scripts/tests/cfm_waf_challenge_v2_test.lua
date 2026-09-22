-- Tests for the "challenge_v2" WAF rule tier (arm-surfaces slice C).
--
-- challenge_v2 is a challenge-TIER mode: at the edge it serves the same
-- challenge page as "challenge" (cfm.lua's else-branch), but the ip_push
-- carries the verbatim "challenge_v2", which the daemon records as a
-- per-(ip,host) rung mark — a solve from that pair failing the passive
-- humanity score then earns no clearance (challenge_v2.go D5). This file
-- covers the cfm_waf.lua half of the contract:
--   * set_rule / rule_mode accept "challenge_v2";
--   * severity ordering: block > challenge_v2 > challenge > logonly;
--   * challenge_v2 does NOT short-circuit evaluation (only block does);
--   * challenge_v2 uses the default TTL, not the block TTL;
--   * post_clearance_action converts challenge_v2 exactly like challenge
--     (cleared clients are never re-challenged on either rung);
--   * should_push keys challenge_v2 as its own action tier.
--
-- The operator scenario this arms (see docs/waf.md): rule_xss = "challenge_v2"
-- in cfm_waf_config.lua, tested with ?q=<script>alert('XSS')</script>.

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

local function set_only(map)
  local snap = waf.get_config()
  for k, _ in pairs(snap) do
    if k:sub(1, 5) == "rule_" then waf.set_rule(k, "disabled") end
  end
  for k, m in pairs(map) do
    local ok, err = waf.set_rule(k, m)
    check(ok == true, "set_only: set_rule(" .. k .. ", " .. tostring(m) .. ") accepted (err=" .. tostring(err) .. ")")
  end
end

local function fresh_ctx(overrides)
  local ctx = {
    uri     = "/",
    args    = "",
    method  = "GET",
    ip      = "203.0.113.42",
    headers = {},
    body    = "",
  }
  for k, v in pairs(overrides or {}) do ctx[k] = v end
  return ctx
end

-- ── 1: set_rule accepts challenge_v2; still rejects garbage ──────────────────
do
  local ok = waf.set_rule("rule_xss", "challenge_v2")
  check(ok == true, "1: set_rule(rule_xss, challenge_v2) accepted")
  local bad = waf.set_rule("rule_xss", "challenge_v3")
  check(bad == false, "1: set_rule rejects unknown mode challenge_v3")
  local snap = waf.get_config()
  check(snap.rule_xss == "challenge_v2", "1: config snapshot shows challenge_v2 (got " .. tostring(snap.rule_xss) .. ")")
end

-- ── 2: the operator's XSS test — rule 302 at challenge_v2 fires with that tier ─
-- The exact smoke-test payload the fleet operator uses against the challenge:
-- ?q=<script>alert('XSS')</script> (also asserted in its %2F-encoded form,
-- which is how it typically arrives on the wire).
do
  set_only({ rule_xss = "challenge_v2" })

  local hit, reason, ttl, action, hits, rule_id = waf.check(fresh_ctx({
    uri = "/page", args = "q=<script>alert('XSS')</script>",
  }))
  check(hit == true,                "2: xss v2 — hit=true")
  check(reason == "WAF_XSS",        "2: xss v2 — reason WAF_XSS (got " .. tostring(reason) .. ")")
  check(action == "challenge_v2",   "2: xss v2 — action challenge_v2 (got " .. tostring(action) .. ")")
  check(rule_id == 302,             "2: xss v2 — rule id 302 (got " .. tostring(rule_id) .. ")")
  check(hits and hits[1] and hits[1].action == "challenge_v2", "2: xss v2 — hits[1] carries the v2 tier")

  local hit2, _r2, _t2, action2 = waf.check(fresh_ctx({
    uri = "/page", args = "q=%3Cscript%3Ealert('XSS')%3C%2Fscript%3E",
  }))
  check(hit2 == true and action2 == "challenge_v2", "2: xss v2 — encoded form fires too")
end

-- ── 3: severity — challenge_v2 beats challenge and logonly ───────────────────
-- Bad UA fires first at plain challenge; XSS fires later at challenge_v2 and
-- must own the headline (higher severity wins, order-independent).
do
  set_only({ rule_bad_ua = "challenge", rule_xss = "challenge_v2" })

  local hit, reason, _ttl, action, hits = waf.check(fresh_ctx({
    uri     = "/login",
    args    = "q=<script>alert(1)</script>",
    method  = "POST",
    headers = { ["User-Agent"] = "" },
  }))
  check(hit == true,              "3: v2 vs challenge — hit=true")
  check(action == "challenge_v2", "3: v2 vs challenge — v2 wins (got " .. tostring(action) .. ")")
  check(reason == "WAF_XSS",      "3: v2 vs challenge — headline is the v2 rule")
  check(#hits == 2,               "3: v2 vs challenge — both hits recorded")
end

-- ── 4: severity — block still beats challenge_v2 ─────────────────────────────
-- Bad UA at challenge_v2 fires first; RCE at block fires later and must win.
do
  set_only({ rule_bad_ua = "challenge_v2", rule_rce = "block" })

  local hit, reason, _ttl, action, hits = waf.check(fresh_ctx({
    args    = "x=${jndi:ldap://",
    uri     = "/login",
    method  = "POST",
    headers = { ["User-Agent"] = "" },
  }))
  check(hit == true,         "4: v2+block — hit=true")
  check(action == "block",   "4: v2+block — block wins over challenge_v2")
  check(reason == "WAF_RCE", "4: v2+block — headline is the block rule")
  check(#hits == 2,          "4: v2+block — challenge_v2 did NOT short-circuit (both recorded)")
end

-- ── 5: TTL — challenge_v2 gets the default TTL, not the block TTL ────────────
do
  set_only({ rule_xss = "challenge_v2" })
  local snap = waf.get_config()

  local _hit, _reason, ttl = waf.check(fresh_ctx({
    uri = "/page", args = "q=<script>alert(1)</script>",
  }))
  check(ttl == snap.default_ttl_sec,
        "5: v2 ttl — default_ttl_sec (got " .. tostring(ttl) .. ", want " .. tostring(snap.default_ttl_sec) .. ")")
end

-- ── 6: post_clearance_action — challenge_v2 converts exactly like challenge ──
-- A cleared client already solved a challenge; re-serving either rung would
-- loop. Non-high-risk degrades to after_challenge, high-risk escalates.
do
  local a, conv = waf.post_clearance_action("challenge_v2", "WAF_XSS", "logonly", "block")
  check(a == "logonly" and conv == true,  "6: v2 post-clearance — WAF_XSS degrades to logonly")

  local b, conv2 = waf.post_clearance_action("challenge_v2", "WAF_RCE", "logonly", "block")
  check(b == "block" and conv2 == true,   "6: v2 post-clearance — high-risk WAF_RCE escalates to block")

  -- Loop guard: a buggy challenge-tier conversion target (either rung) must
  -- not survive — the coercion covers "challenge" AND "challenge_v2".
  local c = waf.post_clearance_action("challenge_v2", "WAF_XSS", "challenge", "challenge")
  check(c ~= "challenge" and c ~= "challenge_v2", "6: v2 post-clearance — never converts back to a challenge tier")
  local c2 = waf.post_clearance_action("challenge", "WAF_XSS", "challenge_v2", "challenge_v2")
  check(c2 == "logonly", "6: post-clearance — challenge_v2 target coerced to logonly (got " .. tostring(c2) .. ")")
  local c3 = waf.post_clearance_action("challenge", "WAF_RCE", "challenge_v2", "challenge_v2")
  check(c3 == "block", "6: post-clearance — high-risk challenge_v2 target coerced to block (got " .. tostring(c3) .. ")")

  -- Non-challenge tiers still pass through untouched.
  local d, conv3 = waf.post_clearance_action("block", "WAF_RCE", "logonly", "block")
  check(d == "block" and conv3 == false,  "6: post-clearance — block passes through unconverted")
end

-- ── 7: should_push — challenge_v2 is its own cooldown tier ───────────────────
-- A plain-challenge push must not consume the window for a later v2 push of
-- the same family (and vice versa): the v2 push is what writes the rung mark
-- daemon-side, so suppressing it would silently downgrade the rung.
do
  local store = {}
  local sh = {
    add = function(_, k, v, _ttl)
      if store[k] ~= nil then return false, "exists" end
      store[k] = v
      return true
    end,
  }
  local IP = "203.0.113.99"
  check(waf.should_push(sh, IP, "WAF_XSS", "challenge") == true,     "7: first challenge push goes out")
  check(waf.should_push(sh, IP, "WAF_XSS", "challenge_v2") == true,  "7: v2 push not masked by the challenge window")
  check(waf.should_push(sh, IP, "WAF_XSS", "challenge_v2") == false, "7: second v2 push within the window deduped")
  check(store["wafpush|WAF_XSS|challenge_v2|" .. IP] ~= nil,         "7: v2 cooldown key carries the v2 tier")
end

if fails > 0 then
  io.stderr:write(fails .. " failure(s)\n")
  os.exit(1)
end
print("OK cfm_waf_challenge_v2_test")

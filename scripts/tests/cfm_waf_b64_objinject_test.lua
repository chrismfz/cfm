-- Tests for the base64 PHP-object-injection sub-rule of detect_b64_injection
-- (WAF_B64_INJECT:B64_OBJ_INJECT, rule 304). Audit F13.
--
-- The sub-rule used to test d:match('%bo%:%d+%:"') / d:match('%bc%:%d+%:"').
-- Lua's %bxy takes the TWO bytes after %b as the balanced delimiters, so %bo%
-- means "balanced o … %" — and a decoded serialized object (o:8:"stdclass")
-- never contains '%', so the match was always nil and the sub-rule was dead.
-- The fix matches frontier-anchored object headers o:<len>:" / c:<len>:" so
-- the marker must START a token (a word ending in o/c like foo:12:"bar" can't
-- false-match), objects only (no a:<len>:{ arrays).
--
-- Rule 304 ships at `challenge`. Because this sub-rule was dead, it burns in at
-- logonly first (F11-style per-tag split): B64_OBJ_INJECT is capped to logonly
-- while the clearly-hostile siblings keep the rule's configured tier.

-- ── ngx mock. decode_base64 is a lookup keyed by the exact base64 candidate the
--    detector's gmatch extracts (=([A-Za-z0-9+/]+=*)), so no real codec needed. ──
local DECODE = {}
_G.ngx = {
  now           = function() return 1000 end,
  decode_base64 = function(c) return DECODE[c] end,
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

local function disable_all_rules()
  local snap = waf.get_config()
  for k, _ in pairs(snap) do
    if k:sub(1, 5) == "rule_" then
      waf.set_rule(k, "disabled")
    end
  end
end

-- POST + non-empty body satisfies the section-33 body_inspect_ok gate.
local function ctx(body)
  return {
    uri     = "/upload/process.php",
    args    = "",
    method  = "POST",
    ip      = "203.0.113.7",
    headers = { ["Content-Type"] = "application/x-www-form-urlencoded" },
    body    = body,
  }
end

-- Distinct base64-shaped candidates (>=24 [A-Za-z0-9+/], no interior '='); the
-- plaintext each "decodes" to is what actually drives the sub-rule.
local CAND_OBJ  = "T2JqZWN0SW5qZWN0aW9uUGF5bG9hZEFBQUFBQQ"
local CAND_CUST = "Q3VzdG9tU2VyaWFsaXplZE9iamVjdEFBQUFBQQ"
local CAND_NEST = "TmVzdGVkT2JqZWN0SW5BcnJheUFBQUFBQUFBQQ"
local CAND_FP   = "Rm9vQmFyQmF6UXV4UGFkZGluZ0FBQUFBQUFBQQ"
local CAND_EVAL = "RXZhbFNpYmxpbmdOb3RDYXBwZWRBQUFBQUFBQQ"
DECODE[CAND_OBJ]  = 'O:8:"stdClass":1:{s:1:"cmd";s:2:"id";}'  -- top-level object
DECODE[CAND_CUST] = 'C:11:"ArrayObject":0:{}'                 -- custom-serialized
DECODE[CAND_NEST] = 'a:1:{i:0;O:4:"Evil":0:{}}'               -- object nested in array
DECODE[CAND_FP]   = 'foo:12:"bar baz qux extra"'              -- word ending in o, NOT an object marker
DECODE[CAND_EVAL] = 'eval(getenv("x"));'                      -- a hostile sibling (B64_EVAL)

-- ── Tier pin: the scanner ships challenge_v2. Guard against silent drift. ─────
-- Promoted challenge→challenge_v2 2026-09-23 (whole challenge tier; attack-only
-- POST-body base64 scanner, a real user's solve still passes).
do
  local snap = waf.get_config()
  check(snap.rule_b64_injection == "challenge_v2",
        "rule 304 (b64 scanner) shipped default is challenge_v2")
end

-- ── Positive: top-level object O:<len>:"Class" fires, but burns in at logonly ─
-- Rule set to challenge; the object tag must be CAPPED to logonly.
do
  disable_all_rules()
  waf.set_rule("rule_b64_injection", "challenge")

  local hit, reason, _ttl, action = waf.check(ctx("data=" .. CAND_OBJ))
  check(hit == true,                               "O: object — hit=true")
  check(reason == "WAF_B64_INJECT:B64_OBJ_INJECT", "O: object — reason (got " .. tostring(reason) .. ")")
  check(action == "logonly",                       "O: object — burns in at logonly despite rule=challenge (got " .. tostring(action) .. ")")
end

-- ── Positive: custom-serialized object C:<len>:"Class" fires (capped logonly) ─
do
  disable_all_rules()
  waf.set_rule("rule_b64_injection", "challenge")

  local hit, reason, _ttl, action = waf.check(ctx("data=" .. CAND_CUST))
  check(hit == true,                               "C: custom object — hit=true")
  check(reason == "WAF_B64_INJECT:B64_OBJ_INJECT", "C: custom object — reason (got " .. tostring(reason) .. ")")
  check(action == "logonly",                       "C: custom object — capped logonly")
end

-- ── Positive: an object nested inside a serialized array still fires ──────────
do
  disable_all_rules()
  waf.set_rule("rule_b64_injection", "challenge")

  local hit, reason = waf.check(ctx("data=" .. CAND_NEST))
  check(hit == true,                               "nested O: object — hit=true")
  check(reason == "WAF_B64_INJECT:B64_OBJ_INJECT", "nested O: object — reason (got " .. tostring(reason) .. ")")
end

-- ── Sibling is NOT capped: a hostile B64_EVAL keeps the rule's challenge tier ─
-- Proves the burn-in downgrade is scoped to the object tag only.
do
  disable_all_rules()
  waf.set_rule("rule_b64_injection", "challenge")

  local hit, reason, _ttl, action = waf.check(ctx("data=" .. CAND_EVAL))
  check(hit == true,                          "B64_EVAL sibling — hit=true")
  check(reason == "WAF_B64_INJECT:B64_EVAL",  "B64_EVAL sibling — reason (got " .. tostring(reason) .. ")")
  check(action == "challenge",                "B64_EVAL sibling — keeps challenge (burn-in is object-only, got " .. tostring(action) .. ")")
end

-- ── FP-negative: a word ending in o followed by :<digits>:" is NOT an object ──
-- The %f[%a] frontier is what keeps foo:12:"bar" from false-matching; a plain
-- o:%d+:" pattern would fire here.
do
  disable_all_rules()
  waf.set_rule("rule_b64_injection", "challenge")

  local hit = waf.check(ctx("data=" .. CAND_FP))
  check(hit == false, "foo:12:\"bar\" — must NOT false-match the object sub-rule (hit=false)")
end

-- ── Disabling rule 304 silences the object tag too (outer gate respected) ─────
do
  disable_all_rules()
  waf.set_rule("rule_b64_injection", "disabled")

  local hit = waf.check(ctx("data=" .. CAND_OBJ))
  check(hit == false, "rule 304 disabled — object tag stays silent (hit=false)")
end

-- ── No-downgrade: a hostile sibling must win over an object marker so the object
--    tag (capped to logonly) can never shadow eval/system/sqli down from challenge.
--    These are the exact bypass shapes the F13 review flagged.
-- Same-candidate: one blob carrying BOTH an object header AND `union select`.
-- The object check is ordered last + deferred, so the SQLi sibling wins.
local CAND_OBJ_SQLI = "T2JqUGx1c1VuaW9uU2FtZUNhbmRpZGF0ZUFBQQ"
DECODE[CAND_OBJ_SQLI] = 'O:8:"stdClass":0:{} union select 1,2,3'
do
  disable_all_rules()
  waf.set_rule("rule_b64_injection", "challenge")

  local hit, reason, _ttl, action = waf.check(ctx("data=" .. CAND_OBJ_SQLI))
  check(hit == true,                                "same-candidate obj+sqli — hit=true")
  check(reason == "WAF_B64_INJECT:B64_SQLI_UNION",
        "same-candidate obj+sqli — SQLi sibling wins, not object (got " .. tostring(reason) .. ")")
  check(action == "challenge",
        "same-candidate obj+sqli — stays challenge, NOT downgraded to logonly (got " .. tostring(action) .. ")")
end

-- Cross-candidate: object marker in an EARLIER candidate, `system(` in a LATER
-- one. First-match-wins would have returned the object (logonly) and never
-- reached system; the deferred fallback must scan on and let system win.
do
  disable_all_rules()
  waf.set_rule("rule_b64_injection", "challenge")

  local hit, reason, _ttl, action = waf.check(ctx("state=" .. CAND_OBJ .. "&payload=" .. CAND_EVAL))
  check(hit == true,                            "cross-candidate obj+eval — hit=true")
  check(reason == "WAF_B64_INJECT:B64_EVAL",
        "cross-candidate obj-then-eval — hostile sibling wins (got " .. tostring(reason) .. ")")
  check(action == "challenge",
        "cross-candidate obj+eval — stays challenge, NOT downgraded (got " .. tostring(action) .. ")")
end

-- Block-arm: when an operator raises rule 304 to block, an object marker must not
-- downgrade a base64'd system() (which also feeds autoblock) to logonly.
do
  disable_all_rules()
  waf.set_rule("rule_b64_injection", "block")

  local hit, reason, _ttl, action = waf.check(ctx("state=" .. CAND_OBJ .. "&payload=" .. CAND_EVAL))
  check(hit == true,                          "block-arm cross-candidate — hit=true")
  check(reason == "WAF_B64_INJECT:B64_EVAL",  "block-arm — hostile sibling wins (got " .. tostring(reason) .. ")")
  check(action == "block",                    "block-arm — stays block, NOT downgraded to logonly (got " .. tostring(action) .. ")")
end

-- ── Pure array (no object) does NOT trip the object sub-rule (arrays excluded) ─
local CAND_ARR = "UHVyZUFycmF5Tm9PYmplY3RIZXJlQUFBQUFBQQ"
DECODE[CAND_ARR] = 'a:2:{i:0;s:1:"x";i:1;s:1:"y";}'
do
  disable_all_rules()
  waf.set_rule("rule_b64_injection", "challenge")

  local hit = waf.check(ctx("data=" .. CAND_ARR))
  check(hit == false, "pure a: array — NOT flagged (only objects drive POP chains)")
end

if fails > 0 then
  io.stderr:write("\n" .. fails .. " test(s) failed in cfm_waf_b64_objinject_test.lua\n")
  os.exit(1)
end
io.stdout:write("ok: cfm_waf base64 PHP-object-injection tests (rule 304, F13 revive + logonly burn-in)\n")

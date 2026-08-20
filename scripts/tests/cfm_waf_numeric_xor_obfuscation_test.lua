-- Tests for the generic phpfuck / numeric-XOR obfuscation detector
-- (rule 439, WAF_BACKDOOR, ships logonly — best-effort visibility for a phpfuck
-- payload against any restricted-charset eval() sink, e.g. vBulletin runMaths /
-- CVE-2026-61511). A phpfuck payload builds arbitrary PHP from XOR (^) of
-- parenthesised digit literals, so it is a long TIGHT run of only [0-9().^] with
-- a storm of parens, ^ and concatenation dots — the shape has_phpfuck_blob keys
-- on. The tight charset is deliberate: operators/spaces/letters fragment the run
-- (that is what keeps ordinary math/code from scoring), at the cost of documented
-- residuals (no-op / strip-char interspersing evades). An endpoint-anchored BLOCK
-- companion (CVE rule 10015) was REMOVED for FP-banning spaced math forum posts;
-- this rule must never be promoted above logonly.

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
  for k, m in pairs(map) do waf.set_rule(k, m) end
end

-- Non-/wp-admin body-carrying POST (mirrors the backdoor suite: exercise the
-- detector at a public endpoint free of the /wp-admin/ carve-outs).
local function ctx(body, ct)
  return { uri = "/upload/process.php", args = "", method = "POST", ip = "203.0.113.7",
           headers = { ["Content-Type"] = ct or "application/x-www-form-urlencoded" },
           body = body or "", cookie = "" }
end

local function fires(body, label, ct)
  local hit, reason = waf.check(ctx(body, ct))
  check(hit == true, label .. " — hit=true (got " .. tostring(hit) .. ")")
  check(reason == "WAF_BACKDOOR:NUMERIC_XOR_OBFUSCATION",
        label .. " — reason (got " .. tostring(reason) .. ")")
end
local function clean(body, label)
  local hit = waf.check(ctx(body))
  check(hit ~= true, label .. " — must NOT fire (got hit=" .. tostring(hit) .. ")")
end

set_only({ rule_php_numeric_xor_obfuscation = "logonly" })

local CHR = "((((99999999999999999999).(9))^((2).(0).(4)))^((8).(6).(((9).(9))^((9).(9)))))"
local PHPFUCK = CHR .. "((6).(5))." .. CHR .. "((7).(3))." .. CHR .. "((1).(2).(1))"
local ENC = (PHPFUCK:gsub("[%(%)%^]", { ["("] = "%28", [")"] = "%29", ["^"] = "%5E" }))

-- ── Positives ───────────────────────────────────────────────────────────────
fires("x=" .. PHPFUCK, "phpfuck blob in a form field (any endpoint)")
fires("x=" .. ENC, "url-encoded phpfuck blob (normalize decodes before scan)")
fires('{"q":"' .. PHPFUCK .. '"}', "phpfuck blob inside a JSON body", "application/json")

-- ── Negatives ───────────────────────────────────────────────────────────────
clean("page=2", "plain integer parameter")
clean("expr=(1+2)^3", "short real arithmetic — below thresholds")
clean("coords=(41.9).(12.5)", "a couple of parenthesised numbers, no ^ storm")
-- Literal-prefilter fast path: a long digit/paren/dot run with NO `^` caret can
-- never reach min_caret, so has_phpfuck_blob returns before the gmatch scan —
-- a JSON-number-heavy body is the common case this skips. Must stay clean.
clean('{"m":[(11).(22).(33).(44).(55).(66).(77).(88).(99).(1234567890)]}',
      "prefilter: long digit/paren run, no caret → clean", "application/json")
clean("body=hello world, this is ordinary text with (parentheses).", "ordinary prose")
-- FP regressions (red-team 2026-08): legit code/math bodies must not log-flag.
-- With the TIGHT `[0-9().^]` run charset, operators and spaces fragment the run,
-- so no single run carries the full paren+caret+dot storm.
clean("message=[code](a^b)+(c^d)+(e^f)+(g^h)+(i^j); (1.5+2.5+3.5)/(2.0*2.0); ((p*q)/(r+s))[/code]",
      "FP: forum C/bit-twiddling code block")
clean("message=f(n)=(a^n)+(b^n)-(c^n) where a=(1.5),b=(2.5),c=(3.5). g(x)=(x^2)+(x^3) at (0.1),(0.2),(0.3).",
      "FP: math/CAS post")
-- The FP-BAN that killed the block-tier CVE rule: a spaced math series whose
-- form-urlencoded spaces arrive as `+`. The tight charset makes the `+`
-- (and literal operators) fragment the run, so it must stay CLEAN here too.
clean("message=(1.5)^2+%2B+(2.5)^2+%2B+(3.5)^2+%2B+(4.5)^2+%2B+(5.5)^2+%2B+(6.5)^2+%2B+(7.5)^2+%2B+(8.5)^2+%2B+(9.5)^2",
      "FP: spaced math series (spaces->'+') — tight charset fragments on '+'")
clean("", "empty body")

if fails > 0 then
  io.stderr:write(("cfm_waf numeric-XOR obfuscation tests: %d FAILED\n"):format(fails))
  os.exit(1)
end
print("ok: cfm_waf generic phpfuck / numeric-XOR obfuscation (rule 439)")

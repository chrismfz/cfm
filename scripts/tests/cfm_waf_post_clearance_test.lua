-- Tests for cfm_waf post-clearance helpers (Step 3 of the WAF rework):
--   _M.is_high_risk_reason(reason)
--   _M.post_clearance_action(action, reason, after_challenge, after_high_risk)
--
-- These are pure functions, so the harness is just a stub ngx for the module
-- to load.

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

-- ── is_high_risk_reason ─────────────────────────────────────────────────────

-- Bare family names match.
check(waf.is_high_risk_reason("WAF_RCE")              == true,  "bare WAF_RCE high-risk")
check(waf.is_high_risk_reason("WAF_UPLOAD_CONTENT")   == true,  "bare WAF_UPLOAD_CONTENT high-risk")
check(waf.is_high_risk_reason("WAF_SHELLSHOCK")       == true,  "bare WAF_SHELLSHOCK high-risk")
check(waf.is_high_risk_reason("WAF_TRAVERSAL")        == true,  "bare WAF_TRAVERSAL high-risk")
check(waf.is_high_risk_reason("WAF_XXE")              == true,  "bare WAF_XXE high-risk")

-- Family:tag forms also match (prefix-based).
check(waf.is_high_risk_reason("WAF_RCE:REVERSE_SHELL")              == true,  "WAF_RCE:tag high-risk")
check(waf.is_high_risk_reason("WAF_UPLOAD_CONTENT:UPLOAD_PHP_TAG")  == true,  "WAF_UPLOAD_CONTENT:tag high-risk")
check(waf.is_high_risk_reason("WAF_PHP_WEBSHELL_BODY:b374k")        == true,  "WAF_PHP_WEBSHELL_BODY:tag high-risk")
check(waf.is_high_risk_reason("WAF_CMD_PAYLOAD:PAY_PIPE_BASH")      == true,  "WAF_CMD_PAYLOAD:tag high-risk")

-- Noisy / non-high-risk families don't match.
check(waf.is_high_risk_reason("WAF_BAD_UA")              == false, "WAF_BAD_UA not high-risk")
check(waf.is_high_risk_reason("WAF_BAD_UA:sqlmap")       == false, "WAF_BAD_UA:tag not high-risk")
check(waf.is_high_risk_reason("WAF_XSS")                 == false, "WAF_XSS not high-risk (noisy)")
check(waf.is_high_risk_reason("WAF_SQLI")                == false, "WAF_SQLI not high-risk (noisy)")
check(waf.is_high_risk_reason("WAF_AUTH_BURST")          == false, "WAF_AUTH_BURST not high-risk")
check(waf.is_high_risk_reason("WAF_DEBUG_TOGGLE:xdebug") == false, "WAF_DEBUG_TOGGLE:tag not high-risk")

-- Empty / malformed inputs.
check(waf.is_high_risk_reason("")           == false, "empty string not high-risk")
check(waf.is_high_risk_reason(nil)          == false, "nil not high-risk")
check(waf.is_high_risk_reason("UNKNOWN")    == false, "unknown family not high-risk")
check(waf.is_high_risk_reason(":WAF_RCE")   == false, "leading colon should not match WAF_RCE")

-- ── post_clearance_action ───────────────────────────────────────────────────

-- challenge + high-risk reason → high-risk default (block).
do
  local act, did = waf.post_clearance_action("challenge", "WAF_RCE:REVERSE_SHELL", "logonly", "block")
  check(act == "block" and did == true, "challenge+high-risk should escalate to block")
end

-- challenge + noisy reason → low-risk default (logonly).
do
  local act, did = waf.post_clearance_action("challenge", "WAF_XSS", "logonly", "block")
  check(act == "logonly" and did == true, "challenge+noisy should degrade to logonly")
end

-- challenge + nil reason → low-risk default.
do
  local act, did = waf.post_clearance_action("challenge", nil, "logonly", "block")
  check(act == "logonly" and did == true, "challenge+nil reason should degrade to logonly")
end

-- block passes through unchanged regardless of reason.
do
  local act, did = waf.post_clearance_action("block", "WAF_RCE", "logonly", "block")
  check(act == "block" and did == false, "block passes through unconverted")
  local act2, did2 = waf.post_clearance_action("block", "WAF_BAD_UA", "logonly", "block")
  check(act2 == "block" and did2 == false, "block passes through even with noisy reason")
end

-- logonly passes through unchanged.
do
  local act, did = waf.post_clearance_action("logonly", "WAF_RCE", "logonly", "block")
  check(act == "logonly" and did == false, "logonly passes through unconverted")
end

-- Custom defaults are honoured (e.g. operator picks logonly for high-risk).
do
  local act, did = waf.post_clearance_action("challenge", "WAF_RCE", "logonly", "logonly")
  check(act == "logonly" and did == true, "custom after_high_risk=logonly should win")
end

-- Missing defaults fall back to "block" / "logonly" so cfm.lua can pass nil
-- without re-implementing the safe defaults.
do
  local act, did = waf.post_clearance_action("challenge", "WAF_RCE", nil, nil)
  check(act == "block" and did == true, "default after_high_risk should be block")
  local act2, did2 = waf.post_clearance_action("challenge", "WAF_BAD_UA", nil, nil)
  check(act2 == "logonly" and did2 == true, "default after_challenge should be logonly")
end

-- Defence in depth: if a buggy caller passes "challenge" as a default,
-- post_clearance_action must coerce it to a safe value (block for the
-- high-risk slot, logonly for the noisy slot). cfm.lua's CFG sanitizer is
-- the primary guard; this is the secondary one.
do
  local act, did = waf.post_clearance_action("challenge", "WAF_BAD_UA", "challenge", "block")
  check(act == "logonly" and did == true, "after_challenge='challenge' must coerce to logonly")
end
do
  local act, did = waf.post_clearance_action("challenge", "WAF_RCE", "logonly", "challenge")
  check(act == "block" and did == true, "after_high_risk='challenge' must coerce to block")
end
do
  local act, did = waf.post_clearance_action("challenge", "WAF_BAD_UA", "challenge", "challenge")
  check(act == "logonly" and did == true, "both='challenge' must still pick safe noisy default")
end

-- ── set_rule guards ─────────────────────────────────────────────────────────

-- Name must be a string starting with "rule_": prevents typos from
-- corrupting non-rule CFG fields.
do
  local ok, err = waf.set_rule("rule_traversal", "logonly")
  check(ok == true, "set_rule(rule_traversal, logonly) accepted")
  ok, err = waf.set_rule("max_scan_len", "block")
  check(ok == false and err ~= nil, "set_rule rejects non-rule_ name")
  ok, err = waf.set_rule("", "logonly")
  check(ok == false, "set_rule rejects empty name")
  ok, err = waf.set_rule(nil, "logonly")
  check(ok == false, "set_rule rejects nil name")
  ok, err = waf.set_rule("rule_traversal", "garbage")
  check(ok == false and err ~= nil, "set_rule rejects unknown mode")
  ok, err = waf.set_rule("rule_traversal", nil)
  check(ok == false, "set_rule rejects nil mode")
  -- Confirm the corruption attempt didn't actually mutate max_scan_len.
  local snap = waf.get_config()
  check(type(snap.max_scan_len) == "number",
        "max_scan_len remained numeric after rejected set_rule call")
end

if fails > 0 then
  io.stderr:write(string.format("\n%d post-clearance test(s) failed\n", fails))
  os.exit(1)
end
print("ok: cfm_waf post-clearance helper tests")

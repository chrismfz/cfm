-- Tests that the three SQLi detectors share ONE comment-strip per scan surface
-- (audit F30b).
--
-- detect_sqli, detect_sqli_blind_lexical and detect_sqli_union_variant each used
-- to call sqli_scan_strings (strip_sql_comments + a '+'/whitespace collapse) on
-- the SAME scan string — 3× redundant per surface, and the engine runs both the
-- URI+args and args+body surfaces, so 6× per request. The fix moves the strip
-- into two memoized engine getters (get_sqli_ua / get_sqli_ab) and passes the
-- (sc, scw) pair into the detectors, so it runs once per surface.
--
-- We drive the REAL engine (waf.check) and count how many times the engine
-- computes the pair by wrapping the exported det.sqli_scan_strings — the only
-- caller of it now is the two getters, so the count IS the number of strips.

_G.ngx = {
  now           = function() return 1000 end,
  decode_base64 = function(_) return nil end,
  log           = function(_, _) end,
  ERR           = 0, WARN = 1, INFO = 2,
}

package.path = "configs/lua/?.lua;" .. package.path
local waf = require("cfm_waf")
local det = require("cfm_waf_detectors")   -- same cached table the engine uses

-- Make sure all three SQLi rules are enabled so all three run each request.
waf.set_rule("rule_sqli",               "challenge")
waf.set_rule("rule_sqli_blind_lexical", "logonly")
waf.set_rule("rule_sqli_union_variant", "logonly")

-- Count strip computations by wrapping the exported helper the getters call.
local orig  = det.sqli_scan_strings
local strips = 0
det.sqli_scan_strings = function(...) strips = strips + 1; return orig(...) end

local fails = 0
local function check(cond, msg)
  if cond then return end
  fails = fails + 1
  io.stderr:write("FAIL: " .. msg .. "\n")
end

-- Browser-like headers so the bad-UA scorer (empty UA/Accept/Referer) stays
-- silent — it fires at `challenge` and wouldn't affect the strip count (it
-- doesn't goto-done), but keeping requests genuinely clean makes the intent
-- and the `hit ~= true` assertions clear.
local function h(extra)
  local base = {
    ["User-Agent"] = "Mozilla/5.0 (X11; Linux x86_64; rv:120.0) Gecko/20100101 Firefox/120.0",
    ["Accept"]     = "text/html,application/xhtml+xml",
    ["Referer"]    = "https://example.com/",
  }
  if extra then for k, v in pairs(extra) do base[k] = v end end
  return base
end

-- ── One strip for the URI surface (GET, no body): 3 rules share it ───────────
do
  strips = 0
  local hit = waf.check({ uri = "/index.php", args = "id=42&q=hello",
                          method = "GET", ip = "203.0.113.7", headers = h(), body = "" })
  check(hit ~= true, "clean GET does not fire the WAF")
  check(strips == 1,
        "F30b: the 3 SQLi rules share ONE strip on the URI surface (got " .. strips .. ")")
end

-- ── One strip per surface for a POST that reaches the body scan: URI + body ──
do
  strips = 0
  local hit = waf.check({ uri = "/submitticket.php", args = "",
                          method = "POST", ip = "203.0.113.8",
                          headers = h({ ["Content-Type"] = "application/x-www-form-urlencoded" }),
                          body = "subject=hello&message=world" })
  check(hit ~= true, "clean POST does not fire the WAF")
  check(strips == 2,
        "F30b: one strip per surface (URI + body) = 2 for a clean POST (got " .. strips .. ")")
end

-- ── Detection is unchanged by the refactor ───────────────────────────────────
do
  local hit, reason = waf.check({ uri = "/index.php", args = "id=1 union select 1,2,3",
                                  method = "GET", ip = "203.0.113.9", headers = h(), body = "" })
  check(hit == true,             "union select still fires (hit=true)")
  check(reason == "WAF_SQLI",    "union select reason is WAF_SQLI (got " .. tostring(reason) .. ")")

  -- A logonly-tier lexical token still routes through the shared pair too.
  local h2, r2 = waf.check({ uri = "/x", args = "id=1 and extractvalue(1,concat(0x7e,version()))",
                             method = "GET", ip = "203.0.113.10", headers = h(), body = "" })
  check(h2 == true,                    "extractvalue( still fires (hit=true)")
  check(r2 == "WAF_SQLI_LEXICAL",      "extractvalue( reason is WAF_SQLI_LEXICAL (got " .. tostring(r2) .. ")")
end

det.sqli_scan_strings = orig

if fails > 0 then
  io.stderr:write("\n" .. fails .. " test(s) failed in cfm_waf_sqli_memoize_test.lua\n")
  os.exit(1)
end
io.stdout:write("ok: SQLi detectors share one comment-strip per surface (F30b)\n")

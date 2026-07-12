-- Tests for is_known_legit_xmlrpc (audit F24).
--
-- The predicate runs on the WAF hot path (cfm_waf.lua sections 26 & 28) for every
-- request, but only /xmlrpc.php traffic can be "legit xmlrpc". It used to
-- normalize (double-url-decode + lowercase + cap) both args AND body BEFORE the
-- cheap /xmlrpc.php URI check — pure waste on the ~99% of non-xmlrpc requests.
-- The fix gates on the URI first. These tests prove the short-circuit (a
-- non-xmlrpc URI performs ZERO normalize calls) and that xmlrpc/Jetpack
-- detection is unchanged.

package.path = "configs/lua/?.lua;" .. package.path
local det = require("cfm_waf_detectors")

-- Inject util helpers, with `normalize` as a counting spy so we can assert the
-- expensive path is skipped for non-xmlrpc URIs.
local normalize_calls = 0
det.init({ max_scan_len = 4096 }, {
  has   = function(h, n) return h ~= nil and n ~= nil and h:find(n, 1, true) ~= nil end,
  lower = string.lower,
  cap   = function(s, n) if #s > n then return s:sub(1, n) end return s end,
  normalize = function(s) normalize_calls = normalize_calls + 1; return s end,
})

local fails = 0
local function check(cond, msg)
  if cond then return end
  fails = fails + 1
  io.stderr:write("FAIL: " .. msg .. "\n")
end

local function reset() normalize_calls = 0 end

-- ── F24: a non-/xmlrpc.php request short-circuits BEFORE normalize ───────────
-- Even with jetpack markers in args/body, a non-xmlrpc URI returns false without
-- normalizing anything.
reset()
check(det.is_known_legit_xmlrpc("/search?q=hello", "for=jetpack", {}, "jetpack") == false,
      "non-xmlrpc URI -> false")
check(normalize_calls == 0,
      "F24: non-xmlrpc URI must NOT normalize args/body (got " .. normalize_calls .. " call(s))")

-- ── Behavior unchanged for real /xmlrpc.php traffic ─────────────────────────
reset()
check(det.is_known_legit_xmlrpc("/xmlrpc.php", "for=jetpack", {}, "") == true,
      "xmlrpc + for=jetpack args -> true")
check(normalize_calls > 0, "xmlrpc path still normalizes (Jetpack detection intact)")

check(det.is_known_legit_xmlrpc("/xmlrpc.php?rest=1", "", {}, "hello jetpack world") == true,
      "xmlrpc + jetpack body -> true")

check(det.is_known_legit_xmlrpc("/xmlrpc.php", "", { ["user-agent"] = "Jetpack/9.9" }, "") == true,
      "xmlrpc + Jetpack UA -> true")
check(det.is_known_legit_xmlrpc("/xmlrpc.php", "", { ["User-Agent"] = "WordPress.com" }, "") == true,
      "xmlrpc + WordPress.com UA (capitalized header key) -> true")

-- A real /xmlrpc.php request without any Jetpack marker is NOT auto-legit.
check(det.is_known_legit_xmlrpc("/xmlrpc.php", "q=x", {}, "generic body") == false,
      "xmlrpc without jetpack markers -> false")

-- The gate is case-insensitive (uri is lower()ed first), so an uppercase URI is
-- still routed to the xmlrpc path — not accidentally short-circuited.
reset()
check(det.is_known_legit_xmlrpc("/XMLRPC.PHP", "for=jetpack", {}, "") == true,
      "uppercase /XMLRPC.PHP + jetpack -> true (gate lower()s the URI)")
check(normalize_calls > 0, "uppercase xmlrpc URI still reaches the normalize path")

-- nil args/body/headers must not error and still short-circuit for non-xmlrpc.
reset()
check(det.is_known_legit_xmlrpc("/wp-login.php", nil, nil, nil) == false,
      "non-xmlrpc with nil args/body/headers -> false")
check(normalize_calls == 0, "F24: nil-args non-xmlrpc still skips normalize")

if fails > 0 then
  io.stderr:write("\n" .. fails .. " test(s) failed in cfm_waf_xmlrpc_gate_test.lua\n")
  os.exit(1)
end
io.stdout:write("ok: is_known_legit_xmlrpc URI-first gate (F24)\n")

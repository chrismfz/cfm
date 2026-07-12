-- Tests for cfm_clearance.normalize_host IPv6-literal handling (audit F40).
--
-- The old normalizer stripped a trailing ":<digits>" as if always a port, which
-- for an UNBRACKETED IPv6 literal deleted the final hextet (2001:db8::1 ->
-- "2001:db8:") and never unwrapped brackets — so distinct IPv6 hosts collapsed
-- to one value and a clearance minted for one was accepted on an adjacent one.
-- The fix mirrors Go's normalizeClearanceHost (challenge_server.go): unwrap
-- [ ... ] and strip a port only for a single-colon host:port; an unbracketed
-- literal (>=2 colons) is left intact.
--
-- The Go-parity block below is copied verbatim from
-- internal/webdetector/challenge_server_clearance_test.go TestNormalizeClearanceHost
-- — keep the two in sync so the server-minted host and the Lua-validated host
-- always normalize identically.

package.loaded["cjson.safe"] = { encode = function() end, decode = function() end }
package.loaded["cjson"]      = package.loaded["cjson.safe"]
_G.ngx = _G.ngx or {}

package.path = "configs/lua/?.lua;" .. package.path
local clearance = require("cfm_clearance")
local nh = clearance.normalize_host

local fails = 0
local function eq(input, want, label)
  local got = nh(input)
  if got == want then return end
  fails = fails + 1
  io.stderr:write(string.format("FAIL: %s — normalize_host(%q) = %q, want %q\n", label, input, got, want))
end
local function check(cond, msg)
  if cond then return end
  fails = fails + 1
  io.stderr:write("FAIL: " .. msg .. "\n")
end

-- ── Go parity: verbatim from Go TestNormalizeClearanceHost ───────────────────
eq("Example.COM.",         "example.com",   "go-parity trailing dot + case")
eq("example.com:443",      "example.com",   "go-parity host:port")
eq("[2001:db8::1]:8443",   "2001:db8::1",   "go-parity bracketed ipv6 + port")
eq("[2001:DB8::1].",       "2001:db8::1",   "go-parity bracketed ipv6 + trailing dot + case")
eq("MiXeD.Example.com:80", "mixed.example.com", "go-parity mixed case host:port")

-- ── F40: IPv6 literals no longer collide / lose a hextet ─────────────────────
eq("2001:db8::1", "2001:db8::1", "F40: unbracketed ipv6 left intact")
eq("2001:db8::2", "2001:db8::2", "F40: unbracketed ipv6 left intact (2)")
eq("::1",         "::1",         "F40: ipv6 loopback intact")
eq("[::1]:53",    "::1",         "F40: bracketed ipv6 loopback + port")
check(nh("2001:db8::1") ~= nh("2001:db8::2"),
      "F40: distinct unbracketed IPv6 hosts must NOT normalize equal (no host-binding bypass)")
check(nh("[2001:db8::1]") ~= nh("[2001:db8::2]"),
      "F40: distinct bracketed IPv6 hosts must NOT normalize equal")

-- ── Regression: ordinary hosts unchanged ─────────────────────────────────────
eq("example.com",      "example.com", "plain host")
eq("example.com:8080", "example.com", "host:port")
eq("  Host:443  ",     "host",        "whitespace + case + port")
eq("host",             "host",        "bare host")
eq("",                 "",            "empty")
-- Non-numeric port: Go's SplitHostPort strips it (any single-colon suffix); the
-- OLD numeric-only `:%d+$` would have LEFT "host:abc" — clearest Go-parity case.
eq("host:abc",         "host",        "F40/parity: non-numeric single-colon port stripped")

if fails > 0 then
  io.stderr:write("\n" .. fails .. " test(s) failed in cfm_clearance_host_test.lua\n")
  os.exit(1)
end
io.stdout:write("ok: cfm_clearance normalize_host IPv6-literal handling, Go-parity (F40)\n")

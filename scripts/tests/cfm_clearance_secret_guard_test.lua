-- Tests that cfm_clearance._M.validate fails CLOSED on a nil/empty HMAC secret
-- (audit F47 hardening).
--
-- The bridge token IS the clearance HMAC secret. Before F47, a missing token
-- 500'd every request, so validate never ran with a nil secret. F47 makes a
-- missing token fail OPEN instead — so validate now runs with secret=nil during
-- the token-missing window. hmac_sha256_hex coerces a nil secret to key="" and
-- computes a real HMAC with an EMPTY key, which is PUBLICLY COMPUTABLE — so an
-- attacker could forge a clearance that validate would accept, which
-- short-circuits forced-challenge gates and downgrades challenge-tier WAF
-- verdicts. mint() already refuses a nil/empty secret; validate() now does too.
--
-- We drive the REAL cfm_clearance module. We install a deterministic
-- ngx.hmac_sha256 (validate's preferred backend), craft a token whose hmac
-- matches the EMPTY-KEY result, and assert validate REJECTS it. Reverting the
-- guard makes that exact forged token validate true — the security flip.

-- cjson stub (module requires it at load; we only need decode to return our obj).
local forged_obj
package.loaded["cjson.safe"] = {
  encode = function(_) return "{}" end,
  decode = function(s) if s == "RAW_FORGED" then return forged_obj end return nil end,
}
package.loaded["cjson"] = package.loaded["cjson.safe"]

-- Deterministic 32-byte "HMAC" (NOT real crypto — only needs to be consistent
-- between craft-time and validate's check-time so the compare is exercised).
local function fake_hmac(key, msg)
  local s = tostring(key) .. "\1" .. tostring(msg)
  local acc = 0
  for i = 1, #s do acc = (acc + s:byte(i) * i) % 251 end
  local out = {}
  for i = 1, 32 do out[i] = string.char((acc + i * 7) % 256) end
  return table.concat(out)
end
local function hexit(bin) return (bin:gsub(".", function(c) return string.format("%02x", c:byte()) end)) end

_G.ngx = {
  time = function() return 1000 end, now = function() return 1000 end,
  worker = { pid = function() return 1 end },
  log = function() end, ERR = 1, WARN = 2, INFO = 3,
  hmac_sha256 = function(key, msg) return fake_hmac(key, msg) end,  -- backend = "ngx"
  decode_base64 = function(_) return "RAW_FORGED" end,             -- token -> our raw
  encode_base64 = function(s) return s end,
  md5 = function(_) return "md5" end,
}

package.path = "configs/lua/?.lua;" .. package.path
local cl = require("cfm_clearance")

local fails = 0
local function check(cond, msg)
  if cond then return end
  fails = fails + 1
  io.stderr:write("FAIL: " .. msg .. "\n")
end

local IP, HOST, SCOPE, NONCE, EXP = "1.2.3.4", "h.example.com", "web", "forgednonce", 9999999999
-- validate rebuilds payload as v|exp|ip|normalize_host(host)|scope|nonce.
-- HOST has no port/brackets/trailing dot, so normalize_host(HOST) == HOST.
local payload = table.concat({ "1", tostring(EXP), IP, HOST, SCOPE, NONCE }, "|")
forged_obj = {
  v = "1", exp = EXP, ip = IP, host = HOST, scope = SCOPE, nonce = NONCE,
  hmac = hexit(fake_hmac("", payload)),   -- <-- forged with the EMPTY key
}
local TOKEN = "FORGED_TOKEN"   -- non-empty; ngx.decode_base64 maps it to RAW_FORGED

-- ── THE forgery flip: an empty-key-forged clearance must be REJECTED ──────────
do
  local ok, reason = cl.validate(TOKEN, IP, HOST, SCOPE, "")
  check(ok == false, "F47: an empty-key-forged clearance is REJECTED with an empty secret")
  check(reason == "missing_secret", "rejection reason is missing_secret (got " .. tostring(reason) .. ")")
  local ok2 = cl.validate(TOKEN, IP, HOST, SCOPE, nil)
  check(ok2 == false, "F47: same forged clearance is REJECTED with a nil secret")
end

-- ── Sanity: the forged token WOULD validate under the empty key if the compare
-- were reached — i.e. our craft is a genuine forgery, so the guard is what stops
-- it (not a malformed token). Prove it by validating with the SAME empty-key
-- secret value the forgery targets, but supplied as a NON-empty string that
-- hmac_sha256_hex treats identically? No — instead confirm the positive path: a
-- correctly-minted-style token with the RIGHT secret gets PAST the guard (so the
-- guard only fires on empty/nil), by checking the reason is a crypto/sig outcome,
-- never missing_secret, for a non-empty secret.
do
  local _, reason = cl.validate(TOKEN, IP, HOST, SCOPE, "some-real-secret")
  check(reason ~= "missing_secret", "a NON-empty secret is never rejected by the missing_secret guard (got " .. tostring(reason) .. ")")
  -- With a real secret the forged (empty-key) hmac must NOT match -> bad_sig,
  -- confirming the token only validates under the empty key (a true forgery).
  check(reason == "bad_sig", "the forged empty-key hmac does NOT match under a real secret -> bad_sig (got " .. tostring(reason) .. ")")
end

-- ── mint already fails closed (symmetry / regression guard) ──────────────────
do
  local t1, e1 = cl.mint(IP, HOST, SCOPE, nil, 3600)
  check(t1 == nil and e1 == "missing_secret", "mint refuses a nil secret (missing_secret)")
  local t2, e2 = cl.mint(IP, HOST, SCOPE, "", 3600)
  check(t2 == nil and e2 == "missing_secret", "mint refuses an empty secret (missing_secret)")
end

if fails > 0 then
  io.stderr:write("\n" .. fails .. " test(s) failed in cfm_clearance_secret_guard_test.lua\n")
  os.exit(1)
end
io.stdout:write("ok: clearance validate/mint fail closed on a nil/empty secret; empty-key forgery rejected (F47)\n")

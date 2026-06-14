-- Regression guard for the /.well-known/ carve-out on the main web listener.
--
-- WHY THIS EXISTS
--   AutoSSL / Let's Encrypt (HTTP-01) and commercial CAs (HTTP DCV) prove
--   domain control by fetching, over plain HTTP:
--       /.well-known/acme-challenge/<token>      (ACME HTTP-01)
--       /.well-known/pki-validation/<file>       (Sectigo/DigiCert DCV)
--   These MUST reach the origin (Apache/cPanel serves the file from the
--   docroot). If a forced/auto vhost challenge — e.g.
--       detectors.conf: CHALLENGE_VHOST = cpanel.*, whm.*, webmail.*
--   — or any per-IP challenge intercepts them first, the CA receives the CFM
--   interstitial HTML instead of the token and validation fails with
--       403 urn:ietf:params:acme:error:unauthorized
--   on exactly the cpanel./webmail./whm. service subdomains.
--
--   cfm.lua is a top-to-bottom access script with many require'd dependencies
--   that are impractical to fully mock in standalone luajit, so this test
--   asserts the invariant at the source level: the /.well-known/ origin
--   carve-out must exist and must appear BEFORE any challenge routing.

local function read(path)
  local f = assert(io.open(path, "r"), "cannot open " .. path)
  local s = f:read("*a")
  f:close()
  return s
end

local fails = 0
local function check(cond, msg)
  if not cond then
    io.stderr:write("FAIL: " .. msg .. "\n")
    fails = fails + 1
  end
end

local cfm = read("configs/lua/cfm.lua")

-- 1) The carve-out exists: it matches the /.well-known/ prefix and routes to
--    the origin upstream (its log marker is bypass=well-known).
local wk_pos = cfm:find("bypass=well-known", 1, true)
check(wk_pos ~= nil,
  "cfm.lua: missing /.well-known/ origin carve-out (ACME/CA HTTP DCV will break under CHALLENGE_VHOST)")
check(cfm:find('"/.well-known/"', 1, true) ~= nil,
  "cfm.lua: /.well-known/ prefix literal not found in the carve-out")

-- The carve-out block must send the request to the origin, not the challenge
-- upstream. Inspect the ~400 bytes following the marker.
if wk_pos then
  local block = cfm:sub(wk_pos, wk_pos + 400)
  check(block:find("origin_pass_for(scheme)", 1, true) ~= nil,
    "cfm.lua: /.well-known/ carve-out does not route to the origin (origin_pass_for missing)")
  check(block:find('cfm_pass = "http://cfm_challenge"', 1, true) == nil,
    "cfm.lua: /.well-known/ carve-out must not route to the challenge upstream")
end

-- 2) It must appear BEFORE the first challenge routing. Steps 1 (post-clearance
--    WAF), 2.5 (forced) and 3 (bridge vhost / per-IP) all assign
--    cfm_upstream = "cfm_challenge"; the carve-out has to win the race.
local chal_pos = cfm:find('cfm_upstream = "cfm_challenge"', 1, true)
check(chal_pos ~= nil,
  "cfm.lua: could not locate any challenge routing (test anchor changed?)")
if wk_pos and chal_pos then
  check(wk_pos < chal_pos, string.format(
    "cfm.lua: /.well-known/ carve-out (offset %d) is NOT before the first challenge routing (offset %d)",
    wk_pos, chal_pos))
end

-- 3) The HTTPS panel listeners must exempt /.well-known/ too (cfm_panel.lua
--    is_exempt_path) — the same gate on the 2083/2087 listeners.
local panel = read("configs/lua/cfm_panel.lua")
check(panel:find("/.well-known/", 1, true) ~= nil,
  "cfm_panel.lua: missing /.well-known/ exemption")

if fails > 0 then
  os.exit(1)
end
print("OK: /.well-known/ (ACME + CA HTTP DCV) carve-out present and ordered before challenge")

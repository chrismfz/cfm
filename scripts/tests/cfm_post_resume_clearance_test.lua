-- Regression guards for the (now-live) challenge POST-resume path.
--
-- WHY THIS EXISTS
--   Until the read_body() fix, try_apply_post_resume threw on every resumed POST,
--   so ngx.ctx.cfm_resumed_post was never set and the whole resume-handling
--   machinery was dead code. Activating it exposed two problems, both fixed here:
--
--   #1  Correctness. Step 1 derived clearance_allow as
--       `clearance_ok and not ngx.ctx.cfm_resumed_post`, forcing a resumed POST
--       out of the Step 2b clearance fast-path. A client that had ALREADY solved
--       the challenge was then 403'd by the Step 3 (or Step 2 challenge-tier)
--       block_replayed guard whenever the vhost/IP was still challenged — losing
--       a legit save in exactly the false-positive-burst case the resume mechanism
--       exists for. Fix: clearance_allow keys on clearance_ok alone, so a cleared
--       resumed POST is treated like any cleared client (WAF still runs
--       unconditionally in Step 2 — block-tier blocks, post_clearance_action
--       risk-downgrades a challenge-tier hit; a clean request then fast-paths to
--       origin at Step 2b). block_replayed now fires only for an UNCLEARED replay.
--
--   #2  Security. waf_should_read_body gated body inspection on
--       $http_content_length, nil on the bodiless resume-carrier GET
--       (set_body_data updates content_length_n, not that header), so a resumed
--       POST to a non-allowlisted clean-URL route skipped WAF body inspection — a
--       solved-challenge client could smuggle a body-borne payload past the WAF on
--       replay. Fix: a resumed POST's captured, bounded body is always inspected.
--
--   cfm.lua is a top-to-bottom access script that is impractical to require
--   standalone (see cfm_well_known_carveout_test.lua), so this asserts the
--   invariants at the source level.

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

-- ── #1: a resumed POST is NOT force-excluded from the clearance fast-path ────
-- The clearance-allow gate must key on clearance_ok alone. The old
-- `and not ngx.ctx.cfm_resumed_post` exclusion is the bug: it pushed a cleared
-- replay past Step 2b into block_replayed and lost the save.
local decl = cfm:match("\nlocal clearance_allow%s*=%s*([^\n]*)")
check(decl ~= nil, "clearance_allow declaration not found in cfm.lua")
decl = decl or ""
check(decl:find("clearance_ok") ~= nil,
  "clearance_allow must derive from clearance_ok")
check(decl:find("cfm_resumed_post") == nil,
  "clearance_allow must NOT exclude resumed POSTs (`and not ngx.ctx.cfm_resumed_post` "
  .. "forced a cleared replay into block_replayed and 403'd the user's save)")

-- The block_replayed guards must still exist (they now catch UNCLEARED replays).
check(cfm:find('"block_replayed"') ~= nil,
  "block_replayed guard must remain for uncleared replays")

-- ── #2: a resumed POST's re-injected body is always WAF-inspected ───────────
-- Isolate waf_should_read_body() with %b() so a signature/format change fails
-- loudly rather than passing vacuously.
local gate = cfm:match("local function waf_should_read_body%s*%b()(.-)\nend")
check(gate ~= nil, "waf_should_read_body() not found in cfm.lua (signature changed?)")
gate = gate or ""
check(gate:find("cfm_resumed_post%s+then%s+return%s+true") ~= nil,
  "a resumed POST must be ALWAYS inspected "
  .. "(`if ngx.ctx.cfm_resumed_post then return true end`), not routed through the "
  .. "$http_content_length gate that reads nil on the resume carrier")

if fails > 0 then
  io.stderr:write(("cfm post-resume clearance tests: %d FAILED\n"):format(fails))
  os.exit(1)
end
print("ok: cleared resumed POST is treated like any cleared client (#1) + body always WAF-inspected (#2)")

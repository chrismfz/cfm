-- Regression guard: the challenge POST-resume replay must read the request
-- body BEFORE re-injecting the stashed body, and must do so UNCONDITIONALLY.
--
-- WHY THIS EXISTS
--   try_apply_post_resume() replays a challenged POST on the bodiless resume
--   carrier GET (/…?cfm_rt=…) by calling ngx.req.set_body_data(body). OpenResty
--   requires the current request body to have been read first (ngx.req.read_body),
--   or set_body_data() raises "request body not read yet". Nothing reads that
--   GET's (absent) body earlier — the WAF body-read gate only fires for
--   POST/PUT/PATCH — so without an explicit read_body() the replay THROWS. The
--   access phase runs under xpcall+fail-open, so the throw is swallowed and the
--   request proceeds as the original GET with NO body: post.php sees an empty
--   submit and WordPress bounces to edit.php, silently losing the user's save
--   (observed on ligaapola.gr, 2026-09-15: edge error.log "request body not read
--   yet" at set_body_data, every resumed save lost).
--
--   cfm.lua is a top-to-bottom access script that is impractical to require
--   standalone (see cfm_well_known_carveout_test.lua), so this asserts the
--   invariant at the source level.

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

-- Isolate the try_apply_post_resume() body so the assertions can't be satisfied
-- by unrelated read_body()/set_body_data() mentions elsewhere in the file. Match
-- the signature with %b() (balanced parens) so a future parameter rename or a
-- reformat of the argument list can't silently defeat the guard — a signature it
-- can't find fails loudly on the next check rather than passing vacuously.
local fn = cfm:match("local function try_apply_post_resume%s*%b()(.-)\nend")
check(fn ~= nil, "try_apply_post_resume() not found in cfm.lua (signature changed?)")
fn = fn or ""

local read_pos = fn:find("ngx%.req%.read_body%s*%(")
local set_pos  = fn:find("ngx%.req%.set_body_data%s*%(")

check(set_pos ~= nil, "try_apply_post_resume no longer calls set_body_data()")
check(read_pos ~= nil,
  "try_apply_post_resume must call ngx.req.read_body() before set_body_data() "
  .. "(else set_body_data throws 'request body not read yet' on the resume GET)")
if read_pos and set_pos then
  check(read_pos < set_pos,
    "ngx.req.read_body() must appear BEFORE ngx.req.set_body_data() in try_apply_post_resume")
end

-- Guard against a CONDITIONAL read_body(): if a future edit tucks the read under
-- `if cond then ngx.req.read_body() end`, the ordering check above still passes
-- but set_body_data() throws at runtime whenever that branch is not taken —
-- exactly the bug this file exists to prevent, now green in CI. Require the call
-- to sit at the function body's base indentation (two spaces): an unconditional
-- statement, not nested under a control block (which would indent it further).
-- Heuristic, but it catches the realistic regression.
check(fn:find("\n  ngx%.req%.read_body%s*%(%s*%)") ~= nil,
  "ngx.req.read_body() must be an UNCONDITIONAL top-level statement in "
  .. "try_apply_post_resume (found only nested/indented — a conditional read "
  .. "reintroduces the 'request body not read yet' throw)")

if fails > 0 then
  io.stderr:write(("cfm post-resume read_body tests: %d FAILED\n"):format(fails))
  os.exit(1)
end
print("ok: challenge POST-resume replay reads body (unconditionally) before set_body_data")

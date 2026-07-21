-- Regression guard for the challenge POST-replay content-type allowlist.
--
-- WHY THIS EXISTS
--   When the WAF challenges a POST, store_post_resume stashes the body and
--   try_apply_post_resume replays it after the challenge solves — otherwise
--   the user's form content is lost (the challenge-server fallback logs
--   note=no_replay and 303s away). Forum posts were saved by this in the
--   urlencoded days; on 2026-07-21 a WHMCS ticket reply was still lost
--   because ticket/forum forms submit multipart/form-data (they carry a file
--   field, used or not) and multipart was not in the allowlist.
--
--   cfm.lua is a top-to-bottom access script that is impractical to require
--   standalone (see cfm_well_known_carveout_test.lua), so this asserts the
--   invariants at the source level:
--     1. every replay-safe content-type — urlencoded, json, text/plain and
--        multipart/form-data — is in ct_allows_resume;
--     2. the size cap (post_resume_max_len) still guards the store path, so
--        allowing multipart did not silently unbound shared-dict memory.

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

-- Isolate the ct_allows_resume function body so the assertions can't be
-- satisfied by unrelated mentions elsewhere in the file.
local fn = cfm:match("local function ct_allows_resume%(ct%)(.-)\nend")
check(fn ~= nil, "ct_allows_resume() not found in cfm.lua")
fn = fn or ""

for _, ct in ipairs({
  "application/x%-www%-form%-urlencoded",
  "application/json",
  "text/plain",
  "multipart/form%-data",
}) do
  check(fn:find('has%(ct, "' .. ct .. '"%)%s+then return true') ~= nil,
    "replay-safe content-type missing from ct_allows_resume: " .. ct:gsub("%%", ""))
end

-- The store path must still enforce the size cap on BOTH the declared
-- Content-Length and the actual body (an over-cap or disk-spooled multipart
-- must fall back to no_replay, not into the shared dict).
local store = cfm:match("local function store_post_resume%(.-\nend")
check(store ~= nil, "store_post_resume() not found in cfm.lua")
store = store or ""
check(store:find('clen > CFG%.post_resume_max_len then return nil, "size_limit"') ~= nil,
  "store_post_resume lost the Content-Length cap")
check(store:find('#body > CFG%.post_resume_max_len then return nil, "body_size"') ~= nil,
  "store_post_resume lost the body-size cap")

if fails > 0 then
  io.stderr:write(("cfm post-resume ctype tests: %d FAILED\n"):format(fails))
  os.exit(1)
end
print("ok: challenge POST-replay allowlist (incl. multipart) + size cap intact")

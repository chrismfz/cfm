-- Tests for cfm_bridge_cfg.refresh_token_throttled (audit F45).
--
-- On a bridge 403 the outbound decision path force-refreshes the token to catch
-- a just-rotated value, but must NOT re-read the file on every request under a
-- persistent 403 (wrong token). refresh_token_throttled re-reads at most once per
-- `min_interval` seconds per worker; a legit rotation is picked up on the first
-- (un-throttled) refresh.

package.path = package.path .. ";configs/lua/?.lua;./?.lua"

local fake_now = 1000
_G.ngx = {
  now = function() return fake_now end,
  log = function(_, ...) end,
  WARN = 1, ERR = 2, INFO = 3, NOTICE = 4,
}

local fc = require "cfm_filecache"
local bc = require "cfm_bridge_cfg"

local TOKEN_PATH = "/var/lib/cfm/lua/cfm_bridge_token.lua"
local token_fixture = "TOKEN_OLD_" .. string.rep("a", 32)   -- >= 32 chars (transform requires it)
local reads = 0
local real_loadfile = loadfile
_G.loadfile = function(path)
  if path == TOKEN_PATH then
    reads = reads + 1
    return assert((loadstring or load)("return " .. string.format("%q", token_fixture)))
  end
  return real_loadfile(path)
end

local failures = 0
local function check(cond, msg)
  if cond then return end
  failures = failures + 1
  io.stderr:write("FAIL: " .. msg .. "\n")
end

-- Prime the cache.
check(bc.token() == token_fixture, "token() reads the fixture")
local reads_after_prime = reads

-- 1) First forced refresh (un-throttled) re-reads the file.
local t1, e1 = bc.refresh_token_throttled(2)
check(t1 == token_fixture and e1 == nil, "first refresh returns the token")
check(reads == reads_after_prime + 1, "first refresh re-read the file")

-- 2) Second refresh within the window is throttled — NO file read.
local reads_before = reads
local t2, e2 = bc.refresh_token_throttled(2)
check(t2 == nil and e2 == "throttled", "refresh within window -> throttled")
check(reads == reads_before, "throttled refresh does NOT re-read the file")

-- 3) A rotation: the file changes, but a throttled call does NOT pick it up.
token_fixture = "TOKEN_NEW_" .. string.rep("b", 32)
local t3 = bc.refresh_token_throttled(2)
check(t3 == nil, "still throttled -> rotation not yet observed")

-- 4) After the window, the refresh re-reads and returns the ROTATED token.
fake_now = fake_now + 3   -- past the 2s window
local t4, e4 = bc.refresh_token_throttled(2)
check(t4 == token_fixture and e4 == nil, "after the window, refresh returns the rotated token")
check(t4 ~= "TOKEN_OLD_" .. string.rep("a", 32), "the rotated (new) token is observed")

-- 5) The throttle window is honoured again right after a fresh read.
local reads_5 = reads
local t5, e5 = bc.refresh_token_throttled(2)
check(t5 == nil and e5 == "throttled", "immediately after a refresh -> throttled again")
check(reads == reads_5, "throttled -> no read")

if failures > 0 then
  io.stderr:write("\n" .. failures .. " test(s) failed in cfm_token_refresh_throttle_test.lua\n")
  os.exit(1)
end
io.stdout:write("ok: cfm_bridge_cfg.refresh_token_throttled (per-worker throttle + rotation pickup) (F45)\n")

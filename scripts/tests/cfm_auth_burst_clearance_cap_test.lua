-- Rule 501 (rule_auth_burst) for a client holding a valid clearance, through
-- cfm.lua. The post-clearance conversion turns its challenge into a logonly,
-- so a client that solved the challenge once could post logins without limit;
-- the submissions that cross the threshold are refused (403) instead, and the
-- hit is still pushed as logonly (no waf_security ban).
--   * cleared: the first 7 login posts in the window pass, the 8th is refused;
--   * cleared, resumed: the replayed POST of a solved challenge passes, once per window;
--   * cleared, another rule headlining (302): still capped;
--   * uncleared: the 8th is challenged, as before.

local H = dofile("scripts/tests/cfm_lua_harness.lua")

local fails = 0
local function check(cond, msg)
  if cond then return end
  fails = fails + 1
  io.stderr:write("FAIL: " .. msg .. "\n")
end
local function desc(r)
  return ("ok=%s action=%s up=%s exit=%s redir=%s err=%s"):format(tostring(r.ok), tostring(r.action),
    tostring(r.upstream), tostring(r.exited), tostring(r.redirected), tostring(r.err))
end

local BODY = "log=admin&pwd=secret1&wp-submit=Log+In"
local function login(SH, cleared, ip, args, resumed)
  local ct = "application/x-www-form-urlencoded"
  return H.run{
    SH = SH, method = "POST", uri = "/wp-login.php", body = BODY, ip = ip or "203.0.113.20",
    clearance = cleared, args = args,
    ctx_init = resumed and function(c) c.cfm_resumed_post = true end or nil,
    headers = { ["content-type"] = ct, ["user-agent"] = "Mozilla/5.0", host = "shop.gr" },
    vars = { http_content_type = ct, http_content_length = tostring(#BODY),
             cookie_cfm_clearance = cleared and "good" or nil },
  }
end

-- Cleared: 7 pass, the 8th and 9th are refused.
do
  local SH
  for i = 1, 9 do
    local r = login(SH, true)
    SH = r.SH
    check(r.ok, "cleared login #" .. i .. " ran (" .. desc(r) .. ")")
    if i < 8 then
      check(r.exited == nil, "cleared login #" .. i .. " passes (" .. desc(r) .. ")")
    else
      check(r.exited == 403 and r.action == "login_capped_pc",
        "cleared login #" .. i .. " is refused (" .. desc(r) .. ")")
      -- The edge pushes once per (ip, family, tier) per push_cooldown.
      if i == 8 then check(r.rpcs:find("ip_push", 1, true) ~= nil, "cleared login #8 pushes the hit") end
    end
  end
end

-- Cleared and resumed: the stashed login the client was challenged for, replayed
-- after the solve, passes even past the threshold; a second one in the same
-- window (resume tokens can be minted by posting without the cookie) does not.
do
  local SH, r
  for _ = 1, 8 do r = login(SH, true, "203.0.113.22"); SH = r.SH end
  r = login(SH, true, "203.0.113.22", nil, true)
  check(r.ok and r.exited ~= 403 and r.action ~= "login_capped_pc",
    "a cleared resumed login past the threshold passes (" .. desc(r) .. ")")
  r = login(r.SH, true, "203.0.113.22", nil, true)
  check(r.ok and r.exited == 403 and r.action == "login_capped_pc",
    "a second resumed login in the window is refused (" .. desc(r) .. ")")
end

-- A cleared client cannot switch the cap off by letting an equal-tier rule
-- that runs earlier take the headline (302 on an XSS-shaped arg).
do
  local SH, r
  for i = 1, 9 do
    r = login(SH, true, "203.0.113.23", "x=%3Cscript%3Ealert(1)%3C/script%3E"); SH = r.SH
    if i >= 8 then
      check(r.ok and r.exited == 403 and r.action == "login_capped_pc",
        "cleared login #" .. i .. " with an XSS-shaped arg is refused (" .. desc(r) .. ")")
    end
  end
end

-- Uncleared: the 8th is challenged, not capped.
do
  local SH, r
  for _ = 1, 8 do r = login(SH, false, "203.0.113.21"); SH = r.SH end
  check(r.ok and r.exited ~= 403 and r.action ~= "login_capped_pc"
    and (r.redirected ~= nil or r.upstream == "cfm_challenge"),
    "uncleared 8th login is challenged (" .. desc(r) .. ")")
end

if fails > 0 then
  io.stderr:write(fails .. " failure(s)\n")
  os.exit(1)
end
print("cfm_auth_burst_clearance_cap_test: OK")

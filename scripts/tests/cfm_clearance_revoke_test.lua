-- Tests cfm_clearance.lua's clearance revocation copy (revoked / revoke_apply /
-- revoke_tick): the edge's list of IPs whose cfm_clearance a malpath challenge
-- revoked (internal/webdetector/clearance_revoke.go), and the cfm.lua Step 1
-- wiring that stops honouring such a cookie.

package.loaded["cjson.safe"] = { encode = function() return "{}" end, decode = function() return nil end }
package.loaded["cjson"] = package.loaded["cjson.safe"]

local now = 1000
local timers = {}

-- A shared dict with TTLs and a switch to refuse writes.
local function new_dict()
  local d = { data = {}, exp = {}, refuse = false }
  local function live(k)
    if d.exp[k] and d.exp[k] <= now then d.data[k], d.exp[k] = nil, nil end
    return d.data[k]
  end
  function d:get(k) return live(k) end
  function d:set(k, v, ttl)
    if self.refuse then return false, "no memory" end
    self.data[k] = v
    self.exp[k] = (ttl and ttl > 0) and (now + ttl) or nil
    return true
  end
  function d:add(k, v, ttl)
    if live(k) ~= nil then return false, "exists" end
    return self:set(k, v, ttl)
  end
  function d:delete(k) self.data[k], self.exp[k] = nil, nil end
  return d
end

local dict = new_dict()
_G.ngx = {
  time = function() return now end, now = function() return now end,
  worker = { pid = function() return 1 end },
  log = function() end, ERR = 1, WARN = 2, INFO = 3,
  md5 = function() return "md5" end,
  escape_uri = function(s) return (s:gsub("[^%w%-%._~]", function(c) return string.format("%%%02X", c:byte()) end)) end,
  shared = { cfm_decisions = dict },
  timer = { at = function(_, cb, ...) timers[#timers + 1] = { cb = cb, args = { ... } }; return true end },
}

package.path = "configs/lua/?.lua;" .. package.path
local cl = require("cfm_clearance")

local fails = 0
local function check(cond, msg)
  if cond then return end
  fails = fails + 1
  io.stderr:write("FAIL: " .. msg .. "\n")
end

-- ── revoke_apply / revoked ──────────────────────────────────────────────────
check(cl.revoked(dict, "1.2.3.4") == false, "nothing listed: not revoked")
check(cl.revoked(nil, "1.2.3.4") == false, "no dict: not revoked (fail open)")

check(cl.revoke_apply(dict, { v = "e:1", ips = { ["1.2.3.4"] = 60, ["2001:db8::1"] = 30 } }), "a list applies")
check(cl.revoked(dict, "1.2.3.4"), "a listed v4 is revoked")
check(cl.revoked(dict, "2001:db8::1"), "a listed v6 is revoked")
check(not cl.revoked(dict, "9.9.9.9"), "an unlisted IP is not")
check(dict:get("clrrv:ver") == "e:1", "the version is kept")

-- "same" changes nothing
check(cl.revoke_apply(dict, { v = "e:1", same = true }), "same applies")
check(cl.revoked(dict, "1.2.3.4"), "same keeps the list")

-- A new list drops what left it (a solve or an unblock)
check(cl.revoke_apply(dict, { v = "e:2", ips = { ["2001:db8::1"] = 30 } }), "second list applies")
check(not cl.revoked(dict, "1.2.3.4"), "an IP the daemon dropped is dropped")
check(cl.revoked(dict, "2001:db8::1"), "an IP still listed stays")

-- An entry runs out with its TTL, no write needed
now = now + 31
check(not cl.revoked(dict, "2001:db8::1"), "an entry expires with the challenge")

-- Junk is ignored: bad version, bad ttl, an IP that would break the list
check(not cl.revoke_apply(dict, { ips = { ["5.5.5.5"] = 60 } }), "no version: refused")
check(not cl.revoked(dict, "5.5.5.5"), "no version: nothing written")
check(cl.revoke_apply(dict, { v = "e:3", ips = { ["6.6.6.6"] = 0, ["7.7.7.7"] = "x", ["a,b"] = 60, ["8.8.8.8"] = 10 } }),
  "a list with junk applies its good entries")
check(not cl.revoked(dict, "6.6.6.6") and not cl.revoked(dict, "7.7.7.7") and not cl.revoked(dict, "a,b"),
  "zero / non-numeric TTLs and a comma IP are skipped")
check(cl.revoked(dict, "8.8.8.8"), "the good entry is written")
check(dict:get("clrrv:ips") == "8.8.8.8", "the kept list holds only the good entry")

-- A write the dict refuses leaves no version: the next poll asks for the list again
dict.refuse = true
check(not cl.revoke_apply(dict, { v = "e:4", ips = { ["4.4.4.4"] = 60 } }), "a refused write fails")
dict.refuse = false
check(dict:get("clrrv:ver") == nil, "a failed apply forgets the version")

-- ── revoke_tick: one poll per RV_POLL_SEC, the version on the query ─────────
local calls = {}
local reply
local dec = { rpc = function(_, kind, method, path) calls[#calls + 1] = { kind = kind, method = method, path = path }; return reply end }
local function decode(s) return s end -- the reply is already a table in this test

cl._revoke_reset()
dict:delete("clrrv:polled"); dict:delete("clrrv:lock")
dict:set("clrrv:ver", "e:9")
reply = { v = "e:10", ips = { ["3.3.3.3"] = 60 } }
cl.revoke_tick("cfm_decisions", dec, decode)
check(#timers == 1, "a due tick schedules one poll")
cl.revoke_tick("cfm_decisions", dec, decode)
check(#timers == 1, "a second tick inside the window does not")
local t = table.remove(timers, 1)
t.cb(false, unpack(t.args))
check(#calls == 1 and calls[1].kind == "clrrevoke" and calls[1].method == "GET", "the poll asks the bridge")
check(calls[1].path == "/nginx/clearance/revoked?v=e%3A9", "the poll sends its version, got " .. tostring(calls[1].path))
check(cl.revoked(dict, "3.3.3.3"), "the polled list is applied")
check(dict:get("clrrv:lock") == nil, "the lock is freed after the poll")

-- A failed RPC (an older daemon: 404) keeps the copy and frees the lock
now = now + cl.RV_POLL_SEC + 1
cl._revoke_reset()
reply = nil
cl.revoke_tick("cfm_decisions", dec, decode)
t = table.remove(timers, 1)
check(t ~= nil, "the next window polls again")
if t then t.cb(false, unpack(t.args)) end
check(cl.revoked(dict, "3.3.3.3"), "a failed poll keeps the copy")
check(dict:get("clrrv:lock") == nil, "a failed poll frees the lock")

-- ── cfm.lua Step 1 wiring (source pin) ──────────────────────────────────────
local f = assert(io.open("configs/lua/cfm.lua"))
local src = f:read("*a"); f:close()
local s1 = src:find("local clearance_ok, clearance_status = validate_clearance_token", 1, true)
local s2b = src:find("── Step 2b: Honour clearance allow", 1, true)
local rv = src:find("clearance_validator.revoked(SH, ip)", 1, true)
local allow = src:find("local clearance_allow = clearance_ok", 1, true)
check(s1 and rv and allow and s2b, "cfm.lua carries the revocation check")
check(s1 and rv and allow and s1 < rv and rv < allow and allow < s2b,
  "the revocation check runs after validation and before clearance_allow is taken")

-- A live decision that answers clrrv=0 drops the copy at once (after a solve);
-- a cached or fail-open answer (no clrrv) never does.
local drop = src:find('clearance_status == "revoked" and SH and d and not d._cache and d.clrrv == 0', 1, true)
local dget = src:find("local d        = decision:get(", 1, true)
check(drop and dget and dget < drop, "cfm.lua drops a revoked IP's copy on a live clrrv=0 decision")

if fails > 0 then
  io.stderr:write(fails .. " failure(s)\n")
  os.exit(1)
end
print("OK: cfm_clearance revoke tests passed")

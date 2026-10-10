-- Tests for sslcollector.lua's poll loop: how a new cert reaches every worker.
--
-- On earth (2026-10-10) a new cert reached the six workers one per minute: the
-- poll was 60 s, and a version-triggered /dumpall took the SHARED dict lock, so
-- every other worker found it held, skipped, and tried again on its next poll.
-- The sixth worker served the new cert 4.5 min after the daemon saw it. Now:
--   * the poll is 10 s;
--   * a version change fetches without the shared lock, after
--     worker_id * DUMPALL_STAGGER_SECS (the workers must not all stall on the
--     same ~1 s decode), and a pending fetch is not scheduled twice;
--   * the startup / age-forced fetches keep the shared lock.

-- ── Mocks ────────────────────────────────────────────────────────────────────
local requests = {}
local stats_version = "v2"
package.loaded["ngx.ssl"] = {
  server_name = function() return "" end,
  parse_pem_cert = function() return {} end,
  parse_pem_priv_key = function() return {} end,
  clear_certs = function() return true end,
  set_cert = function() return true end,
  set_priv_key = function() return true end,
}
package.loaded["resty.http"] = {
  new = function()
    local c = {}
    function c:set_timeout() end
    function c:connect() return true end
    function c:request(req)
      requests[#requests + 1] = req.path
      local body = (req.path == "/stats") and ("STATS:" .. stats_version) or "DUMPALL"
      return { status = 200, read_body = function() return body end }
    end
    function c:close() end
    return c
  end,
}
package.loaded["cjson.safe"] = {
  encode = function() return "{}" end,
  decode = function(s)
    local v = type(s) == "string" and s:match("^STATS:(.*)$")
    if v then return { version = v } end
    return nil -- a /dumpall body: rejected by validation, which is fine here
  end,
}

local dict_data = {}
local dict = {
  get = function(_, k) return dict_data[k] end,
  set = function(_, k, v) dict_data[k] = v; return true end,
  add = function(_, k, v)
    if dict_data[k] ~= nil then return false, "exists" end
    dict_data[k] = v; return true
  end,
  delete = function(_, k) dict_data[k] = nil end,
}

local timers = {}
_G.ngx = {
  shared = { sslcache = dict },
  log = function() end,
  now = function() return 1000 end,
  time = function() return 1000 end,
  WARN = 1, ERR = 2, INFO = 3, DEBUG = 4, NOTICE = 5,
  timer = {
    at = function(delay, fn) timers[#timers + 1] = { delay = delay, fn = fn }; return true end,
    every = function() return true end,
  },
  worker = { id = function() return 3 end, count = function() return 6 end, pid = function() return 1 end, exiting = function() return false end },
  config = { subsystem = "http" },
  re = { match = function() return nil end },
}

local _real_loadfile = loadfile
_G.loadfile = function(path)
  if path == "/var/lib/cfm/lua/cfm_token.lua" then
    return function() return string.rep("a", 48) end
  end
  return _real_loadfile(path)
end
package.path = "configs/lua/?.lua;" .. package.path
local M = require("sslcollector")
_G.loadfile = _real_loadfile

local fails = 0
local function check(cond, msg)
  if cond then return end
  fails = fails + 1
  io.stderr:write("FAIL: " .. msg .. "\n")
end

local function upvalue(fn, want)
  local i = 1
  while true do
    local name, val = debug.getupvalue(fn, i)
    if not name then return nil end
    if name == want then return val end
    i = i + 1
  end
end

local poll_stats = upvalue(M.start_background, "poll_stats")
check(poll_stats ~= nil, "found poll_stats")
local function count(path)
  local n = 0
  for _, p in ipairs(requests) do if p == path then n = n + 1 end end
  return n
end

if poll_stats then
  -- Another worker holds the shared lock (its startup / forced fetch).
  dict_data["lock:dumpall"] = true
  -- The force path must not fire here (it would add a shared-lock attempt).
  dict_data["meta:last_dumpall_attempt_at"] = 1000

  poll_stats(false)
  check(count("/stats") == 1, "one /stats poll")
  check(count("/dumpall") == 0, "no immediate fetch on a version change (staggered)")

  local fetch, reschedule
  for _, t in ipairs(timers) do
    if t.fn == poll_stats then reschedule = t else fetch = t end
  end
  check(reschedule and reschedule.delay == 10,
        "next poll in 10 s (got " .. tostring(reschedule and reschedule.delay) .. ")")
  check(fetch and fetch.delay == 6,
        "fetch staggered by worker_id*2 = 6 s (got " .. tostring(fetch and fetch.delay) .. ")")

  -- A second poll before the fetch fires schedules nothing more.
  timers = {}
  poll_stats(false)
  local extra = 0
  for _, t in ipairs(timers) do if t.fn ~= poll_stats then extra = extra + 1 end end
  check(extra == 0, "a pending fetch is not scheduled twice (got " .. extra .. ")")

  -- The fetch runs although the shared lock is held: one worker per poll was
  -- the 4.5-minute stagger.
  if fetch then fetch.fn(false) end
  check(count("/dumpall") == 1,
        "version-triggered fetch ignores the shared lock (got " .. count("/dumpall") .. " /dumpall)")
  check(dict_data["lock:dumpall"] == true, "the other worker's lock is left alone")

  -- The startup fetch still takes the shared lock: held → skipped.
  local do_dumpall = upvalue(M.start_background, "do_dumpall")
  check(do_dumpall ~= nil, "found do_dumpall")
  if do_dumpall then
    local before = count("/dumpall")
    do_dumpall(true)
    check(count("/dumpall") == before, "a shared-lock fetch is skipped while the lock is held")
  end
end

-- 32 workers: the stagger shrinks so the last one starts within the window.
if poll_stats then
  ngx.worker.count = function() return 32 end
  ngx.worker.id = function() return 31 end
  stats_version = "v3"
  timers = {}
  poll_stats(false)
  local fetch
  for _, t in ipairs(timers) do if t.fn ~= poll_stats then fetch = t end end
  check(fetch and fetch.delay <= 20,
        "32 workers: the last worker's delay stays within 20 s (got " .. tostring(fetch and fetch.delay) .. ")")
end

if fails > 0 then
  io.stderr:write(fails .. " failure(s)\n")
  os.exit(1)
end
print("sslcollector_poll_test: ok")

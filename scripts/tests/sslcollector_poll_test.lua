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
--   * the startup / age-forced fetches keep the shared lock;
--   * a worker makes one version fetch per DUMPALL_MIN_GAP_SECS, none while
--     one runs, and none for a version it already holds (2026-10-11).

-- ── Mocks ────────────────────────────────────────────────────────────────────
local requests = {}
local stats_version = "v2"
-- nil: /dumpall bodies fail validation (no ingest). Set: a valid one-cert list
-- of that version, which the worker ingests.
local dumpall_version
local on_dumpall -- called while a /dumpall request is in flight
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
      if req.path == "/dumpall" and dumpall_version then
        body = ("DUMPALL:" .. dumpall_version .. ":"):rep(30) -- past SNAP_MIN_BYTES
      end
      if on_dumpall and req.path == "/dumpall" then on_dumpall() end
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
    local d = type(s) == "string" and s:match("^DUMPALL:([^:]*):")
    if d then
      return { version = d, wild = {},
               exact = { { host = "a.example", cert_pem = "C", key_pem = "K" } } }
    end
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

-- A fetch already running in this worker blocks a second one on either path.
if poll_stats then
  local do_dumpall = upvalue(M.start_background, "do_dumpall")
  local nested
  local real_request = package.loaded["resty.http"].new
  dict_data["lock:dumpall"] = nil
  package.loaded["resty.http"].new = function()
    local c = real_request()
    local req = c.request
    function c:request(r)
      if r.path == "/dumpall" and nested == nil then
        nested = count("/dumpall")
        do_dumpall(true)  -- a forced fetch while the version fetch runs
        nested = count("/dumpall") - nested
      end
      return req(self, r)
    end
    return c
  end
  do_dumpall(false)
  package.loaded["resty.http"].new = real_request
  check(nested == 0, "a forced fetch inside a running fetch is skipped (got " .. tostring(nested) .. ")")
  check(dict_data["lock:dumpall"] == nil, "the skipped forced fetch took no shared lock")
end

-- 32 workers: the stagger shrinks so the last one starts within the window.
if poll_stats then
  ngx.worker.count = function() return 32 end
  ngx.worker.id = function() return 31 end
  -- Past the min gap since the fetch above (the stagger alone is under test).
  ngx.now = function() return 1100 end
  ngx.time = function() return 1100 end
  stats_version = "v3"
  timers = {}
  poll_stats(false)
  local fetch
  for _, t in ipairs(timers) do if t.fn ~= poll_stats then fetch = t end end
  check(fetch and fetch.delay <= 20,
        "32 workers: the last worker's delay stays within 20 s (got " .. tostring(fetch and fetch.delay) .. ")")
end

-- The last worker (stagger == poll interval) fetched every version twice: its
-- fetch cleared _dumpall_scheduled, and the poll that ran in the same second,
-- before the ingest, saw the old version and scheduled another (every node,
-- 2026-10-11). And during an AutoSSL burst each version change was a fetch of
-- the whole list per worker: at most one per DUMPALL_MIN_GAP_SECS now.
if poll_stats then
  for _, t in ipairs(timers) do if t.fn ~= poll_stats then t.fn(true) end end -- drop the 32-worker fetch
  local clock = 2000
  ngx.now = function() return clock end
  ngx.time = function() return clock end
  ngx.worker.count = function() return 6 end
  ngx.worker.id = function() return 5 end
  local function poll()
    dict_data["meta:last_dumpall_attempt_at"] = clock -- keep the forced path quiet
    poll_stats(false)
  end
  local function pending()
    local list = {}
    for _, t in ipairs(timers) do if t.fn ~= poll_stats then list[#list + 1] = t end end
    return list
  end

  stats_version, dumpall_version = "v10", "v10"
  timers = {}
  poll()
  local f = pending()
  check(#f == 1 and f[1].delay == 10, "last worker: fetch in 10 s (got " .. tostring(f[1] and f[1].delay) .. ")")

  -- The fetch fires; the next poll runs in the same second, before the ingest.
  clock = 2010
  timers = {}
  on_dumpall = function() on_dumpall = nil; poll() end
  local before = count("/dumpall")
  f[1].fn(false)
  check(count("/dumpall") == before + 1, "the fetch ran")
  check(#pending() == 0, "no second fetch scheduled by the poll that overlapped the first (got " .. #pending() .. ")")
  for _, t in ipairs(pending()) do t.fn(false) end
  check(count("/dumpall") == before + 1, "the version was fetched once (got " .. (count("/dumpall") - before) .. ")")

  -- A scheduled fetch whose version arrived another way does not fetch.
  stats_version, dumpall_version = "v11", "v11"
  clock = 2100
  timers = {}
  poll()
  f = pending()
  local do_dumpall = upvalue(M.start_background, "do_dumpall")
  dict_data["lock:dumpall"] = nil
  do_dumpall(true) -- e.g. the age-forced fetch, brings v11
  before = count("/dumpall")
  if f[1] then f[1].fn(false) end
  check(count("/dumpall") == before, "a scheduled fetch is skipped when the worker already holds the version")

  -- An AutoSSL burst: the first change goes out on the stagger; the next one
  -- within DUMPALL_MIN_GAP_SECS of that fetch waits for the gap.
  stats_version, dumpall_version = "v12", "v12"
  clock = 2200
  timers = {}
  poll()
  f = pending()
  check(f[1] and f[1].delay == 10, "first change of a burst: stagger only (got " .. tostring(f[1] and f[1].delay) .. ")")
  clock = 2210
  if f[1] then f[1].fn(false) end
  stats_version, dumpall_version = "v13", "v13"
  clock = 2215
  timers = {}
  poll()
  f = pending()
  check(f[1] and f[1].delay == 25,
        "next change 5 s after a fetch waits out the 30 s gap (got " .. tostring(f[1] and f[1].delay) .. ")")

  -- A wall clock stepped back 1 h after a fetch: the wait is capped at the gap.
  if f[1] then f[1].fn(false) end -- fetch v13 at 2215+25
  local fetched_at = clock
  stats_version, dumpall_version = "v14", "v14"
  clock = fetched_at - 3600
  timers = {}
  poll()
  f = pending()
  check(f[1] and f[1].delay <= 30,
        "clock stepped back: the wait stays within the gap (got " .. tostring(f[1] and f[1].delay) .. ")")
  if f[1] then f[1].fn(true) end

  -- No timer available: no fetch inside the gap (the next poll retries).
  clock = fetched_at + 5
  timers = {}
  local real_at = ngx.timer.at
  ngx.timer.at = function(delay, fn)
    if fn == poll_stats then return real_at(delay, fn) end
    return nil, "too many pending timers"
  end
  before = count("/dumpall")
  poll()
  check(count("/dumpall") == before, "timer failure inside the gap: no fetch")
  clock = fetched_at + 31
  poll()
  check(count("/dumpall") == before + 1, "timer failure past the gap: fetches inline")
  ngx.timer.at = real_at

  -- A scheduled fetch that fires while a forced fetch runs does nothing and
  -- stamps no gap (the forced one's result is not one the gap should hold).
  stats_version, dumpall_version = "v15", "v15"
  clock = fetched_at + 100
  timers = {}
  poll()
  f = pending()
  local stamp = upvalue(f[1].fn, "fetch") and upvalue(upvalue(f[1].fn, "fetch"), "_last_version_fetch_at")
  dumpall_version = "v14" -- the forced fetch returns an older build
  on_dumpall = function() on_dumpall = nil; f[1].fn(false) end
  dict_data["lock:dumpall"] = nil
  do_dumpall(true)
  local after = upvalue(upvalue(f[1].fn, "fetch"), "_last_version_fetch_at")
  check(after == stamp, "no gap stamped by a fetch skipped for a running one (" .. tostring(stamp) .. " -> " .. tostring(after) .. ")")
  dumpall_version = "v15"
  timers = {}
  poll()
  f = pending()
  check(f[1] and f[1].delay == 10,
        "the next poll retries on the stagger, not a fresh gap (got " .. tostring(f[1] and f[1].delay) .. ")")
  on_dumpall = nil
end

if fails > 0 then
  io.stderr:write(fails .. " failure(s)\n")
  os.exit(1)
end
print("sslcollector_poll_test: ok")

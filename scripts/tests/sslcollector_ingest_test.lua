-- Tests for sslcollector.lua's ingest: a /dumpall REPLACES the worker's store.
--
-- rigel, 2026-11-17: cPanel installed a self-signed placeholder for a new
-- account (names spoolbox.gr + www.spoolbox.gr); AutoSSL replaced it with
-- *.spoolbox.gr + spoolbox.gr. The daemon dropped the exact www. entry, but the
-- additive ingest kept it in every worker, and an exact entry outranks a
-- wildcard: www. served the self-signed cert until a reload. Pinned here:
--   * a COMPLETE payload replaces: a name absent from it is dropped (the
--     wildcard then serves it);
--   * an incomplete payload (complete ~= true: a name whose PEM the daemon
--     could not read is left out of it) merges, keeping every old name;
--   * a payload entry whose PEM is missing or fails to parse keeps the old pair;
--   * a shrink under two thirds of the last payload TAKEN merges for
--     SHRINK_HOLD_SECS, through any number of degraded payloads, then is taken;
--   * an empty / all-failed payload changes nothing;
--   * the ingest line names the mode.

-- ── Mocks ────────────────────────────────────────────────────────────────────
local sslmock
sslmock = {
  _sni = "",
  server_name = function() return sslmock._sni end,
  -- "BAD" fails to parse; anything else parses to a table naming its PEM.
  parse_pem_cert = function(p)
    if p == "BAD" then return nil, "bad pem" end
    return { pem = p }
  end,
  parse_pem_priv_key = function(p) return { pem = p } end,
  clear_certs = function() return true end,
  set_cert = function(c) sslmock._served = c and c.pem; return true end,
  set_priv_key = function() return true end,
}
package.loaded["ngx.ssl"] = sslmock
package.loaded["resty.http"] = { new = function() return {} end }
package.loaded["cjson.safe"] = { encode = function() return "{}" end, decode = function() return nil end }

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

local warn_lines = {}
_G._test_now = 1000
_G._test_timers = {}
_G.ngx = {
  shared = { sslcache = dict },
  log = function(lvl, ...)
    if lvl == 1 then warn_lines[#warn_lines + 1] = table.concat({ ... }) end
  end,
  now = function() return 1000 end,
  time = function() return _G._test_now end,
  WARN = 1, ERR = 2, INFO = 3, DEBUG = 4, NOTICE = 5,
  timer = {
    at = function(delay, fn) _G._test_timers[#_G._test_timers + 1] = { delay = delay, fn = fn }; return true end,
    every = function() return true end,
  },
  worker = { id = function() return 0 end, count = function() return 1 end, pid = function() return 1 end, exiting = function() return false end },
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

-- Depth-first search of the upvalue graph for a named local function.
local function find_upvalue(fn, want, seen)
  seen = seen or {}
  if seen[fn] then return nil end
  seen[fn] = true
  local i = 1
  while true do
    local name, val = debug.getupvalue(fn, i)
    if not name then return nil end
    if name == want then return val end
    if type(val) == "function" then
      local r = find_upvalue(val, want, seen)
      if r then return r end
    end
    i = i + 1
  end
end

local ingest = find_upvalue(M.start_background, "ingest_dumpall")
check(ingest ~= nil, "found ingest_dumpall")
if not ingest then os.exit(1) end

local function serve(sni)
  sslmock._sni, sslmock._served = sni, nil
  M.set_cert()
  return sslmock._served
end

local function counts()
  local e, w = M.cert_counts()
  return e + w
end

-- ── The spoolbox case: a dropped exact name stops outranking the wildcard ────
do
  ingest({ version = "v1", complete = true, wild = {}, exact = {
    { host = "spoolbox.gr",     cert_pem = "SELF", key_pem = "K" },
    { host = "www.spoolbox.gr", cert_pem = "SELF", key_pem = "K" },
  } }, "dumpall")
  check(serve("www.spoolbox.gr") == "SELF", "v1: www. served the placeholder")

  ingest({ version = "v2", complete = true,
    exact = { { host = "spoolbox.gr", cert_pem = "LE", key_pem = "K" } },
    wild  = { { suffix = "spoolbox.gr", cert_pem = "LE", key_pem = "K" } },
  }, "dumpall")
  check(serve("spoolbox.gr") == "LE", "v2: apex serves the new cert")
  check(serve("www.spoolbox.gr") == "LE",
        "v2: www. must fall to the wildcard, not the stale exact entry (got " ..
        tostring(serve("www.spoolbox.gr")) .. ")")
  check(counts() == 2, "v2: store holds exactly the payload's 2 names (got " .. counts() .. ")")
end

-- ── A payload entry that fails to parse keeps the worker's current pair ──────
do
  ingest({ version = "v3", complete = true,
    exact = { { host = "spoolbox.gr", cert_pem = "BAD", key_pem = "K" } },
    wild  = { { suffix = "spoolbox.gr", cert_pem = "LE2", key_pem = "K" } },
  }, "dumpall")
  check(serve("spoolbox.gr") == "LE", "v3: unparsable apex keeps the old pair (got " ..
        tostring(serve("spoolbox.gr")) .. ")")
  check(serve("x.spoolbox.gr") == "LE2", "v3: the parsable wildcard is updated")
end

-- ── An empty or all-failed payload changes nothing ───────────────────────────
do
  ingest({ version = "v4", complete = true, exact = {}, wild = {} }, "dumpall")
  check(counts() == 2, "v4: an empty payload keeps the store (got " .. counts() .. ")")
  ingest({ version = "v5", complete = true, wild = {},
    exact = { { host = "other.gr", cert_pem = "BAD", key_pem = "K" } } }, "dumpall")
  check(serve("spoolbox.gr") == "LE", "v5: an all-failed payload keeps the store")
end

-- ── A payload entry without a PEM keeps the worker's current pair too ───────
do
  ingest({ version = "v5b", complete = true,
    exact = { { host = "spoolbox.gr", key_pem = "K" } },  -- no cert_pem
    wild  = { { suffix = "spoolbox.gr", cert_pem = "LE2", key_pem = "K" } },
  }, "dumpall")
  check(serve("spoolbox.gr") == "LE", "v5b: a PEM-less apex keeps the old pair (got " ..
        tostring(serve("spoolbox.gr")) .. ")")
end

local function names(prefix, n, pem)
  local t = {}
  for i = 1, n do
    t[#t + 1] = { host = prefix .. i .. ".example", cert_pem = pem .. i, key_pem = "K" }
  end
  return t
end

local function logged(want)
  for _, l in ipairs(warn_lines) do
    if l:find(want, 1, true) then return true end
  end
  return false
end

-- ── The daemon's real skip shape: a name LEFT OUT of an incomplete payload ───
do
  warn_lines = {}
  -- spoolbox.gr's PEM could not be read: the daemon omits it and says
  -- complete=false. The worker must keep serving its current pair.
  ingest({ version = "v5c", complete = false, exact = {},
    wild = { { suffix = "spoolbox.gr", cert_pem = "LE3", key_pem = "K" } } }, "dumpall")
  check(serve("spoolbox.gr") == "LE", "v5c: a name left out of an incomplete payload stays (got " ..
        tostring(serve("spoolbox.gr")) .. ")")
  check(serve("x.spoolbox.gr") == "LE3", "v5c: the incomplete payload's names are still updated")
  check(logged("mode=merge_incomplete"), "v5c: the ingest line says mode=merge_incomplete")
  -- A payload without the field (an older daemon, the streamed fallback)
  -- merges too.
  ingest({ version = "v5d", exact = {}, wild = {
    { suffix = "spoolbox.gr", cert_pem = "LE4", key_pem = "K" } } }, "dumpall")
  check(serve("spoolbox.gr") == "LE", "v5d: no complete field: merged")
end

-- ── Shrink guard: under 2/3 of the last payload TAKEN is held for an hour ────
do
  _G._test_now = 10000
  warn_lines = {}
  ingest({ version = "v6", complete = true, exact = names("h", 30, "A"), wild = {} }, "dumpall")
  check(counts() == 30, "v6: 30-name store (got " .. counts() .. ")")
  check(logged("mode=replace"), "v6: the ingest line says mode=replace")

  -- 19 of 30 is under two thirds (a half-loss guard would take it).
  warn_lines = {}
  ingest({ version = "v7", complete = true, exact = names("h", 19, "B"), wild = {} }, "dumpall")
  check(counts() == 30, "v7: a 19-of-30 payload is held (got " .. counts() .. ")")
  check(serve("h1.example") == "B1", "v7: the held payload's names are updated")
  check(serve("h25.example") == "A25", "v7: the missing names stay")
  check(logged("merged, not replaced"), "v7: the shrink is logged")
  check(logged("mode=merge_shrink"), "v7: the ingest line says mode=merge_shrink")

  -- A second degraded payload, new version, still inside the hold: held.
  _G._test_now = 10000 + 1800
  ingest({ version = "v8", complete = true, exact = names("h", 10, "C"), wild = {} }, "dumpall")
  check(counts() == 30, "v8: a second degraded payload is held too (got " .. counts() .. ")")
  check(serve("h25.example") == "A25", "v8: the missing names still stay")

  -- The shrink lasted SHRINK_HOLD_SECS: taken.
  _G._test_now = 10000 + 3600
  ingest({ version = "v9", complete = true, exact = names("h", 10, "D"), wild = {} }, "dumpall")
  check(counts() == 10, "v9: a shrink that lasted the hold is taken (got " .. counts() .. ")")
  check(serve("h25.example") == nil, "v9: a dropped name is no longer served")

  -- The baseline is now 10: 30 again is growth, then 25 of 30 (>= 2/3) is
  -- taken at once, and a recovered payload clears a running hold.
  ingest({ version = "v10", complete = true, exact = names("h", 30, "E"), wild = {} }, "dumpall")
  ingest({ version = "v11", complete = true, exact = names("h", 25, "F"), wild = {} }, "dumpall")
  check(counts() == 25, "v11: a 25-of-30 payload replaces (got " .. counts() .. ")")
  _G._test_now = 20000
  ingest({ version = "v12", complete = true, exact = names("h", 5, "G"), wild = {} }, "dumpall")
  check(counts() == 25, "v12: held")
  ingest({ version = "v13", complete = true, exact = names("h", 25, "H"), wild = {} }, "dumpall")
  _G._test_now = 20000 + 3600
  ingest({ version = "v14", complete = true, exact = names("h", 5, "I"), wild = {} }, "dumpall")
  check(counts() == 25, "v14: a shrink after a recovery starts a new hold (got " .. counts() .. ")")
end

-- ── A small node is guarded too ───────────────────────────────────────────────
do
  ingest({ version = "v15", complete = true, exact = names("h", 25, "J"), wild = {} }, "dumpall")
  _G._test_now = 50000
  ingest({ version = "v16", complete = true, exact = names("s", 4, "K"), wild = {} }, "dumpall")
  _G._test_now = 50000 + 3600
  ingest({ version = "v17", complete = true, exact = names("s", 4, "K"), wild = {} }, "dumpall")
  check(counts() == 4, "v17: 4-name store (got " .. counts() .. ")")
  ingest({ version = "v18", complete = true, exact = names("s", 1, "L"), wild = {} }, "dumpall")
  check(counts() == 4, "v18: 1 of 4 is held (got " .. counts() .. ")")
end

-- ── A snapshot that throws in ingest must not stop the fetch and the poll ───
-- start_background's timer loads the snapshot, then fetches, then starts the
-- poll loop. Unprotected, an error in the snapshot ingest ended that timer
-- and the worker never refreshed again.
do
  local json = package.loaded["cjson.safe"]
  local real_decode, real_open = json.decode, io.open
  json.decode = function() return { version = "snap", exact = "not-a-list", wild = {} } end
  io.open = function(path, mode)
    if path == "/var/lib/cfm/sslcollector/dump.json" then
      return { read = function() return "{}" end, close = function() end }
    end
    return real_open(path, mode)
  end
  dict_data["meta:last_dumpall_attempt_at"] = nil
  _G._test_timers = {}
  M.start_background()
  local boot = _G._test_timers[1]
  check(boot ~= nil, "start_background scheduled its boot timer")
  _G._test_timers = {}
  local ok, err = pcall(boot.fn, false)
  json.decode, io.open = real_decode, real_open
  check(ok, "the boot timer survives a throwing snapshot ingest (" .. tostring(err) .. ")")
  check(dict_data["meta:last_dumpall_attempt_at"] ~= nil, "the boot timer still tried /dumpall")
  local polled = false
  for _, t in ipairs(_G._test_timers) do
    if t.delay == 1 then polled = true end
  end
  check(polled, "the boot timer still scheduled the poll loop")
end

if fails > 0 then
  io.stderr:write(fails .. " failure(s)\n")
  os.exit(1)
end
print("sslcollector_ingest_test: OK")

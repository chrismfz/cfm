-- Tests for sslcollector.lua's ingest: a /dumpall REPLACES the worker's store.
--
-- rigel, 2026-11-17: cPanel installed a self-signed placeholder for a new
-- account (names spoolbox.gr + www.spoolbox.gr); AutoSSL replaced it with
-- *.spoolbox.gr + spoolbox.gr. The daemon dropped the exact www. entry, but the
-- additive ingest kept it in every worker, and an exact entry outranks a
-- wildcard: www. served the self-signed cert until a reload. Pinned here:
--   * a name absent from the payload is dropped (the wildcard then serves it);
--   * a payload entry whose PEM fails to parse keeps the worker's old pair;
--   * a payload under half of a store of >= SHRINK_GUARD_MIN names is merged;
--   * an empty / all-failed payload changes nothing.

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
_G.ngx = {
  shared = { sslcache = dict },
  log = function(lvl, ...)
    if lvl == 1 then warn_lines[#warn_lines + 1] = table.concat({ ... }) end
  end,
  now = function() return 1000 end,
  time = function() return 1000 end,
  WARN = 1, ERR = 2, INFO = 3, DEBUG = 4, NOTICE = 5,
  timer = { at = function() return true end, every = function() return true end },
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
  ingest({ version = "v1", wild = {}, exact = {
    { host = "spoolbox.gr",     cert_pem = "SELF", key_pem = "K" },
    { host = "www.spoolbox.gr", cert_pem = "SELF", key_pem = "K" },
  } }, "dumpall")
  check(serve("www.spoolbox.gr") == "SELF", "v1: www. served the placeholder")

  ingest({ version = "v2",
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
  ingest({ version = "v3",
    exact = { { host = "spoolbox.gr", cert_pem = "BAD", key_pem = "K" } },
    wild  = { { suffix = "spoolbox.gr", cert_pem = "LE2", key_pem = "K" } },
  }, "dumpall")
  check(serve("spoolbox.gr") == "LE", "v3: unparsable apex keeps the old pair (got " ..
        tostring(serve("spoolbox.gr")) .. ")")
  check(serve("x.spoolbox.gr") == "LE2", "v3: the parsable wildcard is updated")
end

-- ── An empty or all-failed payload changes nothing ───────────────────────────
do
  ingest({ version = "v4", exact = {}, wild = {} }, "dumpall")
  check(counts() == 2, "v4: an empty payload keeps the store (got " .. counts() .. ")")
  ingest({ version = "v5", wild = {},
    exact = { { host = "other.gr", cert_pem = "BAD", key_pem = "K" } } }, "dumpall")
  check(serve("spoolbox.gr") == "LE", "v5: an all-failed payload keeps the store")
end

-- ── Shrink guard: under half of a >= 20-name store is merged, not replaced ───
do
  local exact = {}
  for i = 1, 30 do
    exact[#exact + 1] = { host = "h" .. i .. ".example", cert_pem = "A" .. i, key_pem = "K" }
  end
  ingest({ version = "v6", exact = exact, wild = {} }, "dumpall")
  check(counts() == 30, "v6: 30-name store (got " .. counts() .. ")")

  warn_lines = {}
  ingest({ version = "v7", wild = {},
    exact = { { host = "h1.example", cert_pem = "B1", key_pem = "K" } } }, "dumpall")
  check(counts() == 30, "v7: a 1-of-30 payload is merged (got " .. counts() .. ")")
  check(serve("h1.example") == "B1", "v7: the merged name is updated")
  check(serve("h2.example") == "A2", "v7: the other names stay")
  local logged = false
  for _, l in ipairs(warn_lines) do
    if l:find("merged, not replaced", 1, true) then logged = true end
  end
  check(logged, "v7: the shrink is logged")

  -- 16 of 30 is at least half: replaced, the other 14 dropped.
  local half = {}
  for i = 1, 16 do
    half[#half + 1] = { host = "h" .. i .. ".example", cert_pem = "C" .. i, key_pem = "K" }
  end
  ingest({ version = "v8", exact = half, wild = {} }, "dumpall")
  check(counts() == 16, "v8: a 16-of-30 payload replaces (got " .. counts() .. ")")
  check(serve("h20.example") == nil, "v8: a dropped name is no longer served")
end

if fails > 0 then
  io.stderr:write(fails .. " failure(s)\n")
  os.exit(1)
end
print("sslcollector_ingest_test: OK")

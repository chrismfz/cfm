-- Standalone test for cfm_filecache (the per-worker TTL cache that keeps
-- cfm.lua's config-file reads off the request hot path). Run with:
--   luajit scripts/tests/cfm_filecache_test.lua
--
-- This is a host-side smoke test, not loaded by nginx. It stubs ngx.now
-- with a controllable fake clock so TTL expiry is tested deterministically,
-- and counts real loadfile() calls to prove the cache actually prevents
-- per-request disk reads (the original bug: TTL state in access_by_lua_file
-- top-level locals reset every request, so every request hit the disk).

package.path = package.path .. ";configs/lua/?.lua;./?.lua"

local fake_now = 1000
_G.ngx = {
  now = function() return fake_now end,
  log = function(_, ...) end,
  WARN = 1, ERR = 2, INFO = 3, NOTICE = 4,
}

-- Count real disk loads without changing loadfile semantics.
local real_loadfile = loadfile
local load_calls = 0
_G.loadfile = function(path)
  load_calls = load_calls + 1
  return real_loadfile(path)
end

local fc = require "cfm_filecache"

local failures = 0
local function check(cond, msg)
  if cond then
    print("ok   - " .. msg)
  else
    failures = failures + 1
    print("FAIL - " .. msg)
  end
end

local function write_file(path, content)
  local f = assert(io.open(path, "w"))
  f:write(content)
  f:close()
end

local tmp = os.tmpname()

-- 1) Basic load + transform.
write_file(tmp, 'return { ips = { ["1.2.3.4"] = true } }')
local val, err = fc.get(tmp, {
  ttl = 30,
  transform = function(raw) return raw.ips end,
})
check(err == nil, "fresh load returns no error")
check(type(val) == "table" and val["1.2.3.4"] == true, "transform result is served")
check(load_calls == 1, "first get() hits the disk once")

-- 2) Cache hit within TTL: no disk read, same value, even if the file
--    changed underneath (that's the point of the TTL).
write_file(tmp, 'return { ips = { ["5.6.7.8"] = true } }')
fake_now = 1010 -- +10s < 30s TTL
local val2 = fc.get(tmp, { ttl = 30, transform = function(raw) return raw.ips end })
check(val2 == val, "within TTL the cached table is returned (no reload)")
check(load_calls == 1, "within TTL there is no disk read")

-- 3) Expiry: the new content is picked up.
fake_now = 1031 -- past the 30s TTL
local val3 = fc.get(tmp, { ttl = 30, transform = function(raw) return raw.ips end })
check(val3 ~= nil and val3["5.6.7.8"] == true, "after TTL expiry the new content is served")
check(load_calls == 2, "expiry causes exactly one more disk read")

-- 4) Transform rejection is cached as a failure (nil + err) for missing_ttl.
write_file(tmp, 'return "not a table"')
fake_now = 2000
local val4, err4 = fc.get(tmp, {
  ttl = 30, missing_ttl = 2,
  transform = function(raw)
    if type(raw) ~= "table" then error("non-table value") end
    return raw
  end,
})
check(val4 == nil and err4 ~= nil and err4:find("non-table value", 1, true) ~= nil,
      "transform error yields nil + descriptive err")
local before = load_calls
fake_now = 2001 -- within missing_ttl
local val5, err5 = fc.get(tmp, { ttl = 30, missing_ttl = 2, transform = function() error("x") end })
check(val5 == nil and err5 ~= nil, "failure is served from cache within missing_ttl")
check(load_calls == before, "failure caching prevents disk reads within missing_ttl")
fake_now = 2003 -- past missing_ttl → retry
write_file(tmp, 'return { ok = true }')
local val6, err6 = fc.get(tmp, { ttl = 30, missing_ttl = 2 })
check(err6 == nil and type(val6) == "table" and val6.ok == true,
      "after missing_ttl the file is retried and recovers")

-- 5) Missing file: nil + err, negative-cached, then recovers when created.
os.remove(tmp)
fake_now = 3000
local mval, merr = fc.get(tmp, { ttl = 30, missing_ttl = 2 })
check(mval == nil and merr == "missing or unreadable", "missing file yields nil + 'missing or unreadable'")
fake_now = 3003
write_file(tmp, 'return 42')
local mval2, merr2 = fc.get(tmp, { ttl = 30, missing_ttl = 2 })
check(merr2 == nil and mval2 == 42, "file created later is picked up after missing_ttl")

-- 6) No transform: raw chunk return value is served.
fake_now = 4000
write_file(tmp, 'return "raw-string-value"')
fc.entries[tmp] = nil -- reset entry for a clean read
local rval, rerr = fc.get(tmp, { ttl = 30 })
check(rerr == nil and rval == "raw-string-value", "without transform the raw value is served")

os.remove(tmp)

if failures > 0 then
  print(string.format("%d failure(s)", failures))
  os.exit(1)
end
print("OK: cfm_filecache TTL caching, failure caching and recovery behave as specified")

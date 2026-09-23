-- Tests for cfm_shdict.incr (configs/lua/cfm_shdict.lua), against a fake shared
-- dict with OpenResty's semantics, and a guard: no edge module may call
-- dict:incr with an init argument (it loses counters on a crc32 collision in
-- lua-nginx-module 0.10.26; see cfm_shdict.lua).

package.path = "configs/lua/?.lua;" .. package.path
local shd = require("cfm_shdict")

local fails = 0
local function check(c, m)
  if c then return end
  fails = fails + 1
  io.stderr:write("FAIL: " .. m .. "\n")
end

-- Fake dict: incr without init on a missing key is "not found"; add refuses an
-- existing key; a key has an optional expiry against clk.t.
local function new_dict()
  local store, clk, hooks = {}, { t = 0 }, {}
  local function live(k)
    local e = store[k]
    if e and e.exp and e.exp <= clk.t then store[k] = nil; e = nil end
    return e
  end
  local d = {}
  function d:incr(k, v, init)
    if hooks.incr then return hooks.incr(k, v, init) end
    assert(init == nil, "cfm_shdict must never pass init to incr")
    local e = live(k)
    if not e then return nil, "not found" end
    if type(e.val) ~= "number" then return nil, "not a number" end
    e.val = e.val + v
    return e.val
  end
  function d:add(k, v, ttl)
    if hooks.add then return hooks.add(k, v, ttl) end
    if live(k) then return false, "exists" end
    store[k] = { val = v, exp = (ttl and ttl > 0) and (clk.t + ttl) or nil, ttl = ttl }
    return true
  end
  function d:set(k, v) store[k] = { val = v } end
  function d:get(k) local e = live(k); return e and e.val or nil end
  function d:entry(k) return live(k) end
  return d, clk, hooks
end

-- create, count, TTL on create only
do
  local d, clk = new_dict()
  check(shd.incr(d, "a", 1, 60) == 1, "first incr creates at n")
  check(d:entry("a").ttl == 60, "a created key gets the ttl")
  check(shd.incr(d, "a") == 2, "n defaults to 1")
  check(shd.incr(d, "a", 5, 999) == 7, "a later incr counts n")
  check(d:entry("a").ttl == 60, "a later incr keeps the creation ttl")
  clk.t = 61
  check(d:get("a") == nil, "the key expires ttl after creation")
  check(shd.incr(d, "a", 1, 60) == 1, "an expired key is created again")
  check(shd.incr(d, "b", 3) == 3 and d:entry("b").exp == nil, "no ttl: no expiry")
  check(shd.incr(d, "c", 2, 0) == 2 and d:entry("c").exp == nil, "ttl 0: no expiry")
end

-- the race: another worker adds the key between our incr and our add
do
  local d, _, hooks = new_dict()
  local calls = 0
  hooks.incr = function(_, v)
    calls = calls + 1
    if calls == 1 then return nil, "not found" end
    return 41 + v
  end
  hooks.add = function() return false, "exists" end
  check(shd.incr(d, "r", 1, 10) == 42, "an add that finds exists falls back to incr")
  check(calls == 2, "incr is retried exactly once")
end

-- errors are returned, not thrown
do
  local d, _, hooks = new_dict()
  hooks.add = function() return false, "no memory" end
  local v, err = shd.incr(d, "m", 1, 10)
  check(v == nil and err == "no memory", "an add failure returns nil + its error")
  local d2 = new_dict()
  d2:set("s", "str")
  v, err = shd.incr(d2, "s", 1)
  check(v == nil and err == "not a number", "an incr error returns nil + its error")
  local d3, _, h3 = new_dict()
  h3.incr = function() return nil, "no memory" end
  v, err = shd.incr(d3, "x", 1)
  check(v == nil and err == "no memory", "an incr error other than not found is returned as is")
end

-- guard: no edge Lua calls dict:incr with an init argument, in the forms a
-- call is written in: d:incr(k, n, init), d.incr(d, k, n, init) and
-- d["incr"](d, k, n, init). An aliased function (local f = d.incr) is not
-- seen. Scans the modules and the *_by_lua blocks of the reference confs. The
-- helper itself is exempt: it is always required as `shd`, and defined as
-- _M.incr in cfm_shdict.lua.
do
  local p = assert(io.popen("ls configs/lua/*.lua configs/*.conf*"))
  local files, mods = {}, 0
  for f in p:lines() do
    files[#files + 1] = f
    if f:match("%.lua$") then mods = mods + 1 end
  end
  p:close()
  check(mods > 20, "found the edge modules")
  check(#files > mods, "found the reference confs")
  -- pattern, and the most top-level commas a call without init has
  local forms = {
    { ":%s*incr%s*%(", 1 },
    { "%.%s*incr%s*%(", 2 },
    { "%[%s*[\"']incr[\"']%s*%]%s*%(", 2 },
  }
  local calls = 0
  for _, path in ipairs(files) do
    local fh = assert(io.open(path, "r"))
    local lineno = 0
    for line in fh:lines() do
      lineno = lineno + 1
      local code = line:gsub("%-%-.*$", "")
      if code:find("cfm_shdict", 1, true) and code:find("require", 1, true) then
        check(code:match("^%s*local%s+shd%s*=%s*require%s*%(?%s*[\"']cfm_shdict[\"']"),
          string.format("%s:%d: require cfm_shdict as `local shd` (the guard exempts shd.incr)", path, lineno))
      end
      for _, form in ipairs(forms) do
        local from = 1
        while true do
          local s, e = code:find(form[1], from)
          if not s then break end
          local recv = code:sub(1, s - 1):match("([%w_]+)%s*$")
          local helper = form[2] == 2 and code:sub(s, s) == "." and
            (recv == "shd" or (recv == "_M" and path:match("cfm_shdict%.lua$")))
          if helper then from = e + 1; goto continue end
          calls = calls + 1
          -- count top-level commas up to the matching ")"
          local depth, commas, i = 1, 0, e + 1
          while i <= #code and depth > 0 do
            local ch = code:sub(i, i)
            if ch == "(" or ch == "{" or ch == "[" then depth = depth + 1
            elseif ch == ")" or ch == "}" or ch == "]" then depth = depth - 1
            elseif ch == "," and depth == 1 then commas = commas + 1 end
            i = i + 1
          end
          check(depth == 0, string.format("%s:%d: an incr call this guard cannot read on one line", path, lineno))
          check(commas <= form[2], string.format("%s:%d: dict:incr with an init argument; use cfm_shdict.incr", path, lineno))
          from = e + 1
          ::continue::
        end
      end
    end
    fh:close()
  end
  check(calls > 0, "the guard saw the helper's own incr calls")
end

if fails > 0 then
  io.stderr:write(fails .. " failure(s)\n")
  os.exit(1)
end
print("cfm_shdict_test: ok")

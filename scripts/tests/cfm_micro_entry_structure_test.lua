-- Structural test: the Tier B micro-cache is entered ONLY from cfm.lua's
-- Step 4 (plain allow), after every decision step. A micro HIT answers the
-- request from the cache without the origin, so an entry any earlier — before
-- the WAF (Step 2), the forced challenge (Step 2.5) or the bridge decision
-- (Step 3) — would serve a cached page to a request those steps block or
-- challenge. (The Step 2b clearance fast-path is deliberately not an entry
-- either; docs/site-cache-design.md §5.6.) Static reading of the source, with
-- Lua comments and string contents stripped, so a comment or a log string
-- can never satisfy (or trip) a check.

local fails = 0
local function check(c, m)
  if c then return end
  fails = fails + 1
  io.stderr:write("FAIL: " .. m .. "\n")
end

local function read(path)
  local f = assert(io.open(path, "rb"))
  local s = f:read("*a")
  f:close()
  return s
end

-- strip(src, keep_strings): Lua source with comments removed (newlines kept,
-- so line numbers still match) and each string literal replaced by "" — or
-- kept as written when keep_strings.
local function strip(src, keep_strings)
  local out, i, n = {}, 1, #src
  local function long_close(pos)
    local eq = src:match("^%[(=*)%[", pos)
    if not eq then return nil end
    local close = "]" .. eq .. "]"
    local e = src:find(close, pos + #eq + 2, true)
    return e and (e + #close - 1) or n, #eq
  end
  while i <= n do
    local c = src:sub(i, i)
    if c == "-" and src:sub(i, i + 1) == "--" then
      local e = long_close(i + 2)
      if not e then e = (src:find("\n", i, true) or (n + 1)) - 1 end
      local body = src:sub(i, e)
      out[#out + 1] = body:gsub("[^\n]", "")
      i = e + 1
    elseif c == "[" and src:match("^%[=*%[", i) then
      local e = long_close(i)
      local body = src:sub(i, e)
      out[#out + 1] = keep_strings and body or ('""' .. body:gsub("[^\n]", ""))
      i = e + 1
    elseif c == '"' or c == "'" then
      local j = i + 1
      while j <= n do
        local d = src:sub(j, j)
        if d == "\\" then j = j + 2
        elseif d == c or d == "\n" then break
        else j = j + 1 end
      end
      out[#out + 1] = keep_strings and src:sub(i, j) or '""'
      i = j + 1
    else
      out[#out + 1] = c
      i = i + 1
    end
  end
  return table.concat(out)
end

-- positions (line numbers) of every match of a Lua pattern
local function lines_of(code, pat)
  local res, init = {}, 1
  while true do
    local s, e = code:find(pat, init)
    if not s then break end
    local _, nl = code:sub(1, s):gsub("\n", "")
    res[#res + 1] = nl + 1
    init = e + 1
  end
  return res
end

local src = read("configs/lua/cfm.lua")
local code = strip(src, false)

-- The stripper itself: a comment or a string naming the call is not code.
check(not strip('-- micro_cache_target()\nlocal s = "micro_cache_target()"\n', false):find("micro_cache_target", 1, true),
      "the stripper leaves comment / string text in the code")

-- Step headers, in the raw source (they are comments).
local step4
local last_step_line = 0
do
  local l = 0
  for line in (src .. "\n"):gmatch("([^\n]*)\n") do
    l = l + 1
    if line:match("^%-%- ── Step ") then
      last_step_line = l
      if line:match("^%-%- ── Step 4: Allow") then step4 = l end
    end
  end
end
check(step4 ~= nil, "cfm.lua has no '-- ── Step 4: Allow' header")
check(step4 == last_step_line, "a step header follows Step 4 (line " .. tostring(last_step_line) ..
      ") — the micro entry must stay the last step")

-- micro_cache_target: defined once, called once, at Step 4.
local def = lines_of(code, "local%s+function%s+micro_cache_target%s*%(")
local uses = lines_of(code, "micro_cache_target%s*%(")
check(#def == 1, #def .. " definitions of micro_cache_target (want 1)")
check(#uses == 2, (#uses - #def) .. " calls of micro_cache_target (want exactly 1, at Step 4)")
local call
for _, l in ipairs(uses) do if l ~= def[1] then call = l end end
check(call and step4 and call > step4, "micro_cache_target is called at line " .. tostring(call) ..
      ", not after the Step 4 header (line " .. tostring(step4) .. ")")

-- The call hands its target straight to ngx.exec, and that is the last
-- statement of cfm_enforce (nothing runs after the micro redirect decision).
local tail = code:match("local%s+micro_target%s*=%s*micro_cache_target%s*%(%s*%)%s*(.-)%f[%w]end%s+local%s+function%s+main%f[%W]")
check(tail ~= nil, "the Step 4 call is not `local micro_target = micro_cache_target()` followed by the end of cfm_enforce")
if tail then
  local t = tail:gsub("%s+", " ")
  check(t == "if micro_target then return ngx.exec(micro_target) end ",
        "after the call, cfm_enforce must only `if micro_target then return ngx.exec(micro_target) end` — got: " .. t)
end

-- cfm_cache.micro_gate is reached only through micro_cache_target (the pcall
-- wrapper), and cfm.lua makes no other internal redirect that could land in
-- an @cfm_micro_<n>s location.
local gate = lines_of(code, "micro_gate")
for _, l in ipairs(gate) do
  check(def[1] and l >= def[1] and l <= def[1] + 12,
        "cfm_cache.micro_gate referenced at line " .. l .. ", outside micro_cache_target")
end
check(#gate >= 1, "micro_cache_target no longer calls cfm_cache.micro_gate")
local execs = lines_of(code, "ngx%.exec%s*%(")
check(#execs == 1 and execs[1] == call + 1,
      #execs .. " ngx.exec call(s) in cfm.lua (want exactly the Step 4 micro one) — if a new one can reach an @cfm_micro_<n>s location it must sit at Step 4; update this test")

-- No other edge module enters micro (or routes to a micro location); only
-- cfm_cache.lua builds the target and cfm.lua execs it.
local all = io.popen("ls configs/lua/*.lua")
for path in all:lines() do
  if path ~= "configs/lua/cfm.lua" and path ~= "configs/lua/cfm_cache.lua" then
    local c = strip(read(path), true)
    check(not c:find("micro_gate", 1, true) and not c:find("@cfm_micro_", 1, true),
          path .. " references micro_gate or an @cfm_micro_ location (only cfm.lua Step 4 enters micro)")
  end
end
all:close()

if fails > 0 then io.stderr:write(fails .. " failure(s)\n"); os.exit(1) end
print("OK cfm_micro_entry_structure_test (micro entry at cfm.lua:" .. tostring(call) .. ", Step 4 at :" .. tostring(step4) .. ")")

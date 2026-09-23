-- Structural test: the Tier B micro-cache is entered ONLY from cfm.lua's
-- Step 4 (plain allow), after every decision step. A micro HIT answers the
-- request from the cache without the origin, so an entry any earlier — before
-- the WAF (Step 2), the forced challenge (Step 2.5) or the bridge decision
-- (Step 3) — would serve a cached page to a request those steps block or
-- challenge. (The Step 2b clearance fast-path is deliberately not an entry
-- either; docs/site-cache-design.md §5.6.) Static reading of the source, with
-- Lua comments and string contents stripped, so a comment or a log string
-- can never satisfy (or trip) a check. It pins the plain spellings; a
-- deliberately obfuscated call (a name computed at run time) is beyond it.

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
      -- a short string: an escape takes the next char (a backslash-newline
      -- continues the string), \z also the whitespace after it; an
      -- unescaped newline ends it (unterminated). Newlines inside it are
      -- kept in the output so line numbers stay right.
      local j = i + 1
      while j <= n do
        local d = src:sub(j, j)
        if d == "\\" then
          if src:sub(j + 1, j + 1) == "z" then
            j = j + 2
            while j <= n and src:sub(j, j):match("%s") do j = j + 1 end
          else
            j = j + 2
          end
        elseif d == c or d == "\n" then break
        else j = j + 1 end
      end
      local body = src:sub(i, j)
      out[#out + 1] = keep_strings and body or ('""' .. body:gsub("[^\n]", ""))
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

-- micro_cache_target: defined once and used once — called at Step 4 (any
-- other mention, an alias included, is a second use).
local def = lines_of(code, "local%s+function%s+micro_cache_target%s*%(")
local uses = lines_of(code, "%f[%w_]micro_cache_target%f[^%w_]")
check(#def == 1, #def .. " definitions of micro_cache_target (want 1)")
check(#uses == 2, (#uses - #def) .. " other uses of micro_cache_target (want exactly 1: the call at Step 4)")
local call
for _, l in ipairs(uses) do if l ~= def[1] then call = l end end
check(call and step4 and call > step4, "micro_cache_target is used at line " .. tostring(call) ..
      ", not after the Step 4 header (line " .. tostring(step4) .. ")")

-- The call hands its target straight to ngx.exec, and that is the last
-- statement of cfm_enforce (nothing runs after the micro redirect decision).
local ts, te = code:find("local%s+([%a_][%w_]*)%s*=%s*micro_cache_target%s*%(%s*%)%s*if%s+%1%s+then%s+return%s+ngx%s*%.%s*exec%s*%(%s*%1%s*%)%s*end%s+end%f[^%w_]")
check(ts ~= nil, "at Step 4, cfm_enforce must end with `local t = micro_cache_target()` + `if t then return ngx.exec(t) end` (nothing after it)")

-- cfm_cache.micro_gate is reached only through micro_cache_target (the pcall
-- wrapper: its body runs from the definition to the first `end` at column
-- 0), and cfm.lua makes no other internal redirect that could land in an
-- @cfm_micro_<n>s location.
local wrap_s = def[1] and code:find("local%s+function%s+micro_cache_target%s*%(")
local wrap_e = wrap_s and code:find("\nend%f[^%w_]", wrap_s)
check(wrap_e ~= nil, "cannot find the end of micro_cache_target")
local ngate, init = 0, 1
while true do
  local gs, ge = code:find("%f[%w_]micro_gate%f[^%w_]", init)
  if not gs then break end
  ngate = ngate + 1
  check(wrap_s and wrap_e and gs > wrap_s and gs < wrap_e,
        "cfm_cache.micro_gate referenced at line " .. select(2, code:sub(1, gs):gsub("\n", "")) + 1 .. ", outside micro_cache_target")
  init = ge + 1
end
check(ngate >= 1, "micro_cache_target no longer calls cfm_cache.micro_gate")
local nexec, einit, exec_in_tail = 0, 1, false
while true do
  local es, ee = code:find("ngx%s*%.%s*exec%s*%(", einit)
  if not es then break end
  nexec = nexec + 1
  if ts and es > ts and es < te then exec_in_tail = true end
  einit = ee + 1
end
check(nexec == 1 and exec_in_tail,
      nexec .. " ngx.exec call(s) in cfm.lua (want exactly one, the Step 4 micro one) — if a new one can reach an @cfm_micro_<n>s location it must sit at Step 4; update this test")

-- No other edge module enters micro (or routes to a micro location); only
-- cfm_cache.lua builds the target and cfm.lua execs it.
local all = io.popen("ls configs/lua/*.lua")
for path in all:lines() do
  if path ~= "configs/lua/cfm.lua" and path ~= "configs/lua/cfm_cache.lua" then
    local src_m = read(path)
    local c, cs = strip(src_m, false), strip(src_m, true)
    check(not c:find("%f[%w_]micro_gate%f[^%w_]") and not cs:find("@cfm_micro_", 1, true),
          path .. " calls micro_gate or names an @cfm_micro_ location (only cfm.lua Step 4 enters micro)")
  end
end
all:close()

if fails > 0 then io.stderr:write(fails .. " failure(s)\n"); os.exit(1) end
print("OK cfm_micro_entry_structure_test (micro entry at cfm.lua:" .. tostring(call) .. ", Step 4 at :" .. tostring(step4) .. ")")

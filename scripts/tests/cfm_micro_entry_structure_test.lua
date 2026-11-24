-- Structural test: the Tier B micro-cache is entered from exactly three places
-- in cfm.lua. Step 4 (plain allow), after every decision step: a micro HIT
-- answers the request from the cache without the origin, so an entry any
-- earlier — before the WAF (Step 2), the forced challenge (Step 2.5) or the
-- bridge decision (Step 3) — would serve a cached page to a request those
-- steps block or challenge. And the Step 0 static bypass, for a crawler of the
-- bypass list ("1") only: none of those steps applies to a bypassed client,
-- and its entries live in the crawler keyspace (ngx.ctx.cfm_micro_class =
-- "crawler", written nowhere else), so a visitor never reads one. And the Step
-- 2b clearance fast path (docs/site-cache-design.md §5.5.1), after the WAF
-- (Step 2) and after the cookie refresh, only on a conf that declares
-- $cfm_edge_sc (the record of the edge's own Set-Cookie lines that keeps the
-- refreshed cookie out of the store decision). Static reading of the source, with
-- Lua comments and string contents stripped, so a comment or a log string
-- can never satisfy (or trip) a check. It pins the plain spellings; a
-- deliberately obfuscated route (a name computed at run time, a helper
-- declared in one place and assigned in another) is beyond it.

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
local step4, step0, step0_end, step2b, step2b_end
local last_step_line = 0
do
  local l = 0
  for line in (src .. "\n"):gmatch("([^\n]*)\n") do
    l = l + 1
    if line:match("^%-%- ── Step ") then
      if step0 and not step0_end then step0_end = l end
      if step2b and not step2b_end then step2b_end = l end
      last_step_line = l
      if line:match("^%-%- ── Step 4: Allow") then step4 = l end
      if line:match("^%-%- ── Step 0: Static IP/CIDR bypass") then step0 = l end
      if line:match("^%-%- ── Step 2b: Honour clearance allow") then step2b = l end
    end
  end
end
check(step0 ~= nil and step0_end ~= nil, "cfm.lua has no '-- ── Step 0: Static IP/CIDR bypass' block")
check(step2b ~= nil and step2b_end ~= nil, "cfm.lua has no '-- ── Step 2b: Honour clearance allow' block")
-- the source text of one line range (raw, or stripped of comments/strings)
local function span(text, a, b)
  local out, l = {}, 0
  for line in (text .. "\n"):gmatch("([^\n]*)\n") do
    l = l + 1
    if l >= a and l < b then out[#out + 1] = line end
  end
  return table.concat(out, "\n")
end
check(step4 ~= nil, "cfm.lua has no '-- ── Step 4: Allow' header")
check(step4 == last_step_line, "a step header follows Step 4 (line " .. tostring(last_step_line) ..
      ") — the micro entry must stay the last step")

-- micro_cache_target: defined once and used once — called at Step 4 (any
-- other mention, an alias included, is a second use).
local def = lines_of(code, "local%s+function%s+micro_cache_target%s*%(")
local uses = lines_of(code, "%f[%w_]micro_cache_target%f[^%w_]")
check(#def == 1, #def .. " definitions of micro_cache_target (want 1)")
check(#uses == 4, (#uses - #def) .. " other uses of micro_cache_target (want exactly 3: the Step 0 crawler, Step 2b clearance and Step 4 calls)")
local call, crawler_call, clearance_call
for _, l in ipairs(uses) do
  if l ~= def[1] then
    if step4 and l > step4 then call = l
    elseif step0 and l > step0 and l < step0_end then crawler_call = l
    elseif step2b and l > step2b and l < step2b_end then clearance_call = l end
  end
end
check(clearance_call ~= nil, "the third micro_cache_target call is not inside the Step 2b clearance block (lines " ..
      tostring(step2b) .. "-" .. tostring(step2b_end) .. ")")

-- The Step 2b entry: inside `if clearance_allow then`, after the cookie refresh
-- (its line must be recorded before the exec), gated on a conf that declares
-- $cfm_edge_sc, and handed straight to ngx.exec.
do
  local code2b = step2b and span(code, step2b, step2b_end) or ""
  local open = code2b:find("if%s+clearance_allow%s+then")
  local refresh = code2b:find("refresh_clearance_cookie%s*%(")
  local gate = code2b:find("if%s+ngx%s*%.%s*var%s*%.%s*cfm_edge_sc%s*~=%s*nil%s+then%s+local%s+([%a_][%w_]*)%s*=%s*micro_cache_target%s*%(%s*%)%s*if%s+%1%s+then%s+return%s+ngx%s*%.%s*exec%s*%(%s*%1%s*%)%s*end")
  check(open ~= nil and refresh ~= nil and gate ~= nil and open < refresh and refresh < gate,
        "at Step 2b the entry must be `if ngx.var.cfm_edge_sc ~= nil then local t = micro_cache_target() if t then return ngx.exec(t) end`, inside `if clearance_allow then`, after refresh_clearance_cookie")
end
check(call ~= nil, "micro_cache_target is not called after the Step 4 header (line " .. tostring(step4) .. ")")
check(crawler_call ~= nil, "the second micro_cache_target call is not inside the Step 0 static-bypass block (lines " ..
      tostring(step0) .. "-" .. tostring(step0_end) .. ")")

-- The Step 0 entry: the crawler class is set in that block, and only there
-- (anywhere else could move visitors into the crawler keyspace or a crawler
-- out of it), and the call hands its target straight to ngx.exec.
do
  local raw0 = step0 and span(strip(src, true), step0, step0_end) or ""
  local code0 = step0 and span(code, step0, step0_end) or ""
  local _, nclass = strip(src, true):gsub("cfm_micro_class%s*=[^=]", "")
  local _, nclass0 = raw0:gsub('ngx%.ctx%.cfm_micro_class%s*=%s*"crawler"', "")
  check(nclass == 1 and nclass0 == 1, "ngx.ctx.cfm_micro_class must be assigned exactly once, to \"crawler\", in the Step 0 block (" ..
        nclass .. " assignment(s), " .. nclass0 .. " there)")
  check(raw0:find('if%s+bp%s*==%s*"1"%s+then%s+ngx%.ctx%.cfm_micro_class%s*=%s*"crawler"') ~= nil,
        "the crawler class is set only for a bypass kind \"1\" client")
  check(code0:find("local%s+([%a_][%w_]*)%s*=%s*micro_cache_target%s*%(%s*%)%s*if%s+%1%s+then%s+return%s+ngx%s*%.%s*exec%s*%(%s*%1%s*%)%s*end") ~= nil,
        "at Step 0 the crawler entry must be `local t = micro_cache_target()` + `if t then return ngx.exec(t) end`")
  -- the CDN kind returns before it: a CDN fetches for a site's visitors (read
  -- on the raw text, strings kept: the stripped code cannot tell "1" from "2")
  local cdn = raw0:find('if%s+bp%s*==%s*"2"%s+then%s+micro_skip%s*%(%s*"cdn"%s*%)%s+return%s+end')
  local entry = raw0:find("micro_cache_target%s*%(")
  check(cdn ~= nil and entry ~= nil and cdn < entry, "at Step 0 a CDN (\"2\") client must return before the crawler micro entry")
end

-- The call hands its target straight to ngx.exec, and that is the last
-- statement of cfm_enforce (nothing runs after the micro redirect decision).
-- (cfm_enforce's own `end` is the next statement, at column 0.)
local ts, te = code:find("local%s+([%a_][%w_]*)%s*=%s*micro_cache_target%s*%(%s*%)%s*if%s+%1%s+then%s+return%s+ngx%s*%.%s*exec%s*%(%s*%1%s*%)%s*end%s*\nend%f[^%w_]")
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
check(ngate == 2, ngate .. " mentions of micro_gate (want 2: the wrapper's nil check and its pcall)")
local nexec, einit, exec_in_tail = 0, 1, false
while true do
  local es, ee = code:find("ngx%s*%.%s*exec%f[^%w_]", einit)
  if not es then break end
  nexec = nexec + 1
  if ts and es > ts and es < te then exec_in_tail = true end
  einit = ee + 1
end
check(nexec == 3 and exec_in_tail,
      nexec .. " mention(s) of ngx.exec in cfm.lua (want exactly three, the Step 0 crawler, Step 2b clearance and Step 4 micro calls; an alias counts) — if a new one can reach an @cfm_micro_<n>s location it must sit at Step 4; update this test")
-- cfm.lua itself never names a micro location (cfm_cache.lua builds it).
check(not strip(src, true):find("@cfm_micro_", 1, true), "cfm.lua names an @cfm_micro_ location in its code — only cfm_cache.lua builds the target")

-- No other edge module enters micro (or routes to a micro location); only
-- cfm_cache.lua builds the target and cfm.lua execs it.
local all = io.popen("ls configs/lua/*.lua")
for path in all:lines() do
  if path ~= "configs/lua/cfm.lua" and path ~= "configs/lua/cfm_cache.lua" then
    local src_m = read(path)
    local c, cs = strip(src_m, false), strip(src_m, true)
    check(not c:find("%f[%w_]micro_gate%f[^%w_]") and not cs:find("@cfm_micro_", 1, true),
          path .. " calls micro_gate or names an @cfm_micro_ location (only cfm.lua enters micro)")
  end
  if path ~= "configs/lua/cfm.lua" then
    -- nor makes an internal redirect at all (cfm_cache.lua included: an exec
    -- there, reached from anywhere in cfm.lua, would bypass the Step 4 pin)
    check(not strip(read(path), false):find("ngx%s*%.%s*exec%f[^%w_]"),
          path .. " uses ngx.exec — only cfm.lua (at Step 4) redirects into micro")
  end
end
all:close()

if fails > 0 then io.stderr:write(fails .. " failure(s)\n"); os.exit(1) end
print("OK cfm_micro_entry_structure_test (micro entries at cfm.lua:" .. tostring(crawler_call) .. " (Step 0 crawler), :" ..
      tostring(clearance_call) .. " (Step 2b clearance) and :" .. tostring(call) .. " (Step 4 at :" .. tostring(step4) .. "))")

-- Guard: no edge Lua module reads or writes an undeclared global.
--
-- A misspelt or forgotten local compiles fine in Lua and reads nil at run
-- time. cfm_waf.lua passed an undeclared `host` to the three auth-burst
-- detectors for months (always nil, so their counters were per IP across
-- vhosts whatever the code seemed to say). The bytecode names every global
-- access (GGET / GSET), so this lists them per module (luajit -bl) and fails
-- on any name that is not a Lua/LuaJIT builtin, ngx, or a documented
-- per-module exception.

package.path = "configs/lua/?.lua;" .. package.path

local fails = 0
local function check(c, m)
  if c then return end
  fails = fails + 1
  io.stderr:write("FAIL: " .. m .. "\n")
end

local BUILTIN = {}
for name in ([[
  _G _VERSION assert collectgarbage coroutine debug dofile error getfenv
  getmetatable io ipairs load loadfile loadstring math module next os package
  pairs pcall print rawequal rawget rawlen rawset require select setfenv
  setmetatable string table tonumber tostring type unpack xpcall
  bit jit ngx
]]):gmatch("%S+") do BUILTIN[name] = true end

-- Deliberate globals, per module, with the reason.
local ALLOW = {
  -- the selftest hook nginx's init_by_lua dofile()s and calls; installed
  -- with rawset(_G, ...) so it doesn't trip the global-write warning.
  ["cfm_panel.lua"] = { cfm_panel_selftest = true },
}

local function shell_quote(s) return "'" .. s:gsub("'", "'\\''") .. "'" end

local list = io.popen("ls configs/lua/*.lua")
local files = {}
for f in list:lines() do files[#files + 1] = f end
list:close()
check(#files > 20, "expected the edge modules under configs/lua, found " .. #files)

for _, path in ipairs(files) do
  local base = path:match("([^/]+)$")
  local p = io.popen("luajit -bl " .. shell_quote(path) .. " 2>&1")
  local out = p:read("*a")
  p:close()
  check(out:find("BYTECODE", 1, true) ~= nil,
        base .. ": luajit -bl produced no bytecode listing (cannot check):\n" .. out:sub(1, 300))
  local seen = {}
  for op, name in out:gmatch("%s(G[GS]ET)%s[^\n]-;%s*\"([^\"]*)\"") do
    local key = op .. " " .. name
    if not seen[key] then
      seen[key] = true
      local ok = (op == "GGET" and BUILTIN[name]) or (ALLOW[base] and ALLOW[base][name])
      check(ok, base .. ": " .. op .. " of undeclared global '" .. name .. "'")
    end
  end
end

-- The matcher itself must see a global: a module that reads one must fail.
do
  local tmp = os.tmpname()
  local fh = io.open(tmp, "w")
  fh:write("local M = {}\nfunction M.f() return hostt end\nreturn M\n")
  fh:close()
  local p = io.popen("luajit -bl " .. shell_quote(tmp) .. " 2>&1")
  local out = p:read("*a")
  p:close()
  os.remove(tmp)
  local found = false
  for op, name in out:gmatch("%s(G[GS]ET)%s[^\n]-;%s*\"([^\"]*)\"") do
    if op == "GGET" and name == "hostt" then found = true end
  end
  check(found, "matcher did not see the planted global read (luajit -bl format changed?)")
end

if fails > 0 then
  io.stderr:write(fails .. " failure(s)\n")
  os.exit(1)
end
print("ok - cfm_lua_globals_test")

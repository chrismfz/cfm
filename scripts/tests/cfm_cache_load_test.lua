-- Load test for cfm_cache.lua: the module must load where no `ngx` global
-- exists (a plain-LuaJIT require), and so must every module it requires at
-- load time. Only `cjson.safe` is stubbed; nginx supplies it at the edge, and
-- a bare luajit may not have it. The NGX_JOINS_HEADERS guard is what this
-- pins: before it, the module failed at load on `ngx.config`.

package.path = "configs/lua/?.lua;" .. package.path

_G.ngx = nil
package.preload["cjson.safe"] = function()
  return { decode = function() return nil end, encode = function() return "{}" end }
end

local fails = 0
local function check(c, m)
  if c then return end
  fails = fails + 1
  io.stderr:write("FAIL: " .. m .. "\n")
end

local ok, mod = pcall(require, "cfm_cache")
check(ok, "cfm_cache loads without ngx: " .. tostring(mod))
check(ok and type(mod) == "table", "cfm_cache returns its module table")
if ok and type(mod) == "table" then
  for _, fn in ipairs({ "observe", "static_gate", "micro_gate", "policy_for",
                        "policy_key_for", "maybe_flush_stats" }) do
    check(type(mod[fn]) == "function", "cfm_cache exports " .. fn)
  end
end
check(_G.ngx == nil, "loading cfm_cache does not create an ngx global")

if fails > 0 then
  io.stderr:write(fails .. " failure(s)\n")
  os.exit(1)
end
print("cfm_cache_load_test: ok")

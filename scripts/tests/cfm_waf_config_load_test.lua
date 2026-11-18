-- How cfm_waf loads the operator's overrides (cfm_waf_config, mirrored from
-- /etc/cfm by the daemon, internal/wafconfig). A missing file is normal and
-- silent; a table is applied; a file that is present but broken (syntax
-- error, no `return`, not a table) must log an ERR instead of being skipped
-- silently, as it was before 2026-11-18.

local logged = {}
_G.ngx = {
  now           = function() return 1000 end,
  decode_base64 = function(_) return nil end,
  log           = function(lvl, ...)
    local parts = {}
    for i = 1, select("#", ...) do parts[#parts + 1] = tostring(select(i, ...)) end
    logged[#logged + 1] = { lvl = lvl, msg = table.concat(parts) }
  end,
  ERR = 0, WARN = 1, INFO = 2,
}
package.path = "configs/lua/?.lua;" .. package.path

local fails = 0
local function check(cond, msg)
  if cond then return end
  fails = fails + 1
  io.stderr:write("FAIL: " .. msg .. "\n")
end

-- Load a fresh cfm_waf with cfm_waf_config set up by `prep`; return the
-- module and the cfm_waf_config log lines it produced.
local function load_with(prep)
  package.loaded["cfm_waf"] = nil
  package.loaded["cfm_waf_config"] = nil
  package.preload["cfm_waf_config"] = nil
  logged = {}
  prep()
  local waf = require("cfm_waf")
  local mine = {}
  for _, l in ipairs(logged) do
    if l.msg:find("cfm_waf_config", 1, true) then mine[#mine + 1] = l end
  end
  package.loaded["cfm_waf_config"] = nil
  package.preload["cfm_waf_config"] = nil
  return waf, mine
end

-- 1. No file: the usual case, nothing logged.
do
  local _, lines = load_with(function() end)
  check(#lines == 0, "a missing cfm_waf_config logs nothing (got " .. #lines .. ")")
end

-- 2. A table: applied.
do
  local waf, lines = load_with(function()
    package.loaded["cfm_waf_config"] = { rule_bad_ua = "disabled" }
  end)
  check(waf.get_config().rule_bad_ua == "disabled", "a table override is applied")
  check(#lines == 0, "a good override logs nothing")
end

-- 3. A syntax error (the chunk fails to load): logged, defaults kept.
do
  local waf, lines = load_with(function()
    package.preload["cfm_waf_config"] = function()
      error("cfm_waf_config.lua:2: '}' expected near 'disabled'")
    end
  end)
  check(#lines == 1 and lines[1].lvl == ngx.ERR, "a broken file logs one ERR")
  check(lines[1] and lines[1].msg:find("NOT applied", 1, true), "the ERR says the overrides are not applied")
  check(lines[1] and lines[1].msg:find("expected near", 1, true), "the ERR carries the load error")
  check(waf.get_config().rule_bad_ua ~= "disabled", "defaults stay in place")
end

-- 4. A file with no `return`: require() yields true; logged.
do
  local _, lines = load_with(function()
    package.preload["cfm_waf_config"] = function() end
  end)
  check(#lines == 1 and lines[1].msg:find("returned nothing", 1, true), "a file without return is logged")
end

-- 5. A file returning a non-table: logged.
do
  local _, lines = load_with(function()
    package.preload["cfm_waf_config"] = function() return "rule_bad_ua=disabled" end
  end)
  check(#lines == 1 and lines[1].msg:find("returned a string", 1, true), "a non-table return is logged")
end

if fails > 0 then
  io.stderr:write(("cfm_waf config-load tests: %d FAILED\n"):format(fails))
  os.exit(1)
end
print("cfm_waf config-load tests: OK")

-- Tests for cfm_geo reading both GeoLite2-City.mmdb schemas CFM installs.
--
-- The MaxMind updater installs IPLocate's free ip-to-country database under the
-- GeoLite2-City.mmdb name when no MaxMind account is configured. Its records are
-- FLAT ({country_code = "GR", country_name = "Greece"}), not MaxMind's nested
-- {country = {iso_code = "GR"}}. cfm_geo read only the nested field, so on such
-- a node every lookup returned "" — as a RESOLVED answer, cached like a real
-- "no country". Both schemas must read, on both lua-resty-maxminddb backends.

_G.ngx = {
  now  = function() return 1000 end,
  log  = function() end,
  WARN = 1, ERR = 2, INFO = 3,
}

local fails = 0
local function check(cond, msg)
  if cond then return end
  fails = fails + 1
  io.stderr:write("FAIL: " .. msg .. "\n")
end

package.path = "configs/lua/?.lua;" .. package.path

-- Records as the two databases return them (IPLocate's as measured on the real
-- 2026-09-22 ip-to-country file).
local records = {
  ["94.68.42.127"] = { country = { iso_code = "GR", names = { en = "Greece" } } },    -- MaxMind
  ["1.1.1.1"]      = { continent_code = "OC", country_code = "AU", country_name = "Australia" }, -- IPLocate
  ["5.5.5.5"]      = { country_code = "de" },                                          -- lower-case flat
  ["9.9.9.9"]      = { country = { names = { en = "?" } } },                          -- nested, no iso_code
  ["0.0.0.0"]      = {},                                                               -- no country at all
}

local function run(backend_name, backend)
  package.loaded["resty.maxminddb"] = backend
  package.loaded["cfm_geo"] = nil
  local geo = require("cfm_geo")
  check(geo.mode() == backend_name, backend_name .. ": backend detected")

  local cc, ok = geo.country("94.68.42.127")
  check(cc == "GR" and ok == true, backend_name .. ": MaxMind nested schema reads GR, resolved")
  cc, ok = geo.country("1.1.1.1")
  check(cc == "AU" and ok == true, backend_name .. ": IPLocate flat schema reads AU, resolved (got '" .. tostring(cc) .. "')")
  cc = geo.country("5.5.5.5")
  check(cc == "DE", backend_name .. ": flat country_code is upper-cased")
  cc, ok = geo.country("9.9.9.9")
  check(cc == "" and ok == true, backend_name .. ": nested record without iso_code is a resolved ''")
  cc, ok = geo.country("0.0.0.0")
  check(cc == "" and ok == true, backend_name .. ": record with no country is a resolved ''")
end

run("init_lookup", {
  init   = function(_) return true end,
  lookup = function(ip) return records[ip] or {} end,
})

run("new_object", {
  new = function(_)
    return { lookup = function(_, ip) return records[ip] or {} end }
  end,
})

if fails > 0 then
  io.stderr:write(fails .. " cfm_geo schema test(s) failed\n")
  os.exit(1)
end
print("cfm_geo schema tests: OK")

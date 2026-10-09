-- Replays scripts/tests/fixtures/php_request_fields.lua — requests with what a
-- real PHP registered in $_GET + $_POST for each, recorded by
-- scripts/tests/php_request_fields_oracle.py — through
-- cfm_waf_detectors.php_request_fields, the reader the field-keyed WAF rules
-- (10017, 10018/10019/10020) use. Every name PHP registered must be read, with
-- PHP's value as the reader's LAST value for it (an array in PHP: name only).
-- The reader may not invent names PHP did not register either, so a
-- divergence in either direction fails. Optional arg: another fixture path.

_G.ngx = {
  now           = function() return 1000 end,
  decode_base64 = function(_) return nil end,
  log           = function(_, _) end,
  ERR           = 0, WARN = 1, INFO = 2,
}
package.path = "configs/lua/?.lua;" .. package.path
require("cfm_waf")
local det = require("cfm_waf_detectors")

local cases = dofile(arg[1] or "scripts/tests/fixtures/php_request_fields.lua")
local function show(s) return (s:gsub("[%c\128-\255]", function(c) return ("\\%03d"):format(c:byte()) end)) end

local fails = 0
for i, c in ipairs(cases) do
  local f = det.php_request_fields(c.method:lower(), c.query, c.body, { ["Content-Type"] = c.ct })
  local bad = {}
  for name, want in pairs(c.want) do
    local got = f[name]
    if not got then
      bad[#bad + 1] = "missing " .. show(name)
    elseif want ~= true and got[#got] ~= want then
      bad[#bad + 1] = ("%s: last=%s php=%s"):format(show(name), show(got[#got]), show(want))
    end
  end
  for name in pairs(f) do
    if name ~= "" and c.want[name] == nil then bad[#bad + 1] = "extra " .. show(name) end
  end
  -- The rules' filtered read (PHP_FIELDS_WANT, lowercased names) must hold
  -- every value PHP registered for a wanted name.
  local fw = det.php_request_fields(c.method:lower(), c.query, c.body, { ["Content-Type"] = c.ct }, det.PHP_FIELDS_WANT)
  for name, want in pairs(c.want) do
    if det.PHP_FIELDS_WANT[name:lower()] and want ~= true then
      local ok = false
      for _, v in ipairs(fw[name:lower()] or {}) do if v == want then ok = true end end
      if not ok then bad[#bad + 1] = "filtered read lacks " .. show(name) .. "=" .. show(want) end
    end
  end
  if #bad > 0 then
    fails = fails + 1
    if fails <= 15 then
      io.stderr:write(("FAIL case %d (%s %s ct=%s): %s\n  body=%s\n"):format(i, c.method, show(c.query), show(c.ct),
        table.concat(bad, "; "), show(c.body):sub(1, 600)))
    end
  end
end
if fails > 0 then
  io.stderr:write(("php_request_fields: %d of %d cases differ from PHP\n"):format(fails, #cases))
  os.exit(1)
end
print(("ok: php_request_fields matches PHP on %d recorded requests"):format(#cases))

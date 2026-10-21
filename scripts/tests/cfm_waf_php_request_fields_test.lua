-- Replays scripts/tests/fixtures/php_request_fields.lua — requests with what a
-- real PHP registered in $_GET + $_POST for each, recorded by
-- scripts/tests/php_request_fields_oracle.py — through
-- cfm_waf_detectors.php_request_fields, the reader the field-keyed WAF rules
-- (10017, 10018/10019/10020) use. Every name PHP registered must be read, with
-- PHP's value as the reader's LAST value for it (an array in PHP: name only),
-- and every file name PHP registered in $_FILES must be a file part the
-- reader sees (php_file_names: the parts rules 401 / 415 read).
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
  -- A body with more non-empty file parts than PHP's default max_file_uploads
  -- (20) is read twice and the reads joined (each_multipart_field): there the
  -- reader must still hold every name and value PHP registered (the rules
  -- read every value), but may hold more. Elsewhere it must match PHP exactly.
  local nfiles = 0
  if c.method == "POST" then
    for _, fname in ipairs(det.php_file_names(c.body, c.ct)) do
      if fname ~= "" then nfiles = nfiles + 1 end
    end
  end
  local superset = nfiles > 20
  local bad = {}
  for name, want in pairs(c.want) do
    local got = f[name]
    if not got then
      bad[#bad + 1] = "missing " .. show(name)
    elseif want ~= true and not superset and got[#got] ~= want then
      bad[#bad + 1] = ("%s: last=%s php=%s"):format(show(name), show(got[#got]), show(want))
    elseif want ~= true and superset then
      local ok = false
      for _, v in ipairs(got) do if v == want then ok = true end end
      if not ok then bad[#bad + 1] = ("%s: php=%s not among the values read"):format(show(name), show(want)) end
    end
  end
  if not superset then
    for name in pairs(f) do
      if name ~= "" and c.want[name] == nil then bad[#bad + 1] = "extra " .. show(name) end
    end
  end
  -- Every file name PHP registered (php_ap_basename of it) must be among the
  -- file parts the reader sees (rules 401 / 415). More is allowed: the reader
  -- also reports a file part PHP skips (past max_file_uploads).
  if c.files and #c.files > 0 then
    local seen = {}
    for _, fname in ipairs(det.php_file_names(c.body, c.ct)) do
      local base = fname:match("[^/\\]*$")
      seen[base] = (seen[base] or 0) + 1
    end
    for _, fname in ipairs(c.files) do
      if (seen[fname] or 0) == 0 then
        bad[#bad + 1] = "missing file " .. show(fname)
      else
        seen[fname] = seen[fname] - 1
      end
    end
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
-- The filtered read skips a whole urlencoded source when its decoded text
-- lacks the pieces of every wanted name; each spelling PHP folds into a wanted
-- name must still be read when it sits in a long query of other keys.
local junk = ("utm_x=1&"):rep(2000)
for _, c in ipairs({
  { "string.ids=1", "string_ids" }, { "STRING%5BIDS=1", "string_ids" }, { "string+ids=1", "string_ids" },
  { "%20%20action=1", "action" }, { "act%69on=1", "action" }, { "ACTION%00x=1", "action" },
  { "user.login=1", "user_login" }, { "wc.reset%5Bpassword=1", "wc_reset_password" },
  { "PAGE%4eAME[x]=1", "pagename" }, { "trp%2Dedit-translation=1", "trp-edit-translation" },
}) do
  for _, where in ipairs({ "args", "body" }) do
    local q = junk .. c[1] .. "&" .. junk
    local f = (where == "args")
      and det.php_request_fields("get", q, "", {}, det.PHP_FIELDS_WANT)
      or det.php_request_fields("post", "", q, { ["Content-Type"] = "application/x-www-form-urlencoded" }, det.PHP_FIELDS_WANT)
    if not (f[c[2]] and f[c[2]][1] == "1") then
      fails = fails + 1
      io.stderr:write(("FAIL filtered read missed %s (as %s) in the %s\n"):format(c[1], c[2], where))
    end
  end
end

if fails > 0 then
  io.stderr:write(("php_request_fields: %d of %d cases differ from PHP\n"):format(fails, #cases))
  os.exit(1)
end
print(("ok: php_request_fields matches PHP on %d recorded requests"):format(#cases))

-- A repeated request header arrives from ngx.req.get_headers() as a Lua table.
-- Pins three places that took one as a string:
--   * rule 412 (detect_polyglot_upload) called :match on it, so two
--     Content-Type headers made check() raise; cfm.lua fails open, and every
--     rule after 412 (traversal 101/103, the 10xxx CVE legs, ...) went unrun;
--   * cfm.lua's /nginx/ip push carried UA / Referer / Content-Type as a table,
--     which cjson encodes as an array and the daemon's string field refuses:
--     the whole push (ban, cfm.waf.log, history, v2 mark) was dropped;
--   * the auth-burst detectors' key host (an undeclared global, now an
--     explicit nil): counters stay per IP across vhosts.

_G.ngx = {
  now           = function() return 1000 end,
  decode_base64 = function(_) return nil end,
  log           = function(_, _) end,
  ERR           = 0, WARN = 1, INFO = 2,
}

package.path = "configs/lua/?.lua;" .. package.path
local waf = require("cfm_waf")
local det = require("cfm_waf_detectors")

local fails = 0
local function check(cond, msg)
  if cond then return end
  fails = fails + 1
  io.stderr:write("FAIL: " .. msg .. "\n")
end

local CHROME = "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 " ..
               "(KHTML, like Gecko) Chrome/131.0.0.0 Safari/537.36"

-- ── rule 412 with two Content-Type headers ──────────────────────────────────
local poly = "--XB\r\nContent-Disposition: form-data; name=\"f\"; filename=\"a.jpg\"\r\n" ..
             "Content-Type: image/jpeg\r\n\r\n<?php system($_GET['c']); ?>\r\n--XB--\r\n"
local one = det.detect_polyglot_upload(poly, { ["content-type"] = "multipart/form-data; boundary=XB" })
check(one ~= nil, "412 sees the polyglot with one Content-Type (fixture sanity)")
local ok, two = pcall(det.detect_polyglot_upload, poly,
  { ["content-type"] = { "multipart/form-data; boundary=XB", "text/plain" } })
check(ok, "412 must not raise on a repeated Content-Type (" .. tostring(two) .. ")")
check(ok and two == one, "412 reads the joined Content-Type when it repeats (got " .. tostring(two) .. ")")
ok = pcall(det.detect_polyglot_upload, poly, { ["content-type"] = {} })
check(ok, "412 must not raise on an empty header table")
-- The boundary PHP splits on, wherever it sits (both reviews of the first
-- cut of this fix): in a second header (Apache joins them with ", "), before
-- a comma, or quoted.
check(det.detect_polyglot_upload(poly,
        { ["content-type"] = { "multipart/form-data", "boundary=XB" } }) == one,
      "412 finds a boundary carried by a second Content-Type")
check(det.detect_polyglot_upload(poly,
        { ["content-type"] = "multipart/form-data; boundary=XB,y" }) == one,
      "412 cuts the boundary at a comma, as PHP does")
local qpoly = poly:gsub("%-%-XB", "--X B")
check(det.detect_polyglot_upload(qpoly,
        { ["content-type"] = 'multipart/form-data; boundary="X B"' }) == one,
      "412 reads a quoted boundary whole")
check(det.detect_polyglot_upload(poly,
        { ["Content-Type"] = "multipart/form-data; boundary=XB" }) == one,
      "412 reads the canonical-case header name")
-- An empty boundary is valid to PHP: parts split on bare `--` lines.
local epoly = poly:gsub("%-%-XB", "--")
for _, ct in ipairs({ "multipart/form-data; boundary=", 'multipart/form-data; boundary=""' }) do
  check(det.detect_polyglot_upload(epoly, { ["content-type"] = ct }) == one,
        "412 walks an empty boundary (" .. ct .. ")")
end
-- PHP's media type is the joined value's first: text/plain first means PHP
-- parses no upload, so 412 has nothing to scan.
check(det.detect_polyglot_upload(poly,
        { ["content-type"] = { "text/plain", "multipart/form-data; boundary=XB" } }) == nil,
      "412 skips a body PHP reads as text/plain")
check(det.detect_polyglot_upload(poly,
        { ["content-type"] = "text/plain; x=multipart/form-data; boundary=XB" }) == nil,
      "412 skips multipart named only in a parameter")

-- ── check(): the rules after 412 still run ─────────────────────────────────
local body = "--XB\r\nContent-Disposition: form-data; name=\"f\"; filename=\"a.txt\"\r\n" ..
             "Content-Type: text/plain\r\n\r\nhello\r\n--XB--\r\n"
local ok2, hit, reason, _, action, _, rule_id = pcall(waf.check, {
  uri = "/index.php", args = "file=../../../../etc/passwd", method = "POST",
  ip = "203.0.113.9", body = body,
  headers = {
    ["content-type"]   = { "multipart/form-data; boundary=XB", "text/plain" },
    ["user-agent"]     = CHROME,
    ["content-length"] = tostring(#body),
  },
})
check(ok2, "check() must not raise on a repeated Content-Type (" .. tostring(hit) .. ")")
check(ok2 and hit == true and rule_id == 101 and action == "block",
      "traversal 101 still blocks behind a repeated Content-Type (got " ..
      tostring(reason) .. "/" .. tostring(action) .. "/" .. tostring(rule_id) .. ")")

-- ── burst detectors: per IP across vhosts ───────────────────────────────────
do
  local keys = {}
  local dict = {}
  function dict:get(k) keys[#keys + 1] = k; return nil end
  function dict:set(k) keys[#keys + 1] = k; return true end
  function dict:add(k) keys[#keys + 1] = k; return true end
  function dict:incr(k) keys[#keys + 1] = k; return 1 end
  waf.check({
    uri = "/xmlrpc.php", args = "", method = "POST", ip = "203.0.113.10",
    body = "<?xml version=\"1.0\"?><methodCall><methodName>wp.getUsersBlogs</methodName></methodCall>",
    headers = { ["user-agent"] = CHROME, ["content-type"] = "text/xml" },
    shdict = dict,
  })
  local burst = 0
  for _, k in ipairs(keys) do
    if k:find("^xmlrpc|") or k:find("^auth|") or k:find("^authwph|") then
      burst = burst + 1
      check(k:find("|203.0.113.10|-", 1, true) ~= nil, "burst key is per IP across vhosts (host \"-\"): " .. k)
    end
  end
  check(burst > 0, "an xmlrpc POST reaches a burst counter (got none)")
  -- The detectors themselves key per IP, whatever host a caller passes.
  keys = {}
  for _ = 1, 2 do
    det.detect_auth_burst("203.0.113.11", "Example.COM", "/wp-login.php", "POST", dict, "", "log=admin&pwd=x",
      { ["content-type"] = "application/x-www-form-urlencoded" })
  end
  det.detect_xmlrpc_post_burst("203.0.113.11", "example.com", "/xmlrpc.php", "POST", dict, "",
    { ["user-agent"] = CHROME }, "<methodCall><methodName>system.multicall</methodName></methodCall>")
  local n = 0
  for _, k in ipairs(keys) do
    if k:find("|203.0.113.11|", 1, true) then
      n = n + 1
      check(k:find("|203.0.113.11|-", 1, true) ~= nil, "a passed host never splits the key: " .. k)
    end
  end
  check(n > 0, "auth/xmlrpc detectors reached their counters")
end

-- ── cfm.lua: the push carries strings ───────────────────────────────────────
do
  local f = assert(io.open("configs/lua/cfm.lua", "r"))
  local src = f:read("*a"); f:close()
  for _, h in ipairs({ "user-agent", "referer", "content-type" }) do
    check(src:find('push_header(req_headers["' .. h .. '"])', 1, true) ~= nil,
          "cfm.lua push passes " .. h .. " through push_header")
    check(src:find('=%s*req_headers%["' .. h:gsub("%-", "%%-") .. '"%],') == nil,
          "cfm.lua push must not carry raw req_headers[\"" .. h .. "\"]")
  end
  -- Run the helper itself, against the real cfm_waf_util.
  local fn_src = src:match("\n(local function push_header%(v%).-\nend)\n")
  check(fn_src ~= nil, "push_header found in cfm.lua")
  if fn_src then
    local env = setmetatable({ wutil_ok = true, wutil = require("cfm_waf_util") }, { __index = _G })
    local chunk = assert(loadstring(fn_src .. "\nreturn push_header"))
    setfenv(chunk, env)
    local push_header = chunk()
    check(push_header("curl/8") == "curl/8", "a single header passes through")
    check(push_header(nil) == nil, "an absent header stays absent")
    check(push_header({ "", "b", "c" }) == "b", "a repeated header is its first non-empty value")
    check(push_header({}) == nil, "an empty table is absent")
    check(push_header({ "a", "b" }) == "a", "the first of two values")
    check(push_header({ 1, {} }) == nil, "non-string values are never sent")
  end
end

if fails > 0 then
  io.stderr:write(("cfm_waf dup-header tests: %d FAILED\n"):format(fails))
  os.exit(1)
end
print("ok: repeated request headers (412 crash, push strings, burst key)")

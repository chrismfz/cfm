-- A POST body with no Content-Length (Transfer-Encoding: chunked, or HTTP/2
-- without the header) went unread by the WAF on every route outside cfm.lua's
-- body allowlist: waf_body_gate treated it as a stream. On the edge confs'
-- `location /` nginx buffers request bodies anyway (proxy_request_buffering on),
-- so a chunked POST of a SQL injection to a clean-URL route (/checkout, a
-- custom router) reached the app uninspected. That location now sets
-- $cfm_body_buffered, and the gate reads such a body there; the streaming
-- locations (PHP/admin, media) leave it empty and keep streaming.
--
-- Also: WooCommerce's `/?wc-ajax=` endpoint, on the allowlist, was matched on
-- $uri, which never carries the query string, so that entry was dead.

local H = dofile("scripts/tests/cfm_lua_harness.lua")
local util = require("cfm_waf_util")

local fails = 0
local function check(cond, msg)
  if cond then return end
  fails = fails + 1
  io.stderr:write("FAIL: " .. msg .. "\n")
end
local function desc(r)
  return ("ok=%s action=%s up=%s exit=%s err=%s"):format(tostring(r.ok), tostring(r.action),
    tostring(r.upstream), tostring(r.exited), tostring(r.err))
end

local SQLI = "q=1' UNION SELECT user_pass FROM wp_users-- -"
local FORM = "application/x-www-form-urlencoded"
local function post(t)
  local vars = { http_content_type = t.ct or FORM, http_content_length = t.cl }
  if t.buffered then vars.cfm_body_buffered = "1" end
  return H.run{ method = "POST", uri = t.uri or "/checkout", args = t.args or "", body = t.body or SQLI,
                headers = { ["content-type"] = t.ct or FORM, ["user-agent"] = "Mozilla/5.0" }, vars = vars }
end

-- ── cfm.lua end to end ──────────────────────────────────────────────────────
do
  local r = post{ cl = tostring(#SQLI) }
  check(r.ok and r.exited == 403, "measured POST to a clean route: inspected, blocked (" .. desc(r) .. ")")

  r = post{ buffered = true }
  check(r.ok and r.exited == 403, "chunked POST to a clean route on `location /`: inspected, blocked (" .. desc(r) .. ")")

  r = post{}
  check(r.ok and r.exited == nil and r.action == "allow",
        "chunked POST where the location streams: still unread, as before (" .. desc(r) .. ")")

  r = post{ buffered = true, ct = "application/octet-stream" }
  check(r.ok and r.exited == nil, "chunked binary body: never read (" .. desc(r) .. ")")

  r = post{ buffered = true, body = "q=hello world&email=a@b.example" }
  check(r.ok and r.exited == nil and r.action == "allow", "chunked clean form on `location /`: allowed (" .. desc(r) .. ")")

  -- wc-ajax rides in the query string: a large (over-cap) or chunked body there
  -- is read via the allowlist, wherever the location.
  r = post{ uri = "/", args = "wc-ajax=checkout" }
  check(r.ok and r.exited == 403, "POST /?wc-ajax=… with no Content-Length: read via the allowlist (" .. desc(r) .. ")")
end

-- ── waf_body_gate's `buffered` argument ─────────────────────────────────────
do
  local g = util.waf_body_gate
  check(g("application/json", nil, 1048576, true) == true, "chunked json where buffered: read")
  check(g("application/json", nil, 1048576, false) == false, "chunked json where it streams: skipped")
  check(g("application/json", nil, 1048576) == false, "chunked json, no flag (old callers): skipped")
  check(g("image/png", nil, 1048576, true) == false, "chunked binary where buffered: skipped")
  check(g("application/json", 2000000, 1048576, true) == false, "over the cap stays skipped where buffered")
end

-- ── Both edge confs mark `location /`, and only it ──────────────────────────
for _, path in ipairs({ "configs/openresty.conf", "configs/angie.conf" }) do
  local f = assert(io.open(path, "r"))
  local src = f:read("*a"); f:close()
  local roots, marks = 0, 0
  for _ in src:gmatch("\n%s*location / {") do roots = roots + 1 end
  for _ in src:gmatch('set %$cfm_body_buffered "1";') do marks = marks + 1 end
  check(roots == 2 and marks == 2, path .. ": every `location /` (" .. roots .. ") sets $cfm_body_buffered (" .. marks .. ")")
  for block in src:gmatch("location / {(.-)\n        }") do
    check(block:find('set $cfm_body_buffered "1";', 1, true) ~= nil, path .. ": a `location /` lacks the marker")
    check(not block:find("proxy_request_buffering%s+off"), path .. ": a marked location must buffer request bodies")
  end
  check(src:find("\n    proxy_request_buffering      on;", 1, true) ~= nil, path .. ": the http block buffers request bodies")
end

if fails > 0 then
  io.stderr:write(("cfm chunked-body tests: %d FAILED\n"):format(fails))
  os.exit(1)
end
print("ok: a chunked body is read where nginx buffers it anyway; wc-ajax matches the query")

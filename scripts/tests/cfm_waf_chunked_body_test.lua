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
  return H.run{ method = t.method or "POST", uri = t.uri or "/checkout", args = t.args or "", body = t.body or SQLI,
                headers = { ["content-type"] = t.ct or FORM, ["user-agent"] = "Mozilla/5.0" }, vars = vars,
                read_body_error = t.read_body_error, verdict = t.verdict, env = t.env }
end

-- ── cfm.lua end to end ──────────────────────────────────────────────────────
local ENFORCE = { CFM_WAF_BODY_BUFFERED_ENFORCE = "1" }
local function has_log(r, word)
  for _, l in ipairs(r.logs) do if l:find(word, 1, true) then return true end end
  return false
end
do
  local r = post{ cl = tostring(#SQLI) }
  check(r.ok and r.exited == 403, "measured POST to a clean route: inspected, blocked (" .. desc(r) .. ")")

  -- A chunked body on `location /`, newly read: in burn-in by default. The
  -- request is decided without it (allowed); its hit is pushed and logged as
  -- logonly, with the action it would have taken.
  r = post{ buffered = true }
  check(r.ok and r.exited == nil and r.action == "logonly" and r.reads == 1,
        "chunked POST on `location /`, burn-in: read, logonly (" .. desc(r) .. ")")
  check(r.rpcs:find("ip_push", 1, true) ~= nil, "the burn-in hit is pushed (" .. r.rpcs .. ")")
  check(has_log(r, "waf_body_burnin would=block"), "the burn-in hit is logged with its would-be action")
  -- Enforced: blocked like any other hit.
  r = post{ buffered = true, env = ENFORCE }
  check(r.ok and r.exited == 403, "chunked POST on `location /`, enforced: inspected, blocked (" .. desc(r) .. ")")
  -- A hit the request makes without its body still decides it, burn-in or not.
  r = post{ buffered = true, args = "id=1' UNION SELECT user_pass FROM wp_users-- -" }
  check(r.ok and r.exited == 403, "burn-in body + a SQLi in the query: blocked by the query (" .. desc(r) .. ")")
  -- The later steps still apply to a burn-in hit (logonly falls through).
  r = post{ buffered = true, verdict = { ip_action = "block" } }
  check(r.ok and r.exited == 403 and r.action == "block", "burn-in hit + IP block → 403 (" .. desc(r) .. ")")

  r = post{}
  check(r.ok and r.exited == nil and r.action == "allow" and r.reads == 0,
        "chunked POST where the location streams: unread, as before (" .. desc(r) .. ")")

  r = post{ buffered = true, ct = "application/octet-stream" }
  check(r.ok and r.exited == nil and r.reads == 0, "chunked binary body: never read (" .. desc(r) .. ")")

  r = post{ buffered = true, body = "q=hello world&email=a@b.example" }
  check(r.ok and r.exited == nil and r.action == "allow" and not has_log(r, "waf_body_burnin"),
        "chunked clean form on `location /`: allowed, nothing logged (" .. desc(r) .. ")")

  -- A body padded past waf_body_read_max_cl (1 MiB): read on `location /`
  -- (burn-in, then enforced), unread where the location streams.
  r = post{ buffered = true, cl = "2000000" }
  check(r.ok and r.action == "logonly" and r.reads == 1, "padded POST on `location /`, burn-in: logonly (" .. desc(r) .. ")")
  r = post{ buffered = true, cl = "2000000", env = ENFORCE }
  check(r.ok and r.exited == 403, "padded POST on `location /`, enforced: blocked (" .. desc(r) .. ")")
  r = post{ cl = "2000000" }
  check(r.ok and r.exited == nil and r.reads == 0, "padded POST where the location streams: unread, as before (" .. desc(r) .. ")")
  -- A measured body under the cap on `location /` was read before: not burn-in.
  r = post{ buffered = true, cl = tostring(#SQLI) }
  check(r.ok and r.exited == 403, "measured POST on `location /`: enforced as before, no burn-in (" .. desc(r) .. ")")

  -- POST only: a chunked PUT / PATCH is not read, as before.
  r = post{ buffered = true, method = "PUT" }
  check(r.ok and r.reads == 0, "chunked PUT on `location /`: not read (" .. desc(r) .. " reads=" .. r.reads .. ")")

  -- wc-ajax rides in the query string, matched by argument name: a large
  -- (over-cap) or chunked body there is read via the allowlist (enforced).
  r = post{ uri = "/", args = "wc-ajax=checkout" }
  check(r.ok and r.exited == 403, "POST /?wc-ajax=… with no Content-Length: read via the allowlist (" .. desc(r) .. ")")
  r = post{ uri = "/", args = "x=1&WC-AJAX=checkout" }
  check(r.ok and r.exited == 403, "wc-ajax matched case-insensitively, after other args (" .. desc(r) .. ")")
  r = post{ uri = "/", args = "zwc-ajax=1" }
  check(r.ok and r.exited == nil and r.reads == 0, "a name merely containing wc-ajax= does not force a read (" .. desc(r) .. ")")

  -- A body read_body cannot read (HTTP/3 without Content-Length) used to raise
  -- out of the access phase into request_failure, which under fail_open skips
  -- every check after the WAF. Now: the body stays unread, the rest still runs.
  local H3 = "http3 requests are not supported without content-length header"
  r = post{ buffered = true, read_body_error = H3, verdict = { ip_action = "block" } }
  check(r.ok and r.exited == 403 and r.action == "block",
        "HTTP/3 CL-less POST, read_body raises: the IP block still applies (" .. desc(r) .. ")")
  r = post{ uri = "/wp-login.php", read_body_error = H3 }
  check(r.ok and r.action == "allow" and r.upstream == "cfm_apache",
        "HTTP/3 CL-less POST to an allowlisted path: no request_failure, allowed unread (" .. desc(r) .. ")")
  check(has_log(r, "waf_body_unread"), "the unread body is logged (waf_body_unread)")
  -- fail_closed: still a 500, as before.
  r = H.run{ method = "POST", uri = "/wp-login.php", body = SQLI, fail_open = false, read_body_error = H3,
             headers = { ["content-type"] = FORM }, vars = { http_content_type = FORM } }
  check(r.ok and r.exited == 500, "HTTP/3 CL-less POST under fail_closed: 500, as before (" .. desc(r) .. ")")
end

-- ── waf_body_gate's `buffered` argument ─────────────────────────────────────
do
  local g = util.waf_body_gate
  check(g("application/json", nil, 1048576, true) == true, "chunked json where buffered: read")
  check(g("application/json", nil, 1048576, false) == false, "chunked json where it streams: skipped")
  check(g("application/json", nil, 1048576) == false, "chunked json, no flag (old callers): skipped")
  check(g("image/png", nil, 1048576, true) == false, "chunked binary where buffered: skipped")
  check(g("application/json", 2000000, 1048576, true) == true, "over the cap: read where buffered")
  check(g("application/json", 2000000, 1048576, false) == false, "over the cap: skipped where it streams")
end

-- ── The confs: `location /` marks itself, every streaming location clears ──
-- Each `location … {` block is cut out by brace matching (comments dropped).
local function location_blocks(src)
  src = src:gsub("#[^\n]*", "")
  local out = {}
  local pos = 1
  while true do
    local s, e, head = src:find("\n%s*(location%s[^{]*){", pos)
    if not s then break end
    local depth, i = 1, e + 1
    while depth > 0 and i <= #src do
      local c = src:sub(i, i)
      if c == "{" then depth = depth + 1 elseif c == "}" then depth = depth - 1 end
      i = i + 1
    end
    out[#out + 1] = { head = head:gsub("%s+$", ""), body = src:sub(e + 1, i - 2) }
    pos = e + 1
  end
  return out
end
for _, path in ipairs({ "configs/openresty.conf", "configs/angie.conf" }) do
  local f = assert(io.open(path, "r"))
  local src = f:read("*a"); f:close()
  local roots = 0
  for _, b in ipairs(location_blocks(src)) do
    local sets_on  = b.body:find('set%s+%$cfm_body_buffered%s+"1"%s*;') ~= nil
    local streams  = b.body:find("proxy_request_buffering%s+off") ~= nil
    if b.head == "location /" then
      roots = roots + 1
      check(sets_on, path .. ": `location /` must set $cfm_body_buffered \"1\"")
    end
    if sets_on then
      check(not streams, path .. ": " .. b.head .. " sets the marker but streams request bodies")
    end
    if streams then
      check(b.body:find('set%s+%$cfm_body_buffered%s+""%s*;') ~= nil,
            path .. ": " .. b.head .. " streams request bodies but does not clear $cfm_body_buffered")
    end
  end
  check(roots >= 1, path .. ": no `location /` found")
  -- Every server that runs cfm.lua declares the default, so no location reads
  -- it uninitialized and an internal redirect starts from "".
  local servers, defaults = 0, 0
  for _ in src:gmatch("\n%s*access_by_lua_file%s+[^\n]*cfm%.lua;") do servers = servers + 1 end
  for _ in src:gmatch('\n        set %$cfm_body_buffered "";') do defaults = defaults + 1 end
  check(servers >= 1 and defaults == servers,
        path .. ": " .. servers .. " cfm.lua server(s), " .. defaults .. " server-level $cfm_body_buffered default(s)")
  check(src:find("\n%s*proxy_request_buffering%s+on%s*;") ~= nil, path .. ": the http block buffers request bodies")
end

if fails > 0 then
  io.stderr:write(("cfm chunked-body tests: %d FAILED\n"):format(fails))
  os.exit(1)
end
print("ok: a chunked body is read where nginx buffers it anyway; wc-ajax matches the query")

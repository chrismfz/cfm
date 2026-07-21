-- Tests for cfm_clamav's INLINE mode edge path: mode = global XOR per-vhost
-- mode override; the edge obeys ONLY the bridge's block flag; and EVERY
-- failure (connect refused, timeout, bad status, bad JSON) is fail-open.
-- Drives the real notify() against a mocked bridge socket.

local S = {}          -- per-scenario request state
local B = {}          -- per-scenario bridge behaviour
local sent_async = {} -- POST /nginx/upload captures
local sent_sync = {}  -- POST /nginx/upload/scan captures

local MODE_OVERRIDE_HOSTS = {} -- set per scenario

local fake_sock
local function make_sock()
  local self = { last_path = nil }
  self.settimeout = function() end
  self.connect = function()
    if B.connect_fail then return nil, "connection refused" end
    return true
  end
  self.send = function(_, req)
    if req:find("POST /nginx/upload/scan", 1, true) then
      self.last_path = "sync"
      sent_sync[#sent_sync + 1] = req
    elseif req:find("POST /nginx/upload", 1, true) then
      self.last_path = "async"
      sent_async[#sent_async + 1] = req
    elseif req:find("GET /nginx/clam/mode_overrides", 1, true) then
      self.last_path = "movr"
    elseif req:find("GET /nginx/clam/overrides", 1, true) then
      self.last_path = "ovr"
    end
    return true
  end
  self.receive = function(_, pat)
    if self.last_path == "movr" or self.last_path == "ovr" then
      local hosts = (self.last_path == "movr") and MODE_OVERRIDE_HOSTS or {}
      local entries = {}
      for _, h in ipairs(hosts) do
        entries[#entries + 1] = '{"type":"host","value":"' .. h .. '"}'
      end
      return "HTTP/1.1 200 OK\r\nContent-Type: application/json\r\n\r\n"
          .. '{"entries":[' .. table.concat(entries, ",") .. "]}"
    end
    if self.last_path == "sync" then
      if B.sync_timeout then return nil, "timeout" end
      if B.sync_garbage then return "not-http-at-all" end
      return "HTTP/1.1 200 OK\r\nContent-Type: application/json\r\n\r\n" .. (B.sync_body or '{"block":false}')
    end
    if pat == "*a" then return "HTTP/1.1 200 OK\r\n\r\n{}" end
    return "HTTP/1.1 200 OK"
  end
  self.close = function() end
  return self
end

local function build_ngx()
  return {
    now = function() return 1000 end,
    log = function() end,
    ERR = 0, WARN = 1, INFO = 2, DEBUG = 3,
    ctx = { waf_body = S.waf_body },
    var = {
      host = S.host, request_uri = S.uri or "/upload",
      content_type = "multipart/form-data; boundary=X",
      request_id = "abcd1234",
    },
    req = {
      get_method    = function() return "POST" end,
      read_body     = function() end,
      get_body_file = function() return S.body_file end,
      get_body_data = function() return S.body_data end,
    },
    socket = { tcp = function() fake_sock = make_sock(); return fake_sock end },
    timer = { at = function(_, fn) fn(false); return true end },
  }
end

_G.ngx = build_ngx()
package.path = "configs/lua/?.lua;" .. package.path
package.loaded["cjson"] = {
  encode = function(_) return "PAYLOAD" end,
  decode = function(s)
    if s:find('"entries"', 1, true) then
      local entries = {}
      for v in s:gmatch('"value":"([^"]+)"') do
        entries[#entries + 1] = { type = "host", value = v }
      end
      return { entries = entries }
    end
    -- sync verdict bodies used in this test
    if s:find('"block":true', 1, true) then
      local sig = s:match('"signature":"([^"]*)"') or ""
      return { block = true, signature = sig }
    end
    if s:find("{malformed", 1, true) then error("bad json") end
    return { block = false }
  end,
}

local M = require("cfm_clamav")

local orig_open = io.open
io.open = function(path, mode)
  if type(path) == "string" and path:find("/scanner/pending/") then
    return { write = function() end, close = function() end }
  end
  return orig_open(path, mode)
end

local fails = 0
local function check(cond, msg)
  if cond then return end
  fails = fails + 1
  io.stderr:write("FAIL: " .. msg .. "\n")
end

-- run: fire one upload notify() under the given global mode + scenario.
local function run(opts)
  M.init({
    token = "t", enabled = true, scan_default = true,
    scan_mode = opts.mode or "async",
    inline_timeout_ms = 1000,
    sock_path = "/run/cfm/scan.sock",
  })
  MODE_OVERRIDE_HOSTS = opts.mode_overrides or {}
  S = {
    host = opts.host or "site.example.gr",
    uri = opts.uri,
    body_file = "/spool/req",
    waf_body = 'Content-Disposition: form-data; name="f"; filename="a.zip"\r\n',
  }
  B = opts.bridge or {}
  sent_async, sent_sync = {}, {}
  _G.ngx = build_ngx()
  -- Force both override caches stale so each run re-fetches through the
  -- synchronous timer stub (module-level ts persists across runs).
  package.loaded["cfm_clamav"] = nil
  M = require("cfm_clamav")
  M.init({
    token = "t", enabled = true, scan_default = true,
    scan_mode = opts.mode or "async",
    inline_timeout_ms = 1000,
    sock_path = "/run/cfm/scan.sock",
  })
  io.open = function(path, mode)
    if type(path) == "string" and path:find("/scanner/pending/") then
      return { write = function() end, close = function() end }
    end
    return orig_open(path, mode)
  end
  return M.notify("203.0.113.9", nil)
end

-- 1. Global async: async lane used, no verdict returned.
local r = run{ mode = "async" }
check(r == nil and #sent_async == 1 and #sent_sync == 0,
  "global async -> async lane, nil result")

-- 2. Global inline + infected verdict -> block table returned.
r = run{ mode = "inline", bridge = { sync_body = '{"block":true,"signature":"Win.Trojan.X"}' } }
check(type(r) == "table" and r.block == true and r.signature == "Win.Trojan.X",
  "inline + infected -> block table")
check(#sent_sync == 1 and #sent_async == 0, "inline used the sync lane only")

-- 3. Global inline + clean verdict -> nil (allow).
r = run{ mode = "inline", bridge = { sync_body = '{"block":false,"verdict":"clean"}' } }
check(r == nil, "inline + clean -> allow")

-- 4. FAIL-OPEN: bridge connect refused.
r = run{ mode = "inline", bridge = { connect_fail = true } }
check(r == nil, "inline + bridge down -> allow (fail-open)")

-- 5. FAIL-OPEN: verdict read timeout.
r = run{ mode = "inline", bridge = { sync_timeout = true } }
check(r == nil, "inline + verdict timeout -> allow (fail-open)")

-- 6. FAIL-OPEN: garbage response.
r = run{ mode = "inline", bridge = { sync_garbage = true } }
check(r == nil, "inline + garbage response -> allow (fail-open)")

-- 7. Mode XOR: global async + host in mode_overrides -> inline for that host.
r = run{ mode = "async", host = "optin.gr", mode_overrides = { "optin.gr" },
         bridge = { sync_body = '{"block":true,"signature":"Sig"}' } }
check(type(r) == "table" and r.block == true,
  "async default + mode override -> inline for the flipped host")

-- 8. Mode XOR: global inline + host in mode_overrides -> async for that host.
r = run{ mode = "inline", host = "optout.gr", mode_overrides = { "optout.gr" } }
check(r == nil and #sent_async == 1 and #sent_sync == 0,
  "inline default + mode override -> async for the flipped host")

-- 9. Inline bypass: /acctxfer* never waits on a verdict (async lane).
r = run{ mode = "inline", uri = "/acctxfer/stream",
         bridge = { sync_body = '{"block":true,"signature":"Sig"}' } }
check(r == nil and #sent_async == 1 and #sent_sync == 0,
  "/acctxfer prefix -> async lane even in inline mode")

if fails > 0 then
  io.stderr:write(("cfm_clamav inline tests: %d FAILED\n"):format(fails))
  os.exit(1)
end
print("ok: cfm_clamav inline mode (XOR, obey-block-only, fail-open)")

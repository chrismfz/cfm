-- Tests for cfm_clamav's per-host scan decision: should_scan(host) =
-- scan_default XOR host-in-override. Drives the real notify() and observes
-- whether an upload was dispatched to the mocked bridge (a POST /nginx/upload
-- == a scan). The per-vhost override set is served by the mocked bridge's
-- GET /nginx/clam/overrides response.

local sent = {}
local OVERRIDE_HOSTS = { "optin.gr" } -- the override list the bridge returns

local fake_sock = {}
fake_sock.settimeout = function() end
fake_sock.connect    = function() return true end
fake_sock.send       = function(_, req)
  if req:find("/nginx/upload", 1, true) then sent[#sent + 1] = req end
  return true
end
fake_sock.receive = function(_, pat)
  -- fetch_overrides() reads the whole response ("*a"); the upload path reads a
  -- status line ("*l").
  if pat == "*a" then
    local entries = {}
    for _, h in ipairs(OVERRIDE_HOSTS) do
      entries[#entries + 1] = '{"type":"host","value":"' .. h .. '"}'
    end
    return "HTTP/1.1 200 OK\r\nContent-Type: application/json\r\n\r\n"
        .. '{"entries":[' .. table.concat(entries, ",") .. "]}"
  end
  return "HTTP/1.1 200 OK"
end
fake_sock.close = function() end

local S = {}
local function build_ngx()
  return {
    now = function() return 1000 end,
    log = function() end,
    ERR = 0, WARN = 1, INFO = 2, DEBUG = 3,
    ctx = { waf_body = S.waf_body },
    var = {
      host = S.host, request_uri = "/upload", content_type = "multipart/form-data; boundary=X",
      request_id = "abcd1234",
    },
    req = {
      get_method     = function() return "POST" end,
      read_body      = function() end,
      get_body_file  = function() return S.body_file end,
      get_body_data  = function() return S.body_data end,
    },
    socket = { tcp = function() return fake_sock end },
    -- The async override refresh runs via ngx.timer.at in production; run it
    -- synchronously here so should_scan() sees a settled cache.
    timer = { at = function(_, fn) fn(false); return true end },
  }
end

_G.ngx = build_ngx()
package.path = "configs/lua/?.lua;" .. package.path

-- cjson is not available in the test env; stub encode (notify payload) + decode
-- (fetch_overrides parses the bridge's /nginx/clam/overrides JSON).
package.loaded["cjson"] = {
  encode = function(_) return "PAYLOAD" end,
  decode = function(s)
    local entries = {}
    for v in s:gmatch('"value":"([^"]+)"') do
      entries[#entries + 1] = { type = "host", value = v }
    end
    return { entries = entries }
  end,
}

local M = require("cfm_clamav")

-- write_temp() intercept (in-memory bodies) — return a fake path so notify proceeds.
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

-- A real multipart file upload (filename= in the inspected view) on `host`.
local function scanned(scan_default, host)
  M.init({ token = "t", enabled = true, scan_default = scan_default,
           sock_path = "/run/cfm/scan.sock" })
  S = { host = host, body_file = "/spool/req",
        waf_body = 'Content-Disposition: form-data; name="f"; filename="a.php"\r\n' }
  sent = {}
  _G.ngx = build_ngx()
  M.notify("203.0.113.9", nil)
  return #sent > 0
end

-- scan_default = OFF: scan ONLY vhosts opted in (in the override set).
check(not scanned(false, "normal.gr"), "default OFF + not overridden -> NO scan")
check(scanned(false, "optin.gr"),      "default OFF + overridden (opt-in) -> scan")

-- scan_default = ON: scan ALL vhosts EXCEPT those opted out (in the set).
check(scanned(true, "normal.gr"),      "default ON + not overridden -> scan")
check(not scanned(true, "optin.gr"),   "default ON + overridden (opt-out) -> NO scan")

if fails > 0 then
  io.stderr:write(("cfm_clamav scan-policy tests: %d FAILED\n"):format(fails))
  os.exit(1)
end
print("ok: cfm_clamav per-host scan policy (scan_default XOR override)")

-- Tests for cfm_clamav.notify()'s file-part detection (audit F17).
--
-- The scan decision used to check only ngx.ctx.waf_body — the WAF's first
-- waf_body_max_len bytes (32KB), and nil when the WAF skipped the body read.
-- A multipart upload whose filename= sits beyond the cap (leading padding),
-- or a body the WAF never inspected, therefore evaded the AV scan. wants_scan()
-- now fails safe: if the inspected view shows no file part but the real body has
-- content beyond it (spooled to disk), scan anyway. A genuinely small,
-- fully-inspected multipart with no filename= still stays in the WAF lane only.
--
-- We drive the real notify() and observe whether a scan was dispatched to the
-- mocked bridge socket (a send == a scan).

-- ── per-scenario request state (set by run()) ────────────────────────────────
local S = {}

local sent, encoded = {}, {}

local fake_sock = {}
fake_sock.settimeout = function() end
fake_sock.connect    = function() return true end
-- Only the upload POST counts as "a scan dispatched"; the per-vhost override
-- GET (/nginx/clam/overrides) that should_scan() issues is not a scan.
fake_sock.send       = function(_, req)
  if req:find("/nginx/upload", 1, true) then sent[#sent + 1] = req end
  return true
end
fake_sock.receive    = function() return "HTTP/1.1 200 OK" end
fake_sock.close      = function() end

package.loaded["cjson"] = {
  encode = function(t) encoded[#encoded + 1] = t; return "PAYLOAD" end,
}

-- write_temp() opens a path under CFG.pending_dir; intercept so the in-memory
-- body_data path never touches the filesystem.
local _real_io_open = io.open
io.open = function(path, mode)
  if type(path) == "string" and path:find("/var/lib/cfm/scanner/pending", 1, true) then
    return { write = function() end, close = function() end }
  end
  return _real_io_open(path, mode)
end

local function build_ngx()
  return {
    ctx = { waf_body = S.waf_body },
    req = {
      get_method    = function() return S.method or "POST" end,
      read_body     = function() end,
      get_body_file = function() return S.body_file end,
      get_body_data = function() return S.body_data end,
    },
    var = {
      host         = S.host or "site.example.gr",
      request_uri  = S.uri or "/wp-admin/async-upload.php",
      content_type = S.ct or "multipart/form-data; boundary=X",
      request_id   = "deadbeef",
    },
    socket = { tcp = function() return fake_sock end },
    -- The async override refresh runs via ngx.timer.at in production; run it
    -- synchronously here so should_scan() sees a settled cache.
    timer = { at = function(_, fn) fn(false); return true end },
    now = function() return 1000 end,
    log = function() end,
    WARN = 1, ERR = 2, INFO = 3, DEBUG = 4,
  }
end

_G.ngx = build_ngx()
package.path = "configs/lua/?.lua;" .. package.path
local M = require("cfm_clamav")
M.init({
  token = "t", enabled = true, scan_default = true, sock_path = "/run/cfm/scan.sock",
  exclude_hosts = { ["blocked.example.gr"] = true },
})

local fails = 0
local function check(cond, msg)
  if cond then return end
  fails = fails + 1
  io.stderr:write("FAIL: " .. msg .. "\n")
end

-- Run notify() under `scenario`; return whether a scan was dispatched.
local function run(scenario)
  S = scenario
  sent, encoded = {}, {}
  _G.ngx = build_ngx()
  M.notify("203.0.113.9", scenario.tag)
  return #sent > 0
end

-- Fast path: filename= within the inspected view (normal upload, file field first).
check(run{ waf_body = 'Content-Disposition: form-data; name="f"; filename="a.php"\r\n',
           body_file = "/spool/req" },
      "fast path: file part in inspected view -> scan")

-- F17: filename= pushed past the cap. waf_body is truncated (all padding, no
-- filename=), the body was spooled -> fail-safe scan.
check(run{ waf_body = string.rep("x", 32768), body_file = "/spool/req" },
      "F17: truncated view + spooled tail -> fail-safe scan (padding evasion)")

-- F17: WAF never populated waf_body (over its CL gate), body spooled -> scan.
check(run{ waf_body = nil, body_file = "/spool/req" },
      "F17: absent view + spooled body -> fail-safe scan")

-- Small, fully-inspected multipart with no filename=: WAF lane only, no scan
-- (resource posture for generic admin-ajax/FormData preserved).
check(not run{ waf_body = 'name="q"\r\n\r\nhello world', body_file = nil,
               body_data = 'name="q"\r\n\r\nhello world' },
      "small no-file multipart -> no scan (resource posture preserved)")

-- Absent view, small in-memory body carrying a file part (e.g. chunked): scan.
check(run{ waf_body = nil, body_file = nil, body_data = 'filename="a.php"' },
      "absent view + in-memory file part -> scan")

-- Absent view, small in-memory body, no file part: no scan.
check(not run{ waf_body = nil, body_file = nil, body_data = "just=text&more=1" },
      "absent view + in-memory no-file -> no scan")

-- F17 config-realistic path: with the shipped client_body_buffer_size 1m, a
-- 32KB-1MB body is held IN MEMORY, so a filename= past the 32KB cap is caught by
-- the get_body_data branch (not the spooled branch). This is the primary
-- real-world beyond-cap disposition.
check(run{ waf_body = string.rep("x", 32768), body_file = nil,
           body_data = string.rep("x", 40000) .. '; filename="a.php"' },
      "F17: in-memory body beyond cap (get_body_data branch) -> scan")

-- Content-Disposition param names are case-insensitive (RFC 2183): an odd-cased
-- FILENAME= in an in-memory body still triggers (would evade a [Ff]ilename match).
check(run{ waf_body = nil, body_file = nil, body_data = 'FILENAME="a.php"' },
      "case-insensitive: FILENAME= in-memory -> scan")

-- PUT is in CFG.methods; a PUT upload is scanned like POST.
check(run{ method = "PUT", waf_body = 'filename="a.php"', body_file = "/spool/req" },
      "PUT method upload -> scan")

-- Excluded host: never scanned regardless of file part.
check(not run{ host = "blocked.example.gr", waf_body = 'filename="a.php"',
               body_file = "/spool/req" },
      "excluded host -> no scan")

-- Non-multipart content-type: not the ClamAV lane at all.
check(not run{ ct = "application/json", waf_body = 'filename="a.php"' },
      "non-multipart CT -> no scan")

if fails > 0 then
  io.stderr:write("\n" .. fails .. " test(s) failed in cfm_clamav_filepart_test.lua\n")
  os.exit(1)
end
io.stdout:write("ok: cfm_clamav file-part detection tests (F17 fail-safe scan)\n")

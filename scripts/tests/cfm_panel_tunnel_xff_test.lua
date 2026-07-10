-- Tests for cfm_panel_tunnel.lua's X-Forwarded-For / real-IP handling (audit F03).
--
-- The tunnel hijacks the raw client socket and replays the request line +
-- headers to the loopback panel origin (cpsrvd). cpsrvd's Apache trusts
-- X-Forwarded-For from loopback (mod_remoteip), so the tunnel MUST take sole
-- authority over the forwarding / real-IP header set: strip any client-supplied
-- copy and inject a value keyed on $remote_addr, exactly as the sibling
-- proxy_set_header $remote_addr blocks do. Otherwise a client can spoof its
-- source IP into cpsrvd's audit log / cPhulk / IP-ACLs.
--
-- We can't open real sockets here, so we stub ngx (client + upstream cosockets,
-- threads) just enough to run the real tunnel top-to-bottom and CAPTURE the exact
-- header block sent upstream via up_sock:send(). Assertions run on that block.

local tunnel_path = "configs/lua/cfm_panel_tunnel.lua"

-- Run the real tunnel with a crafted raw request header; return the bytes it
-- sent upstream (the rebuilt header block) plus the exit code it used.
local function run(raw_header, opts)
  opts = opts or {}
  local up = { sent = {} }
  function up:settimeouts() end
  function up:connect() return true end
  function up:sslhandshake() return {}, nil end          -- session, err
  function up:send(data) self.sent[#self.sent + 1] = data; return #data, nil end
  function up:receiveany() return nil, "closed" end       -- make the pump exit at once
  function up:close() end

  local client = {}
  function client:settimeouts() end
  function client:receiveany() return nil, "closed" end
  function client:send(data) return #data, nil end
  function client:close() end

  local exit_code
  local ngx = {
    ERR = 0, WARN = 2, NOTICE = 5, INFO = 1, DEBUG = 3,
    var = {
      cfm_panel_origin = opts.origin or "https://127.0.0.1:2087",
      remote_addr      = opts.remote_addr or "203.0.113.9",
      host             = opts.host or "src.example",
      server_port      = opts.server_port or "12087",
      scheme           = opts.scheme or "https",
      request_uri      = opts.request_uri or "/acctxferrsync/foo",
    },
    req = {
      socket     = function() return client end,
      raw_header = function() return raw_header end,
    },
    socket = { tcp = function() return up end },
    thread = {
      spawn = function(fn, ...) local a, b = pcall(fn, ...); return { a, b } end,
      wait  = function() return true end,
      kill  = function() return true end,
    },
    log  = function() end,
    exit = function(code) exit_code = code end,
  }
  _G.ngx = ngx
  assert(loadfile(tunnel_path))()
  return up.sent[1] or "", exit_code
end

-- ── assertion helpers ────────────────────────────────────────────────────────
local function fail(msg) error(msg, 2) end

-- All header values for `name` (case-insensitive), in order, from a header block.
local function values(block, name)
  local out = {}
  local want = name:lower()
  local first = true
  for line in block:gmatch("[^\r\n]+") do
    if first then first = false           -- skip request line
    else
      local n, v = line:match("^([%w%-]+)%s*:%s*(.*)$")
      if n and n:lower() == want then out[#out + 1] = v end
    end
  end
  return out
end

local function assert_single(block, name, expected, ctx)
  local v = values(block, name)
  if #v ~= 1 then
    fail(ctx .. ": expected exactly 1 " .. name .. ", got " .. #v .. " (" .. table.concat(v, " | ") .. ")")
  end
  if expected and v[1] ~= expected then
    fail(ctx .. ": " .. name .. " = '" .. v[1] .. "', expected '" .. expected .. "'")
  end
end

local function assert_absent_substr(block, needle, ctx)
  if block:find(needle, 1, true) then
    fail(ctx .. ": spoofed value '" .. needle .. "' should have been stripped but is present")
  end
end

local function assert_present_substr(block, needle, ctx)
  if not block:find(needle, 1, true) then
    fail(ctx .. ": expected '" .. needle .. "' to be present")
  end
end

local function request_line(block) return (block:match("^([^\r\n]+)")) end

local CRLF = "\r\n"
local TRUE_IP = "203.0.113.9"

-- ── Case 1: legitimate transfer (client sends no forwarding headers) ─────────
-- Behaviour must be identical to today: inject $remote_addr-derived values,
-- preserve request line + benign headers.
do
  local raw = "GET /acctxferrsync/foo?rsync_command=x HTTP/1.1" .. CRLF ..
              "Host: src.example:2087" .. CRLF ..
              "User-Agent: cPanel-Transfer" .. CRLF ..
              "Authorization: WHM root:deadbeef" .. CRLF .. CRLF
  local block, code = run(raw)
  assert_single(block, "X-Forwarded-For", TRUE_IP, "case1")
  assert_single(block, "X-Real-IP", TRUE_IP, "case1")
  assert_single(block, "CF-Connecting-IP", TRUE_IP, "case1")
  assert_single(block, "X-Forwarded-Host", "src.example", "case1")
  assert_single(block, "X-Forwarded-Proto", "https", "case1")
  assert_present_substr(block, "Host: src.example:2087", "case1 preserves Host")
  assert_present_substr(block, "Authorization: WHM root:deadbeef", "case1 preserves auth")
  if request_line(block) ~= "GET /acctxferrsync/foo?rsync_command=x HTTP/1.1" then
    fail("case1: request line altered: " .. tostring(request_line(block)))
  end
  if block:sub(-4) ~= CRLF .. CRLF then fail("case1: header block not CRLFCRLF-terminated: " .. string.format("%q", block:sub(-6))) end
  assert(code == 444, "case1: expected ngx.exit(444), got " .. tostring(code))
end

-- ── Case 2: spoofed X-Forwarded-For must be overwritten ──────────────────────
do
  local raw = "GET /acctxferrsync/foo HTTP/1.1" .. CRLF ..
              "Host: src.example" .. CRLF ..
              "X-Forwarded-For: 6.6.6.6" .. CRLF .. CRLF
  local block = run(raw)
  assert_absent_substr(block, "6.6.6.6", "case2")
  assert_single(block, "X-Forwarded-For", TRUE_IP, "case2")
end

-- ── Case 3: spoofed X-Real-IP + CF-Connecting-IP, mixed case ─────────────────
do
  local raw = "GET /acctxferrsync/foo HTTP/1.1" .. CRLF ..
              "Host: src.example" .. CRLF ..
              "x-real-ip: 6.6.6.6" .. CRLF ..
              "CF-Connecting-IP: 9.9.9.9" .. CRLF .. CRLF
  local block = run(raw)
  assert_absent_substr(block, "6.6.6.6", "case3 x-real-ip")
  assert_absent_substr(block, "9.9.9.9", "case3 cf-connecting-ip")
  assert_single(block, "X-Real-IP", TRUE_IP, "case3")
  assert_single(block, "CF-Connecting-IP", TRUE_IP, "case3")
end

-- ── Case 4: duplicate spoofed XFF headers all stripped ───────────────────────
do
  local raw = "GET /acctxferrsync/foo HTTP/1.1" .. CRLF ..
              "Host: src.example" .. CRLF ..
              "X-Forwarded-For: 6.6.6.6" .. CRLF ..
              "X-Forwarded-For: 7.7.7.7" .. CRLF .. CRLF
  local block = run(raw)
  assert_absent_substr(block, "6.6.6.6", "case4")
  assert_absent_substr(block, "7.7.7.7", "case4")
  assert_single(block, "X-Forwarded-For", TRUE_IP, "case4")
end

-- ── Case 5: obsolete-fold smuggling — continuation of a stripped header must
-- not survive as an orphan line ──────────────────────────────────────────────
do
  local raw = "GET /acctxferrsync/foo HTTP/1.1" .. CRLF ..
              "Host: src.example" .. CRLF ..
              "X-Forwarded-For: 1.1.1.1," .. CRLF ..
              "\t2.2.2.2" .. CRLF .. CRLF
  local block = run(raw)
  assert_absent_substr(block, "1.1.1.1", "case5 folded head")
  assert_absent_substr(block, "2.2.2.2", "case5 folded continuation")
  assert_single(block, "X-Forwarded-For", TRUE_IP, "case5")
end

-- ── Case 6: obs-fold continuation lines are dropped wholesale ────────────────
-- Deprecated RFC 7230 §3.2.4 folding; legit clients never fold. The parent
-- header survives; its folded continuation does not.
do
  local raw = "GET /acctxferrsync/foo HTTP/1.1" .. CRLF ..
              "Host: src.example" .. CRLF ..
              "X-Custom: alpha," .. CRLF ..
              " beta" .. CRLF .. CRLF
  local block = run(raw)
  assert_present_substr(block, "X-Custom: alpha,", "case6 parent kept")
  assert_absent_substr(block, " beta", "case6 folded continuation dropped")
end

-- ── Case 7: spoofed XFF smuggled as a fold of a BENIGN surviving header ──────
-- must not survive — a lenient upstream parser could otherwise read the
-- leading-whitespace line as a standalone X-Forwarded-For.
do
  local raw = "GET /acctxferrsync/foo HTTP/1.1" .. CRLF ..
              "Host: src.example" .. CRLF ..
              "X-Custom: alpha" .. CRLF ..
              " X-Forwarded-For: 6.6.6.6" .. CRLF .. CRLF
  local block = run(raw)
  assert_absent_substr(block, "6.6.6.6", "case7 fold-smuggled spoof dropped")
  assert_present_substr(block, "X-Custom: alpha", "case7 benign parent kept")
  assert_single(block, "X-Forwarded-For", TRUE_IP, "case7")
end

-- ── Case 8: spoofed XFF folded onto the request line is dropped ──────────────
do
  local raw = "GET /acctxferrsync/foo HTTP/1.1" .. CRLF ..
              " X-Forwarded-For: 6.6.6.6" .. CRLF ..
              "Host: src.example" .. CRLF .. CRLF
  local block = run(raw)
  assert_absent_substr(block, "6.6.6.6", "case8 fold-off-request-line dropped")
  assert_single(block, "X-Forwarded-For", TRUE_IP, "case8")
  if request_line(block) ~= "GET /acctxferrsync/foo HTTP/1.1" then
    fail("case8: request line altered: " .. tostring(request_line(block)))
  end
  assert_present_substr(block, "Host: src.example", "case8 Host preserved")
end

-- ── Case 9: the non-IP forwarding headers are ALSO overwritten, not just the
-- three IP-bearing ones (the fix owns all 7). A client-supplied value for each
-- must be replaced by the server-computed value. ───────────────────────────────
do
  local raw = "GET /acctxferrsync/foo HTTP/1.1" .. CRLF ..
              "Host: src.example" .. CRLF ..
              "X-Forwarded-Host: evil.com" .. CRLF ..
              "X-Forwarded-Port: 31337" .. CRLF ..
              "X-Forwarded-Proto: evilscheme" .. CRLF ..
              "X-Forwarded-Server: evilsrv" .. CRLF .. CRLF
  local block = run(raw)
  assert_absent_substr(block, "evil.com", "case9 X-Forwarded-Host spoof dropped")
  assert_absent_substr(block, "31337", "case9 X-Forwarded-Port spoof dropped")
  assert_absent_substr(block, "evilscheme", "case9 X-Forwarded-Proto spoof dropped")
  assert_absent_substr(block, "evilsrv", "case9 X-Forwarded-Server spoof dropped")
  assert_single(block, "X-Forwarded-Host", "src.example", "case9")
  assert_single(block, "X-Forwarded-Port", "12087", "case9")   -- ngx.var.server_port stub
  assert_single(block, "X-Forwarded-Proto", "https", "case9")
  assert_single(block, "X-Forwarded-Server", "src.example", "case9")
end

-- ── Case 10: request-line-only (zero client headers) still yields a well-formed,
-- CRLFCRLF-terminated block with the 7 trusted headers. ─────────────────────────
do
  local raw = "GET /acctxferrsync/foo HTTP/1.1" .. CRLF .. CRLF
  local block = run(raw)
  if request_line(block) ~= "GET /acctxferrsync/foo HTTP/1.1" then
    fail("case10: request line altered: " .. tostring(request_line(block)))
  end
  assert_single(block, "X-Forwarded-For", TRUE_IP, "case10")
  if block:sub(-4) ~= CRLF .. CRLF then fail("case10: not CRLFCRLF-terminated") end
end

-- ── Case 11: an empty-valued benign header is preserved verbatim ──────────────
do
  local raw = "GET /acctxferrsync/foo HTTP/1.1" .. CRLF ..
              "Host: src.example" .. CRLF ..
              "X-Empty:" .. CRLF .. CRLF
  local block = run(raw)
  assert_present_substr(block, "X-Empty:", "case11 empty benign header preserved")
  assert_single(block, "X-Forwarded-For", TRUE_IP, "case11")
end

print("cfm_panel_tunnel_xff_test: all cases passed")

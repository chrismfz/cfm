-- Behaviour test for cfm.lua's log-forging defences (F39).
--
-- cfm.lua is an access_by_lua_file: requiring it runs main() top-to-bottom, so
-- it is not loadable as a module. Instead we extract the real log_sanitize()
-- and log_ev() sources out of configs/lua/cfm.lua and load() them — so this
-- test exercises the PRODUCTION functions (no drifting hand-copy).
--
-- The value they protect: ngx.var.uri is percent-DECODED, so a request path
-- with %0A/%0D decodes to a literal newline inside `uri`; without neutralising
-- it, ngx.log writes a second, attacker-controlled "[cfm] ..." line into
-- error.log (log forging). log_ev() sanitises EVERY argument, so no call site
-- (host/uri/scope/...) can forge a line.

-- ── Extract log_sanitize()/log_ev() from cfm.lua and load them ───────────────
local path = "configs/lua/cfm.lua"
local f = assert(io.open(path, "r"), "cannot open " .. path)
local src = f:read("*a"); f:close()

-- Pull a `local function NAME(` … top-level `\nend\n` block. Inner if/for ends
-- are inline or indented, so the first column-0 "\nend\n" is the function close.
local function extract_fn(name)
  local start = src:find("local function " .. name .. "%(")
  assert(start, name .. "() not found in " .. path .. " (renamed/moved?)")
  local body = src:sub(start)
  local stop = body:find("\nend\n")
  assert(stop, "could not delimit " .. name .. "() body")
  return body:sub(1, stop + 4)
end

-- log_ev calls ngx.log — capture it.
local captured
_G.ngx = { log = function(level, msg) captured = { level = level, msg = msg } end }

local chunk = assert(load(
  extract_fn("log_sanitize") .. "\n" ..
  extract_fn("log_ev") .. "\n" ..
  "return log_sanitize, log_ev"))
local log_sanitize, log_ev = chunk()
assert(type(log_sanitize) == "function" and type(log_ev) == "function",
  "extracted symbols are not functions")

local fails = 0
local function check(cond, msg)
  if cond then return end
  fails = fails + 1
  io.stderr:write("FAIL: " .. msg .. "\n")
end
local function has_newline(s) return s:find("\n", 1, true) ~= nil end

-- ── log_sanitize: log-forge attempt (%0A → real newline in the decoded uri) ──
local forged = "bypass=well-known host=evil.example uri=/.well-known/x\n" ..
               "2026/07/08 12:00:00 [error] 1#1: *1 [cfm] block ip=1.2.3.4 forged=1"
local clean = log_sanitize(forged)
check(not has_newline(clean),
      "F39: embedded newline is neutralised (no forged second log line)")
check(clean:find("\\x0A", 1, true) ~= nil,
      "F39: the newline is hex-escaped to \\x0A (kept visible, not dropped)")
check(clean:find("uri=/.well-known/x", 1, true) ~= nil, "F39: surrounding text preserved")
check(not log_sanitize("a\rb"):find("\r", 1, true), "F39: CR neutralised")
check(log_sanitize("a\0b") == "a\\x00b", "F39: NUL neutralised")
check(log_sanitize("a\127b") == "a\\x7Fb", "F39: DEL (0x7F) neutralised")

-- clean messages unchanged (byte-identical, hot-path no-op)
local legit = "allow ip=203.0.113.9 host=shop.example.com pass=http://127.0.0.1:80 cache=miss"
check(log_sanitize(legit) == legit, "F39: a clean message is unchanged")
check(log_sanitize(nil) == nil, "F39: nil passes through")
check(log_sanitize(42) == 42, "F39: non-string passes through")

-- ── log_ev: the central path — neutralises control chars in ANY argument ─────
log_ev(2, "host=", "evil\nX [cfm] block ip=6.6.6.6 forged=1", " uri=", "/a\rb")
check(captured ~= nil, "log_ev called ngx.log")
check(not has_newline(captured.msg),
      "F39: log_ev neutralises a newline in a middle argument (any call site is safe)")
check(captured.msg:find("\\x0A", 1, true) and captured.msg:find("\\x0D", 1, true),
      "F39: log_ev hex-escapes CR and LF across args")
check(captured.msg:find("host=", 1, true) and captured.msg:find(" uri=", 1, true),
      "F39: log_ev preserves the static parts")
log_ev(2, "allow ip=1.2.3.4 host=a.b")
check(captured.msg == "allow ip=1.2.3.4 host=a.b", "F39: log_ev leaves a clean message intact")
log_ev(2, "n=", 42)
check(captured.msg == "n=42", "F39: log_ev coerces non-string args (concat-safe)")

if fails > 0 then
  io.stderr:write("\n" .. fails .. " test(s) failed in cfm_log_sanitize_test.lua\n")
  os.exit(1)
end
io.stdout:write("ok: cfm.lua log_sanitize/log_ev control-char neutralisation (F39)\n")

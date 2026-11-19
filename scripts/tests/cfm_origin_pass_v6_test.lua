-- cfm.lua origin_pass_for(): the direct origin URL ($cfm_pass) for an allowed
-- request. Run with:
--   luajit scripts/tests/cfm_origin_pass_v6_test.lua
--
-- An IPv6 $server_addr must go in brackets: nginx parses
-- "https://2001:db8::1:443" as host "2001" with an invalid port and fails
-- every request ("invalid port in upstream", seen on an operator's node that
-- added `listen [::]` by hand). IPv4 must stay byte-for-byte what it was.
--
-- cfm.lua is a per-request script, not a module, so the function is cut out
-- of the file (from `local function origin_pass_for` to the first column-0
-- `end`) and run against stubbed ngx / CFG. If the function is renamed or
-- moved so it can no longer be found, this test FAILS, never skips.

local src = assert(io.open("configs/lua/cfm.lua", "r")):read("*a")
local body = src:match("\n(local function origin_pass_for%(s_in%).-\nend)\n")
if not body then
  print("FAIL - origin_pass_for not found in configs/lua/cfm.lua")
  os.exit(1)
end

local env = {
  string = string,
  CFG = { origin_keepalive = false },
  ngx = {
    var = {},
    now = function() return 0 end,
    req = { start_time = function() return 0 end },
  },
}
local chunk = assert(loadstring(body .. "\nreturn origin_pass_for", "=origin_pass_for"))
setfenv(chunk, env)
local origin_pass_for = chunk()

local failures = 0
local function check(got, want, msg)
  if got == want then
    print("ok   - " .. msg)
  else
    failures = failures + 1
    print("FAIL - " .. msg .. ": got " .. tostring(got) .. ", want " .. want)
  end
end

env.ngx.var.server_addr = "203.0.113.7"
check(origin_pass_for("https"), "https://203.0.113.7:443", "IPv4 https unchanged")
check(origin_pass_for("http"), "http://203.0.113.7:80", "IPv4 http unchanged")

env.ngx.var.server_addr = "2001:4ba0:cafe:3dd::1"
check(origin_pass_for("https"), "https://[2001:4ba0:cafe:3dd::1]:443", "IPv6 https bracketed")
check(origin_pass_for("http"), "http://[2001:4ba0:cafe:3dd::1]:80", "IPv6 http bracketed")

env.ngx.var.server_addr = nil
check(origin_pass_for("https"), "https://127.0.0.1:443", "no server_addr falls back to 127.0.0.1")

-- Keepalive pools armed (sentinel present): the named upstreams, whatever the
-- address family (cfm_origin_ka.lua brackets the peer; its own test covers it).
env.CFG.origin_keepalive = true
env.ngx.var.cfm_origin_ka_conf = "1"
env.ngx.var.server_addr = "2001:db8::1"
check(origin_pass_for("https"), "https://cfm_origin_https", "keepalive armed: named https upstream")
check(origin_pass_for("http"), "http://cfm_origin_http", "keepalive armed: named http upstream")

if failures > 0 then
  print(string.format("%d failure(s)", failures))
  os.exit(1)
end
print("OK: origin_pass_for brackets an IPv6 destination and leaves IPv4 unchanged")

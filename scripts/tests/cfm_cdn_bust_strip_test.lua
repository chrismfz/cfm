-- strip_cdn_bust_arg (cfm.lua pre-step): the challenge server's ?cfm_nc= CDN
-- cache-bust is for the CDN only, so the edge drops it before the origin sees
-- the query (Laravel signed URLs and HMAC'd callbacks reject an extra
-- parameter). Extracts the production function and runs it against a stub
-- ngx: the cfm_nc pairs go, every other byte of the query stays as sent.

local f = assert(io.open("configs/lua/cfm.lua", "r"))
local src = f:read("*a"); f:close()
local a = assert(src:find("local function strip_cdn_bust_arg(", 1, true), "strip_cdn_bust_arg() not found")
local body = src:sub(a)
local fnsrc = body:sub(1, assert(body:find("\nend\n")) + 4)

local fails = 0
local function check(cond, msg)
  if cond then return end
  fails = fails + 1
  io.stderr:write("FAIL: " .. msg .. "\n")
end

local set_calls, set_arg
_G.ngx = { var = {}, req = {
  set_uri_args = function(v)
    local t = type(v)
    if t ~= "string" and t ~= "number" and t ~= "table" then
      error("bad argument #1 to 'set_uri_args' (string, number, or table expected, got " .. t .. ")")
    end
    set_calls = set_calls + 1; set_arg = v
  end,
} }
local strip = assert(load(fnsrc .. "\nreturn strip_cdn_bust_arg"))()

-- args: the raw query; gate: what ngx.var.arg_cfm_nc returns (nginx matches
-- the name case-insensitively, the edge's key test does not).
local function run(args, gate)
  set_calls, set_arg = 0, nil
  ngx.var.args, ngx.var.arg_cfm_nc = args, gate
  local ok, res = pcall(strip)
  check(ok, "strip raised on " .. tostring(args) .. ": " .. tostring(res))
  return res
end

-- The busted URL cdnBustNext builds: the pair is appended last.
check(run("a=1&b=%2F&cfm_nc=0123456789ab", "0123456789ab") == true and set_arg == "a=1&b=%2F",
  "trailing cfm_nc dropped, the rest byte for byte (" .. tostring(set_arg) .. ")")
-- A bare "/?cfm_nc=": the query is cleared with an empty table, never nil.
check(run("cfm_nc=0123456789ab", "0123456789ab") == true and type(set_arg) == "table" and next(set_arg) == nil,
  "a query holding only cfm_nc is cleared")
-- Every cfm_nc pair goes, wherever it sits; order, empty pairs and an empty
-- value of another key are kept.
check(run("cfm_nc=1&a=1&&cfm_nc=2&b=&c=%E2%82%AC+x", "1") == true and set_arg == "a=1&&b=&c=%E2%82%AC+x",
  "all cfm_nc pairs dropped, the rest as sent (" .. tostring(set_arg) .. ")")
check(run("cfm_nc&a=1", "") == true and set_arg == "a=1", "a valueless cfm_nc is dropped too")
-- Not the key: a longer name, the name as a value, another case. Nothing is
-- rewritten, so the upstream URI stays exactly as the client sent it.
check(run("cfm_ncx=1&a=1", nil) == false and set_calls == 0, "cfm_ncx is not cfm_nc (gate closed)")
check(run("x=cfm_nc&a=1", nil) == false and set_calls == 0, "cfm_nc as a value is not the key")
check(run("CFM_NC=1&a=1", "1") == false and set_calls == 0, "a case variant opens the gate but is kept")
check(run("a=1&cfm_ncx=2", "") == false and set_calls == 0, "gate open on a prefix match changes nothing")
-- No query, or the gate closed: no work at all.
check(run(nil, nil) == false and set_calls == 0, "no query")
check(run("", "") == false and set_calls == 0, "empty query")

-- It runs before Step 0, so no step below ever reads the cache-bust (and is
-- pcall-guarded, so a failure there cannot end the access phase).
local call = assert(src:find("\npcall(strip_cdn_bust_arg)\n", 1, true), "the pre-step call is missing")
local step0 = assert(src:find("-- ── Step 0: Static IP/CIDR bypass", 1, true))
check(call < step0, "strip_cdn_bust_arg runs before Step 0")

if fails > 0 then os.exit(1) end
print("cfm_cdn_bust_strip_test: ok")

-- cfm_ipkey.client against scripts/tests/fixtures/ipkey.txt, the fixture Go's
-- internal/ipkey TestClientFixture runs too.
package.path = "configs/lua/?.lua;" .. package.path
local ipkey = require("cfm_ipkey")

local n, bad = 0, 0
for line in io.lines("scripts/tests/fixtures/ipkey.txt") do
  if line:sub(1, 1) ~= "#" then
    local input, want = line:match("^([^\t]*)\t(.*)$")
    assert(input, "bad fixture line: " .. line)
    local got = ipkey.client(input)
    if got ~= want then
      bad = bad + 1
      io.stderr:write(string.format("FAIL: client(%q) = %q, want %q\n", input, tostring(got), want))
    end
    n = n + 1
  end
end
assert(n >= 25, "only " .. n .. " fixture cases")
assert(bad == 0, bad .. " fixture case(s) failed")
assert(ipkey.client(nil) == nil, "nil stays nil")
print("ok: cfm_ipkey client key matches the shared fixture (" .. n .. " cases)")

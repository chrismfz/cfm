-- Unit tests for cfm_selfip — the self-origin / IGNORE_NETS bypass predicate
-- shared by cfm.lua (web) and cfm_panel.lua (panel). A fake cfm_filecache
-- injects the self-ips + ignore-nets data (and exercises the module's own
-- transforms), so we can pin the three bypass sources: loopback/link-local,
-- the server's self-IP set, and [global] IGNORE_IPS/IGNORE_NETS (ips + v4 ranges).

package.path = "configs/lua/?.lua;" .. package.path

-- 10.0.0.0 .. 10.0.0.255 as uint32 (what Go writes into v4_ranges).
local RANGE_LO = 10 * 16777216 -- 167772160
local RANGE_HI = RANGE_LO + 255 -- 167772415

local rawByPath = {
  ["/var/lib/cfm/lua/cfm_self_ips.lua"] = {
    ips = { ["1.2.3.4"] = true, ["2001:DB8::1"] = true, ["fe80::abcd"] = true },
  },
  ["/var/lib/cfm/lua/cfm_ignore_nets.lua"] = {
    ips = { ["9.9.9.9"] = true, ["2a06:1:2:3::9"] = true },
    v4_ranges = { { RANGE_LO, RANGE_HI } },
    -- what Go writes (IPIgnore.WriteLuaCache): network as 32 hex digits + prefix.
    v6_ranges = {
      { "2a0145f8000000000000000000000000", 32 },   -- 2a01:45f8::/32
      { "2a144280000100010000000000000000", 64 },   -- 2a14:4280:1:1::/64
      { "20010db8800000000000000000000000", 33 },   -- 2001:db8:8000::/33 (partial nibble)
      { "zz", 64 },                                 -- malformed: dropped
      { "2a0c0000000000000000000000000000", 129 },  -- bad prefix: dropped
      { "00000000000000000000000000000000", 80 },   -- ::/80 covers ::ffff:0:0/96
      { "fe800000000000000000000000000000", 10 },   -- IGNORE_NETS fe80::/10: ignored by design
      { "2a050000000000000000000000010000", 112 },  -- 2a05::1:0/112: inside one /64
    },
  },
}

package.loaded["cfm_filecache"] = {
  get = function(path, opts)
    local raw = rawByPath[path]
    if raw == nil then return nil end
    if opts and opts.transform then
      local ok, v = pcall(opts.transform, raw)
      if ok then return v end
      return nil
    end
    return raw
  end,
}

local selfip = require("cfm_selfip")

local function assert_true(c, m) if not c then error(m, 2) end end

-- normalize_ip: bracket strip + lowercase.
assert_true(selfip.normalize_ip("[2001:DB8::1]") == "2001:db8::1", "normalize_ip bracket+lower")
assert_true(selfip.normalize_ip("") == "", "normalize_ip empty")

-- loopback / link-local.
for _, ip in ipairs({ "127.0.0.1", "127.9.9.9", "::1", "169.254.10.10" }) do
  assert_true(selfip.is_loopback_or_linklocal(ip), "loopback/linklocal should match " .. ip)
  assert_true(selfip.is_self_origin(ip), "is_self_origin loopback " .. ip)
end
assert_true(not selfip.is_loopback_or_linklocal("8.8.8.8"), "8.8.8.8 is not loopback")

-- IPv6 link-local (fe80::/10) is NEVER self: with the edge listening on IPv6,
-- a host on the same L2 segment can connect from any fe80:: address it likes,
-- and a self bypass would skip WAF, challenge and edge bans. Even the node's
-- own fe80:: address (Go may list it in cfm_self_ips.lua) is refused.
for _, ip in ipairs({ "fe80::1", "fe80::1c2:3ff:fe04:506", "FE80::1", "[fe80::1]", "fe90::1", "febf::1", "fe80:0:0:0:0:0:0:1" }) do
  assert_true(not selfip.is_loopback_or_linklocal(ip), "IPv6 link-local is not loopback " .. ip)
  assert_true(not selfip.is_self_origin(ip), "IPv6 link-local is never self-origin " .. ip)
end
assert_true(not selfip.is_self_origin("fe80::abcd"), "the node's own fe80:: in the self set is still refused")
assert_true(not selfip.is_self_origin("fec0::1"), "fec0:: (outside fe80::/10) is not self either")
assert_true(not selfip.is_self_origin("fe80::2"), "an IGNORE_NETS fe80::/10 entry does not make link-local self (ignored by design)")

-- cfm_panel.lua's fallback (cfm_selfip absent: upgrade lag) agrees: loopback
-- and 169.254/16 only, never fe80::/10. Extracted from the source and run.
do
  local fh = assert(io.open("configs/lua/cfm_panel.lua", "r"))
  local src = fh:read("*a"); fh:close()
  local body = src:match("\n(local function panel_is_loopback%(ip%).-\nend)\n")
  assert_true(body ~= nil, "cfm_panel.lua: panel_is_loopback not found")
  local chunk = assert((loadstring or load)(body .. "\nreturn panel_is_loopback"))
  local fb = chunk()
  for _, ip in ipairs({ "::1", "[::1]", "127.0.0.1", "169.254.1.1" }) do
    assert_true(fb(ip), "panel fallback: " .. ip .. " is self")
  end
  for _, ip in ipairs({ "fe80::1", "FE80::1", "[fe80::1]", "febf::1", "8.8.8.8", "" }) do
    assert_true(not fb(ip), "panel fallback: " .. ip .. " is not self")
  end
end

-- self-IP set (incl. IPv6 normalize on both stored and queried side).
assert_true(selfip.is_self_origin("1.2.3.4"), "self ip 1.2.3.4")
assert_true(selfip.is_self_origin("[2001:db8::1]"), "self ip ipv6 bracketed/lowercased matches stored 2001:DB8::1")

-- IGNORE_IPS exact + IGNORE_NETS v4 range.
assert_true(selfip.is_self_origin("9.9.9.9"), "ignore exact ip")
assert_true(selfip.is_self_origin("10.0.0.50"), "ignore v4 range inside")
assert_true(selfip.is_self_origin("10.0.0.0"), "ignore v4 range low edge")
assert_true(selfip.is_self_origin("10.0.0.255"), "ignore v4 range high edge")

-- ipv6_to_hex32: the expansion Go's hex.EncodeToString(ip.To16()) gives.
local H = selfip.ipv6_to_hex32
assert_true(H("2001:db8::1") == "20010db8000000000000000000000001", "hex32 compressed")
assert_true(H("::1") == "00000000000000000000000000000001", "hex32 ::1")
assert_true(H("::") == "00000000000000000000000000000000", "hex32 ::")
assert_true(H("2001:DB8:0:0:0:0:0:1") == "20010db8000000000000000000000001", "hex32 full + upper")
assert_true(H("fe80::1%eth0") == nil, "hex32 refuses a zone id (as Go's ParseIP does)")
assert_true(H("2001:db8::1%25eth0") == nil, "hex32 refuses an encoded zone id")
assert_true(H("::ffff:1.2.3.4") == "00000000000000000000ffff01020304", "hex32 embedded v4")
assert_true(H("::ffff:10.0.0.1") == "00000000000000000000ffff0a000001", "hex32 embedded v4 with a 0 octet")
assert_true(H("1::") == "00010000000000000000000000000000", "hex32 trailing ::")
for _, bad in ipairs({ "1.2.3.4", "1::2::3", "12345::1", "1:2:3:4:5:6:7", "1:2:3:4:5:6:7:8:9",
                       "g::1", ":1::", "1:2:3:4:5:6:7::8", "", "::ffff:1.2.3.999",
                       "1::01.2.3.4", "1::1.2.3.04", "::ffff:010.0.0.1" }) do
  assert_true(H(bad) == nil, "hex32 rejects " .. bad)
end

-- IGNORE_NETS v6 ranges.
assert_true(selfip.is_self_origin("2a01:45f8:1234::5"), "ignore v6 /32 inside")
assert_true(selfip.is_self_origin("2A01:45F8::"), "ignore v6 /32 network address, upper case")
assert_true(not selfip.is_self_origin("2a01:45f9::1"), "ignore v6 /32: next /32 outside")
assert_true(selfip.is_self_origin("2a14:4280:1:1:925a:8ff:fe3c:f289"), "ignore v6 /64 inside")
assert_true(not selfip.is_self_origin("2a14:4280:1:2::1"), "ignore v6 /64: neighbour /64 outside")
assert_true(selfip.is_self_origin("2001:db8:8000::1"), "ignore v6 /33 low half-nibble inside")
assert_true(selfip.is_self_origin("2001:db8:ffff:ffff::1"), "ignore v6 /33 top inside")
assert_true(not selfip.is_self_origin("2001:db8:7fff::1"), "ignore v6 /33: other half outside")
assert_true(not selfip.is_self_origin("2a0c::1"), "malformed v6_ranges entries never match")
assert_true(not selfip.is_self_origin("::ffff:10.0.1.1"), "v4-mapped never matches a v6 range (::/80 here), as in Go")
assert_true(not selfip.is_self_origin("::ffff:8.8.8.8"), "v4-mapped public never matches a v6 range")
assert_true(selfip.is_self_origin("::abcd"), "::/80 still matches a plain v6 inside it")

-- Outside every bypass source → NOT self-origin.
assert_true(not selfip.is_self_origin("10.0.1.1"), "10.0.1.1 outside range")
assert_true(not selfip.is_self_origin("8.8.8.8"), "8.8.8.8 public")
assert_true(not selfip.is_self_origin(""), "empty is not self-origin")

-- count_key: an IPv6 client's /64, but the address where the /64 holds this
-- node's own address or an IGNORE entry (as the daemon's firewall.CountKey).
for ip, want in pairs({
  ["2001:db9:1:2::5"]  = "2001:db9:1:2::/64", -- an unguarded /64
  ["2001:db8::99"]     = "2001:db8::99",      -- holds the node's 2001:db8::1
  ["2a01:45f8:1:2::5"] = "2a01:45f8:1:2::5",  -- inside an ignored /32
  ["2a14:4280:1:1::9"] = "2a14:4280:1:1::9",  -- an ignored /64 itself
  ["2a05::2:9"]        = "2a05::2:9",         -- holds an ignored /112
  ["2a14:4280:1:2::9"] = "2a14:4280:1:2::/64", -- the ignored /64's neighbour
  ["203.0.113.7"]      = "203.0.113.7",
  ["fe80::1"]          = "fe80::1",           -- ungrouped (cfm_ipkey)
  ["-"]                = "-",
}) do
  local got = selfip.count_key(ip)
  assert_true(got == want, "count_key(" .. ip .. ") = " .. tostring(got) .. ", want " .. want)
end
assert_true(selfip.is_self_origin("2a05::1:5"), "ignore v6 /112 inside")

assert_true(selfip.count_key("2a06:1:2:3::77") == "2a06:1:2:3::77", "a /64 holding an IGNORE_IPS IPv6 address counts per address")
assert_true(selfip.count_key("2a06:1:2:4::77") == "2a06:1:2:4::/64", "its neighbour /64 is grouped")

-- The guarded /64s are worked out once per cfm_filecache table and follow a
-- reload: a filecache that hands back the same table until the file changes.
do
  local tables = {}
  local self_ips = { ips = { ["2001:db8:aa::1"] = true } }
  local ignore = { ips = { ["2001:db8:bb::1"] = true }, v6_ranges = {} }
  package.loaded["cfm_filecache"] = {
    get = function(path, opts)
      if not tables[path] then
        local raw = path:find("self_ips", 1, true) and self_ips or ignore
        tables[path] = opts.transform(raw)
      end
      return tables[path]
    end,
  }
  package.loaded["cfm_selfip"] = nil
  local s2 = require("cfm_selfip")
  assert_true(s2.count_key("2001:db8:aa::9") == "2001:db8:aa::9", "cached: the self /64 counts per address")
  assert_true(s2.count_key("2001:db8:bb::9") == "2001:db8:bb::9", "cached: the ignore /64 counts per address (not the self set again)")
  assert_true(s2.count_key("2001:db8:aa::9") == "2001:db8:aa::9", "cached, second call")
  assert_true(s2.count_key("2001:db8:cc::9") == "2001:db8:cc::/64", "cached: an unguarded /64")
  -- A reload (a new table): the old self /64 is free, the new one guarded.
  self_ips = { ips = { ["2001:db8:cc::1"] = true } }
  tables["/var/lib/cfm/lua/cfm_self_ips.lua"] = nil
  assert_true(s2.count_key("2001:db8:aa::9") == "2001:db8:aa::/64", "after a reload the old self /64 is grouped")
  assert_true(s2.count_key("2001:db8:cc::9") == "2001:db8:cc::9", "after a reload the new self /64 counts per address")
end

print("ok: cfm_selfip self-origin / IGNORE_NETS bypass (loopback + self-IP + ignore ips + v4/v6 ranges)")

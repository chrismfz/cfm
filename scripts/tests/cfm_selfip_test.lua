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
    ips = { ["1.2.3.4"] = true, ["2001:DB8::1"] = true },
  },
  ["/var/lib/cfm/lua/cfm_ignore_nets.lua"] = {
    ips = { ["9.9.9.9"] = true },
    v4_ranges = { { RANGE_LO, RANGE_HI } },
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
for _, ip in ipairs({ "127.0.0.1", "127.9.9.9", "::1", "fe80::1", "169.254.10.10" }) do
  assert_true(selfip.is_loopback_or_linklocal(ip), "loopback/linklocal should match " .. ip)
  assert_true(selfip.is_self_origin(ip), "is_self_origin loopback " .. ip)
end
assert_true(not selfip.is_loopback_or_linklocal("8.8.8.8"), "8.8.8.8 is not loopback")

-- self-IP set (incl. IPv6 normalize on both stored and queried side).
assert_true(selfip.is_self_origin("1.2.3.4"), "self ip 1.2.3.4")
assert_true(selfip.is_self_origin("[2001:db8::1]"), "self ip ipv6 bracketed/lowercased matches stored 2001:DB8::1")

-- IGNORE_IPS exact + IGNORE_NETS v4 range.
assert_true(selfip.is_self_origin("9.9.9.9"), "ignore exact ip")
assert_true(selfip.is_self_origin("10.0.0.50"), "ignore v4 range inside")
assert_true(selfip.is_self_origin("10.0.0.0"), "ignore v4 range low edge")
assert_true(selfip.is_self_origin("10.0.0.255"), "ignore v4 range high edge")

-- Outside every bypass source → NOT self-origin.
assert_true(not selfip.is_self_origin("10.0.1.1"), "10.0.1.1 outside range")
assert_true(not selfip.is_self_origin("8.8.8.8"), "8.8.8.8 public")
assert_true(not selfip.is_self_origin(""), "empty is not self-origin")

print("ok: cfm_selfip self-origin / IGNORE_NETS bypass (loopback + self-IP + ignore ips/ranges)")

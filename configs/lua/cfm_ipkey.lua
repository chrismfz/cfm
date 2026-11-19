-- cfm_ipkey: the key a per-client control counts and bans on (docs/edge-ipv6.md
-- "IPv6 /64 grouping"). The Go twin is internal/ipkey; both run
-- scripts/tests/fixtures/ipkey.txt, so the edge and the daemon can never key
-- one client differently.
--
-- An IPv6 client is its /64: any VPS or ISP line hands its customer a /64,
-- and a client rotating its address inside it would otherwise get a fresh
-- identity (counters, rate limits, bans) per address. So:
--   client("2001:db8:1:2:a:b:c:d") -> "2001:db8:1:2::/64"  (RFC 5952 text, as
--                                      Go's netip.Prefix.String() prints it)
--   client("::ffff:1.2.3.4")         -> "1.2.3.4"  (a v4-mapped client is IPv4)
--   client("1.2.3.4")                -> "1.2.3.4"  (IPv4: the address itself)
--   UNCHANGED (never a /64): loopback (::1), link-local (fe80::/10: a /64
--   there is every neighbour on the link), any address in ::/64 (that /64
--   holds ::1, the edge's own origin hop), multicast (ff00::/8),
--   64:ff9b::/64 (it holds NAT64's 64:ff9b::/96, each address there an IPv4
--   client), the local-use NAT64 64:ff9b:1::/48 (RFC 8215), Teredo 2001::/32
--   (a /64 there is a Teredo server, shared by its clients), a zone id ("%eth0")
--   and anything unparsable.
--
-- Never key an ALLOW or an exact match on this (an allow widened to a /64
-- would allow a whole customer prefix), nor a clearance cookie, nor a log
-- line: those stay the full address.
--
-- It also holds the address parsers cfm_selfip uses (one copy).

local lower = string.lower

local M = {}

-- ipv4_to_uint32("1.2.3.4") -> 16909060; nil for anything else.
function M.ipv4_to_uint32(ip)
  local a, b, c, d = ip:match("^(%d+)%.(%d+)%.(%d+)%.(%d+)$")
  if not a then return nil end
  a, b, c, d = tonumber(a), tonumber(b), tonumber(c), tonumber(d)
  if not (a and b and c and d) then return nil end
  if a > 255 or b > 255 or c > 255 or d > 255 then return nil end
  return a * 16777216 + b * 65536 + c * 256 + d
end

-- ipv6_to_hex32("2001:db8::1") -> "20010db8000000000000000000000001": the full
-- 128-bit address as 32 lowercase hex digits, in the same form Go writes the
-- v6_ranges networks. Accepts "::" compression, an embedded IPv4 tail
-- ("::ffff:1.2.3.4"). A zone suffix ("fe80::1%eth0") is refused like Go's
-- net.ParseIP refuses it.
-- Anything it cannot read as exactly 8 groups returns nil, and a nil never
-- matches a range.
function M.ipv6_to_hex32(ip)
  if type(ip) ~= "string" or not ip:find(":", 1, true) then return nil end
  if ip:find("%", 1, true) then return nil end
  ip = lower(ip)
  local head4, v4 = ip:match("^(.*:)(%d+%.%d+%.%d+%.%d+)$")
  if v4 then
    -- Go's ParseIP refuses an octet with a leading zero ("1::01.2.3.4");
    -- so does the edge, or it would ignore a client Go does not.
    if ("." .. v4):find("%.0%d") then return nil end
    local n = M.ipv4_to_uint32(v4)
    if not n then return nil end
    ip = head4 .. string.format("%x:%x", math.floor(n / 65536), n % 65536)
  end
  local function groups(part)
    local out = {}
    if part == "" then return out end
    for g in (part .. ":"):gmatch("([^:]*):") do
      if not g:match("^[0-9a-f][0-9a-f]?[0-9a-f]?[0-9a-f]?$") then return nil end
      out[#out + 1] = string.rep("0", 4 - #g) .. g
    end
    return out
  end
  local hd, tl, gs
  local dc = ip:find("::", 1, true)
  if dc then
    if ip:find("::", dc + 1, true) then return nil end
    hd, tl = groups(ip:sub(1, dc - 1)), groups(ip:sub(dc + 2))
    if not hd or not tl or #hd + #tl > 7 then return nil end
    gs = hd
    for _ = 1, 8 - #hd - #tl do gs[#gs + 1] = "0000" end
    for i = 1, #tl do gs[#gs + 1] = tl[i] end
  else
    gs = groups(ip)
    if not gs or #gs ~= 8 then return nil end
  end
  return table.concat(gs)
end

local V4MAPPED = "00000000000000000000ffff"
local LOOPBACK = "00000000000000000000000000000001"
local NAT64 = "0064ff9b00000000"
local NAT64_LOCAL = "0064ff9b0001" -- /48
local TEREDO = "20010000"         -- /32

-- client(ip): the key described above.
function M.client(ip)
  if type(ip) ~= "string" or not ip:find(":", 1, true) then return ip end
  local h = M.ipv6_to_hex32(ip)
  if not h then return ip end
  if h:sub(1, 24) == V4MAPPED then
    local n = tonumber(h:sub(25), 16)
    return string.format("%d.%d.%d.%d", math.floor(n / 16777216), math.floor(n / 65536) % 256,
      math.floor(n / 256) % 256, n % 256)
  end
  if h == LOOPBACK or h:match("^fe[89ab]") or h:sub(1, 16) == "0000000000000000"
     or h:sub(1, 2) == "ff" or h:sub(1, 16) == NAT64
     or h:sub(1, 12) == NAT64_LOCAL or h:sub(1, 8) == TEREDO then
    return ip
  end
  -- The first four groups; the zero run that ends the /64 (at least the four
  -- zero groups of the interface id) is the longest, so RFC 5952 compresses
  -- exactly the trailing zero groups.
  local g = {}
  for i = 0, 3 do g[#g + 1] = tonumber(h:sub(i * 4 + 1, i * 4 + 4), 16) end
  while #g > 0 and g[#g] == 0 do g[#g] = nil end
  for i = 1, #g do g[i] = string.format("%x", g[i]) end
  return table.concat(g, ":") .. "::/64"
end

return M

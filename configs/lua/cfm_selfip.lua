-- cfm_selfip: the self-origin / IGNORE_NETS bypass predicate, shared by the web
-- edge (cfm.lua) and the panel edge (cfm_panel.lua) so the two can never drift.
--
-- is_self_origin(ip) answers "should CFM leave this client entirely alone?" and
-- is true for:
--   * loopback / link-local (127/8, ::1, fe80::-feb0::, 169.254/16),
--   * the server's own public IPs — /var/lib/cfm/lua/cfm_self_ips.lua, written
--     by Go (firewall/selfip), and
--   * [global] IGNORE_IPS / IGNORE_NETS from cfm.cfg (IPv4 and IPv6 CIDRs) — /var/lib/cfm/lua/
--     cfm_ignore_nets.lua, written by Go (detectors.IPIgnore.WriteLuaCache),
--     so the Lua self-bypass honours the SAME allowlist as the challenge-engine
--     bypass predicate (an operator-ignored network bypasses the whole CFM
--     stack, not just the challenge step).
--
-- Both caches live in cfm_filecache (require'd module state) with a ~30s TTL so
-- config edits propagate without an nginx reload. The old in-file caches in
-- cfm.lua re-initialised their `expires_at = 0` on every request (the
-- access_by_lua_file re-execution PITFALL), so the intended TTL was a permanent
-- miss and both files were loadfile()'d + re-parsed on every single request;
-- routing through cfm_filecache fixes that here for both edges at once.

local fc = require("cfm_filecache")

local lower = string.lower

local _SELF_IPS_FILE = "/var/lib/cfm/lua/cfm_self_ips.lua"
local _SELF_IPS_TTL_SEC = tonumber(os.getenv("CFM_SELF_IPS_TTL_SEC") or "30")
local _IGNORE_NETS_FILE = "/var/lib/cfm/lua/cfm_ignore_nets.lua"

local function normalize_ip(raw)
  local ip = tostring(raw or "")
  if ip == "" then return "" end
  if ip:sub(1, 1) == "[" and ip:sub(-1) == "]" then
    ip = ip:sub(2, -2)
  end
  return lower(ip)
end

local function is_loopback_or_linklocal(ip)
  ip = normalize_ip(ip)
  if ip == "" then return false end
  local b2 = tonumber(ip:match("^169%.(%d+)%."))
  if ip == "::1" then return true end
  if ip:sub(1, 4) == "127." then return true end
  if ip:sub(1, 6) == "fe80::" or ip:sub(1, 6) == "fe90::" or ip:sub(1, 6) == "fea0::" or ip:sub(1, 6) == "feb0::" then
    return true
  end
  if b2 and b2 == 254 then return true end
  return false
end

local function load_self_ip_cache()
  local map = fc.get(_SELF_IPS_FILE, {
    ttl = _SELF_IPS_TTL_SEC,
    transform = function(val)
      if type(val) ~= "table" then error("non-table value") end
      if type(val.ips) ~= "table" then error("missing ips table") end
      local m = {}
      for k, v in pairs(val.ips) do
        if v then
          local nk = normalize_ip(k)
          if nk ~= "" then m[nk] = true end
        end
      end
      return m
    end,
  })
  return map or {}
end

-- Short TTL applied when the cache file is missing/broken on disk. The Go
-- side writes /var/lib/cfm/lua/cfm_ignore_nets.lua on engine startup and on
-- every config reload, but on a freshly-booted host there's a window
-- where the file doesn't exist yet. Falling all the way back to the
-- 30s SELF_IPS_TTL during that window means IGNORE_NETS is silently
-- ignored for the first half-minute. Re-poll every 2s instead.
local _IGNORE_NETS_MISSING_TTL_SEC = 2

local _EMPTY_IGNORE = { ips = {}, v4_ranges = {}, v6_ranges = {} }

local function load_ignore_cache()
  local cache = fc.get(_IGNORE_NETS_FILE, {
    ttl = _SELF_IPS_TTL_SEC,
    missing_ttl = _IGNORE_NETS_MISSING_TTL_SEC,
    transform = function(val)
      if type(val) ~= "table" then error("non-table value") end
      local ips, v4_ranges, v6_ranges = {}, {}, {}
      if type(val.ips) == "table" then
        for k, v in pairs(val.ips) do
          if v then
            local nk = normalize_ip(k)
            if nk ~= "" then ips[nk] = true end
          end
        end
      end
      if type(val.v4_ranges) == "table" then
        for i = 1, #val.v4_ranges do
          local r = val.v4_ranges[i]
          if type(r) == "table" and type(r[1]) == "number" and type(r[2]) == "number" then
            v4_ranges[#v4_ranges + 1] = { r[1], r[2] }
          end
        end
      end
      -- { "<32 hex digits>", prefix } per IPv6 CIDR (Go: IPIgnore.WriteLuaCache).
      -- An entry that is not exactly that shape is dropped, never widened.
      if type(val.v6_ranges) == "table" then
        for i = 1, #val.v6_ranges do
          local r = val.v6_ranges[i]
          if type(r) == "table" and type(r[1]) == "string" and type(r[2]) == "number"
             and #r[1] == 32 and not r[1]:find("[^0-9a-f]")
             and r[2] >= 0 and r[2] <= 128 and r[2] == math.floor(r[2]) then
            v6_ranges[#v6_ranges + 1] = { r[1], r[2] }
          end
        end
      end
      return { ips = ips, v4_ranges = v4_ranges, v6_ranges = v6_ranges }
    end,
  })
  return cache or _EMPTY_IGNORE
end

local function ipv4_to_uint32(ip)
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
-- net.ParseIP refuses it (link-local is the loopback/link-local rule's job).
-- Anything it cannot read as exactly 8 groups returns nil, and a nil never
-- matches a range.
local function ipv6_to_hex32(ip)
  if type(ip) ~= "string" or not ip:find(":", 1, true) then return nil end
  if ip:find("%", 1, true) then return nil end
  ip = lower(ip)
  local head4, v4 = ip:match("^(.*:)(%d+%.%d+%.%d+%.%d+)$")
  if v4 then
    -- Go's ParseIP refuses an octet with a leading zero ("1::01.2.3.4");
    -- so does the edge, or it would ignore a client Go does not.
    if ("." .. v4):find("%.0%d") then return nil end
    local n = ipv4_to_uint32(v4)
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

-- hex32_in_prefix: do the first `bits` bits of hex32 equal those of net_hex?
-- Whole nibbles compare as a string prefix; a trailing partial nibble compares
-- its top (bits % 4) bits numerically.
local function hex32_in_prefix(hex32, net_hex, bits)
  local whole = math.floor(bits / 4)
  if whole > 0 and hex32:sub(1, whole) ~= net_hex:sub(1, whole) then return false end
  local rem = bits % 4
  if rem == 0 then return true end
  local shift = 2 ^ (4 - rem)
  local a = tonumber(hex32:sub(whole + 1, whole + 1), 16)
  local b = tonumber(net_hex:sub(whole + 1, whole + 1), 16)
  return math.floor(a / shift) == math.floor(b / shift)
end

local function is_in_ignore_nets(ip)
  local cache = load_ignore_cache()
  if cache.ips[ip] then return true end
  local n = ipv4_to_uint32(ip)
  if n then
    local ranges = cache.v4_ranges
    for i = 1, #ranges do
      if n >= ranges[i][1] and n <= ranges[i][2] then return true end
    end
    return false
  end
  local ranges6 = cache.v6_ranges
  if ranges6 and #ranges6 > 0 then
    local h = ipv6_to_hex32(ip)
    -- A v4-mapped address (::ffff:a.b.c.d) is an IPv4 client to Go: its
    -- IPNet.Contains never matches it against an IPv6 network, so neither
    -- does the edge (a ::/0 entry must not swallow every IPv4-mapped client).
    if h and h:sub(1, 24) ~= "00000000000000000000ffff" then
      for i = 1, #ranges6 do
        if hex32_in_prefix(h, ranges6[i][1], ranges6[i][2]) then return true end
      end
    end
  end
  return false
end

local function is_self_origin(ip)
  local nip = normalize_ip(ip)
  if nip == "" then return false end
  if is_loopback_or_linklocal(nip) then return true end
  local map = load_self_ip_cache()
  if map[nip] == true then return true end
  if is_in_ignore_nets(nip) then return true end
  return false
end

return {
  normalize_ip           = normalize_ip,
  is_loopback_or_linklocal = is_loopback_or_linklocal,
  is_self_origin         = is_self_origin,
  ipv6_to_hex32          = ipv6_to_hex32,
}

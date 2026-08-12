-- cfm_selfip: the self-origin / IGNORE_NETS bypass predicate, shared by the web
-- edge (cfm.lua) and the panel edge (cfm_panel.lua) so the two can never drift.
--
-- is_self_origin(ip) answers "should CFM leave this client entirely alone?" and
-- is true for:
--   * loopback / link-local (127/8, ::1, fe80::-feb0::, 169.254/16),
--   * the server's own public IPs — /var/lib/cfm/lua/cfm_self_ips.lua, written
--     by Go (firewall/selfip), and
--   * [global] IGNORE_IPS / IGNORE_NETS from cfm.cfg — /var/lib/cfm/lua/
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

local _EMPTY_IGNORE = { ips = {}, v4_ranges = {} }

local function load_ignore_cache()
  local cache = fc.get(_IGNORE_NETS_FILE, {
    ttl = _SELF_IPS_TTL_SEC,
    missing_ttl = _IGNORE_NETS_MISSING_TTL_SEC,
    transform = function(val)
      if type(val) ~= "table" then error("non-table value") end
      local ips, v4_ranges = {}, {}
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
      return { ips = ips, v4_ranges = v4_ranges }
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

local function is_in_ignore_nets(ip)
  local cache = load_ignore_cache()
  if cache.ips[ip] then return true end
  local n = ipv4_to_uint32(ip)
  if n then
    local ranges = cache.v4_ranges
    for i = 1, #ranges do
      if n >= ranges[i][1] and n <= ranges[i][2] then return true end
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
}

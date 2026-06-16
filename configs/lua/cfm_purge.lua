-- /var/lib/cfm/lua/cfm_purge.lua  (CFM-managed canonical location)
--
-- Force-unblock support for the OpenResty/Lua WAF planes.
--
-- Deletes every per-IP key for a given IP from the `cfm_decisions` shared dict.
-- These keys are the WAF enforcement/cache state that lives entirely inside
-- nginx and is invisible to any firewall/blocklist search:
--
--   tr|<profile>|<host>|<ip>[:lock|:tok|:ts]   throttle token buckets (cfm_rules)
--   d|<ip>|<host>|<method>|<scheme>|<uri>      per-URL decision cache (cfm.lua)
--   ds|<ip>|<host>|<scope>                     static-asset decision cache
--   geo|<ip>                                   country-code cache
--   ok_touch|<ip>|<host>|<scope>               solved-IP touch gate
--   wafpush|<ip>|<reason>                      WAF push cooldown
--
-- Invoked from the `= /cfm-admin/purge-ip` location, which the cfm daemon
-- (internal/webdetector NginxBridge.purgeShared) calls over loopback during a
-- force unblock. Matching is field-positional (never a naive substring) so an
-- IP that merely appears inside a host or URI is not collateral-purged.

local _M = {}

local SHNAME     = "cfm_decisions"
local TOKEN_FILE = "/var/lib/cfm/lua/cfm_bridge_token.lua"

-- load_token reads the canonical bridge token (the same file cfm.lua trusts).
-- Read fresh on each call so a daemon-side token rotation is picked up without
-- an nginx reload; the file is tiny and purges are rare.
local function load_token()
  local chunk = loadfile(TOKEN_FILE)
  if not chunk then return nil end
  local ok, val = pcall(chunk)
  if not ok or type(val) ~= "string" or #val < 32 then return nil end
  return val
end

-- check_token returns true iff the request carries the matching bridge token.
-- The endpoint is also locked to loopback at the nginx layer; this is the
-- second factor so a compromised local user without the token cannot purge.
function _M.check_token()
  local want = load_token()
  if not want then return false end
  local got = ngx.req.get_headers()["X-CFM-Token"]
  return type(got) == "string" and got == want
end

-- split_pipe splits on the literal '|'. IPv6 addresses contain ':' but never
-- '|', so an address always stays intact within a single field.
local function split_pipe(s)
  local parts, start = {}, 1
  while true do
    local sep = string.find(s, "|", start, true)
    if not sep then
      parts[#parts + 1] = string.sub(s, start)
      break
    end
    parts[#parts + 1] = string.sub(s, start, sep - 1)
    start = sep + 1
  end
  return parts
end

-- strip_tr_suffix removes the token-bucket sub-key suffixes (:lock/:tok/:ts).
-- IPv6 fields cannot end in these (they are not hex), so this is unambiguous.
local function strip_tr_suffix(s)
  for _, suf in ipairs({ ":lock", ":tok", ":ts" }) do
    if s:sub(-#suf) == suf then
      return s:sub(1, #s - #suf)
    end
  end
  return s
end

-- purge_ip deletes all per-IP keys for `ip` and returns per-plane counts.
function _M.purge_ip(ip)
  local deleted = { throttle = 0, decision_cache = 0, geo = 0, ok_touch = 0, wafpush = 0 }
  local sh = ngx.shared[SHNAME]
  if not sh then
    return { ip = ip or "", deleted = deleted, scanned = 0, error = "shdict unavailable" }
  end
  if type(ip) ~= "string" or ip == "" then
    return { ip = "", deleted = deleted, scanned = 0, error = "bad ip" }
  end

  -- 0 = all keys; a purge is a rare admin action so scanning the whole dict
  -- is acceptable. The dict is shared across all workers, so one pass clears
  -- every worker.
  local keys = sh:get_keys(0)
  local scanned = #keys

  for _, k in ipairs(keys) do
    local parts = split_pipe(k)
    local prefix = parts[1]
    local plane

    if prefix == "d" or prefix == "ds" then
      if parts[2] == ip then plane = "decision_cache" end
    elseif prefix == "geo" then
      if parts[2] == ip then plane = "geo" end
    elseif prefix == "ok_touch" then
      if parts[2] == ip then plane = "ok_touch" end
    elseif prefix == "wafpush" then
      if parts[2] == ip then plane = "wafpush" end
    elseif prefix == "tr" then
      if strip_tr_suffix(parts[#parts]) == ip then plane = "throttle" end
    end

    if plane then
      sh:delete(k)
      deleted[plane] = deleted[plane] + 1
    end
  end

  return { ip = ip, deleted = deleted, scanned = scanned }
end

return _M

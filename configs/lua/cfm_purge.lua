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
--   wafpush|<reason>|<ip>                      WAF push cooldown (IP is the LAST field)
--   panel_cooldown|<ip>|<host>                 panel challenge cooldown (cfm_panel)
--   panel_ok|<ip>|<host>                       panel challenge passed/bypass
--   panel_loop|<ip>|<host>                     panel challenge loop counter
--
-- Invoked from the `= /cfm-admin/purge-ip` location, which the cfm daemon
-- (internal/webdetector NginxBridge.purgeShared) calls over loopback during a
-- force unblock. Matching is field-positional (never a naive substring) so an
-- IP that merely appears inside a host or URI is not collateral-purged.

local _M = {}

local SHNAME     = "cfm_decisions"

-- load_token returns the canonical bridge token (the same one cfm.lua
-- trusts) via the shared cached accessor (cfm_bridge_cfg → cfm_filecache,
-- 10s TTL) — the validity rule lives in one place. Rotation freshness is
-- handled by check_token's refresh-on-mismatch below, so the cache TTL
-- never rejects a just-rotated token. pcall guards an upgrade lag where
-- the module set is older than this file.
local function load_token()
  local ok, bc = pcall(require, "cfm_bridge_cfg")
  if ok and type(bc) == "table" and bc.token then
    return (bc.token())
  end
  return nil
end

-- check_token returns true iff the request carries the matching bridge token.
-- The endpoint is also locked to loopback (see check_loopback); this token is
-- the second factor so a compromised host without the secret cannot purge.
--
-- Freshness: unlike every other consumer, this validates an INBOUND
-- credential — the daemon may force-unblock (and therefore purge) right
-- after rotating a weak token at startup, and rejecting its brand-new token
-- because our cache is up to 10s old would leave the "unblocked" IP with
-- stale edge state. On a mismatch, force one fresh read and re-compare:
-- restores the old read-fresh-per-call guarantee at purge cost only
-- (purges are rare; the hot path never pays it).
function _M.check_token()
  local got = ngx.req.get_headers()["X-CFM-Token"]
  if type(got) ~= "string" or got == "" then return false end
  local want = load_token()
  if want and got == want then return true end
  local ok, bc = pcall(require, "cfm_bridge_cfg")
  if ok and type(bc) == "table" and bc.refresh_token then
    want = bc.refresh_token()
    return type(want) == "string" and got == want
  end
  return false
end

-- check_loopback returns true iff the *real* TCP peer is loopback.
--
-- It must read $realip_remote_addr (the original peer), NOT $remote_addr:
-- the real_ip module rewrites $remote_addr to the client-supplied
-- CF-Connecting-IP for trusted proxies, so a request arriving via Cloudflare
-- with header "CF-Connecting-IP: 127.0.0.1" would otherwise forge a loopback
-- origin and defeat an `allow 127.0.0.1` rule. $realip_remote_addr is the
-- pre-rewrite peer and cannot be spoofed by a header. Falls back to
-- $remote_addr when realip is not in play (e.g. a direct loopback call with
-- no CF header, where the two are identical anyway).
function _M.check_loopback()
  local peer = ngx.var.realip_remote_addr
  if peer == nil or peer == "" then
    peer = ngx.var.remote_addr or ""
  end
  return peer == "127.0.0.1" or peer == "::1"
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
  local deleted = { throttle = 0, decision_cache = 0, geo = 0, ok_touch = 0, wafpush = 0, panel = 0 }
  local sh = ngx.shared[SHNAME]
  if not sh then
    return { ip = ip or "", deleted = deleted, scanned = 0, error = "shdict unavailable" }
  end
  if type(ip) ~= "string" or ip == "" then
    return { ip = "", deleted = deleted, scanned = 0, error = "bad ip" }
  end

  -- 0 = all keys. This holds the dict lock for the duration of the scan, so
  -- it is deliberately reserved for this rare, loopback+token-gated admin
  -- action (a force unblock) rather than the request hot path. We scan ALL
  -- keys on purpose: a bounded get_keys(N) could skip the very key that is
  -- keeping a visitor stuck, which would defeat the whole point. The dict is
  -- shared across all workers, so a single pass clears every worker.
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
    elseif prefix == "panel_ok" or prefix == "panel_cooldown" or prefix == "panel_loop" then
      -- cfm_panel.lua: panel_*|<ip>|<host>. panel_cooldown is active
      -- "stuck behind a challenge" state, so it must be cleared on unblock.
      if parts[2] == ip then plane = "panel" end
    elseif prefix == "wafpush" then
      -- cfm_waf.lua writes wafpush|<reason>|<ip>: the IP is the LAST field,
      -- not field 2 (reason can itself be arbitrary text).
      if parts[#parts] == ip then plane = "wafpush" end
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

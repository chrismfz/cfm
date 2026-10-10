-- cfm_edgeban.lua — the edge's own copy of the daemon's edge bans.
--
-- WHY
--
-- An nft ban never reaches a client that comes in through a trusted proxy
-- (Cloudflare): on the wire it is the proxy's address. The daemon keeps the
-- web-related and manual bans in its edge-ban store (internal/edgeban) and
-- the bridge decision answers ip_action=block for them, but the decision is
-- asked late (Step 3) and its clean allows are cached for up to 90 s, so a
-- banned client still got through a clearance cookie (Step 2b), the
-- cPanel/webmail proxy hostnames (Step 0d), /.well-known/ (0a1), the static
-- locations, and any URL it had fetched in the last 90 s. This module checks
-- the ban at the TOP of cfm.lua and on the static location.
--
-- HOW
--
-- The daemon serves the whole list (/nginx/edgeban: address → expiry) with a
-- generation that is a hash of the content. One worker at a time (shared-dict
-- lock) pulls it every POLL_SEC from a timer. The list lives in two slots,
-- "eb|a|<ip>" and "eb|b|<ip>", each address's value the generation it was
-- written for, and "eb:cur" = "<slot><generation>" names the live one. A new
-- list is written into the other slot, then "eb:cur" flips to it in one set:
-- a lookup never sees a half-written list, and an address left over from an
-- older list in that slot carries an older generation, so it never matches
-- (it expires on its own TTL). A lookup is two dict gets. Each entry's TTL is the ban's remaining time, capped at
-- ENTRY_TTL_MAX: the full list is fetched again every FULL_SEC, which
-- refreshes them, so with the daemon unreachable the copy fades out within
-- ENTRY_TTL_MAX (fail open) instead of holding unbans back forever.
--
-- PROXIED ONLY: a direct client is nft's (an allow set there wins over a
-- block), so check() answers for a request whose connection came from a
-- trusted proxy only (realip replaced the address). The daemon's list already
-- leaves out allowed addresses, trusted-proxy addresses and IGNORE_IPS.
--
-- FAIL-OPEN: no dict, no list yet, daemon down, a bad reply — every failure
-- answers "not banned". [webdetector] EDGE_BAN = 0 empties the daemon's list.
--
-- ISOLATION: entries live in the dedicated cfm_edgeban dict; on upgrade lag
-- (new Lua, conf not reloaded yet) in cfm_decisions, under the same keys.
--
-- Timer callbacks get everything as arguments (the per-request chunk's
-- upvalues are not safe there: see waf_insp_flush_cb in cfm.lua).

local M = {}

local POLL_SEC      = 2
local FULL_SEC      = 60
local ENTRY_TTL_MAX = 300
local CUR_KEY       = "eb:cur"   -- "<slot><gen>", slot "a" or "b"
local POLLED_KEY    = "eb:polled"
local FULL_KEY      = "eb:full"
local LOCK_KEY      = "eb:lock"

local function dict()
  local sh = ngx.shared
  return sh.cfm_edgeban or sh.cfm_decisions
end
M._dict = dict

-- proxied reports whether realip replaced the connection's address, i.e. the
-- request came through a trusted proxy (the same test cfm_decision's px=1).
function M.proxied()
  local ok, raw, addr = pcall(function()
    return ngx.var.realip_remote_addr, ngx.var.remote_addr
  end)
  return ok and raw ~= nil and raw ~= "" and addr ~= nil and raw ~= addr
end

-- banned reports whether ip is on the current list.
function M.banned(ip)
  local d = dict()
  if not d or not ip or ip == "" then return false end
  local cur = d:get(CUR_KEY)
  if type(cur) ~= "string" or #cur < 2 then return false end
  return d:get("eb|" .. cur:sub(1, 1) .. "|" .. ip) == cur:sub(2)
end

-- check is the request-path entry: banned AND proxied. Never raises.
function M.check(ip)
  local ok, hit = pcall(function() return M.proxied() and M.banned(ip) end)
  return ok and hit == true
end

-- static_gate is the static-asset location's check (that location skips
-- cfm.lua): a banned proxied client gets 403 there too. It ends the request
-- or returns; it never raises.
function M.static_gate()
  if not M.check(ngx.var.remote_addr) then return end
  pcall(function()
    ngx.var.cfm_upstream = "cfm_block"
    ngx.header["X-CFM-Action"] = "block"
    ngx.header["X-CFM-Edge-Ban"] = "1"
  end)
  return ngx.exit(403)
end

-- current returns the live slot and generation (nil when none).
local function current(d)
  local cur = d:get(CUR_KEY)
  if type(cur) ~= "string" or #cur < 2 then return nil, nil end
  return cur:sub(1, 1), cur:sub(2)
end
M._current = current

-- apply writes one reply (decoded) into d. Returns true if it switched the
-- list. Exposed for the tests.
function M.apply(d, r, now)
  if type(r) ~= "table" or type(r.gen) ~= "string" or r.gen == "" then return false end
  if r.unchanged then return false end
  if type(r.ips) ~= "table" then return false end
  local slot, gen = current(d)
  -- The same generation (a periodic full fetch) refreshes the live slot in
  -- place: same content, same values. A new one goes to the other slot.
  if gen ~= r.gen then slot = (slot == "a") and "b" or "a" end
  local pfx = "eb|" .. slot .. "|"
  for ip, exp in pairs(r.ips) do
    if type(ip) == "string" and ip ~= "" then
      exp = tonumber(exp) or 0
      local ttl = ENTRY_TTL_MAX
      if exp > 0 then ttl = math.min(ENTRY_TTL_MAX, exp - now) end
      if ttl > 0 then
        d:set(pfx .. ip, r.gen, ttl)
      end
    end
  end
  d:set(CUR_KEY, slot .. r.gen)
  return true
end

local function poll_cb(premature, dec, decode, full)
  if premature or not dec or not decode then return end
  local d = dict()
  if not d then return end
  local path = "/nginx/edgeban"
  local _, have = current(d)
  if have and not full then path = path .. "?gen=" .. ngx.escape_uri(have) end
  local body = dec:rpc("edgeban", "GET", path)
  if not body then return end
  local r = decode(body)
  M.apply(d, r, ngx.now())
end

-- tick starts a poll when one is due: called on every cfm.lua request, one
-- dict get in the common case. dec is cfm.lua's bridge client, decode a JSON
-- decoder; both go to the timer as arguments.
function M.tick(dec, decode)
  local d = dict()
  if not d or not dec then return end
  local now = ngx.now()
  if now - (d:get(POLLED_KEY) or 0) < POLL_SEC then return end
  if not d:add(LOCK_KEY, 1, POLL_SEC) then return end
  d:set(POLLED_KEY, now)
  local full = now - (d:get(FULL_KEY) or 0) >= FULL_SEC
  if full then d:set(FULL_KEY, now) end
  ngx.timer.at(0, poll_cb, dec, decode, full)
end

M._poll_cb = poll_cb
M.POLL_SEC, M.FULL_SEC, M.ENTRY_TTL_MAX = POLL_SEC, FULL_SEC, ENTRY_TTL_MAX

return M

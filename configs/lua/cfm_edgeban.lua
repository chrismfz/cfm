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
-- locations, and any URL it had fetched in the last 90 s. cfm.lua checks this
-- copy at its top (Step 0e) and the static locations call static_gate().
--
-- HOW
--
-- One worker at a time (a dict lock held while a poll is in flight) polls
-- GET /nginx/edgeban every POLL_SEC from a timer that cfm.lua requests start
-- (the static location only reads). The edge sends its position in the
-- daemon's change journal (epoch, seq) and gets only what changed since, so
-- a poll costs what changed (usually nothing), not the list. The whole list
-- comes on the first poll, after a daemon restart (new epoch), when the edge
-- is further behind than the journal reaches, and every FULL_SEC (a
-- consistency check).
--
-- The list lives in two slots, "eb|a|<ip>" and "eb|b|<ip>", each value the id
-- of the full list it belongs to ("<epoch>:<seq>"); "eb:cur" = "<slot>|<id>"
-- names the live one. A whole list is written into the other slot and
-- "eb:cur" flips in one set, so a lookup never sees half a list, and an
-- address left over from an older list carries an older id and never
-- matches. Changes are written into the live slot directly. Each entry lives
-- as long as its ban (a permanent one has no TTL), as in nft: with the daemon
-- down the edge keeps enforcing what nft enforces. The dict is sized for two
-- copies of the daemon's cap (16m for 20k; measured on nginx 1.24): a write
-- into a full dict does not fail, it evicts the least recently used keys,
-- and those are the leftovers of older lists, so the live list stays whole.
-- Past that size the evictions would reach live entries silently (they come
-- back with the next whole list); a lost eb:cur makes the next poll ask for
-- one. A write the dict does refuse leaves the position where it was (the
-- same changes or list come again). A daemon whose store was cleared (nft unreadable, the table
-- gone after `cfm disable`) sends an empty list: the copy is emptied.
--
-- A lookup is two dict gets, for a proxied request only.
--
-- MODE ([webdetector] EDGE_BAN_MODE, sent with every reply): "log" (the
-- default, burn-in) counts and logs what it would block; "enforce" answers
-- 403. The counts ride on the next poll to the daemon (cfm debug / the
-- admin API). Logging is one line per address per minute.
--
-- PROXIED ONLY: a direct client is nft's (an allow set there wins over a
-- block), so only a request whose connection came from a trusted proxy
-- (realip replaced the address) is checked. The daemon's list already leaves
-- out allowed addresses, trusted-proxy addresses and IGNORE_IPS.
--
-- FAIL-OPEN: no dict, no list yet, a bad reply — every failure answers "not
-- banned". A daemon that has not reconciled yet replies {"ready":false} and
-- the copy stays. [webdetector] EDGE_BAN = 0 empties the daemon's list.
--
-- ISOLATION: entries live in the dedicated cfm_edgeban dict; on upgrade lag
-- (new Lua, conf not reloaded yet) in cfm_decisions, under the same keys.
--
-- Timer callbacks get everything as arguments (the per-request chunk's
-- upvalues are not safe there: see waf_insp_flush_cb in cfm.lua).

local shd = require "cfm_shdict" -- counters: never dict:incr(key, n, init)

local M = {}

local POLL_SEC   = 5
local FULL_SEC   = 600
local LOCK_TTL   = 30    -- frees a lock only if its timer never ran
local LOG_SEC    = 60    -- one log line per address per LOG_SEC
local CUR_KEY    = "eb:cur"    -- "<slot>|<list id>"
local POS_KEY    = "eb:pos"    -- "<epoch>:<seq>" last applied
local MODE_KEY   = "eb:mode"
local POLLED_KEY = "eb:polled"
local FULL_KEY   = "eb:full"
local LOCK_KEY   = "eb:lock"
local WOULD_KEY  = "eb:n:would"
local BLOCK_KEY  = "eb:n:block"

local function dict()
  local sh = ngx.shared
  return sh.cfm_edgeban or sh.cfm_decisions
end
M._dict = dict

-- current returns the live slot and list id (nil when none). The parse is
-- cached per worker on the raw value (it changes only on a whole-list flip).
local cur_raw, cur_slot, cur_id
local function current(d)
  local cur = d:get(CUR_KEY)
  if cur ~= cur_raw then
    cur_raw, cur_slot, cur_id = cur, nil, nil
    if type(cur) == "string" then cur_slot, cur_id = cur:match("^([ab])|(.+)$") end
  end
  return cur_slot, cur_id
end
M._current = current

-- banned reports whether ip is on the current list.
local function banned(d, ip)
  if not ip or ip == "" then return false end
  -- nginx prints an IPv4-mapped peer as ::ffff:a.b.c.d; the daemon keys it
  -- as a.b.c.d.
  if ip:sub(1, 7) == "::ffff:" and ip:find(".", 8, true) then ip = ip:sub(8) end
  local slot, id = current(d)
  if not slot then return false end
  return d:get("eb|" .. slot .. "|" .. ip) == id
end

function M.banned(ip)
  local d = dict()
  return d ~= nil and banned(d, ip)
end

-- proxied reports whether realip replaced the connection's address, i.e. the
-- request came through a trusted proxy (cfm_decision's px=1 test). addr is
-- $remote_addr when the caller has it already.
local function proxied(addr)
  local raw = ngx.var.realip_remote_addr
  addr = addr or ngx.var.remote_addr
  return raw ~= nil and raw ~= "" and addr ~= nil and raw ~= addr
end
M.proxied = function()
  local ok, r = pcall(proxied)
  return ok and r == true
end

-- verdict: "block" (enforce), "log" (would block) or nil. ip is the request's
-- $remote_addr (the client, after realip).
local function verdict_impl(ip)
  if not proxied(ip) then return nil end
  local d = dict()
  if not d or not banned(d, ip) then return nil end
  local mode = (d:get(MODE_KEY) == "enforce") and "block" or "log"
  shd.incr(d, (mode == "block") and BLOCK_KEY or WOULD_KEY, 1)
  if d:add("eb:l|" .. ip, 1, LOG_SEC) then
    ngx.log(ngx.WARN, "[cfm] ", (mode == "block") and "block" or "would_block",
      " edge_ban ip=", ip, " (one line per address per ", LOG_SEC, "s)")
  end
  return mode
end

function M.verdict(ip)
  local ok, v = pcall(verdict_impl, ip)
  return ok and v or nil
end

-- check is M.verdict == "block" (enforce mode only).
function M.check(ip)
  return M.verdict(ip) == "block"
end

-- static_gate is the static-asset location's check (that location skips
-- cfm.lua): in enforce mode a banned proxied client gets 403 there too. It
-- ends the request or returns; it never raises.
function M.static_gate()
  local ok, addr = pcall(function() return ngx.var.remote_addr end)
  if not ok or M.verdict(addr) ~= "block" then return end
  pcall(function()
    ngx.var.cfm_upstream = "cfm_block"
    ngx.header["X-CFM-Action"] = "block"
    ngx.header["X-CFM-Edge-Ban"] = "1"
  end)
  return ngx.exit(403)
end

-- ttl_for: the dict TTL for an expiry (0 = none, permanent); false if it is
-- past; nil if it is not a number (missing / null: skipped, never permanent).
local function ttl_for(exp, now)
  exp = tonumber(exp)
  if not exp then return nil end
  if exp == 0 then return 0 end
  local ttl = exp - now
  if ttl <= 0 then return false end
  return ttl
end

-- apply writes one decoded reply into d. Returns true if it moved the
-- position. Exposed for the tests.
function M.apply(d, r, now)
  if type(r) ~= "table" then return false end
  -- The mode applies whatever else the reply holds ("not ready" included).
  if r.mode == "enforce" or r.mode == "log" then d:set(MODE_KEY, r.mode) end
  if r.ready == false then return false end
  local epoch, seq = r.epoch, tonumber(r.seq)
  if type(epoch) ~= "string" or epoch == "" or not seq then return false end
  local pos = epoch .. ":" .. string.format("%d", seq)

  if r.full then
    if type(r.ips) ~= "table" then return false end
    local slot = current(d)
    slot = (slot == "a") and "b" or "a"
    local pfx = "eb|" .. slot .. "|"
    for ip, exp in pairs(r.ips) do
      if type(ip) == "string" and ip ~= "" then
        local ttl = ttl_for(exp, now)
        if ttl and not d:set(pfx .. ip, pos, ttl) then
          return false -- refused: keep the old list, the whole list comes again
        end
      end
    end
    -- The position only with the list it belongs to: changes are applied
    -- onto the live list from the position.
    if not d:set(CUR_KEY, slot .. "|" .. pos) then return false end
    d:set(POS_KEY, pos)
    return true
  end

  -- Changes since our position: only onto the list they continue.
  local have = d:get(POS_KEY)
  local hepoch = type(have) == "string" and have:match("^(.+):%d+$")
  local slot, id = current(d)
  if not slot or hepoch ~= epoch then return false end
  local pfx = "eb|" .. slot .. "|"
  if type(r.set) == "table" then
    for ip, exp in pairs(r.set) do
      if type(ip) == "string" and ip ~= "" then
        local ttl = ttl_for(exp, now)
        if ttl == false then
          d:delete(pfx .. ip) -- expired meanwhile
        elseif ttl and not d:set(pfx .. ip, id, ttl) then
          return false -- refused: the same changes come again
        end
      end
    end
  end
  if type(r.del) == "table" then
    for _, ip in ipairs(r.del) do
      if type(ip) == "string" and ip ~= "" then d:delete(pfx .. ip) end
    end
  end
  d:set(POS_KEY, pos)
  return true
end

local function poll(d, dec, decode, full)
  local would, blocked = d:get(WOULD_KEY) or 0, d:get(BLOCK_KEY) or 0
  local path = "/nginx/edgeban?would=" .. would .. "&blocked=" .. blocked
  local have = d:get(POS_KEY)
  local epoch, seq
  if type(have) == "string" then epoch, seq = have:match("^(.+):(%d+)$") end
  -- No live list (eb:cur evicted, or never written): changes have nothing to
  -- go onto, so ask for the whole list.
  if full or not epoch or not current(d) then
    path = path .. "&full=1"
  else
    path = path .. "&epoch=" .. ngx.escape_uri(epoch) .. "&seq=" .. seq
  end
  local body = dec:rpc("edgeban", "GET", path)
  if not body then return end
  -- Reported: take them off the counters (what arrived meanwhile stays).
  for k, n in pairs({ [WOULD_KEY] = would, [BLOCK_KEY] = blocked }) do
    if n > 0 then
      local v = d:incr(k, -n)
      if v and v < 0 then d:set(k, 0) end -- the key was evicted meanwhile
    end
  end
  M.apply(d, decode(body), ngx.now())
end

local function poll_cb(premature, dec, decode, full)
  local d = dict()
  if not d then return end
  if not premature and dec and decode then
    pcall(poll, d, dec, decode, full)
  end
  -- The lock covers the poll in flight only; POLLED_KEY paces the next one.
  d:delete(LOCK_KEY)
end
M._poll_cb = poll_cb

-- tick starts a poll when one is due: called on every cfm.lua request, one
-- dict get in the common case. dec is cfm.lua's bridge client, decode a JSON
-- decoder; both go to the timer as arguments.
local next_check = 0 -- per worker: no dict read before this
local function tick_impl(dec, decode)
  local now = ngx.now()
  if now < next_check then return end
  local d = dict()
  if not d or not dec then return end
  local polled = d:get(POLLED_KEY) or 0
  if now - polled < POLL_SEC then
    next_check = polled + POLL_SEC
    return
  end
  next_check = now + 1 -- another worker may be polling: look again in a second
  if not d:add(LOCK_KEY, 1, LOCK_TTL) then return end
  d:set(POLLED_KEY, now)
  local full = now - (d:get(FULL_KEY) or 0) >= FULL_SEC
  if full then d:set(FULL_KEY, now) end
  if not ngx.timer.at(0, poll_cb, dec, decode, full) then d:delete(LOCK_KEY) end
end

function M.tick(dec, decode)
  pcall(tick_impl, dec, decode)
end

-- step is cfm.lua's Step 0e: start a poll when due, then the verdict for ip
-- ("block" in enforce mode, "log" when it would block, nil). Never raises.
function M.step(ip, dec, decode)
  local ok, v = pcall(verdict_impl, ip)
  -- One pcall in the common case: the poll check runs only once this
  -- worker's deadline has passed, and its failure never touches the verdict.
  if ngx.now() >= next_check then pcall(tick_impl, dec, decode) end
  return ok and v or nil
end

M.POLL_SEC, M.FULL_SEC, M.LOG_SEC = POLL_SEC, FULL_SEC, LOG_SEC

-- _reset clears the per-worker state (tests).
function M._reset() next_check, cur_raw, cur_slot, cur_id = 0, nil, nil, nil end

return M

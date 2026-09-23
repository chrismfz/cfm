-- cfm_fppolicy.lua — edge-local lookup of fleet-armed fingerprint policies
-- (master plan E3 node slice; central store: cfm-web fingerprint_policies).
--
-- WHAT THIS DOES
--
-- cfm-web lets an operator arm a per-fingerprint action (deny / challenge /
-- challenge_v2); the daemon pulls the armed list and answers per-fingerprint
-- lookups on the bridge socket (GET /nginx/fppolicy). This module asks that
-- question ONCE per distinct fingerprint per cache window and caches the
-- answer in the shared dict, so the per-request cost on the hot path is one
-- dict get.
--
-- WHY THE DAEMON ANSWERS INSTEAD OF MATCHING HERE
--
-- The policy list is keyed by the 8-hex fingerprint id, which is a sha256 of
-- the normalised handshake tuple computed by internal/tlsfp — the ONLY home of
-- that hash (repo rule: never keep a second copy that can drift). Porting the
-- hash to Lua would create exactly that second copy, so the edge sends the RAW
-- tuple (cfm_tlsfp.value()) and the daemon maps it to id + action.
--
-- WHY THE CACHE KEY STRIPS GREASE
--
-- Chrome-class stacks insert a RANDOM GREASE value into the offered ciphers
-- and curves on every connection (RFC 8701), and nginx renders it as 0x?a?a.
-- Keying the cache on the raw tuple would therefore miss on nearly every
-- request from the busiest real browsers and pay the RPC each time. The key
-- built here mirrors the daemon's id INPUT (version|proto|ciphers|curves|alpn,
-- GREASE-stripped) — but it is ONLY a cache key: if this normalisation ever
-- drifted from Go's, the cost is extra cache misses (more RPCs), never a wrong
-- verdict, because the daemon always parses the raw tuple itself.
--
-- FAIL-OPEN BY CONSTRUCTION: no fingerprint (plain HTTP), RPC error, daemon
-- down, dict full — every failure path answers "" (no action). A short
-- negative cache (ERR_TTL) bounds retry pressure during a daemon outage, and
-- the decision circuit breaker PROTECTS this kind too (a tripped breaker
-- fails the lookup fast instead of paying decision_timeout_ms per uncached
-- fingerprint on a hung daemon) while only decision outcomes trip/clear it —
-- see cfm_decision.lua breaker_should_skip/breaker_note.
-- Token-rotation note: unlike decision:get, this lookup has no 403-refresh
-- retry of its own; after a bridge-token rotation it fails open for at most
-- the decision path's ~10s token refresh plus ERR_TTL of cached negatives —
-- and the daemon's policy store is freshly-pulling at startup anyway.
--
-- ISOLATION: cache entries live in the DEDICATED cfm_fppolicy dict (falling
-- back to the caller-provided dict only on upgrade lag before the proxy
-- reloads the new conf). A client can mint a fresh cache key per connection
-- by offering rotating unknown cipher values (only GREASE is normalised
-- away), so fpp| keys must never share LRU space with the decision
-- clean-allow cache or the circuit-breaker state — the same churn lesson
-- that gave geo its own dict. The same minting also forces an RPC per new
-- key, so RPC_BUDGET caps lookups node-wide per second; over budget the
-- lookup fails open without caching (bounded work, no dict churn).

local cjson = require "cjson.safe"
local shd = require "cfm_shdict" -- counters: never dict:incr(key, n, init) (see cfm_shdict.lua)

local M = {}

-- Cache TTLs (seconds). The positive TTL is normally overridden by the ttl the
-- daemon returns (fpPolicyEdgeCacheTTL); the negative/error TTLs are local.
local DEFAULT_TTL = 30
local MISS_TTL    = 30  -- "no policy" answers — the common case, cache it too
local ERR_TTL     = 10  -- RPC failure — retry soon, but never per-request

-- RPC_BUDGET: max uncached lookups per second, node-wide. Real fleets see a
-- few hundred distinct fingerprints; steady state re-asks each once per TTL,
-- so a healthy node sits far under this. Sustained saturation means either a
-- key-minting client (which this bounds) or a much bigger fleet (raise it).
local RPC_BUDGET = 50

-- is_grease mirrors internal/tlsfp.isGREASE: a 6-char 0x?a?a token whose two
-- hex bytes are identical with low nibble 'a' (how nginx renders the RFC 8701
-- GREASE code points OpenSSL does not know).
local function is_grease(tok)
  if #tok ~= 6 then return false end
  local hi1, hi2 = tok:match("^0[xX](%x)[aA](%x)[aA]$")
  if not hi1 then return false end
  return hi1:lower() == hi2:lower()
end

-- strip_grease drops GREASE tokens from a colon-separated list, preserving
-- the client's offered order (the order is part of the fingerprint).
function M.strip_grease(list)
  if not list or list == "" or not list:find("0", 1, true) then return list or "" end
  local kept, found = {}, false
  for tok in list:gmatch("[^:]+") do
    if is_grease(tok) then found = true else kept[#kept + 1] = tok end
  end
  if not found then return list end
  return table.concat(kept, ":")
end

-- key_input reduces a raw cfm_tlsfp tuple to the daemon's id input
-- ("1|proto|ciphers|curves|alpn", GREASE-stripped) for use as a stable cache
-- key. nil when the tuple is absent/unversioned (plain HTTP, older edge).
function M.key_input(raw)
  if not raw or raw == "" then return nil end
  local f = {}
  -- Split on "|" keeping EMPTY fields (gmatch("[^|]+") would collapse them
  -- and shift positions — the fields are positional).
  local start = 1
  while true do
    local sep = raw:find("|", start, true)
    if not sep then f[#f + 1] = raw:sub(start); break end
    f[#f + 1] = raw:sub(start, sep - 1)
    start = sep + 1
  end
  if f[1] ~= "1" or not f[2] or f[2] == "" then return nil end
  return table.concat({ "1", f[2], M.strip_grease(f[3]), M.strip_grease(f[4]), f[5] or "" }, "|")
end

-- lookup answers (action, id) for the current request's fingerprint.
--   deps.raw  the raw cfm_tlsfp.value() tuple (nil on plain HTTP)
--   deps.sh   the shared dict for caching (nil degrades to per-request RPC)
--   deps.rpc  function(path) -> body|nil, err  (the bridge client, best-effort kind)
-- action is "" when nothing is armed or on any failure. Never raises when
-- called under the caller's pcall; internally defensive anyway.
function M.lookup(deps)
  local key_in = M.key_input(deps and deps.raw)
  if not key_in then return "", nil end

  local sh = deps.sh
  local ck = "fpp|" .. ngx.md5(key_in)

  if sh then
    local cached = sh:get(ck)
    if cached then
      -- "action|id" ("|" alone = cached no-policy answer)
      local sep = cached:find("|", 1, true)
      if sep then return cached:sub(1, sep - 1), cached:sub(sep + 1) end
      return "", nil
    end
  end

  -- Node-wide per-second budget on uncached lookups (see ISOLATION above).
  -- Over budget: fail open, cache nothing (a churning attacker must not be
  -- able to write either).
  if sh then
    local n = shd.incr(sh, "fpp|rpc_budget", 1, 1)
    if n and n > RPC_BUDGET then return "", nil end
  end

  local body, err = deps.rpc("/nginx/fppolicy?fp=" .. ngx.escape_uri(deps.raw))
  if not body then
    if sh then sh:set(ck, "|", ERR_TTL) end
    return "", nil
  end

  local obj = cjson.decode(body)
  if type(obj) ~= "table" then
    if sh then sh:set(ck, "|", ERR_TTL) end
    return "", nil
  end

  local action = type(obj.action) == "string" and obj.action or ""
  local id     = type(obj.id) == "string" and obj.id or ""
  -- ttl <= 0 must never reach sh:set: exptime 0 means NEVER-expire in
  -- ngx.shared, which would pin a stale action until LRU/restart and swallow
  -- a central disarm.
  local ttl = tonumber(obj.ttl) or DEFAULT_TTL
  if ttl <= 0 then ttl = DEFAULT_TTL end
  if action == "" then ttl = math.min(ttl, MISS_TTL) end
  if sh then sh:set(ck, action .. "|" .. id, ttl) end
  return action, id ~= "" and id or nil
end

return M

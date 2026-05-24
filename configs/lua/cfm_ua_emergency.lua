-- /var/lib/cfm/lua/cfm_ua_emergency.lua (CFM-managed canonical location)
--
-- Box-wide UA emergency rule reader for cfm.lua.
--
-- The Go side (cfm/internal/webdetector/ua_emergency.go) writes its rule
-- set as JSON to /var/lib/cfm/ua_emergency.json on every Set/Delete and
-- on every TTL expiry. This module re-reads that file lazily inside each
-- worker (no timer, no shdict) and answers check(ua_raw) in O(1).
--
-- Lazy refresh:
--   * Per request we check ngx.now() against _last_refresh_at. If the
--     delta is below REFRESH_INTERVAL_SEC, no work is done.
--   * Otherwise we stat the file (mtime via io.open + content read) and
--     re-parse only if the on-disk content differs. The file is small
--     (handful of rules); the read itself is cheap.
--
-- Per-worker state: each nginx worker has its own _rules table, populated
-- independently. Convergence latency = REFRESH_INTERVAL_SEC across the
-- pool, which is acceptable for an operator-driven emergency surface.

local _M = {}

local cjson = require "cjson.safe"

local PATH = "/var/lib/cfm/ua_emergency.json"
local REFRESH_INTERVAL_SEC = 3

local _last_refresh_at = 0
local _last_content = ""
local _rules = {}  -- normalized UA → { action, expires_at_unix, reason, created_by }

-- Bot markers — keep aligned with internal/webdetector/ua_norm.go.
local _BOT_MARKERS = {
  "bot", "spider", "crawl", "agent", "fetch", "externalhit",
  "scrap", "preview", "embed", "monitor", "checker",
}

local function has_bot_marker(tok)
  for _, m in ipairs(_BOT_MARKERS) do
    if string.find(tok, m, 1, true) then
      return true
    end
  end
  return false
end

-- first_token returns the substring of `s` up to the first /, ;, space,
-- tab or '('. Mirrors firstUAToken in ua_norm.go.
local function first_token(s)
  if not s or s == "" then return "" end
  local m = string.match(s, "^([^/;%s%(]+)")
  return m or ""
end

-- normalize_ua mirrors NormalizeUA in ua_norm.go exactly.
function _M.normalize_ua(ua)
  if not ua then return "-" end
  ua = string.gsub(ua, "^%s+", "")
  ua = string.gsub(ua, "%s+$", "")
  if ua == "" or ua == "-" then return "-" end
  ua = string.lower(ua)

  local head = first_token(ua)
  if head == "" then return "-" end
  if head ~= "mozilla" then return head end

  -- Mozilla envelope: scan inside the first "(...)".
  local lp = string.find(ua, "(", 1, true)
  if not lp then return "mozilla" end
  local rp = string.find(ua, ")", lp, true)
  if not rp or rp <= lp then return "mozilla" end
  local inner = string.sub(ua, lp + 1, rp - 1)

  for part in string.gmatch(inner, "[^;,]+") do
    part = string.gsub(part, "^%s+", "")
    part = string.gsub(part, "%s+$", "")
    local tok = first_token(part)
    if tok ~= "" and has_bot_marker(tok) then
      return tok
    end
  end
  return "mozilla"
end

local function refresh_if_needed()
  local now = ngx.now()
  if (now - _last_refresh_at) < REFRESH_INTERVAL_SEC then
    return
  end
  _last_refresh_at = now

  local f = io.open(PATH, "r")
  if not f then
    -- File missing → treat as no rules. Drop our cache.
    if _last_content ~= "" then
      _last_content = ""
      _rules = {}
    end
    return
  end
  local content = f:read("*a")
  f:close()

  if not content then
    return
  end
  if content == _last_content then
    return  -- unchanged, keep parsed table
  end
  _last_content = content

  if content == "" then
    _rules = {}
    return
  end

  local parsed = cjson.decode(content)
  if type(parsed) ~= "table" then
    return  -- leave previous rules in place on parse error
  end

  local new_rules = {}
  local now_unix = ngx.time()
  for i = 1, #parsed do
    local r = parsed[i]
    if type(r) == "table" and type(r.ua) == "string" and type(r.action) == "string" then
      local exp = tonumber(r.expires_at_unix) or 0
      if exp > now_unix then
        new_rules[r.ua] = {
          action       = r.action,
          expires_at   = exp,
          reason       = r.reason or "",
          created_by   = r.created_by or "",
        }
      end
    end
  end
  _rules = new_rules
end

-- check returns { action = "block"|"throttle"|"allow", expires_at = unix, ... }
-- if an emergency rule matches the given raw UA, or nil otherwise. Callers
-- should pass ngx.var.http_user_agent directly.
function _M.check(ua_raw)
  refresh_if_needed()
  local nu = _M.normalize_ua(ua_raw)
  if nu == "" or nu == "-" then return nil end
  local r = _rules[nu]
  if not r then return nil end
  -- Defensive expiry check between refreshes.
  if r.expires_at and r.expires_at < ngx.time() then
    return nil
  end
  -- Return a snapshot with the matched normalized UA for logging.
  return {
    ua         = nu,
    action     = r.action,
    expires_at = r.expires_at,
    reason     = r.reason,
    created_by = r.created_by,
  }
end

-- count returns the number of active rules currently loaded. Useful for
-- test / debug only.
function _M.count()
  refresh_if_needed()
  local n = 0
  for _ in pairs(_rules) do n = n + 1 end
  return n
end

-- ── Box-wide UA throttle ────────────────────────────────────────────────────
--
-- The throttle action is enforced via a token bucket keyed on the normalized
-- UA only (no host, no IP). One bucket per UA across the whole box, which is
-- what the operator wants: "FB hitting 100 vhosts at 5 r/s each = 500 r/s
-- aggregate; cap it at 10 r/s box-wide."
--
-- We reuse the cfm_decisions shdict that cfm_rules already relies on, so no
-- new shared_dict declaration is needed in the nginx config.

local BOX_RATE  = 10.0  -- tokens/sec
local BOX_BURST = 20.0

local _SH = ngx.shared.cfm_decisions

-- throttle returns (hit, retry_after_seconds). When hit==true the caller
-- should reject the request (typically with 429). When hit==false the
-- request consumed a token and should proceed normally.
function _M.throttle(normalized_ua)
  if not _SH or not normalized_ua or normalized_ua == "" or normalized_ua == "-" then
    return false, 0
  end

  local key      = "ua_emerg|" .. normalized_ua
  local lock_key = key .. ":lock"
  local now      = ngx.now()

  -- Brief lock to avoid two workers racing the same token bucket.
  local locked = false
  for _ = 1, 10 do
    if _SH:add(lock_key, true, 0.05) then
      locked = true
      break
    end
    ngx.sleep(0.001)
  end
  if not locked then
    return true, 0.05
  end

  local state = _SH:get(key)
  local tokens, last
  if state then
    local t, ts = string.match(tostring(state), "^([^:]+):([^:]+)$")
    tokens = tonumber(t)
    last   = tonumber(ts)
  end
  if not tokens then tokens = BOX_BURST end
  if not last   then last   = now end

  local elapsed = now - last
  if elapsed < 0 then elapsed = 0 end
  tokens = math.min(BOX_BURST, tokens + elapsed * BOX_RATE)

  local allow = tokens >= 1
  local retry_after = 0
  if allow then
    tokens = tokens - 1
  else
    local need = 1 - tokens
    retry_after = (need > 0) and (need / BOX_RATE) or 1
  end

  local ttl = math.max(2, math.floor((BOX_BURST / BOX_RATE) * 2))
  _SH:set(key, tostring(tokens) .. ":" .. tostring(now), ttl)
  _SH:delete(lock_key)

  return (not allow), retry_after
end

return _M

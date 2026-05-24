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

-- Optional config file. Operators ship this to flip behavior knobs
-- without editing the module. Matches the cfm_bridge_config.lua pattern
-- (see cfm.lua). The file must return a table; missing file = defaults.
--
-- Supported keys:
--   fail_closed = true|false   when an inner error or lock-contention
--                              edge fires, fail-closed returns 429 with
--                              an integer Retry-After. Default false
--                              (fail-open) so transient cfm bugs can't
--                              black out legitimate traffic.
local _CFG_FILE = "/var/lib/cfm/lua/cfm_ua_emergency_config.lua"
local _cfg = { fail_closed = false }
do
  local chunk = loadfile(_CFG_FILE)
  if chunk then
    local ok, val = pcall(chunk)
    if ok and type(val) == "table" then
      if val.fail_closed ~= nil then
        _cfg.fail_closed = (val.fail_closed == true)
      end
    else
      ngx.log(ngx.WARN, "[cfm_ua_emergency] config file did not return a table: ", _CFG_FILE)
    end
  end
end
local FAIL_CLOSED = _cfg.fail_closed

local _last_refresh_at = 0
local _last_content = ""
local _last_bad_content = ""  -- last content that failed to parse/validate (log de-spam)
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
-- tab or '('. Mirrors firstUAToken in ua_norm.go *exactly* — note the
-- character class uses a literal space and tab, NOT %s, because Lua's
-- %s also matches \n \r \v \f while Go's firstUAToken breaks only on
-- space/tab. A UA like "Foo\nBot/1.0" must normalize to the same key on
-- both sides; using %s here would silently desync the two normalizers.
local function first_token(s)
  if not s or s == "" then return "" end
  local m = string.match(s, "^([^/;%( \t]+)")
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

  if content == "" then
    _last_content = content
    _rules = {}
    return
  end

  -- Helper: log once per distinct bad-content snapshot, then suppress.
  -- We don't cache into _last_content because that would short-circuit
  -- recovery once the operator fixes the file. Instead, _last_bad_content
  -- gates the log line so a single typo doesn't spam ERR every 3 seconds
  -- across every worker forever.
  local function note_bad_content(level, msg)
    if content ~= _last_bad_content then
      ngx.log(level, msg)
      _last_bad_content = content
    end
  end

  local parsed = cjson.decode(content)
  if parsed == nil then
    -- Parse error or literal "null". Keep previous rules (fail-static);
    -- log only on first observation of this bad snapshot.
    note_bad_content(ngx.WARN,
      "[cfm_ua_emergency] decode returned nil for " .. PATH .. " — keeping previous rules")
    return
  end
  if type(parsed) ~= "table" then
    -- Structurally valid JSON but not the expected array shape (number,
    -- string, boolean). Keep the previous in-memory ruleset (fail-static).
    -- A typo like `echo 42 > /var/lib/cfm/ua_emergency.json` must not
    -- wipe live emergency rules out from under operators.
    note_bad_content(ngx.ERR,
      "[cfm_ua_emergency] non-array content in " .. PATH ..
      " (type=" .. type(parsed) .. ") — keeping previous rules")
    return
  end
  -- Reaching here means we have a valid parse. Any prior bad-content
  -- guard is now stale; reset so a future bad write logs once again.
  _last_bad_content = ""

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
  _last_content = content  -- commit cache only after successful parse
end

-- check returns { action = "block"|"throttle", expires_at = unix, ... }
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
--
-- The token-bucket update is wrapped in pcall so any runtime error
-- between acquiring and releasing the shdict lock still drops the lock,
-- otherwise the 50ms TTL would stall every other worker hitting the same
-- UA. Lua has no defer; pcall is the canonical pattern.
local function _throttle_inner(key, now)
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
  local ok_set, err_set, forcible = _SH:set(key, tostring(tokens) .. ":" .. tostring(now), ttl)
  if not ok_set then
    -- shdict full and forcible eviction failed; bucket state isn't
    -- persisted. Next request will read nil and reset to a full bucket,
    -- effectively disabling the throttle. Rate-limit the log so a
    -- saturated shdict can't turn into a logging outage.
    if _SH:add("ua_emerg|_set_fail_logged", true, 60) then
      ngx.log(ngx.ERR, "[cfm_ua_emergency] shdict :set failed (rate-limited 60s) key=", key,
        " err=", tostring(err_set), " — throttle may be ineffective")
    end
  elseif forcible then
    -- Stored, but evicted some other key. Rate-limit identically —
    -- forcible is normal under LRU pressure and should not page.
    if _SH:add("ua_emerg|_set_forcible_logged", true, 60) then
      ngx.log(ngx.WARN, "[cfm_ua_emergency] shdict :set forced eviction (rate-limited 60s) key=", key)
    end
  end
  return allow, retry_after
end

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
    -- Lock contention is a workload signal (many workers hitting the same
    -- UA at once), not an internal error. The right response is brief
    -- backpressure — give the lock a moment to clear — regardless of the
    -- FAIL_CLOSED knob, which governs internal-error policy. Admitting
    -- unconditionally here would defeat the throttle on exactly the
    -- bot-wave conditions it exists for; closing for a full second is too
    -- aggressive for a routine contention edge. 50ms is enough to let the
    -- previous lock holder finish (the lock itself has a 50ms TTL).
    return true, 0.05
  end

  -- pcall ensures _SH:delete runs even if _throttle_inner raises.
  local ok, allow_or_err, retry_after = pcall(_throttle_inner, key, now)
  _SH:delete(lock_key)

  if not ok then
    -- Internal error. Default policy is fail-open (return false, 0 ->
    -- admit the request) so a transient bug can't black out legitimate
    -- traffic. Operators who would rather 429 than risk silent
    -- under-enforcement can set fail_closed=true in
    -- /var/lib/cfm/lua/cfm_ua_emergency_config.lua (see top of file).
    --
    -- Return an INTEGER retry_after: the caller serialises it into an
    -- HTTP Retry-After header, which is integer-seconds per RFC 7231 —
    -- a fractional value floors to 0 and tells the client to retry
    -- immediately, defeating the fail-closed intent entirely.
    ngx.log(ngx.ERR, "[cfm_ua_emergency] throttle inner error: ", tostring(allow_or_err),
      " fail_closed=", tostring(FAIL_CLOSED))
    if FAIL_CLOSED then
      return true, 1
    end
    return false, 0
  end
  return (not allow_or_err), (retry_after or 0)
end

return _M

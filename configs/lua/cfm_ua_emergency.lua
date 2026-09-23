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
--   * Otherwise we re-read the file and re-parse only if the on-disk CONTENT
--     differs (a full read + string-compare — NOT an mtime stat; Lua has no
--     stat without lfs). The file is small (a handful of rules).
--   * The read is kept off the request's access phase: the first load per worker
--     is synchronous (so the very first request sees any rules), and every later
--     refresh runs in a background ngx.timer.at(0) (the cfm_h3 pattern) while we
--     serve the current in-memory rules. The one request that crosses the interval
--     boundary serves under the pre-refresh ruleset (that is the point of the
--     fix) — safe here because rule propagation is operator-driven and already
--     tolerated multi-second lag, and expiries are enforced per-request in check()
--     independently of the refresh. Convergence latency is ~REFRESH_INTERVAL_SEC
--     plus the timer's dispatch delay (bounded, self-healing — not an exact bound).
--
-- Per-worker state: each nginx worker has its own _rules table, populated
-- independently. Convergence latency is ~REFRESH_INTERVAL_SEC across the
-- pool, which is acceptable for an operator-driven emergency surface.

local _M = {}

local cjson = require "cjson.safe"
local shd = require "cfm_shdict" -- counters: never dict:incr(key, n, init) (see cfm_shdict.lua)

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
local _refresh_in_progress = false  -- dedupes the async refresh timer (F48)

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

-- Read + parse the rule file, updating _rules / _last_content. No timing logic:
-- callers own _last_refresh_at. Runs synchronously on cold start, and inside the
-- async refresh timer thereafter (F48). Content-compare (NOT mtime) short-circuits
-- when the file is unchanged.
local function do_refresh()
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

-- Called on every request from check(). The FIRST load per worker is synchronous
-- so the very first request is checked against any emergency rules; every LATER
-- refresh is scheduled off the request path via ngx.timer.at(0) (the cfm_h3
-- pattern), so the periodic file read no longer blocks the access phase. We keep
-- serving the current in-memory rules meanwhile (the boundary request serves the
-- pre-refresh ruleset); convergence latency is ~REFRESH_INTERVAL_SEC plus timer
-- dispatch delay across the worker pool. F48.
local function refresh_if_needed()
  local now = ngx.now()
  if (now - _last_refresh_at) < REFRESH_INTERVAL_SEC then
    return
  end

  if _last_refresh_at == 0 then
    -- Cold start: load synchronously (a one-time per-worker cost).
    _last_refresh_at = now
    do_refresh()
    return
  end

  -- Steady state: refresh in the background. The dedupe flag keeps concurrent
  -- requests in this worker from stacking timers.
  if _refresh_in_progress then return end
  _refresh_in_progress = true
  local ok, terr = ngx.timer.at(0, function(premature)
    -- Clear the flag even if the body raises, or the worker would never refresh
    -- again until restart. Advance _last_refresh_at BEFORE the read so a failing
    -- read doesn't retry on every request.
    local pok, perr = pcall(function()
      if premature then return end
      _last_refresh_at = ngx.now()
      do_refresh()
    end)
    _refresh_in_progress = false
    if not pok then
      ngx.log(ngx.ERR, "[cfm_ua_emergency] refresh handler raised: ", tostring(perr))
    end
  end)
  if not ok then
    _refresh_in_progress = false
    ngx.log(ngx.WARN, "[cfm_ua_emergency] could not schedule refresh timer: ", tostring(terr))
  end
end

-- check returns { action = "block"|"throttle", expires_at = unix, ... }
-- if an emergency rule matches the given raw UA, or nil otherwise. Callers
-- should pass ngx.var.http_user_agent directly.
--
-- Fast path on idle boxes: if _rules is empty after refresh, we skip
-- normalize_ua() entirely. This makes the per-request cost a single
-- next(_rules) call (a C builtin returning nil immediately) when no
-- emergency rules are installed — paired with the Go-side HasActive()
-- gate in the ingest path, the feature has effectively zero overhead
-- when not in use.
function _M.check(ua_raw)
  refresh_if_needed()
  if next(_rules) == nil then return nil end
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
-- The throttle action caps request rate per normalized UA (no host, no IP) —
-- one budget per UA across the whole box, which is what the operator wants:
-- "FB hitting 100 vhosts at 5 r/s each = 500 r/s aggregate; cap it at 10 r/s
-- box-wide."
--
-- Implemented as a LOCK-FREE fixed-window counter (audit F22): each request does
-- ONE atomic shdict:incr (a window's first hit also an add, via cfm_shdict) —
-- no per-UA spin-lock, no read-modify-write, no get/set/delete. This matters precisely under the bot wave the throttle exists
-- for: thousands of req/s of the SAME UA previously thundered on one per-UA 50ms
-- lock (each loser spinning up to 10x ngx.sleep(1ms)) and did ~3-4 shdict writes
-- per request. One incr replaces all of it.
--
-- The counter lives in its OWN dict (cfm_ua_throttle), NOT cfm_decisions, so the
-- throttle's writes never contend with the decision cache and abuse counters
-- that share cfm_decisions — same isolation rationale as the geo cache (F25),
-- and it means this hot-under-attack path can't slow unrelated lookups.
--
-- Window/limit preserve the old token bucket's intent: LIMIT requests per WINDOW
-- seconds == BOX_RATE long-run (10/s) with a BOX_BURST head (20 in one window).
-- A fixed window can admit up to ~2x LIMIT across a window boundary; for a coarse
-- emergency cap that is acceptable. The key embeds the window index, so each
-- window is a fresh key that self-expires via the TTL it is created with (no scan/delete),
-- bounding live keys to ~2 per UA.
local BOX_RATE  = 10.0                              -- requests/sec, long-run
local BOX_BURST = 20                                -- requests allowed within one window
-- WINDOW/LIMIT are DERIVED so LIMIT/WINDOW == BOX_RATE. NB: that invariant only
-- holds while BOX_BURST is an integer multiple of BOX_RATE (true for 20/10 = 2s).
-- If these ever become tunable, compute WINDOW to preserve the long-run rate
-- rather than flooring the ratio (e.g. RATE=10,BURST=15 would floor to WINDOW=1
-- and silently cap at 15/s).
local WINDOW    = math.max(1, math.floor(BOX_BURST / BOX_RATE))  -- seconds (20/10 = 2)
local LIMIT     = BOX_BURST                         -- max requests per window

local _SH = ngx.shared.cfm_ua_throttle
-- One-shot per-worker guard: a missing dict disables the throttle, so warn once
-- (see the _SH-nil branch in throttle). _SH is bound at module load and never
-- changes for the worker's life, so once is the right cadence.
local _dict_missing_warned = false

-- throttle returns (hit, retry_after_seconds). When hit==true the caller should
-- reject the request (typically with 429). When hit==false the request is within
-- the window budget and should proceed. retry_after is returned as an integer
-- (>=1) on a hit: the caller serialises it into an HTTP Retry-After header, which
-- is integer-seconds per RFC 7231 — a fractional value floors to 0 ("retry now")
-- and defeats the throttle.
function _M.throttle(normalized_ua)
  if not _SH then
    -- The dedicated dict is not declared — e.g. a hand-edited live /etc/cfm nginx
    -- conf that didn't pick up the new `lua_shared_dict cfm_ua_throttle` line on
    -- upgrade. Fail OPEN (a missing dict must never black out traffic), but this
    -- silently DISABLES the emergency throttle while `block` rules keep working,
    -- so surface it once per worker rather than no-op quietly.
    if not _dict_missing_warned then
      _dict_missing_warned = true
      ngx.log(ngx.ERR, "[cfm_ua_emergency] shared dict 'cfm_ua_throttle' is not declared — ",
        "UA emergency throttle is DISABLED; add `lua_shared_dict cfm_ua_throttle 4m;` to the nginx http block")
    end
    return false, 0
  end
  if not normalized_ua or normalized_ua == "" or normalized_ua == "-" then
    return false, 0
  end

  local now = ngx.now()
  local win = math.floor(now / WINDOW)
  local key = "ua_emerg|" .. normalized_ua .. "|" .. win

  -- Atomic increments: no lock, no read-modify-write. A fresh window key
  -- starts at 1; its TTL (2x the window) is applied only when the key is
  -- created, so the key ages out on its own once the window has passed — no
  -- scan, no delete, ~2 live keys per UA (current + previous).
  local count, err = shd.incr(_SH, key, 1, WINDOW * 2)
  if not count then
    -- incr failed (shdict full and forcible eviction failed): the counter can't
    -- be maintained. Mirror the internal-error policy — fail-open by default so
    -- a saturated dict can't black out legitimate traffic; operators who would
    -- rather 429 can set fail_closed=true in
    -- /var/lib/cfm/lua/cfm_ua_emergency_config.lua (see top of file). Rate-limit
    -- the log so a saturated dict can't turn into a logging outage.
    if _SH:add("ua_emerg|_incr_fail_logged", true, 60) then
      ngx.log(ngx.ERR, "[cfm_ua_emergency] shdict :incr failed (rate-limited 60s) key=", key,
        " err=", tostring(err), " — throttle may be ineffective")
    end
    if FAIL_CLOSED then
      return true, 1
    end
    return false, 0
  end

  if count > LIMIT then
    -- Over budget for this window. retry_after = whole seconds until the window
    -- rolls (floored to >=1 so the integer Retry-After header stays meaningful).
    local retry = WINDOW - (now - win * WINDOW)
    if retry < 1 then retry = 1 end
    return true, math.ceil(retry)
  end

  return false, 0
end

return _M

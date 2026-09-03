-- cfm_pcw.lua — Track-2 Stage 1b/B2: post-clearance nav-cadence shadow counter.
--
-- PURE logic (no ngx / no os), so it unit-tests with a fake shared dict. cfm.lua
-- wires it at Step 2b (the clearance short-circuit): for a CLEARED client it
-- counts navigation requests per fixed window and, when a cleared client sustains
-- a human-implausible nav rate, tells cfm.lua to emit ONE `[cfm_pcw]` line per
-- (ip, verdict) per LOG_EVERY. It NEVER blocks / challenges / changes flow — pure
-- edge-local measurement of the "solved the challenge, now scraping page after
-- page" class, which the in-path decision path cannot act on (Step 2b skips the
-- /nginx/decision RPC). Read the lines via edge_error_tail. Docs:
-- docs/challenge-score-b2.md, docs/challenge-score.md.
--
-- Why cadence, NOT the plan's original "no-asset silence": static assets bypass
-- cfm.lua entirely (the static-asset location's `access_by_lua_block { return; }`),
-- so asset fetches are invisible here and every real browser would look "silent";
-- browser caching breaks it further. Nav cadence is cache-immune and fully
-- observable. (docs/challenge-score-b2.md §2.)

local _M = { _VERSION = "1" }

-- Burn-in STARTING constants (tune from the [cfm_pcw] lines; NOT config knobs).
local WINDOW_SEC = 60   -- fixed rate window
local T1         = 30   -- navs in one window → would_harden (a page every 2s, sustained)
local T2         = 60   -- navs in one window → would_deny  (a page every 1s)
local LOG_EVERY  = 300  -- re-log one (ip, verdict) at most this often

-- is_nav: a top-level page navigation — GET|HEAD asking for text/html. That is
-- what a page-scraper pulls; JSON/API AJAX (Accept: application/json) and static
-- assets (which bypass cfm.lua anyway) are excluded, so genuine in-app activity
-- never inflates the count.
local function is_nav(method, accept)
  method = string.lower(method or "")
  if method ~= "get" and method ~= "head" then return false end
  accept = string.lower(accept or "")
  return accept:find("text/html", 1, true) ~= nil
end

-- verdict maps a per-window nav count to its shadow verdict ("" below T1 → nil).
local function verdict(n)
  if n >= T2 then return "would_deny" end
  if n >= T1 then return "would_harden" end
  return nil
end

-- observe folds one CLEARED request into the per-IP nav-cadence window and returns
-- (verdict, navs) ONLY when a `[cfm_pcw]` line is DUE (a threshold crossed AND the
-- (ip, verdict) throttle allows it), else nil. Pure side-effects on `dict` (an
-- ngx.shared-like object exposing :incr/:get/:set); it never throws and never
-- affects request flow. cfm.lua does the logging (no per-request closure).
function _M.observe(dict, ip, method, accept)
  if not dict or not ip or ip == "" then return nil end
  if not is_nav(method, accept) then return nil end
  -- Fixed-window nav counter. incr initialises to 0 (+1) with a WINDOW_SEC TTL on
  -- the first nav; the TTL is NOT refreshed by later incrs, so the window resets
  -- WINDOW_SEC after its first nav — a true fixed window, self-cleaning.
  local n = dict:incr("pcw|c|" .. ip, 1, 0, WINDOW_SEC)
  if not n then return nil end -- dict full / error → skip silently (never throw)
  local v = verdict(n)
  if not v then return nil end
  -- Per-(ip, verdict) log throttle, bounded by its own TTL (no unbounded map). The
  -- two tiers throttle independently, so an escalation (harden → deny) still logs
  -- the deny line even though a harden line was just emitted.
  local lkey = "pcw|l|" .. ip .. "|" .. v
  if dict:get(lkey) then return nil end -- logged recently → nothing due
  dict:set(lkey, 1, LOG_EVERY)
  return v, n
end

-- Exposed for tests / the caller's log line.
_M.is_nav  = is_nav
_M.verdict = verdict
_M.WINDOW_SEC, _M.T1, _M.T2, _M.LOG_EVERY = WINDOW_SEC, T1, T2, LOG_EVERY
return _M

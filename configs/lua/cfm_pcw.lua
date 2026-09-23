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
local shd = require "cfm_shdict" -- counters: never dict:incr(key, n, init) (see cfm_shdict.lua)

-- Burn-in STARTING constants (tune from the [cfm_pcw] lines; NOT config knobs).
local WINDOW_SEC = 60   -- fixed rate window
local T1         = 30   -- navs in one window → would_harden (a page every 2s, sustained)
local T2         = 60   -- navs in one window → would_deny  (a page every 1s)
local LOG_EVERY  = 300  -- re-log one (ip, verdict) at most this often

-- is_nav: a TOP-LEVEL page navigation. That is what a page-scraper pulls; it must
-- NOT count sub-resources or speculative loads that inflate one page view into
-- many:
--   * GET|HEAD only.
--   * Prefetch / prerender speculation (Sec-Purpose / Purpose: prefetch) is not a
--     user navigation — skip it.
--   * When Sec-Fetch-Dest is present (a modern browser), require `document` — this
--     excludes same-origin iframes/embeds/objects and every asset dest.
--   * When Sec-Fetch-Dest is ABSENT (older browsers, and the headless automation
--     we most want to measure — it ships no Sec-Fetch), fall back to Accept:
--     text/html. JSON/API AJAX (Accept: application/json) and static assets (which
--     bypass cfm.lua anyway) are still excluded.
-- KNOWN BLIND SPOT: a scraper that pulls page HTML via fetch()/XHR sends
-- Sec-Fetch-Dest: empty (or a non-text/html Accept), so it is NOT counted. This
-- signal only catches FULL-NAVIGATION scraping; a signal-aware farm can dodge by
-- fetching pages as sub-resources. Acceptable for a log-only burn-in — the intent
-- is to size the naive-navigation cadence, not to be evasion-proof.
local function is_nav(method, accept, dest, purpose)
  method = string.lower(method or "")
  if method ~= "get" and method ~= "head" then return false end
  purpose = string.lower(purpose or "")
  if purpose:find("prefetch", 1, true) or purpose:find("prerender", 1, true) then
    return false
  end
  dest = string.lower(dest or "")
  if dest ~= "" then
    return dest == "document"
  end
  accept = string.lower(accept or "")
  return accept:find("text/html", 1, true) ~= nil
end

-- verdict maps a per-window nav count to its shadow verdict ("" below T1 → nil).
local function verdict(n)
  if n >= T2 then return "would_deny" end
  if n >= T1 then return "would_harden" end
  return nil
end

-- observe folds one CLEARED request into a nav-cadence window and returns
-- (verdict, navs) ONLY when a `[cfm_pcw]` line is DUE (a threshold crossed AND the
-- throttle allows it), else nil. Pure side-effects on `dict` (an ngx.shared-like
-- object exposing :incr/:get/:set); it never throws and never affects request
-- flow. cfm.lua does the logging (no per-request closure).
--
-- `keyid` is the CLEARED-IDENTITY key the caller passes — `ip|host|scope`, the
-- same grain clearance itself is minted at (the cookie is HMAC(ip,host,scope)). So
-- this is a per-IP-per-host counter, NOT per-browser: the clearance cookie is not a
-- per-browser identity, so a shared egress (CGNAT / office NAT) where many real
-- users are cleared for the SAME host still pools into one counter — a known FP
-- class this shadow measures and that B3 must handle NAT-aware before it ever gates
-- traffic (docs/challenge-score-b2.md §6). Keying by host (not IP alone) at least
-- stops cross-host aggregation and matches the "one client hammering one host"
-- scraper shape.
function _M.observe(dict, keyid, method, accept, dest, purpose)
  if not dict or not keyid or keyid == "" then return nil end
  if not is_nav(method, accept, dest, purpose) then return nil end
  -- Fixed-window nav counter. The first nav creates it at 1 with a WINDOW_SEC
  -- TTL; the TTL is NOT refreshed by later incrs, so the window resets
  -- WINDOW_SEC after its first nav — a true fixed window, self-cleaning.
  local n = shd.incr(dict, "pcw|c|" .. keyid, 1, WINDOW_SEC)
  if not n then return nil end -- dict full / error → skip silently (never throw)
  local v = verdict(n)
  if not v then return nil end
  -- Per-(keyid, verdict) log throttle, bounded by its own TTL (no unbounded map).
  -- The two tiers throttle independently, so an escalation (harden → deny) still
  -- logs the deny line even though a harden line was just emitted.
  local lkey = "pcw|l|" .. keyid .. "|" .. v
  if dict:get(lkey) then return nil end -- logged recently → nothing due
  dict:set(lkey, 1, LOG_EVERY)
  return v, n
end

-- Exposed for tests / the caller's log line.
_M.is_nav  = is_nav
_M.verdict = verdict
_M.WINDOW_SEC, _M.T1, _M.T2, _M.LOG_EVERY = WINDOW_SEC, T1, T2, LOG_EVERY
return _M

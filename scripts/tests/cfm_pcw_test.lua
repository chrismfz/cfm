-- Tests for cfm_pcw.lua — Track-2 B2 post-clearance nav-cadence shadow counter.
-- Pure logic: no ngx needed. A fake ngx.shared dict honours TTL against a manual
-- clock so the fixed-window and throttle behaviour is deterministic.

package.path = "configs/lua/?.lua;" .. package.path
local pcw = require("cfm_pcw")

local fails = 0
local function check(c, m)
  if c then return end
  fails = fails + 1
  io.stderr:write("FAIL: " .. m .. "\n")
end

-- Fake ngx.shared dict: :incr/:get/:set with TTL expiry against clk.t.
local function new_dict()
  local store, clk = {}, { t = 0 }
  local function live(k)
    local e = store[k]
    if not e then return nil end
    if e.exp and e.exp <= clk.t then store[k] = nil; return nil end
    return e
  end
  local d = {}
  function d:incr(k, v, init, ttl)
    local e = live(k)
    if not e then
      store[k] = { val = (init or 0) + v, exp = ttl and (clk.t + ttl) or nil }
      return store[k].val
    end
    e.val = e.val + v
    return e.val
  end
  function d:get(k) local e = live(k); return e and e.val or nil end
  function d:set(k, v, ttl) store[k] = { val = v, exp = ttl and (clk.t + ttl) or nil } end
  return d, clk
end

-- ── is_nav ───────────────────────────────────────────────────────────────────
check(pcw.is_nav("GET", "text/html,application/xhtml+xml"), "GET text/html is a nav")
check(pcw.is_nav("HEAD", "text/html"), "HEAD text/html is a nav")
check(not pcw.is_nav("POST", "text/html"), "POST is not a nav")
check(not pcw.is_nav("GET", "application/json"), "GET json (AJAX) is not a nav")
check(not pcw.is_nav("GET", ""), "GET with no Accept is not a nav")
check(not pcw.is_nav("GET", nil), "GET nil Accept is not a nav")

-- ── verdict ──────────────────────────────────────────────────────────────────
check(pcw.verdict(pcw.T1 - 1) == nil, "below T1 → no verdict")
check(pcw.verdict(pcw.T1) == "would_harden", "T1 → would_harden")
check(pcw.verdict(pcw.T2) == "would_deny", "T2 → would_deny")

-- ── observe: only navs count ─────────────────────────────────────────────────
do
  local d = new_dict()
  check(pcw.observe(d, "1.1.1.1", "POST", "text/html") == nil, "non-nav returns nil")
  check(d:get("pcw|c|1.1.1.1") == nil, "non-nav creates no counter")
  check(pcw.observe(nil, "1.1.1.1", "GET", "text/html") == nil, "nil dict → nil (never throws)")
  check(pcw.observe(d, "", "GET", "text/html") == nil, "empty ip → nil")
end

-- ── observe: crossing T1 is due once, then throttled within the window ────────
do
  local d = new_dict()
  for i = 1, pcw.T1 - 1 do
    check(pcw.observe(d, "2.2.2.2", "GET", "text/html") == nil, "below T1 not due (i=" .. i .. ")")
  end
  local v, n = pcw.observe(d, "2.2.2.2", "GET", "text/html") -- the T1-th nav
  check(v == "would_harden" and n == pcw.T1, "T1-th nav due would_harden (navs=" .. tostring(n) .. ")")
  check(pcw.observe(d, "2.2.2.2", "GET", "text/html") == nil, "second harden in-window is throttled")
  check(d:get("pcw|l|2.2.2.2|would_harden") ~= nil, "harden throttle key armed")
end

-- ── observe: escalation to would_deny logs on its own tier throttle ───────────
do
  local d = new_dict()
  for i = 1, pcw.T2 - 1 do pcw.observe(d, "3.3.3.3", "GET", "text/html") end
  local v = pcw.observe(d, "3.3.3.3", "GET", "text/html") -- the T2-th nav
  check(v == "would_deny", "T2-th nav due would_deny even though harden already fired")
end

-- ── observe: fixed window resets after WINDOW_SEC ─────────────────────────────
do
  local d, clk = new_dict()
  for _ = 1, pcw.T1 do pcw.observe(d, "4.4.4.4", "GET", "text/html") end
  check(d:get("pcw|c|4.4.4.4") == pcw.T1, "counter sits at T1 within the window")
  clk.t = pcw.WINDOW_SEC + 1
  check(d:get("pcw|c|4.4.4.4") == nil, "counter expires after WINDOW_SEC")
  check(pcw.observe(d, "4.4.4.4", "GET", "text/html") == nil, "fresh window starts at 1, below T1")
end

-- ── observe: log throttle releases after LOG_EVERY ───────────────────────────
do
  local d, clk = new_dict()
  for _ = 1, pcw.T1 - 1 do pcw.observe(d, "5.5.5.5", "GET", "text/html") end
  check(pcw.observe(d, "5.5.5.5", "GET", "text/html") == "would_harden", "first harden due")
  check(d:get("pcw|l|5.5.5.5|would_harden") ~= nil, "throttle key armed after logging")
  clk.t = pcw.LOG_EVERY + 1
  check(d:get("pcw|l|5.5.5.5|would_harden") == nil, "throttle key expires after LOG_EVERY")
end

-- ── observe: a full dict (incr returns nil) is handled without throwing ───────
do
  local full = { incr = function() return nil, "no memory" end, get = function() end, set = function() end }
  check(pcw.observe(full, "7.7.7.7", "GET", "text/html") == nil, "dict full (incr nil) → nil, no throw")
end

-- ── conf wiring: both edge confs declare the dict AND the env kill-switch ─────
for _, conf in ipairs({ "configs/openresty.conf", "configs/angie.conf" }) do
  local fh = assert(io.open(conf, "r"), "cannot open " .. conf)
  local src = fh:read("*a"); fh:close()
  check(src:find("lua_shared_dict%s+cfm_pcw%s") ~= nil, conf .. " declares lua_shared_dict cfm_pcw")
  check(src:find("env%s+CFM_PCW%s*;") ~= nil, conf .. " declares `env CFM_PCW;` (else the kill-switch is inert in workers)")
end

-- ── cfm_cfg kill-switch: default ON; CFM_PCW=0 disables ───────────────────────
do
  package.loaded["cfm_cfg"] = nil
  check(require("cfm_cfg").pcw_enabled == true, "pcw_enabled defaults ON when CFM_PCW unset")
  package.loaded["cfm_cfg"] = nil
  local real = os.getenv
  os.getenv = function(k) if k == "CFM_PCW" then return "0" end return real(k) end
  local ok, cfg2 = pcall(require, "cfm_cfg")
  os.getenv = real
  package.loaded["cfm_cfg"] = nil
  check(ok and cfg2.pcw_enabled == false, "CFM_PCW=0 disables pcw_enabled")
end

if fails > 0 then
  io.stderr:write(("cfm_pcw tests: %d FAILED\n"):format(fails))
  os.exit(1)
end
print("ok: cfm_pcw post-clearance nav-cadence shadow (Track-2 B2)")

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

-- Fake ngx.shared dict: :incr/:add/:get/:set with TTL expiry against clk.t,
-- with OpenResty's semantics: incr without init on a missing key is
-- "not found" (cfm_shdict then adds it with its TTL).
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
      if init == nil then return nil, "not found" end
      store[k] = { val = init + v, exp = ttl and (clk.t + ttl) or nil }
      return store[k].val
    end
    e.val = e.val + v
    return e.val
  end
  function d:add(k, v, ttl)
    if live(k) then return false, "exists" end
    store[k] = { val = v, exp = (ttl and ttl > 0) and (clk.t + ttl) or nil }
    return true
  end
  function d:get(k) local e = live(k); return e and e.val or nil end
  function d:set(k, v, ttl) store[k] = { val = v, exp = ttl and (clk.t + ttl) or nil } end
  return d, clk
end

-- Drive N navs for one keyid; return the last observe() result.
local function drive(d, keyid, n)
  local v, navs
  for _ = 1, n do v, navs = pcw.observe(d, keyid, "GET", "text/html") end
  return v, navs
end

-- ── is_nav: only a top-level document navigation counts ──────────────────────
check(pcw.is_nav("GET", "text/html,application/xhtml+xml"), "GET text/html (no Sec-Fetch) is a nav")
check(pcw.is_nav("HEAD", "text/html"), "HEAD text/html is a nav")
check(not pcw.is_nav("POST", "text/html"), "POST is not a nav")
check(not pcw.is_nav("GET", "application/json"), "GET json (AJAX) is not a nav")
check(not pcw.is_nav("GET", ""), "GET with no Accept and no Sec-Fetch is not a nav")
check(not pcw.is_nav("GET", nil), "GET nil Accept is not a nav")
-- Sec-Fetch-Dest present: only `document` counts (excludes iframe/embed/asset).
check(pcw.is_nav("GET", "text/html", "document"), "Sec-Fetch-Dest=document is a nav")
check(not pcw.is_nav("GET", "text/html", "iframe"), "Sec-Fetch-Dest=iframe is NOT a nav")
check(not pcw.is_nav("GET", "text/html", "embed"), "Sec-Fetch-Dest=embed is NOT a nav")
check(not pcw.is_nav("GET", "text/html", "image"), "Sec-Fetch-Dest=image is NOT a nav")
-- Prefetch / prerender speculation is never a user navigation.
check(not pcw.is_nav("GET", "text/html", "document", "prefetch"), "Purpose=prefetch is NOT a nav")
check(not pcw.is_nav("GET", "text/html", "document", "prefetch;prerender"), "Sec-Purpose prerender is NOT a nav")

-- ── verdict ──────────────────────────────────────────────────────────────────
check(pcw.verdict(pcw.T1 - 1) == nil, "below T1 → no verdict")
check(pcw.verdict(pcw.T1) == "would_harden", "T1 → would_harden")
check(pcw.verdict(pcw.T2) == "would_deny", "T2 → would_deny")

-- ── observe: only navs count; nil-safe ───────────────────────────────────────
do
  local d = new_dict()
  check(pcw.observe(d, "1.1.1.1|h|web", "POST", "text/html") == nil, "non-nav returns nil")
  check(d:get("pcw|c|1.1.1.1|h|web") == nil, "non-nav creates no counter")
  check(pcw.observe(nil, "1.1.1.1|h|web", "GET", "text/html") == nil, "nil dict → nil (never throws)")
  check(pcw.observe(d, "", "GET", "text/html") == nil, "empty keyid → nil")
end

-- ── observe: crossing T1 is due once, then throttled within the window ────────
do
  local d = new_dict()
  local key = "2.2.2.2|shop.gr|web"
  for i = 1, pcw.T1 - 1 do
    check(pcw.observe(d, key, "GET", "text/html") == nil, "below T1 not due (i=" .. i .. ")")
  end
  local v, n = pcw.observe(d, key, "GET", "text/html") -- the T1-th nav
  check(v == "would_harden" and n == pcw.T1, "T1-th nav due would_harden (navs=" .. tostring(n) .. ")")
  check(pcw.observe(d, key, "GET", "text/html") == nil, "second harden in-window is throttled")
  check(d:get("pcw|l|" .. key .. "|would_harden") ~= nil, "harden throttle key armed")
end

-- ── observe: escalation to would_deny logs on its own tier throttle ───────────
do
  local d = new_dict()
  local v = drive(d, "3.3.3.3|shop.gr|web", pcw.T2)
  check(v == "would_deny", "T2-th nav due would_deny even though harden already fired")
end

-- ── observe: per-(ip,host) keying — the SAME IP on a DIFFERENT host does NOT ──
--    pool (the fix for the CGNAT cross-host FP).
do
  local d = new_dict()
  drive(d, "9.9.9.9|hostA|web", pcw.T1) -- hostA reaches T1
  -- Same IP, hostB: a single nav must NOT inherit hostA's count.
  check(pcw.observe(d, "9.9.9.9|hostB|web", "GET", "text/html") == nil,
        "same IP, different host starts a fresh counter (no cross-host pooling)")
  check(d:get("pcw|c|9.9.9.9|hostB|web") == 1, "hostB counter is 1, independent of hostA")
end

-- ── observe: fixed window resets after WINDOW_SEC ─────────────────────────────
do
  local d, clk = new_dict()
  local key = "4.4.4.4|shop.gr|web"
  drive(d, key, pcw.T1)
  check(d:get("pcw|c|" .. key) == pcw.T1, "counter sits at T1 within the window")
  clk.t = pcw.WINDOW_SEC + 1
  check(d:get("pcw|c|" .. key) == nil, "counter expires after WINDOW_SEC")
  check(pcw.observe(d, key, "GET", "text/html") == nil, "fresh window starts at 1, below T1")
end

-- ── observe: throttle releases after LOG_EVERY → re-emits on a fresh window ───
do
  local d, clk = new_dict()
  local key = "5.5.5.5|shop.gr|web"
  check(drive(d, key, pcw.T1) == "would_harden", "first harden due")
  check(d:get("pcw|l|" .. key .. "|would_harden") ~= nil, "throttle key armed after logging")
  -- Advance past both the window and the log throttle, then re-drive a full window.
  clk.t = pcw.LOG_EVERY + 1
  check(d:get("pcw|l|" .. key .. "|would_harden") == nil, "throttle key expired after LOG_EVERY")
  check(drive(d, key, pcw.T1) == "would_harden", "re-emits would_harden on a fresh window after the throttle lapses")
end

-- ── observe: a full dict (incr returns nil) is handled without throwing ───────
do
  local full = { incr = function() return nil, "no memory" end, get = function() end, set = function() end }
  check(pcw.observe(full, "7.7.7.7|h|web", "GET", "text/html") == nil, "dict full (incr nil) → nil, no throw")
end

-- ── conf wiring: both edge confs declare the dict; the toggle is NO LONGER env ─
-- (it moved to the bridge config — [webdetector] POST_CLEARANCE_CADENCE).
local function slurp(p)
  local fh = assert(io.open(p, "r"), "cannot open " .. p)
  local s = fh:read("*a"); fh:close(); return s
end
for _, conf in ipairs({ "configs/openresty.conf", "configs/angie.conf" }) do
  local src = slurp(conf)
  check(src:find("lua_shared_dict%s+cfm_pcw%s") ~= nil, conf .. " declares lua_shared_dict cfm_pcw")
  check(src:find("env%s+CFM_PCW%s*;") == nil, conf .. " no longer declares `env CFM_PCW;` (toggle moved to config)")
end

-- ── config-driven toggle wiring: bridge-cfg exposes it, cfm.lua reads it, the
--    reference detectors.conf documents the [webdetector] key, and the env read
--    is gone from cfm_cfg.
check(slurp("configs/lua/cfm_bridge_cfg.lua"):find("post_clearance_cadence", 1, true) ~= nil,
      "cfm_bridge_cfg exposes post_clearance_cadence")
check(slurp("configs/lua/cfm.lua"):find("CFG.post_clearance_cadence", 1, true) ~= nil,
      "cfm.lua Step 2b gates on CFG.post_clearance_cadence")
check(slurp("configs/lua/cfm.lua"):find("CFG.pcw_enabled", 1, true) == nil,
      "cfm.lua no longer reads the removed CFG.pcw_enabled")
check(slurp("configs/lua/cfm_cfg.lua"):find("CFM_PCW", 1, true) == nil,
      "cfm_cfg no longer reads the CFM_PCW env var")
check(slurp("configs/detectors.conf"):find("POST_CLEARANCE_CADENCE", 1, true) ~= nil,
      "reference detectors.conf documents [webdetector] POST_CLEARANCE_CADENCE")

if fails > 0 then
  io.stderr:write(("cfm_pcw tests: %d FAILED\n"):format(fails))
  os.exit(1)
end
print("ok: cfm_pcw post-clearance nav-cadence shadow (Track-2 B2)")

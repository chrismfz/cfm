-- Tests for util.strip_sql_comments — the SQL-comment stripper run before the
-- SQLi detectors scan the (attacker-controlled) URI+args surface.
--
-- The block-comment removal used a `/%*.-%*/` gsub whose lazy `.-` was O(n^2)
-- on crafted input with many `/*` starts and no closing `*/` (e.g.
-- `?x=/*a/*a/*a...`): each unmatched `/*` re-scanned to end-of-string, then
-- gsub advanced a byte and repeated. Because this runs up to 3x/request across
-- the SQLi rules, it was a CPU-DoS amplifier (~5ms at the 2048 scan cap, ~5.4s
-- at a 64KB request line). The fix replaces it with a single-pass O(n) scan.
--
-- Two things must hold, and this file asserts both:
--   1. PARITY — the new scan is byte-for-byte identical to the old gsub for
--      every input (hand-picked edge cases + a deterministic fuzz corpus,
--      compared against a local copy of the ORIGINAL implementation).
--   2. LINEAR — a 64KB pathological input completes in well under a threshold
--      the old quadratic could never meet (regression guard: a revert to the
--      `.-` gsub takes seconds and trips the ceiling).

_G.ngx = {
  now           = function() return 1000 end,
  decode_base64 = function(_) return nil end,
  log           = function(_, _) end,
  ERR           = 0, WARN = 1, INFO = 2,
}

package.path = "configs/lua/?.lua;" .. package.path
local util = require("cfm_waf_util")
local strip = util.strip_sql_comments

-- The ORIGINAL implementation, verbatim — the parity oracle.
local function strip_orig(s)
  return (s:gsub("/%*.-%*/", ""):gsub("%-%-[^\n]*", ""))
end

local fails = 0
local function check(cond, msg)
  if cond then return end
  fails = fails + 1
  io.stderr:write("FAIL: " .. msg .. "\n")
end

local function eq(s, label)
  local got, want = strip(s), strip_orig(s)
  check(got == want,
    (label or "case") .. ": strip mismatch\n  in  = " .. string.format("%q", s) ..
    "\n  new = " .. string.format("%q", got) ..
    "\n  old = " .. string.format("%q", want))
end

-- ── 1) Hand-picked edge cases (parity with the original) ─────────────────────
eq("",                         "empty")
eq("no comments here",         "plain text")
eq("/**/",                     "empty block comment")
eq("/*A*/",                    "single block comment")
eq("a/*A*/b",                  "block comment between text")
eq("/*A*//*B*/",               "two adjacent block comments")
eq("/*A/*B*/C*/",              "nested-looking: shortest close, C*/ survives")
eq("/*/",                      "slash-star-slash: no valid close, verbatim")
eq("/*a/*a/*a",                "unterminated: three /* no close, verbatim")
eq("a/*a/*a/*a",               "unterminated with leading text")
eq("/*A*/B/*C",                "one closed then an unterminated /* ")
eq("un/**/ion se/**/lect",     "the keyword-splitting bypass this exists for")
eq("-- line comment\nkeep",    "line comment stripped to newline, rest kept")
eq("a-- c1\nb-- c2\nc",        "multiple line comments")
eq("/*x--y*/z",                "line-comment marker inside a block comment")
eq("--/*x*/",                  "block inside a line comment")
eq("val*/orphan",              "orphan close */ with no open, verbatim")
eq("/*unclosed -- with dashes","unterminated block containing dashes")
eq("select 1 -- ",            "trailing line comment, empty body")
eq("*/*/*/*/",                 "alternating close/open noise")

-- ── 2) Deterministic fuzz corpus (parity) ────────────────────────────────────
-- Alphabet biased toward the comment metacharacters so /*, */, -- and \n
-- actually form and interleave. Fixed seed → reproducible.
math.randomseed(20260712)
local alpha = { "/", "*", "-", "\n", " ", "a", "b", "c", "1" }
local NA = #alpha
local cases = 0
for _ = 1, 20000 do
  local n = math.random(0, 40)
  local t = {}
  for j = 1, n do t[j] = alpha[math.random(1, NA)] end
  local s = table.concat(t)
  cases = cases + 1
  local got, want = strip(s), strip_orig(s)
  if got ~= want then
    fails = fails + 1
    io.stderr:write("FUZZ FAIL: in=" .. string.format("%q", s) ..
      " new=" .. string.format("%q", got) ..
      " old=" .. string.format("%q", want) .. "\n")
    if fails > 5 then break end
  end
end

-- ── 3) Linearity / ReDoS regression guard ────────────────────────────────────
-- The pathological input: many `/*` starts, never a `*/`. The old gsub is
-- O(n^2) here (~5.4s at 64KB); the new scan is O(n) (sub-millisecond). A
-- generous 2s ceiling cleanly separates the two and won't flake on slow CI.
do
  local L = 65536
  local pathological = ("/*a"):rep(math.floor(L / 3)):sub(1, L)
  local t0 = os.clock()
  local out = strip(pathological)
  local dt = os.clock() - t0
  check(dt < 2.0,
    string.format("64KB pathological input must strip in O(n) time (took %.3fs; a revert to the /%%*.-%%*/ gsub takes ~5s)", dt))
  -- ...and still be correct: no `*/` anywhere, so nothing is removed.
  check(out == pathological, "pathological input has no valid block comment, so it is returned verbatim")
end

if fails > 0 then
  io.stderr:write("\n" .. fails .. " check(s) failed in cfm_waf_sqlcomment_strip_test.lua\n")
  os.exit(1)
end
io.stdout:write("ok: strip_sql_comments parity (" .. cases .. " fuzz cases) + O(n) linearity\n")

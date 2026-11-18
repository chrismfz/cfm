-- Tests for util.strip_sql_comments_query — the SQL-comment stripper run
-- before the SQLi detectors scan the (attacker-controlled) PATH + QUERY
-- surface. (The args+body surface keeps util.strip_sql_comments, pinned by
-- cfm_waf_sqlcomment_strip_test.lua.)
--
-- The block-comment removal used a `/%*.-%*/` gsub whose lazy `.-` was O(n^2)
-- on crafted input with many `/*` starts and no closing `*/` (e.g.
-- `?x=/*a/*a/*a...`): each unmatched `/*` re-scanned to end-of-string, then
-- gsub advanced a byte and repeated. Because this runs up to 3x/request across
-- the SQLi rules, it was a CPU-DoS amplifier (~5ms at the 2048 scan cap, ~5.4s
-- at a 64KB request line). The fix replaces it with a single-pass O(n) scan.
--
-- Since 2026-11-18 a comment no longer hides what follows its parameter or
-- the path (a `?x=--` used to hide every later parameter from the SQLi rules;
-- the strip adds a reading of each part between `&` and `?`), a MySQL
-- executable comment `/*!NNNNN…*/` keeps its content (the server runs it), and
-- a `--` comment leaves ` --` behind (docs/waf.md "SQLi gaps, 2026-11-18").
--
-- Three things must hold, and this file asserts them:
--   1. BEHAVIOUR — hand-picked cases, incl. the bypasses this exists for.
--   2. PARITY — the O(n) scan equals a gsub reference of the same rules for
--      every input of a deterministic fuzz corpus. The reference keeps the
--      ORIGINAL `/%*.-%*/` gsub's shortest-close semantics, applied per part
--      and to the whole string.
--   3. LINEAR — a 64KB pathological input completes in well under a threshold
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
local strip = util.strip_sql_comments_query

-- The reference: the original gsub pair, with the executable-comment unwrap
-- and the ` --` marker, applied to each `&`-separated part.
local function ref_part(s, glued)
  s = s:gsub("/%*(.-)%*/", function(c)
    local run = c:match("^[mM]?!%d*(.*)$")
    if run and run ~= "" then return glued and run or (" " .. run .. " ") end
    return ""
  end)
  return (s:gsub("%-%-[^\n]*\n", "\n"):gsub("%-%-[^\n]*$", " --"))
end
local function ref_reading(s, glued)
  if not s:find("[&?]") then return ref_part(s, glued) end
  -- split by hand (not the scan's gmatch), delimiters kept
  local out, cur = {}, {}
  for i = 1, #s do
    local c = s:sub(i, i)
    if c == "&" or c == "?" then
      out[#out + 1] = ref_part(table.concat(cur), glued) .. c
      cur = {}
    else
      cur[#cur + 1] = c
    end
  end
  out[#out + 1] = ref_part(table.concat(cur), glued)
  return table.concat(out) .. "&" .. ref_part(s, glued)
end
local function strip_ref(s)
  if not s:find("/*", 1, true) and not s:find("--", 1, true) then return s end
  local r = ref_reading(s, false)
  if s:find("/%*[mM]?!") then r = r .. "&" .. ref_reading(s, true) end
  return r
end

local fails = 0
local function check(cond, msg)
  if cond then return end
  fails = fails + 1
  io.stderr:write("FAIL: " .. msg .. "\n")
end

local function is(s, want, label)
  local got = strip(s)
  check(got == want,
    (label or "case") .. "\n  in   = " .. string.format("%q", s) ..
    "\n  got  = " .. string.format("%q", got) ..
    "\n  want = " .. string.format("%q", want))
  local r = strip_ref(s)
  check(got == r, (label or "case") .. ": scan differs from the reference: " ..
    string.format("%q vs %q", got, r))
end

-- ── 1) Hand-picked cases ─────────────────────────────────────────────────────
is("",                          "",                      "empty")
is("no comments here",          "no comments here",      "plain text")
is("/**/",                      "",                      "empty block comment")
is("a/*A*/b",                   "ab",                    "block comment between text")
is("/*A/*B*/C*/",               "C*/",                   "nested-looking: shortest close, C*/ survives")
is("/*/",                       "/*/",                   "slash-star-slash: no valid close, verbatim")
is("/*a/*a/*a",                 "/*a/*a/*a",             "unterminated: verbatim")
is("un/**/ion se/**/lect",      "union select",          "the keyword-splitting bypass")
is("-- line comment\nkeep",     "\nkeep",                "line comment stripped to newline")
is("1'--\nunion select",        "1'\nunion select",       "a comment the next line continues: no marker")
is("select 1 -- ",              "select 1  --",          "trailing line comment keeps a marker")
is("val*/orphan",               "val*/orphan",           "orphan close, verbatim")
-- a comment never reaches past its parameter
is("x=--&id=1' union select 1", "x= --&id=1' union select 1&x= --", "`--` stops at `&`")
is("x=a--b&id=1;waitfor delay", "x=a --&id=1;waitfor delay&x=a --",  "`--` mid-value stops at `&`")
is("a=/*&id=1' or 1=1&b=*/",    "a=/*&id=1' or 1=1&b=*/&a=",   "`/*` and `*/` in different parameters")
is("id=1'/*&*/union select",    "id=1'/*&*/union select&id=1'union select", "a decoded `&` inside a comment")
is("&&", "&&", "empty parameters, no comment: unchanged")
is("/index.php/--?id=1' union", "/index.php/ --?id=1' union&/index.php/ --",  "`--` in the path stops at `?`")
is('a="--"&q=1', 'a=" --&q=1&a=" --',          "`\"` is not a delimiter")
-- executable comments keep their content
is("0' /*!11110procedure*/ /*!11110analyse*/ (/*!11110extractvalue*/(1",
   "0'  procedure   analyse  ( extractvalue (1&0' procedure analyse (extractvalue(1",
   "versioned executable comments: spaced reading, then glued")
is("1/*!union*//*!50000select*/2", "1 union  select 2&1unionselect2", "unversioned + versioned, adjacent")
is("1'union/*!all*/select", "1'union all select&1'unionallselect", "content between keywords (union all select)")
is("/*M!100000sleep(5)*/",      " sleep(5) &sleep(5)",   "MariaDB /*M!…*/")
is("/*!*/",                     "&",                     "empty executable comment: removed, as before")
is("/* !x*/",                   "",                      "a space before ! is a plain comment")

-- ── 2) Deterministic fuzz corpus (scan == reference) ─────────────────────────
-- Alphabet biased toward the comment metacharacters so /*, */, /*!, -- and &
-- actually form and interleave. Fixed seed → reproducible.
math.randomseed(20260712)
local alpha = { "/", "*", "-", "\n", " ", "a", "!", "&", "1", "m", "?", '"' }
local NA = #alpha
local cases = 0
for _ = 1, 20000 do
  local n = math.random(0, 40)
  local t = {}
  for j = 1, n do t[j] = alpha[math.random(1, NA)] end
  local s = table.concat(t)
  cases = cases + 1
  local got, want = strip(s), strip_ref(s)
  if got ~= want then
    fails = fails + 1
    io.stderr:write("FUZZ FAIL: in=" .. string.format("%q", s) ..
      " new=" .. string.format("%q", got) ..
      " ref=" .. string.format("%q", want) .. "\n")
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

-- A run of dashes with no newline: a `%-%-[^\n]*\n` gsub backtracks to the end
-- for every `--` (O(n^2): 8 KB cost ~0.5 s). The scan cuts with plain finds.
do
  local t0 = os.clock()
  strip(("-"):rep(65536))
  strip("\n" .. ("-"):rep(65536))
  strip(("a--b&"):rep(13000))
  local dt = os.clock() - t0
  check(dt < 2.0, string.format("64KB dash runs must strip in O(n) time (took %.3fs)", dt))
end

if fails > 0 then
  io.stderr:write("\n" .. fails .. " check(s) failed in cfm_waf_sqlcomment_query_strip_test.lua\n")
  os.exit(1)
end
io.stdout:write("ok: strip_sql_comments_query behaviour + reference parity (" .. cases .. " fuzz cases) + O(n) linearity\n")

-- Tests for util.body_budget: content-type-aware body-scan budget.
--
-- Verifies that:
--   * each known Content-Type returns its configured budget
--   * missing / empty / unknown Content-Type returns the "other" default
--   * Content-Type parameters after ";" (charset, boundary) are handled
--   * table-form header values (duplicates) are collapsed to first non-empty
--   * lower-cased and Mixed-Case header keys both resolve
--   * fallback to CFG.max_scan_len when body_scan_budget is missing
--   * cap() honours the picked budget end-to-end (via the engine's
--     get_norm_ab path) — body bytes past the picked budget are dropped
--     but body bytes within it survive

_G.ngx = {
  now            = function() return 1000 end,
  decode_base64  = function(_) return nil end,
  log            = function(_, _) end,
  ERR            = 0, WARN = 1, INFO = 2,
}

package.path = "configs/lua/?.lua;" .. package.path
local util = require("cfm_waf_util")
local waf  = require("cfm_waf")

local fails = 0
local function check(cond, msg)
  if cond then return end
  fails = fails + 1
  io.stderr:write("FAIL: " .. msg .. "\n")
end

-- The engine wires CFG into util via util.init(CFG) at module load; loading
-- cfm_waf above triggers that, so util.body_budget already sees the live
-- CFG.body_scan_budget table.

-- ── Test 1: known content-types map to their budgets ─────────────────────────
do
  local cases = {
    { ct = "application/json",                             want = 32768, label = "json" },
    { ct = "application/json; charset=utf-8",              want = 32768, label = "json+charset" },
    { ct = "multipart/form-data; boundary=----abc",        want = 16384, label = "multipart" },
    { ct = "application/x-www-form-urlencoded",            want = 8192,  label = "urlencoded" },
    { ct = "application/x-www-form-urlencoded; charset=utf-8", want = 8192, label = "urlencoded+charset" },
    { ct = "application/xml",                              want = 16384, label = "xml-app" },
    { ct = "text/xml; charset=utf-8",                      want = 16384, label = "xml-text" },
  }
  for _, c in ipairs(cases) do
    local got = util.body_budget({ ["content-type"] = c.ct })
    check(got == c.want,
      "content-type " .. c.label .. " budget=" .. tostring(got) .. " want=" .. tostring(c.want))
  end
end

-- ── Test 2: missing / empty / unknown content-type returns "other" ───────────
do
  check(util.body_budget(nil) == 2048,           "nil headers -> other")
  check(util.body_budget({}) == 2048,            "no content-type -> other")
  check(util.body_budget({ ["content-type"] = "" })   == 2048, "empty content-type -> other")
  check(util.body_budget({ ["content-type"] = "text/plain" }) == 2048, "text/plain -> other")
  check(util.body_budget({ ["content-type"] = "application/octet-stream" }) == 2048, "octet-stream -> other")
end

-- ── Test 3: table-form header values (multiple Content-Type headers) ─────────
do
  -- ngx.req.get_headers() can return a table when a header appears multiple
  -- times. header_string() collapses to the first non-empty string.
  local got = util.body_budget({ ["content-type"] = { "", "application/json" } })
  check(got == 32768, "table-form duplicate header collapses to first non-empty")
end

-- ── Test 4: Mixed-case header key fallback ───────────────────────────────────
do
  -- OpenResty normalises keys to lower-case, but be defensive: explicit
  -- "Content-Type" key must also resolve.
  local got = util.body_budget({ ["Content-Type"] = "application/json" })
  check(got == 32768, "Mixed-case Content-Type key resolves")
end

-- ── Test 5: fallback to CFG.max_scan_len when budget table absent ────────────
do
  -- Simulate a stale config layout by stashing and clearing the budget
  -- table on the live CFG, then restoring it.
  local snap = waf.get_config()
  -- get_config returns a shallow copy, so we can't mutate via it. Instead,
  -- exercise the fallback by passing an isolated CFG to a fresh util via
  -- the same module's init.
  local fresh_util = loadfile("configs/lua/cfm_waf_util.lua")()
  fresh_util.init({ max_scan_len = 1234 })  -- no body_scan_budget at all
  check(fresh_util.body_budget({ ["content-type"] = "application/json" }) == 1234,
    "missing body_scan_budget falls back to CFG.max_scan_len")
  check(fresh_util.body_budget(nil) == 1234,
    "missing body_scan_budget + nil headers falls back to CFG.max_scan_len")

  fresh_util.init({})  -- both absent
  check(fresh_util.body_budget(nil) == 2048,
    "missing CFG entirely defaults to 2048")
  -- snap unused; included to assert get_config() is still callable post-load.
  check(type(snap) == "table" and snap.max_scan_len == 2048,
    "live CFG still exposes max_scan_len = 2048 fallback")
end

-- ── Test 5b: defensive config — malformed body_scan_budget must never crash ──
-- A user override (cfm_waf_config.lua) can replace any CFG entry. body_budget
-- runs on every body-aware request, so a bad override must fall back rather
-- than bubble nil / non-numeric values into cap(), where #s <= n would error.
do
  local cases = {
    { cfg = { max_scan_len = 4096, body_scan_budget = "not a table" }, want = 4096, label = "non-table -> max_scan_len" },
    { cfg = { max_scan_len = 4096, body_scan_budget = 1234 },          want = 4096, label = "number -> max_scan_len" },
    { cfg = { max_scan_len = 4096, body_scan_budget = {} },            want = 4096, label = "empty table -> max_scan_len (no other)" },
    { cfg = { max_scan_len = 4096, body_scan_budget = { other = 999 } }, want = 999,  label = "only other -> other" },
    { cfg = { max_scan_len = 4096, body_scan_budget = { json = -1, other = 999 } },     want = 999,  label = "negative json -> other" },
    { cfg = { max_scan_len = 4096, body_scan_budget = { json = 0,  other = 999 } },     want = 999,  label = "zero json -> other" },
    { cfg = { max_scan_len = 4096, body_scan_budget = { json = "32k", other = 999 } },  want = 999,  label = "string json -> other" },
    { cfg = { max_scan_len = 4096, body_scan_budget = { json = -1, other = -1 } },      want = 4096, label = "all bad -> max_scan_len" },
    { cfg = {},                                                                          want = 2048, label = "no CFG entries at all -> 2048" },
  }
  for _, c in ipairs(cases) do
    local fresh = loadfile("configs/lua/cfm_waf_util.lua")()
    fresh.init(c.cfg)
    local got = fresh.body_budget({ ["content-type"] = "application/json" })
    check(got == c.want,
      "defensive json: " .. c.label .. " budget=" .. tostring(got) .. " want=" .. tostring(c.want))
  end
end

-- ── Test 6: end-to-end via the engine's body scan (smoke) ────────────────────
-- The body-aware scan in cfm_waf.lua (get_norm_ab) feeds rule_php_wrappers,
-- among others. With a 2 KB legacy cap, a php:// marker placed past byte
-- 2048 in a JSON body would be truncated away and never matched. With the
-- 32 KB json budget, it stays visible. We disable every other rule first
-- to keep the assertion deterministic.
do
  local function disable_all_rules()
    local snap = waf.get_config()
    for k, _ in pairs(snap) do
      if k:sub(1, 5) == "rule_" then
        waf.set_rule(k, "disabled")
      end
    end
  end

  -- Sanity: with json budget at 32KB the marker must be reachable.
  disable_all_rules()
  waf.set_rule("rule_php_wrappers", "block")

  local filler  = string.rep("a", 2500)
  local payload = '"f":"php://input"'
  local body    = '{"pad":"' .. filler .. '",' .. payload .. '}'

  local hit, _reason, _ttl, action = waf.check({
    uri     = "/",
    args    = "",
    method  = "POST",
    ip      = "1.2.3.4",
    headers = { ["content-type"] = "application/json" },
    body    = body,
  })

  check(hit == true,        "json body > 2KB php-wrapper: hit expected")
  check(action == "block",  "json body > 2KB php-wrapper: action=block expected, got " .. tostring(action))

  -- Negative control: same payload, but Content-Type that maps to "other"
  -- (2048 budget). The marker now sits past the cap and must NOT be seen.
  disable_all_rules()
  waf.set_rule("rule_php_wrappers", "block")

  local hit2, _r2, _t2, action2 = waf.check({
    uri     = "/",
    args    = "",
    method  = "POST",
    ip      = "5.6.7.8",
    headers = { ["content-type"] = "text/plain" },
    body    = body,
  })

  check(hit2 == false,    "text/plain body > 2KB php-wrapper: must NOT hit (other budget=2048)")
  check(action2 == nil,   "text/plain body > 2KB php-wrapper: action=nil expected, got " .. tostring(action2))
end

-- ── Test 7: normalize() fast path is semantically identical ──────────────────
-- The fast path (no "%" in input) skips both url_decode_once gsubs. Verify
-- that for a representative set of inputs the result still matches what
-- the slow path would produce. Build a fresh util module loaded with a
-- dummy CFG to access its private helpers.
do
  -- Slow-path reference: replicate the original normalize using the public
  -- helpers we still have. url_decode_once isn't exported, so test by
  -- comparing fast-path output to manually-constructed expectations.
  local cases = {
    { input = "Hello, World",          want = "hello, world",       label = "ascii no %" },
    { input = "ABC123",                want = "abc123",             label = "no special chars" },
    { input = "",                      want = "",                   label = "empty" },
    { input = "{\"a\":1,\"b\":\"X\"}", want = "{\"a\":1,\"b\":\"x\"}", label = "json no %" },
    -- With "%": slow path runs url_decode_once twice. Both should produce
    -- the same output regardless of fast path, since the input is the same.
    { input = "%41%42",                want = "ab",                 label = "double-decoded ascii" },
    { input = "abc%20def",             want = "abc def",            label = "single decode space" },
    { input = "100%",                  want = "100%",               label = "trailing % no hex (slow path no-op)" },
    { input = "%2541",                 want = "a",                  label = "double-encoded A" },
  }
  for _, c in ipairs(cases) do
    -- Use util.normalize indirectly: util.scan_str(uri="", args=input) calls
    -- normalize(cap(input, budget)). For these short inputs cap is a no-op.
    local got = util.scan_str("", c.input)
    -- scan_str prepends "?" between uri and args, so input becomes "?<c.input>".
    local want = "?" .. c.want
    check(got == want,
      "normalize semantics " .. c.label .. ": got=" .. tostring(got) .. " want=" .. tostring(want))
  end
end

-- ── Test 8: pre-cap before concat keeps end-to-end semantics ─────────────────
-- Body of 1MB followed by a php:// marker beyond the json budget cap. The
-- marker MUST NOT be visible regardless of optimisation, because cap() still
-- enforces the final ceiling. This guards against an off-by-one in the
-- pre-cap path letting truncated bytes leak through.
do
  local function disable_all_rules()
    local snap = waf.get_config()
    for k, _ in pairs(snap) do
      if k:sub(1, 5) == "rule_" then
        waf.set_rule(k, "disabled")
      end
    end
  end

  disable_all_rules()
  waf.set_rule("rule_php_wrappers", "block")

  -- 35KB filler (past json budget=32768), then a php:// marker at the very end.
  local filler  = string.rep("a", 35000)
  local body    = '{"pad":"' .. filler .. '","f":"php://input"}'

  local hit, _r, _t, action = waf.check({
    uri     = "/",
    args    = "",
    method  = "POST",
    ip      = "1.2.3.4",
    headers = { ["content-type"] = "application/json" },
    body    = body,
  })

  check(hit == false,    "pre-cap: marker past budget must NOT be visible (got hit=" .. tostring(hit) .. ")")
  check(action == nil,   "pre-cap: action=nil expected, got " .. tostring(action))

  -- Now move the marker into-budget (body around 30K) — must hit, confirming
  -- the pre-cap doesn't accidentally truncate too aggressively.
  disable_all_rules()
  waf.set_rule("rule_php_wrappers", "block")
  local in_budget_body = '{"pad":"' .. string.rep("a", 30000) .. '","f":"php://input"}'
  local hit2, _r2, _t2, action2 = waf.check({
    uri     = "/",
    args    = "",
    method  = "POST",
    ip      = "5.6.7.8",
    headers = { ["content-type"] = "application/json" },
    body    = in_budget_body,
  })
  check(hit2 == true,        "pre-cap: marker within budget MUST be visible")
  check(action2 == "block",  "pre-cap: action=block expected, got " .. tostring(action2))
end

-- ── Test 9: a padded query string must NOT evict the POST body (audit F09) ────
-- get_norm_ab now caps args and body INDEPENDENTLY. Before the fix it did
-- cap(args .. "&" .. body, budget) with args first, so a query string padded to
-- the budget pushed the body — and any body-borne payload — out of every
-- body-aware rule's scan surface (php_wrappers here, but also ssrf/sqli/…).
do
  local function disable_all_rules()
    local snap = waf.get_config()
    for k, _ in pairs(snap) do
      if k:sub(1, 5) == "rule_" then waf.set_rule(k, "disabled") end
    end
  end

  -- urlencoded budget = 8192; pad the query past it. The php:// marker lives in
  -- the (short) body, so only a body that survives the cap can be seen.
  local padded_args = string.rep("x=1&", 2500)   -- ~10 KB, well over 8192
  local body        = "f=php://input"

  -- Baseline: short args, marker in body → seen (works before and after the fix).
  disable_all_rules(); waf.set_rule("rule_php_wrappers", "block")
  local hit0 = waf.check({
    uri = "/", args = "a=1", method = "POST", ip = "1.1.1.1",
    headers = { ["content-type"] = "application/x-www-form-urlencoded" }, body = body,
  })
  check(hit0 == true, "F09 baseline: php:// in body with short args must hit")

  -- The bug case: a query padded past the budget must NOT evict the body.
  -- Pre-fix this returned hit=false (body truncated away); post-fix it hits.
  disable_all_rules(); waf.set_rule("rule_php_wrappers", "block")
  local hit1, _r9, _t9, action1 = waf.check({
    uri = "/", args = padded_args, method = "POST", ip = "2.2.2.2",
    headers = { ["content-type"] = "application/x-www-form-urlencoded" }, body = body,
  })
  check(hit1 == true,       "F09: padded query must NOT evict the body php:// (got hit=" .. tostring(hit1) .. ")")
  check(action1 == "block", "F09: action=block expected with padded args, got " .. tostring(action1))

  -- Cross-budget: JSON budget (32768) — pad the query past it, php:// in the body.
  disable_all_rules(); waf.set_rule("rule_php_wrappers", "block")
  local json_pad = string.rep("x=1&", 8500)   -- ~34 KB, over the 32768 json budget
  local jhit = waf.check({
    uri = "/", args = json_pad, method = "POST", ip = "3.3.3.3",
    headers = { ["content-type"] = "application/json" }, body = '{"f":"php://input"}',
  })
  check(jhit == true, "F09 (json budget): padded query must NOT evict the body php://")

  -- Second detector: body-borne SQLi via get_norm_ab must survive a padded query.
  disable_all_rules(); waf.set_rule("rule_sqli", "block")
  local shit, sreason = waf.check({
    uri = "/", args = padded_args, method = "POST", ip = "4.4.4.4",
    headers = { ["content-type"] = "application/x-www-form-urlencoded" },
    body = "q=1 UNION SELECT username,password FROM users",
  })
  check(shit == true and sreason == "WAF_SQLI",
    "F09 (sqli): padded query must NOT evict a body-borne UNION SELECT (got hit=" .. tostring(shit) .. " reason=" .. tostring(sreason) .. ")")

  -- Separate scan surface: detect_crlf_injection builds its own args&body string
  -- (rule 605) and had the same args-first eviction — now capped independently.
  disable_all_rules(); waf.set_rule("rule_crlf_injection", "block")
  local crlf_pad = string.rep("x=1&", 600)   -- ~2.4 KB, over max_scan_len 2048
  local chit, creason = waf.check({
    uri = "/", args = crlf_pad, method = "POST", ip = "6.6.6.6",
    headers = { ["content-type"] = "application/x-www-form-urlencoded" },
    -- lowercase header name: detect_crlf_injection matches case-sensitively
    -- (that case gap is a separate finding, F34); here we only assert the body
    -- survives a padded query.
    body = "u=x\r\nset-cookie: evil=1",
  })
  check(chit == true and creason == "WAF_CRLF:CRLF_SET_COOKIE",
    "F09 (crlf): padded query must NOT evict a body-borne CRLF injection (got hit=" .. tostring(chit) .. " reason=" .. tostring(creason) .. ")")
end

-- ── Test 10 (F08): the cfm.lua body reader must not truncate below the WAF's
-- largest per-Content-Type budget, or that budget is unreachable ──────────────
-- cfm.lua reads at most `waf_body_max_len` body bytes and hands them to the WAF,
-- which then applies `body_scan_budget[ct]`. If the reader cap is smaller than
-- the biggest budget (json = 32768), a JSON/multipart/xml payload past the cap
-- escapes every body-aware rule regardless of the budget. Assert the invariant
-- against the LIVE budgets (via util.body_budget) and cfm.lua's actual default.
do
  local max_budget = 0
  for _, ct in ipairs({
    "application/json",
    "application/x-www-form-urlencoded",
    "multipart/form-data; boundary=x",
    "text/xml",
    "application/octet-stream",   -- -> "other"
  }) do
    local b = util.body_budget({ ["content-type"] = ct })
    if type(b) == "number" and b > max_budget then max_budget = b end
  end
  check(max_budget == 32768,
    "max body_scan_budget expected 32768 (json); got " .. tostring(max_budget) ..
    " — if a budget was raised, raise cfm.lua waf_body_max_len to match")

  local fh = assert(io.open("configs/lua/cfm.lua", "r"))
  local src = fh:read("*a"); fh:close()
  local cap = tonumber(src:match('CFM_WAF_BODY_MAX_LEN"%)%s*or%s*"(%d+)"'))
  check(cap ~= nil, "could not read waf_body_max_len default from cfm.lua")
  check(cap ~= nil and cap >= max_budget,
    "F08: cfm.lua waf_body_max_len default (" .. tostring(cap) .. ") must be >= " ..
    "max body_scan_budget (" .. tostring(max_budget) .. "), else the WAF budget " ..
    "is never realised and a body payload past byte " .. tostring(cap) .. " escapes")
end

-- ── Test 11 (F07): ct_is_inspectable — the Content-Type gate for the body-read
-- decision. Inspectable (structured/text) CTs -> read+scan; binary/media CTs ->
-- skip (so large uploads keep streaming past the proxy_request_buffering=off
-- media location instead of being buffered). ─────────────────────────────────
do
  local f = util.ct_is_inspectable
  check(type(f) == "function", "ct_is_inspectable is exported")
  local yes = {
    "", "application/json", "application/json; charset=utf-8",
    "application/x-www-form-urlencoded", "multipart/form-data; boundary=----x",
    "text/xml", "application/xml", "application/soap+xml", "text/plain",
    "TEXT/HTML", "Application/JSON",   -- case-insensitive
  }
  local no = {
    "image/png", "image/jpeg", "video/mp4", "audio/mpeg",
    "application/octet-stream", "application/zip", "application/gzip",
    "application/pdf", "font/woff2",
  }
  for _, ct in ipairs(yes) do
    check(f(ct) == true,  "ct_is_inspectable should accept " .. (ct == "" and "<empty>" or ct))
  end
  for _, ct in ipairs(no) do
    check(f(ct) == false, "ct_is_inspectable should skip " .. ct)
  end
end

-- ── Test 12 (F07): waf_body_gate — the pure read/skip truth table that cfm.lua's
-- body-read gate delegates to. Given (Content-Type, numeric Content-Length, cap)
-- it decides whether to read+buffer the body for WAF scanning. This is where the
-- large-upload / chunked-body streaming protections live, unit-tested directly
-- because cfm.lua itself is not loadable. ────────────────────────────────────
do
  local g = util.waf_body_gate
  check(type(g) == "function", "waf_body_gate is exported")
  local CAP = 1048576  -- 1 MiB, matches CFG.waf_body_read_max_cl default
  local cases = {
    -- inspectable CT, measured & within cap -> READ
    { ct = "application/json",                  cl = 500,       want = true,  label = "json small" },
    { ct = "application/x-www-form-urlencoded", cl = CAP,       want = true,  label = "urlencoded at cap" },
    { ct = "text/plain",                        cl = 0,         want = true,  label = "text empty-body" },
    { ct = "",                                  cl = 100,       want = true,  label = "empty CT, measured" },
    -- inspectable CT but OVER the cap -> SKIP (keep streaming; #1 regression fix)
    { ct = "application/json",                  cl = CAP + 1,   want = false, label = "json over cap" },
    { ct = "multipart/form-data; boundary=x",   cl = 50000000,  want = false, label = "multipart 50MB over cap" },
    { ct = "text/plain",                        cl = 3000000000, want = false, label = "text 3GB over cap" },
    -- inspectable CT but UNMEASURABLE (chunked, no Content-Length) -> SKIP (#2 fix)
    { ct = "application/json",                  cl = nil,       want = false, label = "json chunked" },
    { ct = "text/plain",                        cl = nil,       want = false, label = "text chunked" },
    { ct = "multipart/form-data; boundary=x",   cl = nil,       want = false, label = "multipart chunked" },
    { ct = "",                                  cl = nil,       want = false, label = "empty CT chunked" },
    -- non-inspectable CT -> SKIP regardless of size (binary/media stays streaming)
    { ct = "application/octet-stream",          cl = 100,       want = false, label = "octet-stream small" },
    { ct = "application/zip",                   cl = 100,       want = false, label = "zip small" },
    { ct = "image/png",                         cl = nil,       want = false, label = "png chunked" },
    { ct = "video/mp4",                         cl = CAP - 1,   want = false, label = "video within cap" },
  }
  for _, c in ipairs(cases) do
    check(g(c.ct, c.cl, CAP) == c.want,
      "waf_body_gate(" .. c.label .. ") should be " .. tostring(c.want))
  end
  -- default cap kicks in when max_cl arg omitted (falls back to 1 MiB)
  check(g("application/json", 1048576, nil) == true,  "waf_body_gate default cap: 1MiB reads")
  check(g("application/json", 1048577, nil) == false, "waf_body_gate default cap: >1MiB skips")
end

if fails > 0 then
  io.stderr:write("\n" .. fails .. " test(s) failed in cfm_waf_body_budget_test.lua\n")
  os.exit(1)
end

io.stdout:write("cfm_waf_body_budget_test.lua: all tests passed\n")

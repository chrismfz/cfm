-- Tests for detect_smuggling_cl duplicate-header handling (audit F37, rule 608
-- WAF_HTTP_SMUGGLING, production tier: challenge).
--
-- ngx.req.get_headers() returns DUPLICATE header lines as a Lua array (e.g.
-- {"5","10"}), NOT a comma-joined string. The detector derived cl/te via
-- header_string(), which collapses that array to the first element, so the
-- comma-based MULTI_CL/MULTI_TE checks never saw the second value — genuine
-- duplicate Content-Length / Transfer-Encoding lines were silently missed.
-- Fix: guard on the table shape first (mirrors detect_range_abuse's
-- MULTI_RANGE_HEADER), while preserving CL_AND_TE as the top-priority signal.
--
-- Tested at "block" for a crisp hit=true assertion; production tier unchanged.

_G.ngx = {
  now           = function() return 1000 end,
  decode_base64 = function(_) return nil end,
  log           = function(_, _) end,
  ERR           = 0, WARN = 1, INFO = 2,
}

package.path = "configs/lua/?.lua;" .. package.path
local waf = require("cfm_waf")

local fails = 0
local function check(cond, msg)
  if cond then return end
  fails = fails + 1
  io.stderr:write("FAIL: " .. msg .. "\n")
end

local function set_only(map)
  local snap = waf.get_config()
  for k, _ in pairs(snap) do
    if k:sub(1, 5) == "rule_" then waf.set_rule(k, "disabled") end
  end
  for k, m in pairs(map) do waf.set_rule(k, m) end
end

-- ngx.req.get_headers() lowercases keys; duplicate lines arrive as an array.
local function req(hdrs)
  return { uri = "/", args = "", method = "POST", ip = "203.0.113.99", headers = hdrs, body = "" }
end

local function fires(ctx, label, want_reason)
  local hit, reason = waf.check(ctx)
  check(hit == true, label .. " — hit=true (got " .. tostring(hit) .. ")")
  check(reason == want_reason, label .. " — reason=" .. want_reason .. " (got " .. tostring(reason) .. ")")
end
local function clean(ctx, label)
  local hit = waf.check(ctx)
  check(hit ~= true, label .. " — must NOT fire (got hit=" .. tostring(hit) .. ")")
end

set_only({ rule_smuggling_cl = "block" })

-- ── F37: duplicate header LINES (array value) now detected ──────────────────
fires(req({ ["content-length"] = { "5", "10" } }),
      "duplicate Content-Length lines (array)", "WAF_HTTP_SMUGGLING:MULTI_CL")
fires(req({ ["transfer-encoding"] = { "chunked", "identity" } }),
      "duplicate Transfer-Encoding lines (array)", "WAF_HTTP_SMUGGLING:MULTI_TE")

-- ── Priority: CL_AND_TE still wins even when a CL line is duplicated ─────────
fires(req({ ["content-length"] = { "5", "10" }, ["transfer-encoding"] = "chunked" }),
      "duplicate CL + a TE present -> CL_AND_TE (strongest)", "WAF_HTTP_SMUGGLING:CL_AND_TE")

-- ── Regressions: single-value shapes unchanged ──────────────────────────────
fires(req({ ["content-length"] = "5", ["transfer-encoding"] = "chunked" }),
      "both present (single values) -> CL_AND_TE", "WAF_HTTP_SMUGGLING:CL_AND_TE")
fires(req({ ["content-length"] = "5, 10" }),
      "single CL value with inline comma -> MULTI_CL", "WAF_HTTP_SMUGGLING:MULTI_CL")
fires(req({ ["content-length"] = "abc" }),
      "non-integer CL -> CL_MALFORMED", "WAF_HTTP_SMUGGLING:CL_MALFORMED")
fires(req({ ["transfer-encoding"] = "chunked, identity" }),
      "TE chunked not last -> MULTI_TE", "WAF_HTTP_SMUGGLING:MULTI_TE")

-- ── Clean ────────────────────────────────────────────────────────────────────
clean(req({ ["content-length"] = "10" }),               "single valid Content-Length")
clean(req({ ["transfer-encoding"] = "gzip, chunked" }),  "valid chained TE (chunked last)")
clean(req({ ["transfer-encoding"] = "chunked" }),        "single chunked TE")
clean(req({ ["content-type"] = "application/json" }),    "unrelated header only")

if fails > 0 then
  io.stderr:write(("cfm_waf smuggling duplicate-header tests: %d FAILED\n"):format(fails))
  os.exit(1)
end
print("ok: cfm_waf detect_smuggling_cl duplicate CL/TE header lines (F37, rule 608)")
